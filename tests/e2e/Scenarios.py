"""Agent journeys with behavioral oracles, not snapshots of implementation output."""

from concurrent.futures import ThreadPoolExecutor
import hashlib
import io
import json
from pathlib import Path
import socket
import time
import unittest
import zipfile

from Client import Agent, require
from Fixtures import BANNER, BUSY_FUNCTIONS


class Workflows(unittest.TestCase):
    service = None
    fixtures = None
    corpus = []

    def setUp(self):
        self.service.transcript.write(scenario=self.id(), phase="begin")
        self.agent = Agent(self.service.http, self.service.token).start()
        self.projects = []
        self.addCleanup(self.cleanup)

    def cleanup(self):
        # Use a fresh modern session: a failed scenario may have restarted the daemon,
        # rotated its token, or lost the transport while retaining jobs and file children.
        inspector = Agent(self.service.http, self.service.token).start()
        errors = []
        for job in inspector.pages("bn_job_list", "jobs", limit=50):
            try:
                if job["state"] in {"queued", "running"}:
                    inspector.call("bn_job_cancel", job=job["job"])
                    job = inspector.call("bn_job_info", job=job["job"])
                inspector.finish_job(job, allowed=("complete", "cancelled", "failed"))
            except Exception as error:
                errors.append(str(error))
        for item in inspector.pages("bn_open_item_list", "openItems", limit=50):
            try:
                inspector.session = item["analysisSession"]
                inspector.call("bn_open_item_close", openItem=item["openItem"], save="discard")
            except Exception as error:
                errors.append(str(error))
        inspector.session = None
        sessions = inspector.pages("bn_analysis_session_list", "sessions", limit=50)
        for session in sessions:
            try:
                inspector.call("bn_analysis_session_close", analysisSession=session["analysisSession"])
            except Exception as error:
                errors.append(str(error))
        # Retain isolated project databases as failure evidence, but release every
        # runtime handle/job/session. Nothing is imported into the user's catalog.
        state = self.service.portal("GET", "/status")["runtime"]
        require(not errors, "cleanup failed: " + "; ".join(errors))
        for key in ("open_items", "jobs", "analysis_sessions", "active_analyses", "queued_analyses", "allocated_workers"):
            require(state[key] == 0, f"scenario leaked {key}: {state}")
        require(state["memory_bytes"] > 0, f"runtime memory was not reported: {state}")
        public_status_code, _, public_status, _ = self.service.http.request("GET", "/healthz/status")
        require(public_status_code == 200, f"public status returned HTTP {public_status_code}: {public_status}")
        require(isinstance(public_status, dict), f"public status was not an object: {public_status}")
        require(set(public_status) == {"analysis_sessions", "open_items", "active_analyses", "queued_analyses",
                                       "memory_bytes"}, f"public status fields changed: {public_status}")
        require(public_status["memory_bytes"] > 0, f"public memory was not reported: {public_status}")
        self.service.transcript.write(scenario=self.id(), phase="clean")

    def project(self):
        name = "e2e-" + self._testMethodName + "-" + str(len(self.projects))
        result = self.agent.call("bn_local_project_create", name=name, description="End-to-end agent workspace")
        self.projects.append(result["project"])
        return result["project"]

    def open(self, path, agent=None, project=None, view_type=None, options=None, analyze=True):
        agent = agent or self.agent
        arguments = {"path": str(path)}
        if project:
            arguments["project"] = project
        item = agent.call("bn_open_item_open", **arguments)
        candidates = [view for view in item["binaryViews"]
                      if view["viewType"] == view_type] if view_type else [
                          view for view in item["binaryViews"] if view["recommended"]]
        require(len(candidates) == 1, f"ambiguous or absent requested view: {item}")
        candidate = candidates[0]
        require(not candidate["created"], "open unexpectedly materialized a view")
        view = candidate["binaryView"]
        settings = agent.call("bn_binary_view_load_settings", binaryView=view)
        require(isinstance(settings, dict), "no loader settings result")
        opened = agent.call("bn_binary_view_open", binaryView=view, analyze=False, **({"options": options} if options else {}))
        require(opened["created"], f"view not materialized: {opened}")
        if view_type:
            require(opened["viewType"] == view_type, f"loaded wrong format: {opened}")
        if analyze:
            agent.analyze(view)
        return item["openItem"], view

    def function(self, view, name, agent=None):
        rows = (agent or self.agent).pages("bn_function_list", "functions", binaryView=view, query=name)
        exact = [row for row in rows if row["name"].lstrip("_") == name]
        require(len(exact) == 1, f"expected exactly one {name}: {rows}")
        return exact[0]["address"]

    def upload(self, project, filename, data, folder="inputs", multipart=False, chunked=False, **commit_args):
        issued = self.agent.call("bn_upload_get_url", project=project, filename=filename)
        require(issued["authorization"] == "URL capability"
                and "requiresBearerAuthentication" not in issued,
                f"upload capability advertised an additional credential: {issued}")
        body = data
        origin = "https://remote.example.invalid"
        status, response_headers, _, _ = self.service.http.request(
            "OPTIONS", issued["url"], headers={"Origin": origin})
        allowed_headers = {header.strip().lower() for header in
                           response_headers.get("access-control-allow-headers", "").split(",")}
        require(status in {200, 204} and "authorization" not in allowed_headers,
                f"upload preflight advertised bearer authorization: HTTP {status}: {response_headers}")
        headers = {"Content-Type": "application/octet-stream", "Origin": origin}
        method = "PUT"
        if multipart:
            boundary = "binjad-e2e-53104f65"
            body = (f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="{filename}"\r\n'
                    'Content-Type: application/octet-stream\r\n\r\n').encode() + data + f"\r\n--{boundary}--\r\n".encode()
            headers["Content-Type"] = "multipart/form-data; boundary=" + boundary
            method = "POST"
        if chunked:
            encoded = body
            body = (encoded[index:index + 137] for index in range(0, len(encoded), 137))
        status, response_headers, response, _ = self.service.http.request(
            method, issued["url"], body, headers, chunked=chunked)
        require(status in {200, 201}, f"upload failed: HTTP {status}: {response}")
        require(response_headers.get("access-control-allow-origin") == origin,
                "upload response did not echo the request Origin")
        result = self.agent.complete(self.agent.call("bn_upload_commit", id=issued["id"], folder=folder, **commit_args))
        require(result["sha256"] == hashlib.sha256(data).hexdigest(), "uploaded bytes changed")
        require(result["size"] == len(data), "uploaded byte count changed")
        again = self.agent.complete(self.agent.call("bn_upload_commit", id=issued["id"], folder=folder, **commit_args))
        require(again == result, "retrying a committed upload changed its identity or created another file")
        return result

    def download(self, issued):
        origin = "https://remote.example.invalid"
        status, headers, _, _ = self.service.http.request("OPTIONS", issued["url"], headers={"Origin": origin})
        allowed_methods = {method.strip() for method in headers.get("access-control-allow-methods", "").split(",")}
        require(status in {200, 204} and headers.get("access-control-allow-origin") == origin
                and {"GET", "OPTIONS"}.issubset(allowed_methods),
                f"download preflight failed: HTTP {status}: {headers}")
        status, headers, body, _ = self.service.http.request(
            "GET", issued["url"], headers={"Origin": origin}, raw_response=True)
        require(status == 200 and isinstance(body, bytes), f"download failed: HTTP {status}: {body}")
        require(headers.get("access-control-allow-origin") == origin, "download did not echo the request Origin")
        require(headers.get("cache-control") == "no-store", "download response was cacheable")
        require(headers.get("x-content-type-options") == "nosniff", "download response permitted content sniffing")
        require(headers.get("content-type", "").split(";")[0] == issued["contentType"],
                f"download content type changed: {headers}")
        require(headers.get("content-disposition") == "attachment; filename=" + issued["filename"],
                f"download attachment name changed: {headers}")
        require(len(body) == issued["size"], "download byte count changed")
        require(hashlib.sha256(body).hexdigest() == issued["sha256"], "download digest changed")
        status, _, response, _ = self.service.http.request("GET", issued["url"])
        require(status == 404 and response == {"error": "download_not_found"},
                f"one-time download capability was reusable: HTTP {status}: {response}")
        return body

    @staticmethod
    def archive_entries(data):
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            require(archive.testzip() is None, "download ZIP failed its CRC check")
            names = archive.namelist()
            require(all(not name.startswith("/") and "\\" not in name
                        and ".." not in Path(name).parts for name in names),
                    f"download ZIP contains an unsafe path: {names}")
            return names, {name: archive.read(name) for name in names if not name.endswith("/")}

    def inspect_packet(self, fixture, view_type):
        item, view = self.open(self.fixtures[fixture], view_type=view_type)
        header = self.agent.call("bn_binary_header_info", binaryView=view)
        require(header["format"] == view_type and header["addressSize"] == 8, f"wrong header: {header}")
        dispatch = self.function(view, "packet_dispatch")
        checksum = self.function(view, "packet_checksum")
        main = header["entryPoint"] if view_type == "PE" else self.function(view, "main")
        decompiled = self.agent.call("bn_function_decompile", binaryView=view, function=dispatch)["text"]
        require("packet_checksum" in decompiled, "decompiler lost the dispatch-to-checksum call")
        callers = self.agent.pages("bn_function_callers", "callers", binaryView=view, function=checksum)
        require(any(row["caller"]["address"] == dispatch for row in callers), "checksum caller is missing")
        callees = self.agent.pages("bn_function_callees", "callees", binaryView=view, function=main)
        require(any(row["target"] == dispatch for row in callees), "main-to-dispatch edge is missing")
        for level in ("llil", "mlil", "hlil"):
            il = self.agent.call("bn_function_il", binaryView=view, function=checksum, level=level, ssa=True)
            require(il["total"] > 3 and il["text"].strip(), f"{level} is empty")
        strings = self.agent.pages("bn_string_list", "strings", binaryView=view, query="BINJAD-PACKET")
        require(len(strings) == 1, f"banner search returned {strings}")
        address = strings[0]["address"]
        memory = self.agent.call("bn_memory_read", binaryView=view, address=address, length=len(BANNER.encode()) + 1)
        require(bytes.fromhex(memory["hex"]) == BANNER.encode() + b"\0", "mapped banner differs from fixture bytes")
        decoded = self.agent.call("bn_string_at", binaryView=view, address=address)
        require(BANNER in json.dumps(decoded, ensure_ascii=False), f"UTF-8 banner was truncated: {decoded}")
        # Small and large pages must describe the same unchanged analysis, without duplicated rows.
        small = self.agent.pages("bn_function_list", "functions", limit=1, binaryView=view)
        large = self.agent.pages("bn_function_list", "functions", limit=100, binaryView=view)
        require(small == large and len({row["address"] for row in small}) == len(small), "function pagination changed rows")
        full = self.agent.call("bn_function_disassembly", binaryView=view, function=dispatch, limit=1000)
        pieces = []
        offset = 0
        while True:
            part = self.agent.call("bn_function_disassembly", binaryView=view, function=dispatch, offset=offset, limit=3)
            pieces.append(part["text"])
            if not part["truncated"]:
                break
            require(part["nextOffset"] > offset, "disassembly pagination stalled")
            offset = part["nextOffset"]
        require("\n".join(pieces) == full["text"], "disassembly pages differ from complete rendering")
        return item, view

    def test_macho_analysis(self):
        _, view = self.inspect_packet("macho", "Mach-O")
        libraries = self.agent.call("bn_linked_library_list", binaryView=view)
        require("libSystem" in json.dumps(libraries), "Mach-O system dependency is missing")
        commands = self.agent.call("bn_macho_load_command_list", binaryView=view)
        require("LC_MAIN" in json.dumps(commands), "Mach-O executable entry command is missing")

    def test_elf_analysis(self):
        _, view = self.inspect_packet("elf", "ELF")
        headers = self.agent.call("bn_elf_program_header_list", binaryView=view)
        require("LOAD" in json.dumps(headers), "ELF loadable segment is missing")

    def test_pe_analysis(self):
        _, view = self.inspect_packet("pe", "PE")
        exports = self.agent.call("bn_export_list", binaryView=view, query="packet_dispatch")
        require("packet_dispatch" in json.dumps(exports), "PE dispatcher export is missing")
        self.agent.call("bn_pe_data_directory_list", binaryView=view)

    def test_stripped_recovery(self):
        _, named = self.open(self.fixtures["elf"])
        _, stripped = self.open(self.fixtures["stripped"])
        dispatch = self.function(named, "packet_dispatch")
        require(not self.agent.call("bn_function_list", binaryView=stripped, query="packet_dispatch")["functions"],
                "stripped fixture unexpectedly retained dispatcher symbols")
        functions = self.agent.call("bn_function_list", binaryView=stripped, address=dispatch)["functions"]
        require(len(functions) == 1, "analysis did not recover the stripped dispatcher")
        # Both link commands place the same .text at the same address. Compare the actual mapped bytes.
        first = self.agent.call("bn_memory_read", binaryView=named, address=dispatch, length=32)
        second = self.agent.call("bn_memory_read", binaryView=stripped, address=dispatch, length=32)
        require(first["hex"] == second["hex"], "stripped and named binaries are not the same code")
        self.agent.call("bn_symbol_define", binaryView=stripped, address=dispatch, name="recovered_dispatch", type="FunctionSymbol")
        self.agent.analyze(stripped)
        require(self.function(stripped, "recovered_dispatch") == dispatch, "function rename changed identity")
        text = self.agent.call("bn_function_decompile", binaryView=stripped, function=dispatch)["text"]
        require("recovered_dispatch" in text and len(text.splitlines()) > 5, "stripped function did not decompile")

    def test_raw_firmware_save_reopen(self):
        item, view = self.open(self.fixtures["raw"], view_type="Mapped", options={
            "loader.platform": "linux-aarch64", "loader.imageBase": 0x80000000, "loader.entryPointOffset": 0})
        self.agent.call("bn_function_create", binaryView=view, address="0x80000000")
        self.agent.analyze(view)
        text = self.agent.call("bn_function_decompile", binaryView=view, function="0x80000000")["text"]
        require("0x2a" in text.lower() or "42" in text, f"firmware constant was not recovered: {text}")
        self.agent.call("bn_comment_set", binaryView=view, address="0x80000000", text="firmware reset returns 42")
        saved = self.agent.complete(self.agent.call("bn_binary_view_save", binaryView=view))
        self.agent.call("bn_open_item_close", openItem=item, save="discard")
        _, reopened = self.open(saved["destination"], analyze=False)
        require(self.agent.call("bn_comment_get", binaryView=reopened, address="0x80000000")["text"] ==
                "firmware reset returns 42", "raw-mapped annotation was not persisted")
        memory = self.agent.call("bn_memory_read", binaryView=reopened, address="0x80000100", length=len(BANNER.encode()))
        require(bytes.fromhex(memory["hex"]) == BANNER.encode(), "firmware mapping changed after reopen")

    def test_uploads_and_project_documents(self):
        project = self.project()
        binary = self.fixtures["elf"].read_bytes()
        uploaded = self.upload(project, "packet café.elf", binary, chunked=True, open=True, analyze=True)
        item = uploaded["openItem"]
        view = next(row["binaryView"] for row in item["binaryViews"] if row["recommended"])
        self.function(view, "packet_dispatch")
        report = "# Findings\npacket checksum confirmed\nUTF-8 café 日本\npacket dispatch confirmed\n"
        self.upload(project, "report.md", report.encode(), folder="reports/nested", multipart=True)
        lines = self.agent.pages("bn_project_text_read", "lines", project=project, path="reports/nested/report.md", limit=1)
        require([row["text"] for row in lines] == report.splitlines(), "project text pagination changed the report")
        matches = self.agent.pages("bn_project_text_read", "lines", project=project, path="reports/nested/report.md", query="PACKET", limit=1)
        require([row["line"] for row in matches] == [2, 4], "filtered report lost original line numbers")
        inventory = {"a/b": {"~entry": ["café", 42, {"verified": True}]}}
        self.upload(project, "inventory.json", json.dumps(inventory).encode(), folder="reports", multipart=True, chunked=True)
        leaf = self.agent.call("bn_project_json_read", project=project, path="reports/inventory.json", pointer="/a~1b/~0entry/1")
        require(leaf["value"] == {"type": "number", "value": 42}, f"JSON Pointer did not select its value: {leaf}")
        files = self.agent.pages("bn_local_project_file_list", "files", project=project, limit=1)
        require({row["path"] for row in files} == {"inputs/packet café.elf", "reports/nested/report.md", "reports/inventory.json"},
                "upload retry or folder creation changed project contents")
        self.agent.call("bn_local_project_file_update", project=project, path="reports/inventory.json", description="checked inventory")
        row = self.agent.call("bn_local_project_file_list", project=project, query="inventory")["files"][0]
        require(row["description"] == "checked inventory", "project description was not stored")

    def test_persistence_across_daemon_restart(self):
        project = self.project()
        self.agent.call("bn_local_project_file_import", project=project, source=str(self.fixtures["macho"]), name="packet.macho")
        item, view = self.open("packet.macho", project=project)
        dispatch = self.function(view, "packet_dispatch")
        self.agent.call("bn_type_define", binaryView=view, source=(
            "struct E2EPacket { unsigned int opcode; unsigned int length; const unsigned char *payload; };"))
        self.agent.call("bn_symbol_define", binaryView=view, address=dispatch, name="reviewed_dispatch", type="FunctionSymbol")
        self.agent.call("bn_function_prototype_set", binaryView=view, function=dispatch,
                        prototype="int reviewed_dispatch(struct E2EPacket* packet);")
        self.agent.analyze(view)
        variables = self.agent.call("bn_variable_list", binaryView=view, function=dispatch)["variables"]
        packet = [row for row in variables if row["name"] == "packet"]
        require(len(packet) == 1, f"prototype argument was not materialized: {variables}")
        self.agent.call("bn_variable_rename", binaryView=view, function=dispatch, variable="packet", newName="requestPacket")
        self.agent.analyze(view)
        self.agent.call("bn_comment_set", binaryView=view, address=dispatch, text="Reviewed length guard — café 日本")
        self.agent.call("bn_bookmark_create", binaryView=view, address=dispatch, note="dispatch review")
        self.agent.call("bn_metadata_set", binaryView=view, key="review", value={"status": "verified", "count": 3})
        saved = self.agent.complete(self.agent.call("bn_binary_view_save", binaryView=view))
        require(saved["createdDatabase"] and saved["destination"] == "packet.macho.bndb", f"wrong save target: {saved}")
        # A second save exercises the existing-BNDB snapshot/commit path.
        self.agent.call("bn_comment_set", binaryView=view, address=dispatch, text="Reviewed twice — café 日本")
        again = self.agent.complete(self.agent.call("bn_binary_view_save_async", binaryView=view))
        require(not again["createdDatabase"] and again["destination"] == saved["destination"], "second save created another database")
        self.agent.call("bn_open_item_close", openItem=item, save="discard")
        project_name = self.agent.call("bn_local_project_info", project=project)["name"]
        self.service.restart()
        self.agent = Agent(self.service.http, self.service.token).start()
        # Friendly references are not durable across daemon lifetimes. Rediscover the project.
        projects = self.agent.pages("bn_local_project_list", "projects", limit=50)
        project = next(row["project"] for row in projects if row["name"] == project_name)
        self.projects = [project]
        files = self.agent.pages("bn_local_project_file_list", "files", project=project)
        require({row["path"] for row in files} == {"packet.macho", "packet.macho.bndb"}, "save lost the original or duplicated the BNDB")
        reopened_item, reopened = self.open(saved["destination"], project=project, analyze=False)
        require(self.function(reopened, "reviewed_dispatch") == dispatch, "function name was not persisted")
        require(self.agent.call("bn_comment_get", binaryView=reopened, address=dispatch)["text"] == "Reviewed twice — café 日本",
                "latest comment was not persisted")
        info = self.agent.call("bn_type_info", binaryView=reopened, type="E2EPacket")
        require("payload" in json.dumps(info), "user structure was not persisted")
        variables = self.agent.call("bn_variable_list", binaryView=reopened, function=dispatch)["variables"]
        require(any(row["name"] == "requestPacket" for row in variables), "argument rename was not persisted")
        bookmarks = self.agent.call("bn_bookmark_list", binaryView=reopened)
        require("dispatch review" in json.dumps(bookmarks), "bookmark was not persisted")
        metadata = self.agent.call("bn_metadata_get", binaryView=reopened, key="review")
        require(metadata["value"] == {"status": "verified", "count": 3}, "custom metadata was not persisted")
        url = self.agent.call("bn_url_project_file", openItem=reopened_item, updated_bndb_has_been_saved=True)
        require("binaryninja:" in json.dumps(url), "saved project link is not a Binary Ninja URL")

    def test_parallel_sessions_and_cancellation(self):
        other = Agent(self.service.http, self.service.token).start()
        with ThreadPoolExecutor(max_workers=3) as pool:
            first = pool.submit(self.open, self.fixtures["busy"], analyze=False)
            second = pool.submit(self.open, self.fixtures["busy"], agent=other, analyze=False)
            survivor = pool.submit(self.open, self.fixtures["elf"], analyze=False)
            _, left = first.result()
            _, right = second.result()
            _, independent = survivor.result()
        with ThreadPoolExecutor(max_workers=2) as pool:
            first = pool.submit(self.agent.call, "bn_analysis_update_async", binaryView=left)
            second = pool.submit(other.call, "bn_analysis_update_async", binaryView=right)
            jobs = [first.result(), second.result()]
        deadline = time.monotonic() + 2
        while True:
            compute = self.agent.call("bn_compute_status")
            if compute["activeAnalyses"] == 1 and compute["queuedAnalyses"] == 1 or time.monotonic() > deadline:
                break
            time.sleep(0.02)
        require(compute["workerBudget"] == 1 and compute["activeAnalyses"] == 1 and compute["queuedAnalyses"] == 1,
                f"concurrent requests did not exercise the scheduler queue: {compute}")
        states = [self.agent.call("bn_job_info", job=job["job"]) for job in jobs]
        require(sorted(job["state"] for job in states) == ["queued", "running"],
                f"job states disagree with the scheduler queue: {states}")
        queued = next(job for job in states if job["state"] == "queued")
        running = next(job for job in states if job["state"] == "running")
        require(queued["progress"]["phase"] == "queued", "queued job claims analysis has already started")
        self.agent.call("bn_job_cancel", job=queued["job"])
        self.agent.finish_job(self.agent.call("bn_job_info", job=queued["job"]), allowed=("cancelled",))
        require(self.agent.call("bn_job_info", job=running["job"])["state"] == "running", "queued cancellation disturbed active analysis")
        # A job is token-owned: another session can cancel/consume it.
        other.call("bn_job_cancel", job=running["job"])
        other.finish_job(other.call("bn_job_info", job=running["job"]), allowed=("cancelled",))
        self.agent.call("bn_job_result", job=running["job"], expect_error=True)
        self.agent.analyze(independent)
        self.function(independent, "packet_dispatch")
        # Explicit view ownership still applies even though job ownership is token-wide.
        error = other.call("bn_function_list", binaryView=independent, expect_error=True)
        require("not found" in json.dumps(error).lower(), f"cross-session view access was not rejected: {error}")

    def test_analysis_completion_is_query_ready(self):
        _, view = self.open(self.fixtures["busy"])
        for name in ("task_0", f"task_{BUSY_FUNCTIONS // 2}", f"task_{BUSY_FUNCTIONS - 1}"):
            address = self.function(view, name)
            info = self.agent.call("bn_function_info", binaryView=view, function=address)
            require(not info["needsUpdate"] and info["basicBlockCount"] >= 2,
                    f"analysis reported complete before {name} was ready: {info}")
            self.agent.call("bn_function_decompile", binaryView=view, function=address)

    def test_attached_disconnect_cancels_analysis(self):
        _, view = self.open(self.fixtures["busy"], analyze=False)
        result = self.agent.rpc("tools/call", {"name": "bn_analysis_update_and_wait", "arguments": {"binaryView": view}},
                                disconnect_phase="analysis")
        job = result["progress"]["job"]
        self.agent.finish_job(self.agent.call("bn_job_info", job=job), allowed=("cancelled",))
        # The same handle must be reusable after cancellation, including lazy
        # child restart if the core needed the cancellation grace fallback.
        self.agent.analyze(view)
        address = self.function(view, f"task_{BUSY_FUNCTIONS - 1}")
        info = self.agent.call("bn_function_info", binaryView=view, function=address)
        require(not info["needsUpdate"] and info["basicBlockCount"] >= 2, "cancelled view did not recover")

    def test_save_collision_preserves_work(self):
        project = self.project()
        self.agent.call("bn_local_project_file_import_batch", project=project, files=[
            {"source": str(self.fixtures["elf"]), "name": "packet.elf"},
            {"source": str(self.fixtures["raw"]), "name": "packet.elf.bndb"}])
        item, view = self.open("packet.elf", project=project)
        address = self.function(view, "packet_dispatch")
        self.agent.call("bn_comment_set", binaryView=view, address=address, text="work before a save collision")
        self.agent.operation_error("bn_binary_view_save", binaryView=view)
        require(self.agent.call("bn_comment_get", binaryView=view, address=address)["text"] == "work before a save collision",
                "failed save discarded the current annotations")
        require(self.agent.call("bn_analysis_status", binaryView=view)["modified"], "failed commit was reported as saved")
        self.agent.call("bn_open_item_close", openItem=item, expect_error=True)
        self.agent.operation_error("bn_binary_view_save", binaryView=view)
        saved = self.agent.complete(self.agent.call("bn_binary_view_save", binaryView=view, destination="reviewed.bndb"))
        require(saved["createdDatabase"], "retry lost raw-to-BNDB save semantics")
        self.agent.call("bn_open_item_close", openItem=item)
        _, reopened = self.open(saved["destination"], project=project, analyze=False)
        require(self.agent.call("bn_comment_get", binaryView=reopened, address=address)["text"] == "work before a save collision",
                "retrying a failed save lost annotations")
        # Read the colliding file as raw bytes: its misleading suffix must not
        # allow a save to overwrite the unrelated original.
        _, original = self.open("packet.elf.bndb", project=project, view_type="Raw", analyze=False)
        memory = self.agent.call("bn_memory_read", binaryView=original, address="0", length=8)
        require(bytes.fromhex(memory["hex"]) == self.fixtures["raw"].read_bytes()[:8], "collision overwrote another file")

    def test_upload_commit_collision_is_retryable(self):
        project = self.project()
        self.agent.call("bn_local_project_file_import", project=project, source=str(self.fixtures["raw"]), name="packet.elf")
        issued = self.agent.call("bn_upload_get_url", project=project, filename="packet.elf")
        data = self.fixtures["elf"].read_bytes()
        status, _, _, _ = self.service.http.request("PUT", issued["url"], data, {"Content-Type": "application/octet-stream"})
        require(status == 201, f"upload transfer failed: HTTP {status}")
        self.agent.operation_error("bn_upload_commit", id=issued["id"])
        self.agent.call("bn_local_project_file_update", project=project, path="packet.elf", name="firmware.bin")
        committed = self.agent.complete(self.agent.call("bn_upload_commit", id=issued["id"]))
        require(committed["sha256"] == hashlib.sha256(data).hexdigest(), "retrying failed commit changed staged data")
        _, view = self.open("packet.elf", project=project)
        self.function(view, "packet_dispatch")

    def test_project_downloads(self):
        original_configuration = self.service.portal("GET", "/config")["configuration"]
        restore_configuration = {"required": False}

        def restore_project_configuration():
            if not restore_configuration["required"]:
                return
            saved = self.service.portal("PUT", "/config", original_configuration)
            if saved["restart_required"]:
                self.service.restart_from_portal()
            restore_configuration["required"] = False

        self.addCleanup(restore_project_configuration)
        project_name = "e2e-" + self._testMethodName + "-0"
        project = self.project()
        self.agent.call("bn_local_project_folder_create", project=project, name="bundle")
        self.agent.call("bn_local_project_folder_create", project=project, parent="bundle", name="nested")
        self.agent.call("bn_local_project_folder_create", project=project, parent="bundle/nested", name="empty")
        self.agent.call("bn_local_project_file_import", project=project, source=str(self.fixtures["raw"]),
                        name="firmware.bin")
        self.agent.call("bn_local_project_file_import", project=project, source=str(self.fixtures["elf"]),
                        folder="bundle/nested", name="packet.elf")

        single = self.agent.complete(self.agent.call(
            "bn_local_project_file_download", project=project, path="firmware.bin"))
        require(not single["archive"] and single["method"] == "GET" and single["singleUse"],
                f"single-file download instructions are incomplete: {single}")
        require(single["authorization"] == "URL capability", f"download authorization changed: {single}")
        require(self.download(single) == self.fixtures["raw"].read_bytes(), "single-file download changed bytes")

        batch = self.agent.complete(self.agent.call(
            "bn_local_project_file_download_batch", project=project,
            paths=["firmware.bin", "bundle/nested/packet.elf"]))
        batch_names, batch_files = self.archive_entries(self.download(batch))
        require(set(batch_files) == {"firmware.bin", "bundle/nested/packet.elf"},
                f"batch download lost project-relative paths: {batch_names}")
        require(batch_files["firmware.bin"] == self.fixtures["raw"].read_bytes(),
                "batch download changed the raw file")
        require(batch_files["bundle/nested/packet.elf"] == self.fixtures["elf"].read_bytes(),
                "batch download changed the ELF file")

        folder = self.agent.complete(self.agent.call(
            "bn_local_project_folder_download", project=project, path="bundle"))
        folder_names, folder_files = self.archive_entries(self.download(folder))
        require("bundle/" in folder_names and "bundle/nested/" in folder_names
                and "bundle/nested/empty/" in folder_names,
                f"folder download lost its directory tree: {folder_names}")
        require(folder_files["bundle/nested/packet.elf"] == self.fixtures["elf"].read_bytes(),
                "folder download changed the nested file")

        complete = self.agent.complete(self.agent.call("bn_local_project_download", project=project))
        require(complete["filename"] == project_name + ".bnpr.zip",
                f"complete project attachment name changed: {complete}")
        project_names, project_files = self.archive_entries(self.download(complete))
        roots = {name.split("/", 1)[0] for name in project_names}
        require(len(roots) == 1 and next(iter(roots)).endswith(".bnpr"),
                f"complete download did not contain one .bnpr root: {project_names}")
        root = next(iter(roots))
        require(root + "/project.bnpm" in project_names, "complete project download omitted project.bnpm")
        require(self.fixtures["raw"].read_bytes() in project_files.values()
                and self.fixtures["elf"].read_bytes() in project_files.values(),
                "complete project download omitted project file data")

        configuration = json.loads(json.dumps(original_configuration))
        configuration["projects"] = {
            "roots": [], "default_root": "", "allow_arbitrary_paths": True,
            "allow_project_registration": True,
        }
        saved = self.service.portal("PUT", "/config", configuration)
        require(saved["restart_required"], "project-registration test configuration did not require restart")
        restore_configuration["required"] = True
        self.service.restart_from_portal()
        self.agent = Agent(self.service.http, self.service.token).start()
        metadata_path = self.service.directory / "projects" / (project_name + ".bnpr") / "project.bnpm"
        registered = self.agent.call("bn_local_project_register", path=str(metadata_path))["project"]
        registered_download = self.agent.complete(self.agent.call("bn_local_project_download", project=registered))
        require(registered_download["filename"] == project_name + ".bnpr.zip",
                f".bnpm download did not use its resolved .bnpr attachment name: {registered_download}")
        registered_names, _ = self.archive_entries(self.download(registered_download))
        registered_roots = {name.split("/", 1)[0] for name in registered_names}
        require(registered_roots == {project_name + ".bnpr"},
                f".bnpm registration did not resolve its complete .bnpr directory: {registered_names}")

        status, _, response, _ = self.service.http.request("GET", "/downloads/" + "0" * 64)
        require(status == 404 and response == {"error": "download_not_found"},
                f"unknown download capability leaked state: HTTP {status}: {response}")

        pending = self.agent.complete(self.agent.call(
            "bn_local_project_file_download", project=registered, path="firmware.bin"))
        self.agent.call("bn_analysis_session_close", analysisSession=self.agent.session)
        self.agent.session = None
        status, _, response, _ = self.service.http.request("GET", pending["url"])
        require(status == 404 and response == {"error": "download_not_found"},
                f"session closure retained an unconsumed download: HTTP {status}: {response}")

    def test_diff_and_name_transfer(self):
        _, primary = self.open(self.fixtures["stripped"])
        _, secondary = self.open(self.fixtures["elf"])
        self.agent.complete(self.agent.call("bn_diff_run_view", primary=primary, secondary=secondary))
        summary = self.agent.call("bn_diff_summary", primary=primary, secondary=secondary)
        require(summary["matches"] >= 3 and summary["exactMatches"] >= 3, f"identical code did not match: {summary}")
        matches = self.agent.pages("bn_diff_match_list", "matches", primary=primary, secondary=secondary, limit=1)
        dispatch = self.function(secondary, "packet_dispatch")
        pair = next(row for row in matches if row["secondaryAddress"] == dispatch)
        self.agent.call("bn_diff_port_name_from_secondary", primary=primary, secondary=secondary,
                        primaryFunction=pair["primaryAddress"], secondaryFunction=pair["secondaryAddress"])
        require(self.function(primary, "packet_dispatch") == pair["primaryAddress"], "matched function name was not transferred")

    def test_brokered_tool_discovery_and_calls(self):
        restore_required = {"value": False}

        def tool_control(request):
            path = self.service.config.parent / "menubar-control.sock"
            require(path.stat().st_mode & 0o777 == 0o600, "menu tool-control socket is not owner-only")
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                connection.settimeout(5)
                connection.connect(str(path))
                connection.sendall(json.dumps(request, separators=(",", ":")).encode() + b"\n")
                response = b""
                while not response.endswith(b"\n"):
                    chunk = connection.recv(4096)
                    require(chunk, "menu tool-control socket closed without a response")
                    response += chunk
                return json.loads(response)

        def save_discovery_mode(mode, binary_ninja=None):
            configuration = self.service.portal("GET", "/config")["configuration"]
            configuration.setdefault("tools", {})["discovery_mode"] = mode
            if binary_ninja is not None:
                configuration.setdefault("binary_ninja", {})["installation_dir"] = str(binary_ninja)
            return self.service.portal("PUT", "/config", configuration)

        def restore_full_discovery():
            if not restore_required["value"]:
                return
            saved = save_discovery_mode("full")
            require(saved["restart_required"], "restoring full discovery did not require restart")
            self.service.restart()
            restore_required["value"] = False

        self.addCleanup(restore_full_discovery)
        self.service.portal("PATCH", "/tools", {"discovery_mode": "brokered"}, expected=400)
        self.service.portal("POST", "/restart", {}, authenticated=False, expected=401)
        self.service.portal("POST", "/restart", {}, expected=409)
        binary_ninja = self.service.config.parent / "Binary Ninja.app"
        binary_ninja.symlink_to(self.service.binary_ninja, target_is_directory=True)
        configured = save_discovery_mode("brokered", binary_ninja)
        restore_required["value"] = True
        require(configured["restart_required"], "brokered discovery save did not require restart")

        still_full = {tool["name"] for tool in self.agent.rpc("tools/list")["tools"]}
        require("bn_tools" not in still_full and "bn_function_list" in still_full,
                "discovery mode changed before service restart")
        listed_packs = tool_control({"operation": "list"})
        require(listed_packs["ok"] and len(listed_packs["packs"]) == 14 and listed_packs["packs"]["search"],
                "menu tool-control socket did not list active packs")
        require(not tool_control({"operation": "set", "pack": "core", "enabled": False})["ok"],
                "menu tool-control socket accepted an unknown or fixed pack")
        updated_packs = tool_control({"operation": "set", "pack": "search", "enabled": False})
        require(updated_packs["ok"] and not updated_packs["packs"]["search"],
                "menu tool-control socket did not disable a pack")
        pending = self.service.portal("GET", "/config")["configuration"]
        require(pending["tools"]["discovery_mode"] == "brokered" and not pending["tools"]["search"],
                "menu tool-control update did not persist or discarded pending discovery mode")
        require(pending["binary_ninja"]["installation_dir"] == str(binary_ninja),
                "pending Binary Ninja installation path was not preserved")
        self.service.portal("PATCH", "/tools", {"search": True})

        self.service.restart_from_portal()
        self.agent = Agent(self.service.http, self.service.token).start()
        status = self.service.portal("GET", "/status")
        require(status["tools"]["discovery_mode"] == "brokered" and not status["restart_required"],
                "service restart did not activate brokered discovery")

        tools = self.agent.rpc("tools/list")["tools"]
        names = {tool["name"] for tool in tools}
        expected = {"bn_tools", "bn_analysis_session_create", "bn_analysis_session_close", "bn_local_project_list",
                    "bn_local_project_file_list", "bn_open_item_open", "bn_open_item_close", "bn_binary_view_open",
                    "bn_analysis_status", "bn_analysis_update_and_wait", "bn_binary_view_save", "bn_job_list",
                    "bn_job_info", "bn_job_result", "bn_job_cancel"}
        require(names == expected, f"brokered discovery exposed an unexpected direct surface: {sorted(names)}")
        for name in ("bn_function_list", "bn_comment_set", "bn_binary_header_info"):
            require(name not in names, f"brokered discovery directly exposed {name}")

        legacy = Agent(self.service.http, self.service.token, "2025-11-25").start()
        legacy_names = {tool["name"] for tool in legacy.rpc("tools/list")["tools"]}
        require(legacy_names == expected - {"bn_analysis_session_create", "bn_analysis_session_close"},
                f"brokered legacy discovery exposed an unexpected surface: {sorted(legacy_names)}")

        categories = self.agent.call("bn_tools", operation="categories")["categories"]
        category_ids = {category["id"] for category in categories}
        require({"core", "function_analysis", "annotations", "debugger"}.issubset(category_ids),
                "broker omitted documented categories")
        listed = self.agent.call("bn_tools", operation="list", category="function_analysis", query="IL")
        require(any(tool["name"] == "bn_function_il" for tool in listed["tools"]),
                "broker category query did not find function IL")
        described = self.agent.call("bn_tools", operation="describe", name="bn_local_project_list")
        require(described["inputSchema"]["type"] == "object", "broker did not return the registered input schema")
        brokered = self.agent.call("bn_tools", operation="call", name="bn_local_project_list", arguments={})
        direct = self.agent.call("bn_local_project_list")
        require(brokered == direct, "brokered invocation changed the underlying tool result")

        item = self.agent.call("bn_open_item_open", path=str(self.fixtures["elf"]))
        candidate = next(view for view in item["binaryViews"] if view["recommended"])
        settings = self.agent.call("bn_tools", operation="call", name="bn_binary_view_load_settings",
                                   arguments={"binaryView": candidate["binaryView"]})
        require(isinstance(settings, dict), "broker did not return BinaryView load settings")
        self.agent.call("bn_binary_view_open", binaryView=candidate["binaryView"], analyze=False)
        header = self.agent.call("bn_tools", operation="call", name="bn_binary_header_info",
                                 arguments={"binaryView": candidate["binaryView"]})
        require(header["format"] == "ELF", "broker did not preserve the forwarded tool name")
        require(self.agent.call("bn_binary_header_info", binaryView=candidate["binaryView"]) == header,
                "direct execution of an unadvertised tool changed its result")
        self.agent.call("bn_open_item_close", openItem=item["openItem"], save="discard")

        documented = self.service.portal("POST", "/mcp/tools", {"protocol": self.agent.protocol})
        function_list = next(tool for tool in documented["tools"] if tool["name"] == "bn_function_list")
        require(function_list["available"] and not function_list["advertised"],
                "tool documentation confused capability availability with direct advertisement")
        context = self.service.portal("POST", "/mcp/context",
                                      {"protocol": self.agent.protocol, "client": "binjad"})
        projection = context["openCodeProjection"]
        require("Flow: project_list" in projection["resourceContext"],
                "model context omitted the quick-start documentation")
        require({item["name"] for item in projection["tools"]} == {"binjad_" + name for name in expected},
                "model context did not match brokered tool discovery")
        require({item["method"] for item in context["mcpWire"]}
                == {"tools/list", "resources/list", "resources/templates/list", "resources/read binjad://docs"},
                "model context omitted an MCP documentation surface")

        restore_full_discovery()
        self.agent = Agent(self.service.http, self.service.token).start()
        full_names = {tool["name"] for tool in self.agent.rpc("tools/list")["tools"]}
        require("bn_function_list" in full_names and "bn_tools" not in full_names,
                "full discovery did not restore the original tool surface")

    def test_legacy_agent_workflow(self):
        legacy = Agent(self.service.http, self.service.token, "2025-11-25").start()
        tools = legacy.rpc("tools/list")["tools"]
        require(not any(row["name"] == "bn_analysis_session_create" for row in tools), "legacy discovery exposed explicit session creation")
        item, view = self.open(self.fixtures["elf"], agent=legacy)
        self.function(view, "packet_checksum", agent=legacy)
        legacy.call("bn_open_item_close", openItem=item, save="discard")
        status, _, _, _ = self.service.http.request("DELETE", "/mcp", headers={
            "Authorization": "Bearer " + self.service.token, "Mcp-Session-Id": legacy.transport_session,
            "MCP-Protocol-Version": legacy.protocol})
        require(status == 204, f"legacy transport detach returned {status}")
        require(self.agent.call("bn_analysis_session_info", analysisSession=legacy.session)["legacy"], "legacy detach lost retained session")

    def test_recover_from_agent_errors(self):
        item = self.agent.call("bn_open_item_open", path=str(self.fixtures["elf"]))
        view = next(row["binaryView"] for row in item["binaryViews"] if row["recommended"])
        error = self.agent.call("bn_function_list", binaryView=view, expect_error=True)
        require("bn_binary_view_open" in json.dumps(error), "unmaterialized-view error has no recovery action")
        self.agent.call("bn_binary_view_open", binaryView=view, analyze=False)
        self.agent.analyze(view)
        error = self.agent.call("bn_function_decompile", binaryView=view, function="definitely_missing", expect_error=True)
        require(error, "missing function returned no diagnostic")
        address = self.function(view, "packet_dispatch")
        self.agent.call("bn_comment_set", binaryView=view, address=address, text="unsaved work")
        self.agent.call("bn_open_item_close", openItem=item["openItem"], expect_error=True)
        require(self.agent.call("bn_comment_get", binaryView=view, address=address)["text"] == "unsaved work", "failed close discarded work")
        self.agent.call("bn_open_item_close", openItem=item["openItem"], save="discard")
        self.agent.call("bn_function_list", binaryView=view, expect_error=True)
        _, healthy = self.open(self.fixtures["elf"])
        self.function(healthy, "packet_dispatch")

    def test_token_rotation_cleans_active_work(self):
        _, view = self.open(self.fixtures["busy"], analyze=False)
        self.agent.call("bn_analysis_update_async", binaryView=view)
        old = self.service.token
        self.service.rotate_token()
        status, headers, _, _ = self.service.http.request("POST", "/mcp", {"jsonrpc": "2.0", "id": 1, "method": "ping"},
                                                         {"Authorization": "Bearer " + old})
        require(status == 401 and "bearer" in headers.get("www-authenticate", "").lower(), "rotated token remained usable")
        self.agent = Agent(self.service.http, self.service.token).start()
        require(not self.agent.pages("bn_job_list", "jobs"), "rotation retained old jobs")
        require(not self.agent.pages("bn_open_item_list", "openItems"), "rotation retained old files")
        _, healthy = self.open(self.fixtures["elf"])
        self.function(healthy, "packet_dispatch")

    def run_corpus(self, entry):
        path = Path(entry["path"]).expanduser().resolve(strict=True)
        if "sha256" in entry:
            with path.open("rb") as source:
                digest = hashlib.file_digest(source, "sha256").hexdigest()
            require(digest == entry["sha256"], "corpus fixture hash changed")
        project = self.project()
        # Project import also tests companion staging for split shared caches.
        files = [path] + [Path(item).expanduser().resolve(strict=True) for item in entry.get("companions", [])]
        self.agent.call("bn_local_project_file_import_batch", project=project,
                        files=[{"source": str(item), "name": item.name} for item in files])
        item, view = self.open(path.name, project=project, view_type=entry["viewType"], options=entry.get("options"), analyze=False)
        if entry.get("image"):
            prefix = "bn_kernel_cache" if entry["viewType"] == "KCView" else "bn_shared_cache"
            images = self.agent.call(prefix + "_image_list", binaryView=view, query=entry["image"], limit=10)
            require(entry["image"] in json.dumps(images), "requested cache image was not discovered")
            self.agent.call(prefix + "_image_load", binaryView=view, image=entry["image"])
        self.agent.complete(self.agent.call("bn_analysis_update_async", binaryView=view), timeout=entry.get("timeout", 900))
        functions = self.agent.call("bn_function_list", binaryView=view, query=entry["functionQuery"], limit=10)["functions"]
        require(functions, "corpus function query found no analyzed functions")
        function = functions[0]["address"]
        text = self.agent.call("bn_function_decompile", binaryView=view, function=function)["text"]
        require(len(text.splitlines()) >= 3, "corpus function did not decompile")
        if entry.get("textContains"):
            require(entry["textContains"] in text, "corpus semantic anchor is absent from decompilation")
        self.agent.call("bn_comment_set", binaryView=view, address=function, text="corpus save/reopen anchor")
        saved = self.agent.complete(self.agent.call("bn_binary_view_save", binaryView=view), timeout=entry.get("timeout", 900))
        self.agent.call("bn_open_item_close", openItem=item, save="discard")
        _, restored = self.open(saved["destination"], project=project, analyze=False)
        require(self.agent.call("bn_comment_get", binaryView=restored, address=function)["text"] == "corpus save/reopen anchor",
                "corpus analysis did not survive save/reopen")


def add_corpus_cases(entries):
    for index, entry in enumerate(entries):
        def test(self, fixture=entry):
            self.run_corpus(fixture)
        setattr(Workflows, f"test_corpus_{index:03d}", test)
