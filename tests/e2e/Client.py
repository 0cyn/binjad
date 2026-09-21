"""The test agent: public HTTP/MCP only, with no imports from the daemon."""

import http.client
import json
import re
import threading
import time
from urllib.parse import quote, urlsplit


class ContractError(AssertionError):
    pass


def require(condition, message):
    if not condition:
        raise ContractError(message)


class Transcript:
    def __init__(self, path):
        self.stream = path.open("w", encoding="utf-8")
        self.lock = threading.Lock()

    @staticmethod
    def redact(value):
        if isinstance(value, dict):
            return {
                key: "<redacted>" if key.lower() in {"authorization", "password", "token"}
                else Transcript.redact(item) for key, item in value.items()
            }
        if isinstance(value, list):
            return [Transcript.redact(item) for item in value]
        if isinstance(value, str):
            return re.sub(r"(/uploads/)[^\s\"?]+", r"\1<redacted>", value)
        return value

    def write(self, **event):
        with self.lock:
            self.stream.write(json.dumps(self.redact({"time": time.time(), **event}), ensure_ascii=False) + "\n")
            self.stream.flush()

    def close(self):
        self.stream.close()


class Http:
    def __init__(self, base_url, transcript, timeout=120):
        self.base_url = base_url.rstrip("/")
        self.transcript = transcript
        self.timeout = timeout

    def request(self, method, path, body=None, headers=None, rpc_id=None, chunked=False, disconnect_phase=None):
        url = urlsplit(path if "://" in path else self.base_url + path)
        headers = dict(headers or {})
        logged_body = body
        if isinstance(body, dict):
            body = json.dumps(body).encode()
            headers.setdefault("Content-Type", "application/json")
        elif isinstance(body, bytes):
            logged_body = {"byteLength": len(body)}
        elif body is not None:
            logged_body = {"streamed": True}
        self.transcript.write(direction="request", method=method, url=url.geturl(), headers=headers, body=logged_body)
        connection_type = http.client.HTTPSConnection if url.scheme == "https" else http.client.HTTPConnection
        connection = connection_type(url.hostname, url.port, timeout=self.timeout)
        response = None
        started = time.monotonic()
        try:
            target = url.path + ("?" + url.query if url.query else "")
            connection.request(method, target, body, headers, encode_chunked=chunked)
            response = connection.getresponse()
            response_headers = dict((key.lower(), value) for key, value in response.getheaders())
            events = []
            if response_headers.get("content-type", "").split(";")[0] == "text/event-stream":
                require(rpc_id is not None, "unexpected unbounded SSE response")
                data = []
                result = None
                total_bytes = 0
                while True:
                    remaining = self.timeout - (time.monotonic() - started)
                    require(remaining > 0, "SSE request exceeded its overall deadline")
                    # http.client may clear connection.sock for a Connection: close response.
                    response.fp.raw._sock.settimeout(remaining)
                    line = response.readline(8 * 1024 * 1024)
                    total_bytes += len(line)
                    require(total_bytes <= 64 * 1024 * 1024, "SSE response exceeded 64 MiB")
                    if not line:
                        break
                    line = line.decode("utf-8").rstrip("\r\n")
                    if line.startswith("data:"):
                        data.append(line[5:].lstrip(" "))
                    elif not line and data:
                        event = json.loads("\n".join(data))
                        data = []
                        self.transcript.write(direction="sse", body=event)
                        require(event.get("jsonrpc") == "2.0", "invalid SSE JSON-RPC envelope")
                        if "id" in event:
                            require(event["id"] == rpc_id, "SSE result has the wrong request ID")
                            require(result is None, "duplicate SSE result")
                            result = event
                        else:
                            require("method" in event, "SSE event is neither result nor notification")
                            events.append(event)
                            if disconnect_phase and event.get("params", {}).get("phase") == disconnect_phase:
                                # Model an agent losing its connection after work has started.
                                time.sleep(0.05)
                                result = {"disconnected": True, "progress": event["params"]}
                                self.transcript.write(direction="disconnect", body=result)
                                break
                require(result is not None, "SSE closed without the request's terminal response")
                payload = result
            else:
                raw = response.read(64 * 1024 * 1024 + 1)
                require(len(raw) <= 64 * 1024 * 1024, "HTTP response exceeded 64 MiB")
                content_type = response_headers.get("content-type", "").split(";")[0]
                if not raw:
                    payload = None
                elif content_type == "application/json" or content_type.endswith("+json"):
                    payload = json.loads(raw)
                elif content_type.startswith("text/"):
                    payload = raw.decode("utf-8")
                else:
                    payload = {"byteLength": len(raw)}
            self.transcript.write(direction="response", status=response.status, headers=response_headers,
                                  body=payload, elapsed=time.monotonic() - started)
            return response.status, response_headers, payload, events
        except Exception as error:
            self.transcript.write(direction="transport_error", error=str(error), elapsed=time.monotonic() - started)
            raise
        finally:
            if response is not None:
                response.close()
            connection.close()


class Agent:
    def __init__(self, http, token, protocol="2026-07-28"):
        self.http = http
        self.token = token
        self.protocol = protocol
        self.session = None
        self.transport_session = None
        self.counter = 0
        self.lock = threading.Lock()
        self.events = []

    def rpc(self, method, params=None, notification=False, expected_status=200, disconnect_phase=None):
        params = dict(params or {})
        headers = {"Authorization": "Bearer " + self.token,
                   "Accept": "application/json, text/event-stream",
                   "Origin": "https://remote.example.invalid"}
        if self.protocol == "2026-07-28":
            headers.update({"MCP-Protocol-Version": self.protocol, "Mcp-Method": method})
            params["_meta"] = {"io.modelcontextprotocol/protocolVersion": self.protocol,
                               "io.modelcontextprotocol/clientCapabilities": {},
                               "io.modelcontextprotocol/clientInfo": {"name": "binjad-e2e", "version": "1"}}
            if self.session:
                params["_meta"]["me.cynder.binjad/analysisSession"] = self.session
            if method in {"tools/call", "resources/read"}:
                headers["Mcp-Name"] = quote(params["name" if method == "tools/call" else "uri"], safe="")
        elif method != "initialize":
            headers["MCP-Protocol-Version"] = self.protocol
            headers["Mcp-Session-Id"] = self.transport_session
        with self.lock:
            self.counter += 1
            request_id = self.counter
        request = {"jsonrpc": "2.0", "method": method, "params": params}
        if not notification:
            request["id"] = request_id
        status, response_headers, payload, events = self.http.request(
            "POST", "/mcp", request, headers, rpc_id=None if notification else request_id,
            disconnect_phase=disconnect_phase)
        self.events.extend(events)
        require(status == expected_status, f"{method}: HTTP {status}: {payload}")
        require(response_headers.get("access-control-allow-origin") == headers["Origin"],
                f"{method}: response did not echo the request Origin")
        if notification:
            return payload
        if disconnect_phase:
            require(payload.get("disconnected"), "attached operation finished without the requested progress phase")
            return payload
        require(isinstance(payload, dict) and payload.get("jsonrpc") == "2.0", f"{method}: invalid JSON-RPC response")
        require(payload.get("id") == request_id, f"{method}: response ID mismatch")
        if method == "initialize":
            self.transport_session = response_headers.get("mcp-session-id")
            require(self.transport_session, "legacy initialize omitted Mcp-Session-Id")
        if expected_status != 200:
            return payload
        require("error" not in payload, f"{method}: JSON-RPC error: {payload.get('error')}")
        require("result" in payload, f"{method}: missing result")
        return payload["result"]

    def start(self):
        if self.protocol == "2026-07-28":
            self.rpc("server/discover")
            self.session = self.call("bn_analysis_session_create")["analysisSession"]
        else:
            self.rpc("initialize", {"protocolVersion": self.protocol, "capabilities": {},
                                    "clientInfo": {"name": "binjad-e2e", "version": "1"}})
            self.rpc("notifications/initialized", notification=True, expected_status=202)
            self.session = self.call("bn_analysis_session_info")["analysisSession"]
        return self

    def call(self, tool, expect_error=False, **arguments):
        result = self.rpc("tools/call", {"name": tool, "arguments": arguments})
        content = self.tool_content(tool, result)
        require(bool(result.get("isError")) == expect_error, f"{tool}: {'expected an error' if expect_error else content}")
        return content

    @staticmethod
    def tool_content(tool, result):
        content = result.get("structuredContent")
        require(isinstance(content, dict), f"{tool}: missing structuredContent")
        text = [item["text"] for item in result.get("content", []) if item.get("type") == "text"]
        require(len(text) == 1 and json.loads(text[0]) == content,
                f"{tool}: structuredContent and text content differ")
        return content

    def operation_error(self, tool, **arguments):
        """A long operation may fail while attached, or after returning a job."""
        result = self.rpc("tools/call", {"name": tool, "arguments": arguments})
        content = self.tool_content(tool, result)
        if result.get("isError"):
            return content
        require("job" in content, f"{tool}: expected operation to fail, got {content}")
        return self.finish_job(content, allowed=("failed",))

    def pages(self, name, key, limit=3, **arguments):
        rows = []
        offset = 0
        total = None
        for _ in range(10000):
            page = self.call(name, offset=offset, limit=limit, **arguments)
            part = page[key]
            require(page.get("count", len(part)) == len(part) <= limit, f"{name}: wrong page count")
            require(total is None or page["total"] == total, f"{name}: unstable total on unchanged data")
            total = page["total"]
            rows.extend(part)
            if not page.get("truncated", page["nextOffset"] is not None):
                require(len(rows) == total, f"{name}: pagination lost rows ({len(rows)} != {total})")
                return rows
            require(page["nextOffset"] == offset + len(part) and part, f"{name}: pagination made no progress")
            offset = page["nextOffset"]
        raise ContractError(f"{name}: excessive pages")

    def finish_job(self, job, timeout=240, allowed=("complete",)):
        deadline = time.monotonic() + timeout
        while job["state"] in {"queued", "running"}:
            delay = max(10, job.get("pollAfterMilliseconds", 10000) / 1000)
            require(time.monotonic() + delay < deadline, f"job deadline exceeded: {job}")
            time.sleep(delay)
            job = self.call("bn_job_info", job=job["job"])
        result = self.call("bn_job_result", job=job["job"])
        require(result["state"] in allowed, f"job ended unexpectedly: {result}")
        return result.get("result", {})

    def complete(self, result, timeout=240):
        return self.finish_job(result, timeout) if "job" in result else result

    def analyze(self, view):
        self.complete(self.call("bn_analysis_update_and_wait", binaryView=view))
        status = self.call("bn_analysis_status", binaryView=view)
        require(status["state"] == "complete", f"analysis did not reach complete: {status}")
