#!/usr/bin/env python3
"""Focused public-HTTP smoke test for a running Linux binjad daemon."""

import argparse
import base64
import os
from pathlib import Path

from Client import Agent, Http, Transcript, require


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default="http://127.0.0.1:8712")
    parser.add_argument("--binary", default="/bin/true")
    parser.add_argument("--username", default="binjad-smoke")
    parser.add_argument("--artifacts", type=Path, required=True)
    args = parser.parse_args()
    password = os.environ.get("BINJAD_SMOKE_PASSWORD")
    require(password and len(password.encode()) >= 9, "BINJAD_SMOKE_PASSWORD must contain at least nine bytes")

    args.artifacts.mkdir(parents=True, exist_ok=True)
    transcript = Transcript(args.artifacts / "transcript.jsonl")
    http = Http(args.base_url, transcript, timeout=180)

    def portal(method, path, body=None, authenticated=True, expected=200):
        headers = {}
        if authenticated:
            basic = base64.b64encode(f"{args.username}:{password}".encode()).decode()
            headers["Authorization"] = "Basic " + basic
        status, _, payload, _ = http.request(method, "/portal/api" + path, body, headers)
        require(status == expected, f"portal {path}: HTTP {status}: {payload}")
        return payload.get("result") if payload else None

    agent = None
    open_item = None
    try:
        if portal("GET", "/setup", authenticated=False):
            portal("POST", "/setup", {"username": args.username, "password": password},
                   authenticated=False, expected=201)
        token = portal("POST", "/token", {"ttl_seconds": 3600}, expected=201)["token"]
        agent = Agent(http, token).start()

        item = agent.call("bn_open_item_open", path=args.binary)
        open_item = item["openItem"]
        candidates = [candidate for candidate in item["binaryViews"] if candidate["recommended"]]
        require(len(candidates) == 1, f"expected one recommended view: {item}")
        view = candidates[0]["binaryView"]
        opened = agent.call("bn_binary_view_open", binaryView=view, analyze=False)
        require(opened["created"], "recommended BinaryView was not materialized")
        agent.analyze(view)
        functions = agent.call("bn_function_list", binaryView=view, limit=5)
        require(functions["functions"] and functions["total"] >= len(functions["functions"]),
                "analyzed view returned no functions")
        print(f"Linux smoke passed: {opened['viewType']}, {functions['total']} functions")
    finally:
        errors = []
        if agent and open_item:
            try:
                agent.call("bn_open_item_close", openItem=open_item, unsavedChanges="discard")
            except Exception as error:
                errors.append(str(error))
        if agent and agent.session:
            try:
                agent.call("bn_analysis_session_close", analysisSession=agent.session)
            except Exception as error:
                errors.append(str(error))
        if agent:
            status = portal("GET", "/status")["runtime"]
            for key in ("analysis_sessions", "open_items", "jobs", "active_analyses", "queued_analyses"):
                if status[key] != 0:
                    errors.append(f"runtime leaked {key}: {status[key]}")
            if status["memory_bytes"] <= 0:
                errors.append(f"runtime memory was not reported: {status}")
            status_code, _, public_status, _ = http.request("GET", "/healthz/status")
            expected_fields = {"analysis_sessions", "open_items", "active_analyses", "queued_analyses", "memory_bytes"}
            if (status_code != 200 or not isinstance(public_status, dict) or set(public_status) != expected_fields
                    or public_status["memory_bytes"] <= 0):
                errors.append(f"public runtime status was invalid: HTTP {status_code}: {public_status}")
        transcript.close()
        require(not errors, "cleanup failed: " + "; ".join(errors))


if __name__ == "__main__":
    main()
