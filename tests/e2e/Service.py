"""Managed service adapter. Scenario code only depends on its public HTTP URL."""

import base64
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import secrets
import socket
import subprocess
import sys
import tempfile
import time

from Client import ContractError, Http, require


class LaunchdService:
    def __init__(self, daemon, directory, transcript, binary_ninja=None):
        require(sys.platform == "darwin", "managed service adapter currently requires macOS")
        self.daemon = Path(daemon).resolve(strict=True)
        self.directory = directory.resolve()
        self.transcript = transcript
        self.domain = f"gui/{os.getuid()}"
        self.label = f"me.cynder.binjad.e2e.{os.getpid()}"
        self.target = f"{self.domain}/{self.label}"
        self.plist = self.directory / "service.plist"
        self.config = self.directory / "config.json"
        self.original = None
        self.loaded = False
        self.lock_stream = None
        self.username = "e2e"
        self.password = secrets.token_urlsafe(32)
        self.binary_ninja = Path(binary_ninja).resolve(strict=True) if binary_ninja else Path("/Applications/Binary Ninja.app")
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            port = listener.getsockname()[1]
        self.http = Http(f"http://127.0.0.1:{port}", transcript)
        self.token = None
        configuration = {
            "binary_ninja": {"installation_dir": str(self.binary_ninja)},
            "listener": {"addresses": ["127.0.0.1"], "port": port},
            "cpu": {"percentage": 1, "fairness": "job"},
            "jobs": {"detach_after_seconds": 1, "cancellation_grace_seconds": 5},
            "uploads": {"memory_threshold_bytes": 1024, "max_bytes": 67108864},
        }
        self.config.write_text(json.dumps(configuration, indent=2) + "\n")
        self.config.chmod(0o600)
        self.plist.write_bytes(plistlib.dumps({
            "Label": self.label, "ProgramArguments": [str(self.daemon), "--config", str(self.config)],
            "RunAtLoad": True, "KeepAlive": True, "ThrottleInterval": 1,
            "MachServices": {"me.cynder.binjad": True},
            "StandardOutPath": str(self.directory / "daemon.stdout.log"),
            "StandardErrorPath": str(self.directory / "daemon.stderr.log"),
        }))

    def command(self, *arguments, check=True):
        result = subprocess.run(arguments, capture_output=True, text=True, timeout=60)
        self.transcript.write(direction="service", command=list(arguments), returncode=result.returncode,
                              stdout=result.stdout, stderr=result.stderr)
        if check:
            require(result.returncode == 0, f"{' '.join(arguments)}: {result.stderr or result.stdout}")
        return result

    def __enter__(self):
        try:
            import fcntl
            self.lock_stream = (Path(tempfile.gettempdir()) / f"binjad-e2e-{os.getuid()}.lock").open("a")
            fcntl.flock(self.lock_stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
            # Restore exactly the registered plist, whether it came from Homebrew or a local install.
            for domain in (self.domain, f"user/{os.getuid()}"):
                target = f"{domain}/me.cynder.binjad"
                state = self.command("launchctl", "print", target, check=False)
                if state.returncode == 0:
                    match = re.search(r"^\s*path = (.+)$", state.stdout, re.MULTILINE)
                    require(match and Path(match[1]).is_file(), "cannot determine installed service plist for restoration")
                    self.stop_target(target, state.stdout)
                    self.original = (domain, match[1])
                    break
            self.start()
            status, headers, _, _ = self.http.request("GET", "/")
            require(status == 302 and headers.get("location") == "/portal",
                    f"root did not redirect to the portal: HTTP {status}, {headers}")
            status, headers, page, _ = self.http.request("GET", "/portal")
            require(status == 302 and headers.get("location") == "/portal/setup",
                    f"fresh portal did not redirect to onboarding: HTTP {status}, {headers}")
            status, headers, setup_page, _ = self.http.request("GET", "/portal/setup")
            require(status == 200 and headers.get("content-type", "").startswith("text/html"),
                    f"onboarding page was unavailable: HTTP {status}")
            require('id="onboarding-project-root"' in setup_page
                    and 'id="onboarding-public-url"' in setup_page
                    and 'id="onboarding-username"' in setup_page
                    and 'data-profile="local"' in setup_page
                    and 'data-profile="remote"' in setup_page
                    and 'id="onboarding-token-ttl"' in setup_page
                    and 'id="onboarding-token-secret"' in setup_page
                    and 'id="login-form"' not in setup_page,
                    "onboarding did not use its dedicated four-page surface")
            status, headers, setup_script, _ = self.http.request("GET", "/portal/setup.js")
            require(status == 200 and headers.get("content-type", "").startswith("text/javascript")
                    and 'request("/onboarding"' in setup_script,
                    f"onboarding script was unavailable: HTTP {status}")
            onboarding = self.portal("GET", "/onboarding", authenticated=False)
            require(onboarding["required"] is True and onboarding["project_root"] == "~/binja-projects",
                    f"fresh onboarding defaults were wrong: {onboarding}")
            missing_root = self.directory / "missing-projects"
            self.portal("POST", "/onboarding", {
                "username": self.username,
                "password": self.password,
                "project_root": str(missing_root),
                "create_project_root": False,
                "public_base_url": self.http.base_url,
                "allow_arbitrary_paths": True,
                "allow_project_registration": False,
            }, authenticated=False, expected=400)
            require(not missing_root.exists()
                    and self.portal("GET", "/onboarding", authenticated=False)["required"] is True,
                    "rejected onboarding changed the project root or account")
            setup = self.portal("POST", "/onboarding", {
                "username": self.username,
                "password": self.password,
                "project_root": "projects",
                "create_project_root": True,
                "public_base_url": self.http.base_url,
                "allow_arbitrary_paths": True,
                "allow_project_registration": False,
            }, authenticated=False, expected=201)
            require(setup["restart_required"] is True
                    and Path(setup["project_root"]) == self.directory / "projects"
                    and (self.directory / "projects").is_dir(),
                    f"onboarding did not create and configure the project root: {setup}")
            self.rotate_token()
            self.restart_from_portal()
            require(self.portal("GET", "/setup", authenticated=False) is False,
                    "onboarding did not create the account")
            status, headers, _, _ = self.http.request("GET", "/portal/setup")
            require(status == 302 and headers.get("location") == "/portal",
                    f"completed onboarding remained accessible: HTTP {status}, {headers}")
            status, headers, page, _ = self.http.request("GET", "/portal")
            require(status == 200 and headers.get("content-type", "").startswith("text/html"),
                    f"portal page was unavailable after onboarding: HTTP {status}")
            require("{{STATUS_PATH}}" not in page
                    and ('<meta name="binjad-status-path" content="/healthz/status" '
                         'data-configured-path="/healthz/status">') in page,
                    "portal page did not receive its public status path")
            require('id="memory-panel"' in page and 'id="memory-chart"' in page and "Service posture" not in page,
                    "portal page did not contain the memory graph")
            require('id="restart-daemon"' in page and 'data-action="restart-daemon"' in page
                    and 'id="restart-badge"' not in page and 'id="config-warning"' not in page,
                    "portal page did not contain the single daemon restart control")
            require('id="setup-user"' not in page and 'data-action="setup"' not in page,
                    "the login page still contained the old setup form")
            persisted = self.portal("GET", "/config")["configuration"]
            require(persisted["http"]["public_base_url"] == self.http.base_url
                    and persisted["projects"]["roots"] == [str(self.directory / "projects")]
                    and persisted["projects"]["default_root"] == str(self.directory / "projects")
                    and persisted["projects"]["allow_arbitrary_paths"] is True
                    and persisted["projects"]["allow_project_registration"] is False
                    and "require_bearer_authentication" not in persisted["uploads"],
                    f"onboarding settings were not persisted: {persisted}")
            return self
        except BaseException:
            self.__exit__(None, None, None)
            raise

    def start(self):
        self.command("launchctl", "bootstrap", self.domain, str(self.plist))
        self.loaded = True
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            try:
                status, _, body, _ = self.http.request("GET", "/healthz")
                if status == 200 and body == {"status": "ok"}:
                    return
            except (OSError, ConnectionError):
                pass
            time.sleep(1)
        self.command("launchctl", "print", self.target, check=False)
        raise ContractError(f"daemon did not become healthy; inspect {self.directory}")

    def stop(self):
        if self.loaded:
            state = self.command("launchctl", "print", self.target)
            self.stop_target(self.target, state.stdout)
            self.loaded = False

    def stop_target(self, target, state):
        pid_match = re.search(r"^\s*pid = (\d+)$", state, re.MULTILINE)
        pid = int(pid_match[1]) if pid_match else None
        self.command("launchctl", "bootout", target)
        # bootout acknowledges removal before the process and Mach endpoint have
        # necessarily gone away. Wait for both before a restart or restoration.
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            alive = False
            if pid:
                try:
                    os.kill(pid, 0)
                    alive = True
                except ProcessLookupError:
                    pass
            if not alive and self.command("launchctl", "print", target, check=False).returncode != 0:
                return
            time.sleep(0.1)
        raise ContractError(f"service did not finish stopping: {target}, pid={pid}")

    def restart(self):
        self.stop()
        self.start()

    def restart_from_portal(self):
        result = self.portal("POST", "/restart", {}, expected=202)
        require(result["restarting"] is True, "portal restart was not acknowledged")
        require(result["portal_url"] == self.http.base_url + "/portal", "portal restart returned the wrong URL")
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            try:
                status = self.portal("GET", "/status")
                if not status["restart_required"]:
                    return result
            except Exception:
                pass
            time.sleep(0.5)
        self.command("launchctl", "print", self.target, check=False)
        raise ContractError("daemon did not return after the portal restart request")

    def portal(self, method, path, body=None, authenticated=True, expected=200):
        headers = {"Origin": "https://remote.example.invalid"}
        if authenticated:
            basic = base64.b64encode(f"{self.username}:{self.password}".encode()).decode()
            headers["Authorization"] = "Basic " + basic
        status, _, payload, _ = self.http.request(method, "/portal/api" + path, body, headers)
        require(status == expected, f"portal {path}: HTTP {status}: {payload}")
        return payload.get("result") if payload else None

    def rotate_token(self):
        self.token = self.portal("POST", "/token", {"ttl_seconds": 3600}, expected=201)["token"]

    def __exit__(self, *_):
        try:
            self.stop()
        finally:
            try:
                if self.original:
                    domain, plist = self.original
                    self.command("launchctl", "bootstrap", domain, plist)
                    self.command("launchctl", "print", f"{domain}/me.cynder.binjad")
            finally:
                # The namespace belongs solely to this newly-created configuration, never the installed vault.
                namespace = hashlib.sha256(str(self.config).encode()).hexdigest()
                self.command("security", "delete-generic-password", "-s", "me.cynder.binjad." + namespace,
                             "-a", "credential-vault", check=False)
                if self.lock_stream:
                    self.lock_stream.close()
                    self.lock_stream = None
