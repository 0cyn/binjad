#!/usr/bin/env python3
"""Run a real daemon and act as an MCP agent. Requires a licensed Binary Ninja."""

import argparse
import json
import os
from pathlib import Path
import signal
import sys
import tempfile
import time
import unittest

from Client import Transcript, require
from Fixtures import build
from Scenarios import Workflows, add_corpus_cases
from Service import LaunchdService


class Results(unittest.TextTestResult):
    def startTest(self, test):
        self.started = time.monotonic()
        super().startTest(test)

    def stopTest(self, test):
        failed = any(case is test for case, _ in self.failures + self.errors)
        skipped = any(case is test for case, _ in self.skipped)
        self.durations.append({"scenario": test.id(), "seconds": time.monotonic() - self.started,
                               "status": "failed" if failed else "skipped" if skipped else "passed"})
        super().stopTest(test)

    def __init__(self, *args):
        super().__init__(*args)
        self.durations = []


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--daemon", required=True, type=Path)
    parser.add_argument("--artifacts", required=True, type=Path)
    parser.add_argument("--binary-ninja", type=Path, help="exact Binary Ninja installation root")
    parser.add_argument("--corpus", type=Path, help="JSON array of local real-world corpus entries")
    parser.add_argument("--require-corpus", action="store_true", help="fail rather than omit external-corpus coverage")
    parser.add_argument("--scenario", action="append", help="unittest method name; repeat to select several")
    parser.add_argument("--clang", default="clang")
    parser.add_argument("--elf-linker", default="ld.lld")
    parser.add_argument("--pe-linker", default="lld-link")
    options = parser.parse_args()
    options.artifacts.mkdir(parents=True, exist_ok=True)
    directory = Path(tempfile.mkdtemp(prefix="run-", dir=options.artifacts.resolve()))
    os.chmod(directory, 0o700)
    print(f"E2E artifacts: {directory}", flush=True)
    transcript = Transcript(directory / "transcript.jsonl")
    result = None
    corpus = []
    report = {"artifacts": str(directory), "status": "failed", "externalCorpus": "not configured"}

    def interrupted(signum, _):
        raise KeyboardInterrupt(f"received signal {signum}")

    signal.signal(signal.SIGTERM, interrupted)
    try:
        if options.corpus:
            corpus = json.loads(options.corpus.read_text())
            require(isinstance(corpus, list) and corpus, "corpus manifest must be a nonempty array")
            for entry in corpus:
                require(all(key in entry for key in ("path", "viewType", "functionQuery")), "invalid corpus entry")
                # Resolve manifest-relative paths before handing the fixture to the daemon.
                for key in ("path",):
                    path = Path(entry[key]).expanduser()
                    entry[key] = str((options.corpus.parent / path).resolve()) if not path.is_absolute() else str(path)
                entry["companions"] = [str((options.corpus.parent / Path(path).expanduser()).resolve())
                                       for path in entry.get("companions", [])]
            report["externalCorpus"] = {"entries": len(corpus)}
        require(not options.require_corpus or corpus, "--require-corpus needs a nonempty --corpus manifest")
        binary_ninja = options.binary_ninja.resolve(strict=True) if options.binary_ninja else None
        require(not binary_ninja or binary_ninja.is_dir(), "--binary-ninja must name an installation directory")
        fixtures = build(directory / "fixtures", transcript, options.clang, options.elf_linker, options.pe_linker)
        with LaunchdService(options.daemon, directory, transcript, binary_ninja) as service:
            Workflows.service = service
            Workflows.fixtures = fixtures
            add_corpus_cases(corpus)
            suite = unittest.TestSuite(Workflows(name) for name in options.scenario) if options.scenario else unittest.defaultTestLoader.loadTestsFromTestCase(Workflows)
            result = unittest.TextTestRunner(verbosity=2, resultclass=Results).run(suite)
            report.update(status="passed" if result.wasSuccessful() else "failed", tests=result.testsRun,
                          failures=[{"scenario": test.id(), "traceback": trace} for test, trace in result.failures + result.errors],
                          skipped=[{"scenario": test.id(), "reason": reason} for test, reason in result.skipped],
                          durations=result.durations)
    except BaseException as error:
        report.update(status="failed", runnerError=f"{type(error).__name__}: {error}")
        raise
    finally:
        transcript.close()
        (directory / "results.json").write_text(json.dumps(report, indent=2) + "\n")
        print(f"Results: {directory / 'results.json'}", flush=True)
        if not corpus:
            print("External corpus: NOT RUN (KernelCache/SharedCache and large real-world binaries).", flush=True)
    return 0 if result and result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main())
