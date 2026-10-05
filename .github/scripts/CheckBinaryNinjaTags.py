#!/usr/bin/env python3
"""Find new Binary Ninja API release tags for the hourly update workflow."""

import argparse
from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import urllib.error
import urllib.request


UPSTREAM = "https://github.com/Vector35/binaryninja-api.git"
CHANNEL = "dev"
BASE_BRANCH = "dev"
TAG_PATTERN = re.compile(r"^(dev)/(\d+)\.(\d+)\.(\d+)$")
SHA_PATTERN = re.compile(r"^[0-9a-f]{40}$")


@dataclass(frozen=True)
class Tag:
    channel: str
    version: tuple[int, int, int]
    name: str
    commit: str

    @property
    def version_text(self):
        return ".".join(str(part) for part in self.version)

    @property
    def branch(self):
        return f"automation/binaryninja-api-{self.channel}-{self.version_text}"


def parse_tag(name, commit):
    match = TAG_PATTERN.fullmatch(name)
    if not match or not SHA_PATTERN.fullmatch(commit):
        return None
    return Tag(match.group(1), tuple(int(value) for value in match.groups()[1:]), name, commit)


def parse_remote_refs(contents):
    direct = {}
    dereferenced = {}
    for line in contents.splitlines():
        fields = line.split("\t", 1)
        if len(fields) != 2:
            continue
        commit, reference = fields
        prefix = "refs/tags/"
        if not reference.startswith(prefix):
            continue
        name = reference[len(prefix):]
        if name.endswith("^{}"):
            dereferenced[name[:-3]] = commit
        else:
            direct[name] = commit

    tags = {}
    for name, direct_commit in direct.items():
        tag = parse_tag(name, dereferenced.get(name, direct_commit))
        if tag:
            tags[name] = tag
    return tags


def query_remote_refs(repository):
    command = [
        "git",
        "ls-remote",
        "--tags",
        repository,
        "refs/tags/dev/*",
    ]
    return subprocess.run(command, check=True, capture_output=True, text=True).stdout


def read_state(path, expected_channel):
    fields = path.read_text(encoding="utf-8").strip().split()
    if len(fields) != 2:
        raise RuntimeError(f"invalid tag state in {path}")
    tag = parse_tag(fields[0], fields[1])
    if not tag or tag.channel != expected_channel:
        raise RuntimeError(f"invalid {expected_channel} tag state in {path}")
    return tag


def remote_branch_exists(remote, branch):
    if not remote:
        return False
    result = subprocess.run(
        ["git", "ls-remote", "--heads", remote, f"refs/heads/{branch}"],
        check=True,
        capture_output=True,
        text=True,
    )
    return bool(result.stdout.strip())


def discover_releases(tags, state_file, branch_exists, formula_is_published=lambda _: True):
    channel_tags = [tag for tag in tags.values() if tag.channel == CHANNEL]
    if not channel_tags:
        raise RuntimeError(f"upstream returned no {CHANNEL} release tags")
    state = read_state(state_file, CHANNEL)
    recorded = tags.get(state.name)
    if not recorded:
        raise RuntimeError(f"recorded upstream tag disappeared: {state.name}")
    if recorded.commit != state.commit:
        raise RuntimeError(f"recorded upstream tag changed commit: {state.name}")
    if not formula_is_published(state.version_text):
        return []
    pending = sorted((tag for tag in channel_tags if tag.version > state.version), key=lambda tag: tag.version)
    if not pending:
        return []
    release = pending[0]
    if branch_exists(release.branch):
        return []
    return [{
        "base": BASE_BRANCH,
        "branch": release.branch,
        "channel": release.channel,
        "sha": release.commit,
        "tag": release.name,
        "version": release.version_text,
    }]


def published_formula_exists(base_url, version):
    if not base_url:
        return True
    request = urllib.request.Request(
        f"{base_url.rstrip('/')}/binjad@{version}.rb",
        method="HEAD",
        headers={"User-Agent": "binjad-release-monitor"},
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.status == 200
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return False
        raise RuntimeError(f"cannot verify published formula: HTTP {error.code}") from error
    except urllib.error.URLError as error:
        raise RuntimeError(f"cannot verify published formula: {error.reason}") from error


def write_github_output(path, releases):
    with Path(path).open("a", encoding="utf-8") as output:
        output.write(f"count={len(releases)}\n")
        output.write("releases=" + json.dumps(releases, separators=(",", ":"), sort_keys=True) + "\n")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", default=UPSTREAM)
    parser.add_argument("--refs-file", type=Path)
    parser.add_argument("--dev-state", type=Path, required=True)
    parser.add_argument("--remote", default="")
    parser.add_argument("--published-formula-base-url", default="")
    parser.add_argument("--github-output", default=os.environ.get("GITHUB_OUTPUT", ""))
    options = parser.parse_args()

    contents = (
        options.refs_file.read_text(encoding="utf-8")
        if options.refs_file
        else query_remote_refs(options.repository)
    )
    tags = parse_remote_refs(contents)
    releases = discover_releases(
        tags,
        options.dev_state,
        lambda branch: remote_branch_exists(options.remote, branch),
        lambda version: published_formula_exists(options.published_formula_base_url, version),
    )
    print(json.dumps(releases, indent=2, sort_keys=True))
    if options.github_output:
        write_github_output(options.github_output, releases)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, subprocess.CalledProcessError) as error:
        print(f"Binary Ninja tag check failed: {error}", file=sys.stderr)
        raise SystemExit(1)
