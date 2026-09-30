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


UPSTREAM = "https://github.com/Vector35/binaryninja-api.git"
CHANNELS = ("stable", "dev")
TAG_PATTERN = re.compile(r"^(stable|dev)/(\d+)\.(\d+)\.(\d+)$")
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
        "refs/tags/stable/*",
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


def discover_releases(tags, state_directory, branch_exists):
    releases = []
    for channel in CHANNELS:
        channel_tags = [tag for tag in tags.values() if tag.channel == channel]
        if not channel_tags:
            raise RuntimeError(f"upstream returned no {channel} release tags")
        latest = max(channel_tags, key=lambda tag: tag.version)
        state = read_state(state_directory / f"{channel}.txt", channel)
        recorded = tags.get(state.name)
        if not recorded:
            raise RuntimeError(f"recorded upstream tag disappeared: {state.name}")
        if recorded.commit != state.commit:
            raise RuntimeError(f"recorded upstream tag changed commit: {state.name}")
        if latest.version <= state.version:
            continue
        if branch_exists(latest.branch):
            continue
        releases.append({
            "branch": latest.branch,
            "channel": latest.channel,
            "sha": latest.commit,
            "tag": latest.name,
            "version": latest.version_text,
        })
    return releases


def write_github_output(path, releases):
    with Path(path).open("a", encoding="utf-8") as output:
        output.write(f"count={len(releases)}\n")
        output.write("releases=" + json.dumps(releases, separators=(",", ":"), sort_keys=True) + "\n")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", default=UPSTREAM)
    parser.add_argument("--refs-file", type=Path)
    parser.add_argument("--state-directory", type=Path, required=True)
    parser.add_argument("--remote", default="")
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
        options.state_directory,
        lambda branch: remote_branch_exists(options.remote, branch),
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
