#!/usr/bin/env python3
"""Add one immutable Binary Ninja release to the tap formula matrix manifest."""

import argparse
import json
from pathlib import Path
import re


VERSION_PATTERN = re.compile(r"^\d+\.\d+\.\d+$")
SHA_PATTERN = re.compile(r"^[0-9a-f]{40}$")


def version_tuple(version):
    if not VERSION_PATTERN.fullmatch(version):
        raise ValueError(f"invalid version: {version}")
    return tuple(int(part) for part in version.split("."))


def add_formula(matrix, channel, binary_ninja_version, api_revision, source_revision, binjad_version):
    if matrix.get("schema") != 1 or not isinstance(matrix.get("formulas"), dict):
        raise ValueError("invalid formula matrix manifest")
    if matrix.get("binjadVersion") != binjad_version:
        raise ValueError("tap formula matrix uses a different binjad version")
    if channel not in {"stable", "dev"}:
        raise ValueError("channel must be stable or dev")
    version_tuple(binary_ninja_version)
    if not SHA_PATTERN.fullmatch(api_revision) or not SHA_PATTERN.fullmatch(source_revision):
        raise ValueError("API and source revisions must be full lowercase Git SHAs")

    record = {
        "channel": channel,
        "apiRevision": api_revision,
        "sourceRevision": source_revision,
    }
    existing = matrix["formulas"].get(binary_ninja_version)
    if existing:
        if existing != record:
            raise ValueError(f"formula matrix already contains a different {binary_ninja_version} record")
        return False
    matrix["formulas"][binary_ninja_version] = record

    if channel == "stable":
        stable = matrix.get("stable")
        if stable and stable != binary_ninja_version:
            raise ValueError("formula matrix already selects a different stable release")
        matrix["stable"] = binary_ninja_version
    else:
        dev_versions = [
            version for version, item in matrix["formulas"].items() if item.get("channel") == "dev"
        ]
        matrix["latestDev"] = max(dev_versions, key=version_tuple)
    return True


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--channel", choices=("stable", "dev"), required=True)
    parser.add_argument("--binary-ninja-version", required=True)
    parser.add_argument("--api-revision", required=True)
    parser.add_argument("--source-revision", required=True)
    parser.add_argument("--binjad-version", required=True)
    options = parser.parse_args()

    matrix = json.loads(options.manifest.read_text(encoding="utf-8"))
    changed = add_formula(matrix, options.channel, options.binary_ninja_version,
                          options.api_revision, options.source_revision, options.binjad_version)
    if changed:
        options.manifest.write_text(json.dumps(matrix, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
