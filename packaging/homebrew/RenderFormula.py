#!/usr/bin/env python3
"""Render one exact-version Homebrew formula from the checked-in template."""

import argparse
from pathlib import Path
import re


VERSION_PATTERN = re.compile(r"^\d+\.\d+\.\d+$")
SHA_PATTERN = re.compile(r"^[0-9a-f]{40}$")
PLACEHOLDER_PATTERN = re.compile(r"@BINJAD_[A-Z0-9_]+@")


def render_formula(template, binary_ninja_version, source_revision, binjad_version, channel):
    if not VERSION_PATTERN.fullmatch(binary_ninja_version):
        raise ValueError("Binary Ninja version must contain three numeric components")
    if not SHA_PATTERN.fullmatch(source_revision):
        raise ValueError("source revision must be a full lowercase Git SHA")
    if not VERSION_PATTERN.fullmatch(binjad_version):
        raise ValueError("binjad version must contain three numeric components")
    if channel not in {"stable", "dev"}:
        raise ValueError("channel must be stable or dev")

    development = channel == "dev"
    replacements = {
        "@BINJAD_BINARY_NINJA_VERSION_IDENTIFIER@": binary_ninja_version.replace(".", ""),
        "@BINJAD_HOMEPAGE@": "https://github.com/0cyn/binjad",
        "@BINJAD_GIT_URL@": "https://github.com/0cyn/binjad.git",
        "@BINJAD_GIT_REVISION@": source_revision,
        "@BINJAD_VERSION@": binjad_version,
        "@BINJAD_LICENSE@": "BSD-3-Clause",
        "@BINJAD_BINARY_NINJA_VERSION@": binary_ninja_version,
        "@BINJAD_BINARY_NINJA_CHANNEL_QUALIFIER@": " development build" if development else "",
        "@BINJAD_BINARY_NINJA_CHANNEL_NOTICE@": (
            "      This development formula shares its service and configuration with stable binjad.\n"
            "      Stop the stable service before starting this formula.\n"
            if development else ""
        ),
    }
    rendered = template
    for marker, value in replacements.items():
        rendered = rendered.replace(marker, value)
    remaining = sorted(set(PLACEHOLDER_PATTERN.findall(rendered)))
    if remaining:
        raise ValueError("unresolved template markers: " + ", ".join(remaining))
    return rendered


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--template", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--binary-ninja-version", required=True)
    parser.add_argument("--source-revision", required=True)
    parser.add_argument("--binjad-version", required=True)
    parser.add_argument("--channel", choices=("stable", "dev"), required=True)
    parser.add_argument("--overwrite", action="store_true")
    options = parser.parse_args()

    if options.output.exists() and not options.overwrite:
        parser.error(f"output already exists: {options.output}")
    rendered = render_formula(
        options.template.read_text(encoding="utf-8"),
        options.binary_ninja_version,
        options.source_revision,
        options.binjad_version,
        options.channel,
    )
    options.output.write_text(rendered, encoding="utf-8")


if __name__ == "__main__":
    main()
