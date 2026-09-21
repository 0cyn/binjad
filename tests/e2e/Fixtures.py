"""Build ordinary binaries with an independent compiler/linker as the oracle."""

import hashlib
import json
from pathlib import Path
import shutil
import struct
import subprocess

from Client import require


BANNER = "BINJAD-PACKET/v1 café 日本"
BUSY_FUNCTIONS = 6000


def build(directory, transcript, clang="clang", linker="ld.lld", pe_linker="lld-link"):
    directory.mkdir()
    source = Path(__file__).parent / "fixtures" / "Packet.c"

    def run(*args):
        result = subprocess.run([str(arg) for arg in args], capture_output=True, text=True, timeout=120)
        transcript.write(direction="fixture_build", command=[str(arg) for arg in args],
                         stdout=result.stdout, stderr=result.stderr, returncode=result.returncode)
        require(result.returncode == 0, f"fixture build failed: {args}: {result.stderr}")

    for tool in (clang, linker, pe_linker):
        require(shutil.which(tool), f"required fixture tool is missing: {tool}; configure its path explicitly")
        run(tool, "--version")

    common = ["-O1", "-fno-inline", "-fno-builtin", "-fno-stack-protector", "-ffreestanding"]
    macho = directory / "packet.macho"
    run(clang, *common, source, "-o", macho)
    elf_object = directory / "packet.elf.o"
    run(clang, "--target=x86_64-unknown-linux-gnu", *common, "-c", source, "-o", elf_object)
    elf = directory / "packet.elf"
    run(linker, "-e", "main", "--build-id=none", elf_object, "-o", elf)
    stripped = directory / "packet.stripped.elf"
    run(linker, "-e", "main", "--build-id=none", "--strip-all", elf_object, "-o", stripped)
    pe_object = directory / "packet.pe.obj"
    run(clang, "--target=x86_64-pc-windows-msvc", *common, "-c", source, "-o", pe_object)
    pe = directory / "packet.exe"
    run(pe_linker, "/entry:main", "/subsystem:console", "/nodefaultlib", "/timestamp:0", pe_object, "/out:" + str(pe))

    # A tiny AArch64 boot routine with code, a constant table and UTF-8 diagnostics.
    # mov w0,#42; ret. Addresses are supplied through Mapped loader settings.
    raw = directory / "firmware.bin"
    raw.write_bytes(bytes.fromhex("40058052c0035fd6") + bytes(0x100 - 8)
                    + BANNER.encode() + b"\0" + struct.pack("<IIII", 3, 5, 8, 13))
    # Keep a real parser workload large enough to exercise queued analysis and cancellation.
    busy_source = directory / "Busy.c"
    functions = [f"__attribute__((noinline)) unsigned task_{i}(unsigned x) {{"
                 f" for (unsigned j=0; j<17; ++j) x=(x*{2*i+3}u)^(x>>3)^j; return x; }}"
                 for i in range(BUSY_FUNCTIONS)]
    functions.append("unsigned main(void) { unsigned x=7; " +
                     " ".join(f"x=task_{i}(x);" for i in range(BUSY_FUNCTIONS)) + " return x; }")
    busy_source.write_text("\n".join(functions) + "\n")
    busy_object = directory / "busy.o"
    run(clang, "--target=x86_64-unknown-linux-gnu", *common, "-c", busy_source, "-o", busy_object)
    busy = directory / "busy.elf"
    run(linker, "-e", "main", busy_object, "-o", busy)
    paths = {"macho": macho, "elf": elf, "stripped": stripped, "pe": pe, "raw": raw, "busy": busy}
    manifest = {name: {"path": str(path), "size": path.stat().st_size,
                       "sha256": hashlib.sha256(path.read_bytes()).hexdigest()} for name, path in paths.items()}
    manifest["source"] = {"path": str(source), "sha256": hashlib.sha256(source.read_bytes()).hexdigest()}
    (directory / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    return paths
