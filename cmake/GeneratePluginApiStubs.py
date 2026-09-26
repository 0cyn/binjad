# Derived from Binary Ninja's MIT-licensed stubs/generate_stubs.py.

import argparse
import pathlib
import re


parser = argparse.ArgumentParser()
parser.add_argument("header")
parser.add_argument("api_macro")
parser.add_argument("output")
args = parser.parse_args()

header = pathlib.Path(args.header)
contents = re.sub(r"//.*\n", "\n", header.read_text())
pattern = re.compile(rf"(?m:^)[ \t]+({re.escape(args.api_macro)} [^;]*);")

definitions = []
for match in pattern.finditer(contents):
    declaration = match.group(1)
    if re.search(rf"{re.escape(args.api_macro)}\s+void\s+", declaration):
        definitions.append(f"{declaration} {{ }}")
    else:
        definitions.append(f"{declaration} {{ return {{ }}; }}")

if not definitions:
    raise RuntimeError(f"no {args.api_macro} declarations found in {header}")

output = pathlib.Path(args.output)
output.parent.mkdir(parents=True, exist_ok=True)
output.write_text(
    '#include <binaryninjacore.h>\n'
    f'#include "{header.resolve()}"\n\n'
    'extern "C" {\n'
    + "\n".join(definitions)
    + '\n}\n'
)
