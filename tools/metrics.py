#!/usr/bin/env python3
"""Measure the shipped header and keep README.md honest about the numbers.

The size figures are the project's headline claim, so quoting them by hand is
exactly the wrong way to carry them: they go stale within a commit or two and
nobody notices. This regenerates the block between the metrics markers in
README.md, and `--check` fails the build when the committed figures no longer
match the tree.

  metrics.py            print the measurements
  metrics.py --write    update README.md in place
  metrics.py --check    fail if README.md is out of date
"""

import argparse
import pathlib
import re
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
README = ROOT / "README.md"
BEGIN = "<!-- metrics:begin -->"
END = "<!-- metrics:end -->"


def measure(cc: str, header: pathlib.Path) -> dict:
    lines = header.read_text().count("\n")
    with tempfile.TemporaryDirectory() as d:
        tmp = pathlib.Path(d)
        src = tmp / "size.c"
        src.write_text(
            "#define BISCUITS_IMPLEMENTATION\n"
            f'#include "{header.resolve()}"\n'
        )
        obj = tmp / "size.o"
        subprocess.run(
            [cc, "-std=c99", "-Os", "-c", str(src), "-o", str(obj)],
            check=True, capture_output=True, text=True,
        )
        size = obj.stat().st_size
    return {"lines": lines, "object": size}


def render(m: dict) -> str:
    return (
        f"{BEGIN}\n"
        "```\n"
        f"header       {m['lines']:>6} lines\n"
        f"object -Os   {m['object']:>6} bytes\n"
        "```\n"
        f"{END}"
    )


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--cc", default="cc")
    ap.add_argument("--header", default=str(ROOT / "biscuits.h"))
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--check", action="store_true")
    args = ap.parse_args()

    m = measure(args.cc, pathlib.Path(args.header))
    block = render(m)

    if not (args.write or args.check):
        print(f"  header       {m['lines']:>6} lines")
        print(f"  object -Os   {m['object']:>6} bytes")
        return 0

    text = README.read_text()
    pattern = re.compile(re.escape(BEGIN) + r".*?" + re.escape(END), re.S)
    if not pattern.search(text):
        sys.exit(f"metrics: README.md has no {BEGIN} .. {END} block")

    updated = pattern.sub(lambda _: block, text)

    if args.write:
        README.write_text(updated)
        print(f"  METRICS      README.md: {m['lines']} lines, {m['object']} bytes")
        return 0

    if updated != text:
        sys.stderr.write(
            "metrics: README.md quotes stale numbers.\n"
            f"  measured: {m['lines']} lines, {m['object']} bytes\n"
            "  Run 'make metrics' and commit the result.\n"
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
