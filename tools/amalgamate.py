#!/usr/bin/env python3
"""Build the shipped single header from the development fragments in src/.

We develop in small fragments and ship one file. The fragments are not
independently compilable on purpose: they are sections of one translation
unit, and every include lives in the prologue. Tests compile the *shipped*
header, so what is tested is exactly what a user gets.

  amalgamate.py --out biscuits.h    regenerate the header
  amalgamate.py --check biscuits.h  fail if the header is stale (CI gate)
  amalgamate.py --list              print fragment paths (for make deps)
"""

import argparse
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
SRC = ROOT / "src"

# Explicit order. A glob would silently reorder the world the day someone
# adds a file, and the failure would be a confusing compile error rather than
# a review comment.
PARTS = [
    "00_prologue.inc",
    "10_config.inc",
    "20_api.inc",
    "30_impl_open.inc",
    "40_util.inc",
    "50_pb.inc",
    "60_token.inc",
    "70_writer.inc",
    "75_symbols.inc",
    "80_term.inc",
    "85_block.inc",
    "90_expr.inc",
    "95_datalog.inc",
    "99_epilogue.inc",
]

BANNER = """\
/* ===========================================================================
 * {name}
 * ======================================================================== */
"""


def render() -> str:
    out = []
    for name in PARTS:
        path = SRC / name
        if not path.is_file():
            sys.exit(f"amalgamate: missing fragment {path}")
        text = path.read_text(encoding="utf-8")
        # The prologue carries the file's own header comment; the rest get a
        # section banner so the shipped file stays navigable.
        if name != PARTS[0]:
            out.append(BANNER.format(name=name))
        out.append(text.rstrip("\n") + "\n")
    return "\n".join(out)


def main() -> int:
    ap = argparse.ArgumentParser()
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--out", metavar="FILE")
    g.add_argument("--check", metavar="FILE")
    g.add_argument("--list", action="store_true")
    args = ap.parse_args()

    if args.list:
        print(" ".join(str(SRC / p) for p in PARTS))
        return 0

    text = render()

    if args.out:
        pathlib.Path(args.out).write_text(text, encoding="utf-8")
        return 0

    target = pathlib.Path(args.check)
    current = target.read_text(encoding="utf-8") if target.is_file() else None
    if current != text:
        sys.stderr.write(
            f"amalgamate: {target} is stale.\n"
            f"  The shipped header does not match src/. Run 'make amalgamate'\n"
            f"  and commit the result.\n"
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
