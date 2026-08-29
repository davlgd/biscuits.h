#!/usr/bin/env python3
"""Compute the worst-case stack depth of the shipped header.

The library claims a bounded stack, which is what makes it usable on a device
whose whole stack is a few kilobytes. A claim like that has to be a number, and
the number has to come from the compiler rather than from reading the code.

Two inputs: `-fstack-usage`, which reports each function's own frame, and the
call graph from the LLVM IR -- the same graph tools/check_invariants.py uses to
prove there is no recursion. Because there is no recursion and no indirect
call, the deepest path is a straightforward longest-path over a DAG, and the
answer is exact rather than an estimate.

What it does not include: the caller's own frame, interrupt or signal frames,
and any red zone. Treat it as the library's contribution.

  stack_usage.py                     print the deepest paths
  stack_usage.py --max-bytes 8192    fail when the deepest path exceeds a bound
"""

import argparse
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile

DEFINE_RE = re.compile(r"^define[^@]*@([A-Za-z0-9_.$]+)\(")
CALL_RE = re.compile(r"\bcall[^@\n]*@([A-Za-z0-9_.$]+)\(")
# clang writes: <file>:<line>:<col>:<name>\t<bytes>\t<qualifier>
SU_RE = re.compile(r"^[^\t]*:(?P<name>[A-Za-z0-9_.$]+)\t(?P<bytes>\d+)\t")


def build(cc: str, header: pathlib.Path, tmp: pathlib.Path, flags: list) -> str:
    src = tmp / "stack.c"
    src.write_text(
        "#define BISCUITS_IMPLEMENTATION\n"
        f'#include "{header.resolve()}"\n'
    )
    proc = subprocess.run(
        [cc, "-std=c99", *flags, str(src)],
        cwd=tmp, capture_output=True, text=True,
    )
    if proc.returncode != 0:
        sys.exit(f"stack_usage: build failed\n{proc.stderr}")
    return proc.stdout


def frames(cc: str, header: pathlib.Path, tmp: pathlib.Path) -> dict:
    build(cc, header, tmp, ["-O2", "-fstack-usage", "-c", "-o", "stack.o"])
    out = {}
    for su in tmp.glob("*.su"):
        for line in su.read_text().splitlines():
            m = SU_RE.match(line)
            if m:
                # A function can appear more than once when it is cloned; the
                # largest frame is the one that matters.
                name = m.group("name")
                out[name] = max(out.get(name, 0), int(m.group("bytes")))
    return out


def callgraph(cc: str, header: pathlib.Path, tmp: pathlib.Path) -> dict:
    ir = build(cc, header, tmp, ["-O0", "-S", "-emit-llvm", "-o", "-"])
    graph, current = {}, None
    for line in ir.splitlines():
        m = DEFINE_RE.match(line)
        if m:
            current = m.group(1)
            graph.setdefault(current, set())
            continue
        if line.startswith("}"):
            current = None
            continue
        if current is not None:
            for callee in CALL_RE.findall(line):
                if not callee.startswith("llvm."):
                    graph[current].add(callee)
    return graph


def deepest(graph: dict, frame: dict) -> dict:
    """Longest path by stack bytes, memoised. Sound only without recursion,
    which tools/check_invariants.py proves separately."""
    best, path = {}, {}

    order = []
    seen = set()
    for root in sorted(graph):
        stack = [(root, False)]
        while stack:
            node, done = stack.pop()
            if done:
                order.append(node)
                continue
            if node in seen:
                continue
            seen.add(node)
            stack.append((node, True))
            for callee in sorted(graph.get(node, ())):
                if callee in graph and callee not in seen:
                    stack.append((callee, False))

    for node in order:
        own = frame.get(node, 0)
        top, via = 0, None
        for callee in sorted(graph.get(node, ())):
            if callee in best and best[callee] > top:
                top, via = best[callee], callee
        best[node] = own + top
        path[node] = via
    return best, path


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--cc", default="clang")
    ap.add_argument("--header", default="biscuits.h")
    ap.add_argument("--max-bytes", type=int, default=0)
    ap.add_argument("--top", type=int, default=5)
    args = ap.parse_args()

    if shutil.which(args.cc) is None:
        sys.exit(f"stack_usage: {args.cc} not found")

    with tempfile.TemporaryDirectory() as d:
        tmp = pathlib.Path(d)
        header = pathlib.Path(args.header)
        frame = frames(args.cc, header, tmp)
        graph = callgraph(args.cc, header, tmp)

    if not frame or not graph:
        sys.exit("stack_usage: no data; does this compiler support -fstack-usage?")

    best, via = deepest(graph, frame)

    # Only the public entry points matter: nothing else is called from outside.
    entries = sorted((n for n in best if n.startswith("bs_") and
                      not n.startswith("bs_na_")),
                     key=lambda n: -best[n])
    worst = best[entries[0]] if entries else 0

    for name in entries[: args.top]:
        chain, node = [], name
        while node is not None:
            chain.append(f"{node}({frame.get(node, 0)})")
            node = via.get(node)
        print(f"  {best[name]:>6} bytes  {' -> '.join(chain)}")

    print(f"\n  worst public entry point: {worst} bytes")

    if args.max_bytes and worst > args.max_bytes:
        sys.stderr.write(
            f"stack_usage: {worst} bytes exceeds the documented bound of "
            f"{args.max_bytes}.\n"
            f"  Either reduce it or change the documented figure -- but the\n"
            f"  documented figure must be the measured one.\n"
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
