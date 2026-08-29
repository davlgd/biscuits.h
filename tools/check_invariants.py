#!/usr/bin/env python3
"""Verify the design invariants against the shipped header, not the intent.

README.md claims five invariants and says CI enforces them. This is that
enforcement. Two of the five are checked here soundly, on the compiled
artifact rather than on the source:

  1. No allocation, and 5. minimal libc
     Compile biscuits.h with BISCUITS_IMPLEMENTATION and list the undefined
     symbols. Anything the library calls and does not define shows up here, so
     a malloc that creeps in through any path -- including one hidden behind a
     macro or a helper -- is caught. The allowed set is the three memory
     functions and nothing else; see ALLOWED_LIBC for why bzero is among
     them.

  2. No recursion
     Emit LLVM IR, build the call graph from it, and look for a cycle. This is
     sound for this codebase specifically because there are no function
     pointers (Power of Ten rule 9, which the same absence of indirect calls
     makes checkable): every edge in the graph is a direct call and the IR
     names both ends.

The remaining invariants are not mechanically checkable and are not claimed to
be. Invariant 3 (bounded loops) is a review property; invariant 4 (pointer
arithmetic confined to named accessors) is pinned by an explicit list below,
so the set cannot grow without someone editing this file.

Usage:  check_invariants.py [--cc clang] [--header biscuits.h]
"""

import argparse
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile

# The complete libc surface this library is allowed to have. Growing this list
# is a design decision, not a build fix: each entry is a dependency every
# embedding target must provide.
#
# bzero and bcmp are here although the source calls neither. Compilers lower
# memset(p, 0, n) to bzero and memcmp(a, b, n) == 0 to bcmp, and which of them
# appears depends on the target: bzero showed up on Darwin, bcmp on Linux with
# glibc. An embedding target must provide whichever its toolchain emits, so
# claiming "memcpy, memcmp, memset" alone would be a claim the shipped object
# does not honour on either platform.
#
# This is the whole reason the check reads symbols instead of grepping source.
ALLOWED_LIBC = {"memcpy", "memcmp", "memset", "bzero", "bcmp"}

# Symbols the toolchain injects rather than the source calling them. Kept
# narrow on purpose; anything not listed here is reported.
TOOLCHAIN_SYMBOLS = {
    "__stack_chk_fail",
    "__stack_chk_guard",
    # _FORTIFY_SOURCE, which Apple's SDK enables by default at -O1 and above,
    # rewrites memcpy and friends into bounds-checking wrappers. These are the
    # allowed functions with a length check bolted on, not new dependencies --
    # but they are listed rather than pattern-matched, so a genuinely new
    # __-prefixed symbol still shows up.
    "__memcpy_chk",
    "__memmove_chk",
    "__memset_chk",
}

# Invariant 4: the functions permitted to do pointer arithmetic or index
# through a raw pointer. Everything else must go through these. Pinned rather
# than inferred, so adding a site is a visible edit to this list.
POINTER_ARITHMETIC_SITES = {
    "bs_span_at",
    "bs_span_slice",
    "bs_span_eq",
    "bs_take_u8",
    "bs_arena_alloc",
    "bs_arena_init",
    "bs_pb_next",     # little-endian assembly of a fixed-width field
    "bs_pb_pubkey",   # SEC1 prefix byte
    "bs_put_span",
    "bs_put_i64",
    "bs_put_pad",
    "bs_put_hex",
    "bs_put_string",
    "bs_symbol_get",
    "bs_scalar_is_canonical",  # walks the 32 bytes of a signature scalar
    # The regex engine walks its pattern and its subject byte by byte; that is
    # what a matcher is.
    "bs_re_class",
    "bs_re_tokenise",
    "bs_re_search",
}


def build_object(cc: str, header: pathlib.Path, tmp: pathlib.Path) -> pathlib.Path:
    src = tmp / "unit.c"
    src.write_text(
        "#define BISCUITS_IMPLEMENTATION\n"
        f'#include "{header.resolve()}"\n'
        # The library is header-only; without a reference the compiler may
        # discard everything and the check would pass vacuously.
        "const void *bs_anchor(void);\n"
        "const void *bs_anchor(void) { return (const void *)&bs_token_parse; }\n"
    )
    obj = tmp / "unit.o"
    subprocess.run(
        [cc, "-std=c99", "-O2", "-c", str(src), "-o", str(obj)],
        check=True, capture_output=True, text=True,
    )
    return obj


def check_symbols(obj: pathlib.Path) -> list:
    """Invariants 1 and 5, read off the compiled object."""
    out = subprocess.run(["nm", "-u", str(obj)],
                         check=True, capture_output=True, text=True).stdout
    problems = []
    for line in out.splitlines():
        name = line.split()[-1] if line.split() else ""
        if not name:
            continue
        # Mach-O prefixes global symbols with an underscore; ELF does not.
        bare = name[1:] if name.startswith("_") else name
        if bare in ALLOWED_LIBC or bare in TOOLCHAIN_SYMBOLS:
            continue
        problems.append(
            f"undefined symbol {bare!r}: the library may only call "
            f"{', '.join(sorted(ALLOWED_LIBC))} (invariants 1 and 5)"
        )
    return problems


DEFINE_RE = re.compile(r"^define[^@]*@([A-Za-z0-9_.$]+)\(")
CALL_RE = re.compile(r"\bcall[^@\n]*@([A-Za-z0-9_.$]+)\(")


def check_recursion(cc: str, header: pathlib.Path, tmp: pathlib.Path) -> list:
    """Invariant 2, from the call graph the compiler itself built."""
    src = tmp / "ir.c"
    src.write_text(
        "#define BISCUITS_IMPLEMENTATION\n"
        f'#include "{header.resolve()}"\n'
    )
    ir = subprocess.run(
        [cc, "-std=c99", "-O0", "-S", "-emit-llvm", str(src), "-o", "-"],
        check=True, capture_output=True, text=True,
    ).stdout

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

    if not graph:
        return ["could not build a call graph: no function definitions in the IR"]

    # Iterative depth-first cycle detection: the checker that enforces "no
    # recursion" does not itself recurse.
    WHITE, GREY, BLACK = 0, 1, 2
    colour = {f: WHITE for f in graph}
    problems = []

    for root in sorted(graph):
        if colour[root] != WHITE:
            continue
        stack = [(root, iter(sorted(graph.get(root, ()))))]
        path = [root]
        colour[root] = GREY
        while stack:
            node, it = stack[-1]
            advanced = False
            for callee in it:
                if callee not in graph:
                    continue  # external or undefined: no edge to follow
                if colour[callee] == GREY:
                    cycle = " -> ".join(path[path.index(callee):] + [callee])
                    problems.append(f"recursion in the call graph: {cycle}")
                    continue
                if colour[callee] == WHITE:
                    colour[callee] = GREY
                    path.append(callee)
                    stack.append((callee, iter(sorted(graph[callee]))))
                    advanced = True
                    break
            if not advanced:
                colour[node] = BLACK
                stack.pop()
                path.pop()
    return problems


def check_pointer_sites(src_dir: pathlib.Path) -> list:
    """Invariant 4, pinned rather than inferred.

    This one is a heuristic and says so: it matches the shapes pointer
    arithmetic actually takes in this codebase -- arithmetic or indexing
    through a span's `p`, and the arena advancing its `base` -- rather than
    attempting to understand C. Its first version matched `fr->base + 1U`,
    which is integer arithmetic on a struct field, and reported three
    findings that were not real. A gate that cries wolf is a gate people
    switch off, so the pattern is narrow on purpose; the safety net underneath
    it is the sanitizer and fuzz coverage, not this.
    """
    func_re = re.compile(r"^(?:static |BS_API )[A-Za-z_][^;]*\b([a-z_0-9]+)\(")
    arith_re = re.compile(r"(?:[.>]p\s*[+\[]|a->base\s*\+|\bbase\s*\+=)")
    problems, current = [], None
    for path in sorted(src_dir.glob("*.inc")):
        for n, line in enumerate(path.read_text().splitlines(), 1):
            m = func_re.match(line)
            if m:
                current = m.group(1)
            stripped = line.split("/*")[0]
            if arith_re.search(stripped) and current not in POINTER_ARITHMETIC_SITES:
                problems.append(
                    f"{path.name}:{n}: pointer arithmetic in {current!r}, which is "
                    f"not in POINTER_ARITHMETIC_SITES (invariant 4)"
                )
    return problems


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--cc", default="clang")
    ap.add_argument("--header", default="biscuits.h")
    args = ap.parse_args()

    header = pathlib.Path(args.header)
    if not header.is_file():
        sys.exit(f"check_invariants: no such header {header}")
    if shutil.which(args.cc) is None:
        sys.exit(f"check_invariants: {args.cc} not found")

    problems = []
    with tempfile.TemporaryDirectory() as d:
        tmp = pathlib.Path(d)
        try:
            obj = build_object(args.cc, header, tmp)
        except subprocess.CalledProcessError as exc:
            sys.exit(f"check_invariants: build failed\n{exc.stderr}")
        problems += check_symbols(obj)
        problems += check_recursion(args.cc, header, tmp)

    problems += check_pointer_sites(pathlib.Path("src"))

    if problems:
        sys.stderr.write("invariant violations:\n")
        for p in problems:
            sys.stderr.write(f"  {p}\n")
        return 1

    print("  INVARIANTS   no allocation, no recursion, minimal libc, "
          "pointer arithmetic confined")
    return 0


if __name__ == "__main__":
    sys.exit(main())
