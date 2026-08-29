#!/bin/sh
# Regenerate the biscuit-rust comparison figures quoted in README.md.
#
# A document whose whole argument is "measure, do not assert" cannot carry
# three numbers nobody can reproduce. This script produces all of them, states
# the versions and the target it measured on, and takes about a minute.
#
#   tools/compare.sh [workdir]
#
# Requires: git, cargo, and enough disk for one Rust build.

set -eu

WORK="${1:-${TMPDIR:-/tmp}/biscuits-compare}"
REPO="https://github.com/biscuit-auth/biscuit-rust.git"

printf 'target      %s\n' "$(cc -dumpmachine 2>/dev/null || uname -sm)"
printf 'rustc       %s\n' "$(rustc --version)"

mkdir -p "$WORK"
if [ ! -d "$WORK/biscuit-rust/.git" ]; then
    git clone --depth 1 "$REPO" "$WORK/biscuit-rust" >/dev/null 2>&1
fi
cd "$WORK/biscuit-rust"

printf 'biscuit-rust %s\n' "$(git rev-parse --short HEAD)"
printf 'version     %s\n' \
    "$(sed -n 's/^version = "\(.*\)"/\1/p' biscuit-auth/Cargo.toml | head -1)"

# The C API crate is the fair comparison: it is what a C project would link.
# Its default crate-type does not include a linkable library, so ask for one.
if ! grep -q 'crate-type' biscuit-capi/Cargo.toml; then
    printf '\n[lib]\ncrate-type = ["staticlib", "cdylib", "rlib"]\n' \
        >> biscuit-capi/Cargo.toml
fi

printf 'crates      %s unique in the biscuit-auth dependency graph\n' \
    "$(cargo tree -p biscuit-auth --edges normal --prefix none 2>/dev/null \
       | awk '{print $1}' | sort -u | grep -c .)"

# release-strip is the crate's own profile: release plus stripped symbols,
# which is the smallest artifact its authors ship.
cargo build --profile release-strip -p biscuit-capi >/dev/null 2>&1

for f in target/release-strip/libbiscuit_capi.dylib \
         target/release-strip/libbiscuit_capi.so \
         target/release-strip/libbiscuit_capi.a; do
    [ -f "$f" ] || continue
    printf '%-11s %s KB  (%s)\n' "$(basename "$f")" \
        "$(( $(wc -c < "$f") / 1024 ))" "release-strip"
done

printf '\nnon-test lines of Rust (naive: everything before the first #[cfg(test)])\n'
total=0
for f in $(find biscuit-auth/src biscuit-parser/src -name '*.rs'); do
    n=$(awk '/#\[cfg\(test\)\]/{exit} {c++} END{print c+0}' "$f")
    total=$((total + n))
done
printf 'biscuit-auth + biscuit-parser  %s\n' "$total"
