# biscuits.h

**Biscuit authorization tokens in a single C99 header. Zero dependencies.**

[Biscuit](https://biscuitsec.org) is a bearer token with offline attenuation
and decentralized verification: a token can be restricted further by anyone
holding it, without talking to the issuer, and verified by anyone holding the
root public key. That design is aimed squarely at the edge — gateways, proxies,
embedded devices, WASM sandboxes.

This is a verification core for exactly those places. One file you drop into a
project. No build system, no code generation, no runtime, no allocator.

> **Status: early development.** The foundation layer is in place and tested.
> Nothing here verifies a token yet. The claims below are tracked as targets
> with measured numbers, not as marketing. See [Progress](#progress).

## Usage

```c
#define BISCUITS_IMPLEMENTATION
#include "biscuits.h"
```

In exactly one translation unit. Everywhere else, include it plain.

The library never allocates. You hand it a buffer; it bump-allocates from that
buffer and nothing else:

```c
uint8_t scratch[64 * 1024];
bs_arena arena;
bs_arena_init(&arena, scratch, sizeof scratch);
```

When the work is done the arena is reset or simply goes out of scope. There is
nothing to free, and `bs_arena_peak()` tells you how large the buffer actually
needed to be, so you can size it from a real workload instead of guessing.

## Why this exists

The reference implementation is [`biscuit-rust`](https://github.com/biscuit-auth/biscuit-rust),
and it is the canonical one — this project does not compete for that role. But
its C API builds to a **2.8 MB** stripped shared library (17.7 MB static) from
a graph of **79 crates**. That is a perfectly reasonable size for a server, and
an impossible one for an nginx module, a Postgres extension, a Cortex-M
firmware, or a browser tab.

Those three figures are reproducible: `tools/compare.sh` regenerates all of
them and prints the revision, the toolchain and the target it measured on. A
project whose argument is *measure, do not assert* has no business quoting
numbers nobody else can check.

So the gap is not quality, it is reach. `biscuits.h` aims to be the artifact
you can put where the reference implementation cannot go — and, because a
single header binds trivially from any language with an FFI, the shared core
behind several language bindings rather than several independent rewrites that
drift apart.

## Design invariants

Four of the five are checked by `make invariants`, on the compiled artifact
rather than on the source — so anything that reaches the shipped object is
covered, including code introduced through a macro. The fifth is labelled as
review, because it is not mechanically checkable and pretending otherwise
would be the kind of claim this table exists to avoid.

| # | Invariant | Why it matters | Enforcement |
|---|---|---|---|
| 1 | **No allocation.** All memory comes from a caller-provided arena, never freed piecewise. | Use-after-free and double-free become unreachable by construction — the bug class a borrow checker exists to prevent. | undefined symbols of the compiled object |
| 2 | **No recursion.** Nested terms and closures are walked with an explicit bounded stack. | Stack depth is a compile-time constant. Deep nesting returns `BS_ERR_DEPTH`, never a crash. | cycle detection over the compiler's own call graph |
| 3 | **Bounded loops.** Every loop has a static or caller-supplied bound. | Datalog evaluation cannot be made to run forever by a hostile token. | review |
| 4 | **Pointer arithmetic is confined** to an enumerated set of accessors. | When a fuzzer finds an out-of-bounds read, the set of places it can have come from is small enough to read in one sitting. | pinned site list |
| 5 | **No libc beyond `memcpy`, `memcmp`, `memset`.** | No stdio, no locale, no floating point. Usable in a kernel module or bare metal without a shim. | undefined symbols of the compiled object |

The checker is itself tested against injected violations — direct recursion,
mutual recursion, and a hidden `malloc` — because a checker that only ever
passes is worth nothing. Its first run found two real breaches of invariant 5:
the optimiser had rewritten a hand-written scan for a string terminator into a
call to `strlen`, and `memset(p, 0, n)` into `bzero`. Neither appears anywhere
in the source. That is why the check reads symbols instead of grepping code.

Invariants 1–3 are the first three rules of the JPL/NASA
[Power of Ten](https://spinroot.com/gerard/pdf/P10.pdf). They are not imposed
from outside: the Biscuit specification's own run limits and nesting rules
demand them anyway.

## On memory safety

C is not memory-safe, and this project does not pretend otherwise. The honest
position is that the arena removes the temporal-safety class outright, and the
residual risk — spatial safety and integer overflow — is answered with
evidence rather than assertion: sanitizers on every commit, continuous
fuzzing, and bounded model checking of the wire decoder, which is the only
code that ever touches attacker-controlled bytes.

[`SECURITY.md`](SECURITY.md) carries the current numbers. Read it before
trusting this with anything.

## Progress

The target is the official conformance suite: 38 test cases shipped with the
[specification](https://github.com/biscuit-auth/biscuit/tree/main/samples/current),
each with a binary token and its expected authorization result. It is an
objective bar — either the number is 36/38 or it is not.

The two ECDSA `secp256r1` cases are explicitly out of scope for 1.0 and
tracked for 1.1: roughly 2000 lines of delicate constant-time crypto for two
test cases is the wrong trade to make first. Everything else is in scope.

| Component | State |
|---|---|
| Arena, spans, cursors | done |
| Conformance harness | done — 4 tiers, 200 checks over 50 validations |
| Protobuf wire decoder | done — **48/48** on the decode tier |
| Token container decoder | done — **43/43** on the revocation-id tier |
| Output writer and symbol table | done |
| Term printer | done — recursion-free, depth-bounded |
| Block decoder and Datalog printer | in progress — unlocks the `blocks` tier |
| Base64url | not started |
| Ed25519 verification | not started |
| Datalog engine | not started |
| Expression VM | not started |
| Datalog text parser | not started |
| Authorizer | not started |
| ECDSA secp256r1 | deferred to 1.1 |

318 unit assertions, all sanitizer- and analyser-clean. Measured on the current
tree — `make metrics` regenerates this block and CI fails if it drifts:

<!-- metrics:begin -->
```
header         1934 lines
object -Os    13728 bytes
```
<!-- metrics:end -->

## Building

```sh
make             # amalgamate, build, test, conformance and invariants
make conformance # the official spec suite, scored by tier
make invariants  # the design invariants, checked on the compiled object
make asan        # AddressSanitizer + UndefinedBehaviorSanitizer
make lint        # amalgamation, format, clang-tidy, cppcheck, invariants
make analyze     # clang static analyzer
make metrics     # regenerate the size figures in this file
```

The conformance suite runs through a shim, so the same runner scores any
Biscuit implementation in any language. See
[`tests/conformance/README.md`](tests/conformance/README.md).

Development happens in `src/*.inc` fragments; `biscuits.h` is generated by
`tools/amalgamate.py` and committed. CI fails if the two ever drift.

The optional analysis targets want a real LLVM rather than Apple's:
`brew install llvm cppcheck cbmc lcov`.

## Layout

```
biscuits.h            the shipped artifact (generated, committed)
src/*.inc             development fragments, in amalgamation order
tools/amalgamate.py   fragments -> header
tests/unit/           unit tests, TAP output
tests/conformance/    runner for the official spec samples
vendor/biscuit-spec/  the specification, pinned as a submodule
docs/                 design and safety rationale
```

Clone with `--recurse-submodules`, or run `git submodule update --init
--depth 1` afterwards.

## License

Apache-2.0. See [LICENSE](LICENSE).

The Biscuit specification and its sample suite are the work of the
[biscuit-auth](https://github.com/biscuit-auth) project, also Apache-2.0.
