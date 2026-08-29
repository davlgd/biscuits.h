# Safety rationale

Why this code is shaped the way it is, and what each rule buys.

## The threat model

One thing crosses the trust boundary: a byte string that arrived from an
untrusted party, usually as a base64url blob in an HTTP header. From it the
library derives a protobuf structure, a Datalog program, and an authorization
decision.

That is the whole attack surface. There is no network code, no file I/O, no
formatted output, no locale handling, no threading, no floating point, and no
dynamic linking. The only libc functions used are `memcpy`, `memcmp` and
`memset` — verified by reading the undefined symbols off the compiled object,
not by inspection. See `tools/check_invariants.py`.

An attacker controls: the length and content of the token, the number and size
of blocks, the shape and nesting of every Datalog term, the opcode sequence of
every expression, and the symbol table. An attacker does not control: the
arena, its size, the root public key, or the authorizer's own facts and
policies.

## The five invariants

### 1. No allocation

All memory comes from a caller-provided buffer through `bs_arena`. The arena
bump-allocates and is never freed piecewise: it is reset or discarded whole.

This removes use-after-free, double-free and dangling pointers outright. Not
"makes them unlikely" — makes them inexpressible, because there is no `free`
to call twice and no lifetime shorter than the arena's.

It also puts a hard ceiling on memory: a token cannot make the process
allocate. The worst it can do is exhaust a buffer the caller sized, which is a
clean `BS_ERR_NOMEM`.

Exhaustion is *sticky*. Once an allocation fails, the arena stays failed and
every later allocation returns `NULL`. This is a safety property, not an
optimisation: it means a chain of allocations can be checked once at the end
instead of once per call, which removes the most common way this pattern goes
wrong — an unchecked pointer in the middle of a long sequence.

### 2. No recursion

Nested terms (sets, arrays, maps) and nested closures are walked with an
explicit stack of depth `BS_MAX_DEPTH`, defaulting to 16. The specification's
own samples nest at most 3 deep.

A recursive decoder over attacker-controlled nesting is a stack overflow with
extra steps, and a stack overflow in a library is not something the caller can
catch. Here, exceeding the bound is `BS_ERR_DEPTH` — an ordinary error return.

Maximum stack usage is therefore a compile-time constant rather than a
function of the input. The constant is measured, not estimated: `make stack`
combines the compiler's own `-fstack-usage` frame sizes with the call graph
from the LLVM IR, and because there is no recursion and no indirect call the
deepest path is an exact longest-path over a DAG.

At `-O2` with clang on arm64, today:

| Entry point | Deepest path |
|---|---|
| `bs_world_run` | **6 864 bytes** |
| `bs_token_verify` | 6 592 bytes |
| `bs_block_print` | 2 752 bytes |
| `bs_world_parse` | 2 240 bytes |

An earlier version of this document claimed 4 KB. That figure was never
measured and was wrong; on the verification path the vendored curve arithmetic
alone accounts for more than half of the real number, with `bs_na_add` at
1 728 bytes and `bs_ed25519_verify_parts` at 2 128. Defining
`BISCUITS_NO_BUNDLED_CRYPTO` removes that path, but not the worst case:
evaluation is deeper than verification.

`make stack` fails above 8 KB, so growth is visible rather than discovered,
and it has caught growth twice. The regex engine first held its thread lists
as locals and pushed the total to 8 896 bytes; they moved to the arena. The
text parser first held its term buffers the same way and reached 8 368; they
moved too, which is why `bs_world_parse` now sits at 2 240. In both cases the
tool objected before the commit, which is the only reason these are
paragraphs rather than incidents.

### 3. Bounded loops

Every loop has a static bound or a caller-supplied one. Datalog evaluation is
governed by the run limits the specification already defines (`maxFacts`,
`maxIterations`, `maxTime`), so this rule costs nothing: the spec demands it
anyway.

### 4. Pointer arithmetic is confined

Byte ranges are `bs_span` — a pointer and a length — with checked accessors.
Pointer arithmetic and raw indexing happen only inside a fixed, enumerated set
of functions: the span and cursor accessors, the arena, and four places that
walk bytes directly (`bs_pb_next`'s little-endian assembly, `bs_pb_pubkey`'s
SEC1 prefix byte, and the writer's copy and hex loops).

That list is not a description, it is a gate: it lives in
`POINTER_ARITHMETIC_SITES` in `tools/check_invariants.py`, and a new site
fails the build until someone adds it there deliberately.

The point is not that checked accessors are individually safer. It is that
when a fuzzer finds an out-of-bounds read, the set of places it can have come
from is small enough to read in one sitting — and small enough to be worth
model-checking exhaustively.

Lengths derived from input never use bare `+` or `*`. `bs_size_add` and
`bs_size_mul` wrap `__builtin_*_overflow` and refuse to produce a wrapped
value. A silent wrap is how a bounds check becomes a no-op.

### 5. Minimal libc

`memcpy`, `memcmp`, `memset`, and nothing else. This is what lets the header
be dropped into a kernel module, a WASM sandbox or bare-metal firmware without
a shim — and it removes `printf` format strings, locale-dependent comparison,
and the `str*` family's off-by-one folklore from the threat model entirely.

Some toolchains lower `memset(p, 0, n)` to `bzero`, so an embedding target
provides one or the other. That is stated because it is what the shipped
object actually requires, and the check reads the object rather than the
source.

The `str*` family is absent by construction rather than by discipline. String
lengths come from `sizeof` at compile time: a hand-written scan for the
terminator is an idiom the optimiser recognises and rewrites into a call to
`strlen`, which puts a `str*` function into the object while the source
contains none. That is not hypothetical — it is what the first run of
`tools/check_invariants.py` found, and why the check reads symbols instead of
grepping code.

## What is enforced, and how

A claim in this file is either checked by a build target or labelled as review.
There is no third category.

| Invariant | Enforcement |
|---|---|
| 1. No allocation | `make invariants` — undefined symbols of the compiled object |
| 2. No recursion | `make invariants` — cycle detection over the compiler's own call graph |
| 3. Bounded loops | Review. Not mechanically checkable; the specification's run limits are the bound. |
| 4. Pointer arithmetic confined | `make invariants` — pinned site list |
| 5. Minimal libc | `make invariants` — undefined symbols of the compiled object |

The symbol and call-graph checks run on `biscuits.h` as shipped, so they cover
anything that reaches the artifact, including code introduced by a macro. The
checker is itself tested against injected violations — direct recursion, mutual
recursion, and a hidden `malloc` — because a checker that only ever passes is
worth nothing.

## Relation to the Power of Ten

The JPL/NASA [Power of Ten](https://spinroot.com/gerard/pdf/P10.pdf) rules for
safety-critical code map onto this project as follows. The convergence is not
a coincidence: a rule set designed for code that cannot fail in flight and a
token library that cannot fail under attack want the same things.

| Rule | Here |
|---|---|
| 1. Simple control flow, no recursion | Adopted for recursion. **Not** adopted for `goto`: single-exit cleanup is the idiom that reduces leaks in C, and CERT C and the Linux kernel both permit it. |
| 2. Fixed loop bounds | Adopted. The specification's run limits are the bound. |
| 3. No dynamic allocation after init | Adopted, in the strong form: no dynamic allocation at all. |
| 4. Functions fit on one page | Adopted as a guideline. The protobuf field dispatcher is a wide switch and is allowed to be long, because splitting it would scatter the wire format. |
| 5. Two assertions per function | **Not** adopted as a count. Assertions state invariants; input validation returns a `bs_status`. A rule that rewards assertion count encourages asserting on attacker input, which is exactly wrong. |
| 6. Smallest possible scope | Adopted. |
| 7. Check every return value | Adopted. Every public entry point carries `warn_unused_result` via `BS_MUST_USE`, so ignoring one is a build failure unless written as an explicit `(void)` cast. |
| 8. Limited preprocessor | Adopted. Configuration macros and include guards only; no code-generating macros. |
| 9. Restricted pointer use | Adopted. One level of dereference, no function pointers in the core. |
| 10. All warnings on, multiple analysers | Adopted, and then some. See below. |

Where a rule is not adopted, the reason is stated. "Too inconvenient" is not
among the reasons.

## What `BS_ASSERT` is for

`BS_ASSERT` documents a fact the code has already established. It compiles to
nothing by default and to `assert()` under test and fuzz builds.

It is never the check standing between attacker input and a buffer. That check
is an `if` returning a `bs_status`, always. If a `BS_ASSERT` can be reached
with hostile bytes, the bug is the missing validation upstream, not the
assert.

The value of this split is that under the fuzzer every documented invariant
becomes an oracle: the fuzzer does not only look for crashes, it looks for
violated beliefs.

The invariants currently asserted are: the cursor never advances past its span
(`bs_cursor_left`, `bs_take_bytes`); an arena allocation lies wholly inside the
buffer (`bs_arena_alloc`); the block index stays below the counted block count
(`bs_token_parse`); and the printer's frame stack never exceeds its bound
(`bs_term_print`). Each one is a fact the surrounding code has already
established by other means, which is what makes it an oracle rather than a
check.

## Compiler flags that are load-bearing

- `-fwrapv` — signed overflow becomes defined wrapping rather than undefined
  behaviour, so the compiler cannot delete an overflow check on the grounds
  that overflow "cannot happen". Detection still uses
  `__builtin_*_overflow`, because the specification requires an overflowing
  Datalog expression to *fail*, not to wrap.
- `-fno-strict-aliasing` — this code decodes wire formats.
- `-Wconversion -Wsign-conversion` — noisy, and the only reliable way to catch
  the silent narrowing that turns a length comparison into a tautology.
- `-fno-sanitize-recover=all` — turns UBSan from a log into a gate.

Hardening flags (`-fstack-protector-strong`, `_FORTIFY_SOURCE=3`,
`-ftrivial-auto-var-init=zero`) are applied to release builds but are never
load-bearing. The code is correct without them.
