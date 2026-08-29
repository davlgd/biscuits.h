# Safety rationale

Why this code is shaped the way it is, and what each rule buys.

## The threat model

One thing crosses the trust boundary: a byte string that arrived from an
untrusted party, usually as a base64url blob in an HTTP header. From it the
library derives a protobuf structure, a Datalog program, and an authorization
decision.

That is the whole attack surface. There is no network code, no file I/O, no
formatted output, no locale handling, no threading, no floating point, and no
dynamic linking. The three libc functions used are `memcpy`, `memcmp` and
`memset`.

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

Maximum stack usage is therefore a compile-time constant, which is what makes
the library usable on a device with a 4 KB stack.

### 3. Bounded loops

Every loop has a static bound or a caller-supplied one. Datalog evaluation is
governed by the run limits the specification already defines (`maxFacts`,
`maxIterations`, `maxTime`), so this rule costs nothing: the spec demands it
anyway.

### 4. No pointer arithmetic

Byte ranges are `bs_span` — a pointer and a length — with checked accessors.
Raw pointer arithmetic exists only inside `bs_span_slice`.

The point is not that checked accessors are individually safer. It is that
when a fuzzer finds an out-of-bounds read, there is one function to look at.

Lengths derived from input never use bare `+` or `*`. `bs_size_add` and
`bs_size_mul` wrap `__builtin_*_overflow` and refuse to produce a wrapped
value. A silent wrap is how a bounds check becomes a no-op.

### 5. Minimal libc

`memcpy`, `memcmp`, `memset`, and nothing else. This is what lets the header
be dropped into a kernel module, a WASM sandbox or bare-metal firmware without
a shim — and it removes `printf` format strings, locale-dependent comparison,
and the `str*` family's off-by-one folklore from the threat model entirely.

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
| 7. Check every return value | Adopted, enforced by `-Wunused-result` and clang-tidy. |
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
