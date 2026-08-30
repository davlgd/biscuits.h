# Security

## Status: do not use this yet

This library is under initial development. It verifies signature chains but
cannot yet authorize anything. Nothing here should be relied on for anything.

It has had one adversarial review, which found a misaligned-pointer defect in
the arena, a specification rule the decoder did not enforce, and several claims
in this documentation that were not true. All are fixed. One review is not a
track record.

This file exists from the first commit on purpose: the evidence table below is
meant to be filled in as the work happens, not assembled afterwards to justify
a release.

The invariant checks earned their place immediately. Their first run found two
real breaches of the minimal-libc rule that no amount of reading the source
would have shown: the optimiser had rewritten a hand-written scan for a string
terminator into a call to `strlen`, and `memset(p, 0, n)` into `bzero`.

## Reporting a vulnerability

Open a private security advisory through GitHub's
[security advisory](https://github.com/davlgd/biscuits.h/security/advisories/new)
form. Please do not open a public issue for anything exploitable.

Expect an acknowledgement within a week.

## What has gone wrong so far

Recording this because a security file that only lists what passes is a
marketing document. Nine of the entries below were found after the code passed
every gate in CI, most of them by adversarial review rather than by a test --
which is the useful lesson: a green suite means the tests pass, not that the
code is right.

**Signature malleability.** An adversarial review found that the vendored
NaCl verifier accepts a non-canonical scalar: L*B is the identity, so S and
S + k*L satisfy the same equation and both verify. The specification defines a
block's revocation identifier as its signature, so the consequence was that
anyone holding a token could produce a different byte string that still
verified with different revocation identifiers — defeating the one control
aimed at an attacker who already holds a valid token. Reproduced on an
unmodified specification sample, confirmed against the reference
implementation, fixed, and pinned by regression tests. It was in the tree for
one commit.

The lesson is narrow and worth stating: vendoring a reviewed implementation
transfers its assumptions along with its code. NaCl's API predates the
requirement to reject malleable signatures; taking `crypto_sign_open` and
calling the result RFC 8032 verification was the error, and no amount of test
vectors from RFC 8032 itself would have caught it, because RFC 8032's vectors
do not include malleated signatures.

**A block that could impersonate the authorizer.** Origins are a 64-bit set:
each block owns a bit, and the authorizer owns one too. `BS_MAX_BLOCKS` was 64,
so blocks owned bits 0 through 63 -- and `BS_ORIGIN_AUTHORIZER` was bit 63. A
token attenuated to the full sixty-four blocks would have had its last block
indistinguishable from the application's own authorizer, and since every
authorizer rule trusts the authorizer by default, that block's facts would
have been trusted as though the application had stated them itself. The bearer
of any token could append blocks until they reached that position. Found while
writing the authorizer, when the two constants had to be read side by side for
the first time; fixed by capping blocks at 63 so bit 63 belongs to nothing
else, and pinned by a test that walks every block index and asserts none of
them collides.

The lesson here is about arithmetic that reads as obviously right. "Sixty-four
blocks, sixty-four bits" is the kind of correspondence that survives review
precisely because it looks like a fit rather than a coincidence.

**A scope annotation that inverted itself.** `trusting previous` is defined as
"the current block and every block before it", and the specification adds that
it "is ignored when used in the authorizer". This implementation reasoned that
the authorizer sits at the end of the chain, so for it `previous` should mean
every block there is -- and wrote that down as a comment explaining the choice.
It is the opposite of what the specification says, and it fails in the unsafe
direction: an annotation whose job is to *narrow* the trusted set to nothing
instead widened it to include every block an attacker had appended. Reproduced
on an unmodified specification sample, where an authorizer policy written
`allow if right($r, $op) ... trusting previous` matched a right that an
appended block had granted itself and the authority never issued. Found by an
adversarial review; the conformance suite could not have caught it, because no
official sample writes `trusting previous` in an authorizer.

**A trust boundary the loader never read.** A block may carry its own
`trusting` annotation covering everything in it. The wire loader looked only
for rule-level annotations, so a block that had deliberately narrowed what its
rules and checks could see silently got the default set instead -- wider, and
containing exactly what the block had asked to exclude. The printer already
knew the field existed and refused to render it, which made the gap visible to
anyone who compared the two; nothing compared them. Now honoured on all three
paths: loader, printer and text parser.

**An unbounded join behind a bounded-looking limit.** `max_iterations` counts
fixpoint rounds and says nothing about the work inside one round. Matching a
body of N predicates against F facts is F^N candidate combinations, and a
token's own blocks choose both, so a single appended rule bought an evaluation
that terminates in theory and not in practice -- with every configured limit
respected. `docs/SAFETY.md` cited the specification's `maxTime` as the bound,
which this library cannot implement: bounding time needs a clock, and the
fifth invariant is "memcpy, memcmp, memset". The bound is now on work
(`bs_limits.max_steps`), which is deterministic where a time bound is not.

**A guard that had gone missing.** `BS_PUT_LIT` takes a string literal and
uses `sizeof` for its length. It once carried a `"" lit` concatenation that
makes anything but a literal a syntax error; at some point that guard was
lost, and the very next use of the macro passed a ternary -- so `sizeof`
measured a pointer and the writer would have emitted seven bytes of whatever
followed. Caught while writing it, not by any tool. The guard is back, with
the reason written next to it.

**An invariant check that could be evaded.** The tool that pins the library's
single indirect call detected it by looking for a register callee on a line
carrying no `@`. An indirect call that also mentions a global -- a string
literal, a static table, a function address passed as an argument -- has an
`@` on the line and was therefore invisible, so a second unpinned indirect
call would have passed `make invariants` silently. The discriminator is now
the callee's form alone, and the check is self-tested against exactly that
evasion.

**Printers that reported success on truncated output.** Every public printer
except `bs_block_print` returned `BS_OK` after the writer had overflowed, so a
caller with a small buffer got a shorter string that still reads as Datalog.
`right("fil` is not an error; it is a different fact.

**A date that was not a date.** The lexer bounded the day at 1..31 with no
per-month limit, so `2020-02-31T00:00:00Z` was accepted and the days-from-civil
conversion silently normalised it to the 2nd of March -- two spellings for one
instant, one of which nobody wrote on purpose.

**Subtraction read as a negative number.** The grammar makes whitespace around
an operator optional, so `3-2` is a subtraction while `f(-2)` is a negative
literal, and nothing about the character says which. The lexer decided on its
own and always chose the literal, which made `3-2` a syntax error. The parser
now says which it expects.

**A stack figure that was never measured.** This documentation claimed the
library ran in 4 KB of stack. The measured worst case is 6 592 bytes. The
figure had been written from intuition; there is now a `make stack` target
that computes it from the compiler's own frame sizes, and CI fails if it
grows. It has since refused three commits -- the regex engine, the text parser
and the authorizer each arrived holding too much on the stack.

## The honest position

This is a C library that parses attacker-controlled bytes. C is not
memory-safe, and no amount of discipline makes it so. The argument this
project makes is narrower and, I think, defensible:

**One whole bug class is removed by construction.** The library never calls
`malloc` and never frees anything piecewise. All memory is bump-allocated from
a buffer the caller owns. Use-after-free, double-free and dangling pointers
are not bugs this code can express — and that is precisely the class a borrow
checker exists to prevent.

**What remains is spatial safety and integer overflow.** Those are real, and
they are answered with evidence rather than with claims. Every length derived
from input goes through checked arithmetic. Every byte range is a
pointer-plus-length pair with checked accessors, so out-of-bounds access has
exactly one place it can originate from. And that place is small enough to
model-check exhaustively.

**The attack surface is enumerable.** No I/O, no formatted output, no locale,
no floating point, no threads, and exactly three libc functions. A reviewer
can read the whole of it.

A note on the fuzzing figures above, because the spread matters. The signature
chain target managed 87 thousand executions where the decoder managed 72
million: verification does curve arithmetic on every input, so it is roughly
a thousand times slower per case. That target therefore needs runs measured in
hours, not minutes, before its number means anything — which is one more
reason the continuous-fuzzing row still says not started.

## Evidence

Claims without a number in this table are not yet claims.

| Property | Method | Status |
|---|---|---|
| No heap allocation | `make invariants` — undefined symbols of the compiled object | passing |
| No recursion | `make invariants` — cycle detection over the compiler's call graph | passing |
| Minimal libc | `make invariants` — same symbol check; `memcpy`, `memcmp`, `memset` only | passing |
| Pointer arithmetic confined | `make invariants` — pinned site list | passing |
| ASan + UBSan clean | `make asan`, at `-O0` and `-O1`, `-fno-sanitize-recover=all` | passing |
| MSan clean | `make msan`, Linux CI job | pending — unsupported on macOS/arm64, so the only evidence is a green Linux run, and there has not been one yet |
| Portable arithmetic path exercised | `make portable` — full suite with `BS_NO_OVERFLOW_BUILTINS` | passing |
| Static analysis clean | clang-tidy (all checks as errors), cppcheck, scan-build | passing |
| CodeQL | weekly and on change | configured, but dormant: code scanning needs Advanced Security while this repository is private |
| Fuzzing as a regression gate | `make fuzz-smoke` — three libFuzzer targets, seeded with the specification samples, on every commit | passing |
| Longest fuzzing run so far | 4 minutes per target under ASan+UBSan with `BS_ASSERT` compiled in: **72M** executions on the decoder, **22M** on the printers, **87k** on the signature chain — no crashes, no violated invariants | recorded, not sufficient |
| Continuous fuzzing | OSS-Fuzz | not started — needs a public repository, and a short run per commit is not a substitute |
| Differential fuzzing vs `biscuit-rust` | Same input, both implementations, verdicts compared | not started |
| Wire decoder bounded model checking | CBMC over the protobuf and base64 decoders | not started |
| Constant-time secret handling | Valgrind/TIMECOP technique on the Linux job | not started |
| Specification conformance | 36 of the 38 official sample tokens | decode 48/48, revocation ids 43/43, signatures 47/47, blocks 43/43, authorize 48/48 — every tier green, no failures |
| Ed25519 against RFC 8032 vectors | `make unit`, positive and rejection cases | passing |
| Signature malleability rejected | non-canonical scalars (S >= L) and small-order public keys refused, matching the reference's strict verification | passing, after a defect |
| Worst-case stack bounded | `make stack` — compiler frame sizes over the call graph, exact because there is no recursion | 6 592 bytes, gated at 8 KB |
| Ed25519 against Project Wycheproof | malleability and low-order points | not started |
| Builds without bundled crypto | `make unbundled` | passing |

## Scope

Out of scope for 1.0, and deliberately so:

- **ECDSA `secp256r1`.** Roughly 2000 lines of constant-time curve arithmetic
  for two of the 38 conformance cases. Deferred to 1.1 rather than rushed.
- **External calls (`extern::`) reach a function the host registers, and the
  library never supplies one.** The specification defines the opcode and says
  the meaning is implementation-defined, so a built-in `extern::` would be
  this implementation inventing semantics the specification declines to fix.
  An unregistered name fails the expression rather than evaluating to
  anything. This is the library's one indirect call, and it is the boundary of
  two guarantees: the measured stack figure covers library frames up to that
  call, and the no-recursion proof cannot see through it — a host function
  that re-enters the library is the host's responsibility. `make invariants`
  pins it as the *only* indirect call site, so a second one cannot appear
  unnoticed.
  Tokens using it are rejected with `BS_ERR_UNSUPPORTED`, never
  mis-verified as valid.
- **Token minting and attenuation.** Verification is what runs at the edge and
  what faces hostile input. Building tokens comes after.

## Cryptography

Ed25519 verification is vendored, not written here. Writing new curve
arithmetic for a project whose selling point is auditability would be a
strange way to spend the trust.

| | |
|---|---|
| Upstream | https://tweetnacl.cr.yp.to/20140427/tweetnacl.c |
| SHA-256 | `02e65bc3013ff2168983365e55906bc783c4c7e0a60d8100f17bb303a17175c4` |
| License | public domain |
| Extracted | the dependency closure of signature verification: no signing, no key generation, no X25519, no secretbox, no Salsa20, no Poly1305 |
| Modified | every symbol renamed and made static; the one-shot hash replaced by a streaming one and the verification equation reassembled, to avoid buffers the size of the message |

Correctness is checked against the RFC 8032 vectors, including rejection
cases — a verifier that accepts everything passes every positive test.
[Project Wycheproof](https://github.com/C2SP/wycheproof), which covers the
malleability and low-order-point edge cases that nominal vectors miss, is not
yet wired in and is tracked in the table above as not started.

Define `BISCUITS_NO_BUNDLED_CRYPTO` to omit all of it and supply your own
verifier. `make unbundled` builds that path on every commit.
