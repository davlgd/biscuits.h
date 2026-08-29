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
marketing document.

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

**A stack figure that was never measured.** This documentation claimed the
library ran in 4 KB of stack. The measured worst case is 6 864 bytes. The
figure had been written from intuition; there is now a `make stack` target
that computes it from the compiler's own frame sizes, and CI fails if it
grows.

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
| Specification conformance | 36 of the 38 official sample tokens | decode 48/48, revocation ids 43/43, signatures 47/47, blocks 43/43; authorization not started |
| Ed25519 against RFC 8032 vectors | `make unit`, positive and rejection cases | passing |
| Signature malleability rejected | non-canonical scalars (S >= L) and small-order public keys refused, matching the reference's strict verification | passing, after a defect |
| Worst-case stack bounded | `make stack` — compiler frame sizes over the call graph, exact because there is no recursion | 6 864 bytes, gated at 8 KB |
| Ed25519 against Project Wycheproof | malleability and low-order points | not started |
| Builds without bundled crypto | `make unbundled` | passing |

## Scope

Out of scope for 1.0, and deliberately so:

- **ECDSA `secp256r1`.** Roughly 2000 lines of constant-time curve arithmetic
  for two of the 38 conformance cases. Deferred to 1.1 rather than rushed.
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
