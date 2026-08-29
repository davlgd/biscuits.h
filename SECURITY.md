# Security

## Status: do not use this yet

This library is under initial development. It does not verify tokens and it has
never been fuzzed. Nothing here should be relied on for anything.

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
| Static analysis clean | clang-tidy (all checks as errors), cppcheck, scan-build, CodeQL | passing |
| Continuous fuzzing | libFuzzer targets, OSS-Fuzz | not started |
| Differential fuzzing vs `biscuit-rust` | Same input, both implementations, verdicts compared | not started |
| Wire decoder bounded model checking | CBMC over the protobuf and base64 decoders | not started |
| Constant-time secret handling | Valgrind/TIMECOP technique on the Linux job | not started |
| Specification conformance | 36 of the 38 official sample tokens | decode 48/48, revocation ids 43/43; authorization not started |

## Scope

Out of scope for 1.0, and deliberately so:

- **ECDSA `secp256r1`.** Roughly 2000 lines of constant-time curve arithmetic
  for two of the 38 conformance cases. Deferred to 1.1 rather than rushed.
  Tokens using it are rejected with `BS_ERR_UNSUPPORTED`, never
  mis-verified as valid.
- **Token minting and attenuation.** Verification is what runs at the edge and
  what faces hostile input. Building tokens comes after.

## Cryptography

The Ed25519 implementation will be vendored from a reviewed, compact,
public-domain source rather than written here, and the provenance will be
stated in this file with the exact upstream revision. Writing new curve
arithmetic for a project whose selling point is auditability would be a
strange way to spend the trust.

Correctness is checked against the RFC 8032 vectors and against
[Project Wycheproof](https://github.com/C2SP/wycheproof), which covers the
malleability and low-order-point edge cases that nominal vectors miss.
