/* ---------------------------------------------------------------------------
 * Compile-time configuration
 *
 * Every knob below has a safe default. Overriding one is a deliberate act:
 * define it before including this header, in the implementation translation
 * unit and in every consumer, or the ABI will not match.
 * ------------------------------------------------------------------------ */

/* Linkage of the public API. Define BISCUITS_STATIC to confine the library to
 * a single translation unit, which lets the compiler inline and drop unused
 * entry points -- worth several kilobytes on an -Os build. */
#ifndef BS_API
#ifdef BISCUITS_STATIC
#define BS_API static
#else
#define BS_API extern
#endif
#endif

/* Internal invariant checks.
 *
 * BS_ASSERT documents facts the code has already established; it is compiled
 * out by default and must never be the thing standing between attacker input
 * and a buffer. Input validation always returns a bs_status. If you can reach
 * a BS_ASSERT with hostile bytes, that is a bug in the caller of the assert,
 * not a missing assert.
 *
 * Test and fuzz builds define BS_ASSERT to abort, which turns every documented
 * invariant into a fuzzing oracle -- that is where the value is. */
#ifndef BS_ASSERT
#define BS_ASSERT(cond) ((void)0)
#endif

/* Maximum nesting depth for terms (sets, arrays, maps) and for expression
 * closures. Invariant 2 forbids recursion, so this bound is what a heap-
 * allocated recursive decoder would call "stack depth"; here it is a fixed
 * array and exceeding it is a clean BS_ERR_DEPTH, never a crash.
 *
 * The specification's own samples nest at most 3 deep. 16 is generous. */
#ifndef BS_MAX_DEPTH
#define BS_MAX_DEPTH 16
#endif

/* Maximum number of blocks in a token, authority included. A Biscuit is
 * attenuated by appending blocks, so this bounds how far a token may have
 * travelled. Each block costs a signature verification. */
#ifndef BS_MAX_BLOCKS
#define BS_MAX_BLOCKS 64
#endif

/* Every fallible entry point reports through its return value, so ignoring one
 * silently is a bug rather than a style choice. Power of Ten rule 7 asks for
 * exactly this; without the attribute the rule was a claim with nothing behind
 * it. Deliberately discarding a result stays possible with an explicit (void)
 * cast, which is the point: it has to be written down. */
#ifndef BS_MUST_USE
#if defined(__GNUC__) || defined(__clang__)
#define BS_MUST_USE __attribute__((warn_unused_result))
#else
#define BS_MUST_USE
#endif
#endif

/* Bundled cryptography.
 *
 * By default the library carries its own Ed25519 verifier, so the header is
 * self-contained. Define BISCUITS_NO_BUNDLED_CRYPTO to omit it and supply
 * your own instead -- worth doing when the process already links libsodium,
 * mbedTLS, BearSSL or a platform keystore, since a second copy of the same
 * curve arithmetic costs space and doubles the code a reviewer must trust.
 *
 * In that mode you define one function:
 *
 *   bs_status bs_ed25519_verify_parts(bs_span pubkey, bs_span sig,
 *                                     const bs_span *parts, size_t count);
 *
 * It must return BS_OK when `sig` is a valid Ed25519 signature by `pubkey`
 * over the concatenation of `parts`, and BS_ERR_SIGNATURE otherwise. The
 * parts are given separately rather than joined because the message includes
 * the block data, and joining it would mean a buffer the size of the input in
 * a library whose first invariant is that it never allocates. Every part is
 * valid for the duration of the call. */
#ifndef BISCUITS_NO_BUNDLED_CRYPTO
#define BS_BUNDLED_CRYPTO 1
#endif

/* ---------------------------------------------------------------------------
 * Protocol constants
 *
 * Widths the wire format fixes, not choices this library makes. They live
 * here rather than beside the cryptography because the container decoder
 * needs them whether or not the bundled verifier is compiled in.
 * ------------------------------------------------------------------------ */

/* Ed25519 keys are compressed Edwards points; secp256r1 keys are compressed
 * SEC1 points, whose leading byte must be 0x02 or 0x03. */
#define BS_ED25519_PUBKEY_LEN 32U
#define BS_ED25519_SIG_LEN 64U
#define BS_ED25519_SECRET_LEN 32U
#define BS_SECP256R1_PUBKEY_LEN 33U

/* The most pieces any signature payload is built from: a version-1 block
 * signature over a third-party block, which is markers, version, data,
 * algorithm, next key, previous signature and external signature. */
#define BS_MAX_SIG_PARTS 12U
