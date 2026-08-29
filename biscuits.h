/*
 * biscuits.h -- Biscuit authorization tokens in a single C99 header.
 *
 * Copyright 2026 davlgd
 * Licensed under the Apache License, Version 2.0. See LICENSE.
 *
 * GENERATED FILE -- do not edit. Sources live in src/, assembled by
 * tools/amalgamate.py. Run `make amalgamate` after editing a fragment.
 *
 * ---------------------------------------------------------------------------
 * Usage
 * ---------------------------------------------------------------------------
 * Drop this file in your project. In exactly one translation unit:
 *
 *     #define BISCUITS_IMPLEMENTATION
 *     #include "biscuits.h"
 *
 * Everywhere else, include it plain.
 *
 * ---------------------------------------------------------------------------
 * Design invariants
 * ---------------------------------------------------------------------------
 * These are not aspirations. Each one is enforced by a CI job, and breaking
 * one is a build failure, not a review comment. See docs/SAFETY.md.
 *
 *   1. No allocation.        The library never calls malloc. All memory comes
 *                            from a caller-provided buffer via bs_arena, which
 *                            bump-allocates and is never freed piecewise. This
 *                            makes use-after-free and double-free unreachable
 *                            by construction, not by discipline.
 *
 *   2. No recursion.         Nested structures (sets, arrays, maps, closures)
 *                            are walked with an explicit, bounded stack. Stack
 *                            depth is therefore a compile-time constant.
 *
 *   3. Bounded loops.        Every loop has a static or caller-supplied upper
 *                            bound. Datalog evaluation is governed by explicit
 *                            fact/iteration limits from the specification.
 *
 *   4. No pointer arithmetic. Byte ranges are bs_span values (pointer+length)
 *                            with checked accessors. Raw pointer arithmetic
 *                            appears only inside bs_span itself.
 *
 *   5. Minimal libc.       memcpy, memcmp and memset, and nothing else --
 *                            no stdio, no locale, no str* family, no floating
 *                            point. Some toolchains lower memset(p, 0, n) to
 *                            bzero, so an embedding target provides one or
 *                            the other. Checked on the compiled object by
 *                            tools/check_invariants.py, not asserted.
 *
 * Invariants 1-3 are the first three rules of the JPL "Power of Ten"; here
 * they are not imposed from outside, they are what the Biscuit threat model
 * demands anyway.
 *
 * ---------------------------------------------------------------------------
 * What this is not
 * ---------------------------------------------------------------------------
 * This library is memory-unsafe in the sense that any C library is: the
 * guarantees above remove whole bug classes but not all of them. The residual
 * risk is spatial safety, and it is addressed by evidence rather than by
 * assertion -- sanitizers, continuous fuzzing and bounded model checking of
 * the wire decoder. The numbers are in SECURITY.md. Read them before trusting
 * this with anything.
 */

#ifndef BISCUITS_H_INCLUDED
#define BISCUITS_H_INCLUDED

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ===========================================================================
 * 10_config.inc
 * ======================================================================== */

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
 * In that mode you define two functions.
 *
 *   bs_status bs_ed25519_verify_parts(bs_span pubkey, bs_span sig,
 *                                     const bs_span *parts, size_t count);
 *
 * Returns BS_OK when `sig` is a valid Ed25519 signature by `pubkey` over the
 * concatenation of `parts`, and BS_ERR_SIGNATURE otherwise. It must reject a
 * non-canonical scalar (S >= L) and a small-order public key, as RFC 8032's
 * strict verification and the reference implementation both do: a signature
 * that is malleable is a revocation identifier that is malleable. The parts
 * are given separately rather than joined because the message includes the
 * block data, and joining it would mean a buffer the size of the input in a
 * library whose first invariant is that it never allocates. Every part is
 * valid for the duration of the call.
 *
 *   bs_status bs_ed25519_public_from_secret(bs_span seed, uint8_t out[32]);
 *
 * Takes a 32-byte Ed25519 seed and writes the RFC 8032 public key derived
 * from it. This is how an unsealed token's proof is checked against the last
 * block's next key, which is what proves the chain was not truncated. */
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

/* ===========================================================================
 * 20_api.inc
 * ======================================================================== */

/* ---------------------------------------------------------------------------
 * Version
 * ------------------------------------------------------------------------ */

#define BS_VERSION_MAJOR 0
#define BS_VERSION_MINOR 1
#define BS_VERSION_PATCH 0
#define BS_VERSION_STRING "0.1.0-dev"

/* ---------------------------------------------------------------------------
 * Status codes
 *
 * Every fallible entry point returns a bs_status. There is no errno, no
 * out-of-band error state and no partially-constructed value handed back on
 * failure: on anything other than BS_OK, output parameters are untouched.
 * ------------------------------------------------------------------------ */

typedef enum bs_status {
  BS_OK = 0,
  BS_ERR_ARGUMENT,    /* caller passed a null or nonsensical argument */
  BS_ERR_NOMEM,       /* the caller-provided arena is exhausted */
  BS_ERR_MALFORMED,   /* input violates the wire format, truncation included */
  BS_ERR_DEPTH,       /* nesting deeper than BS_MAX_DEPTH */
  BS_ERR_OVERFLOW,    /* an arithmetic operation overflowed */
  BS_ERR_LIMIT,       /* a configured evaluation limit was reached */
  BS_ERR_UNSUPPORTED, /* well-formed, but this build cannot handle it */
  BS_ERR_SIGNATURE,   /* a signature did not verify */
  BS_STATUS_COUNT,    /* not a status; keep last */
} bs_status;

/* Short, stable, allocation-free description. Never NULL, even for a value
 * outside the enum -- a corrupted status must not become a crash. */
BS_API BS_MUST_USE const char *bs_strstatus(bs_status st);

/* ---------------------------------------------------------------------------
 * Byte ranges
 *
 * bs_span is the only way this library refers to a range of bytes. Raw pointer
 * arithmetic is confined to the accessors below (invariant 4), so an
 * out-of-bounds access has exactly one place it can originate from, and that
 * place is a hundred lines long and model-checked.
 *
 * A span does not own its bytes. It is valid for as long as the buffer the
 * caller handed in is valid.
 * ------------------------------------------------------------------------ */

typedef struct bs_span {
  const uint8_t *p;
  size_t n;
} bs_span;

BS_API BS_MUST_USE bs_span bs_span_make(const void *p, size_t n);

/* Byte at index i. Returns 0 and leaves *out untouched if i is out of range. */
BS_API BS_MUST_USE int bs_span_at(bs_span s, size_t i, uint8_t *out);

/* Sub-range [off, off+len). Returns 0 on any overflow or overrun. */
BS_API BS_MUST_USE int bs_span_slice(bs_span s, size_t off, size_t len,
                                     bs_span *out);

/* Content equality. Two empty spans are equal regardless of their pointers. */
BS_API BS_MUST_USE int bs_span_eq(bs_span a, bs_span b);

/* ---------------------------------------------------------------------------
 * Cursor
 *
 * A forward-only reader over a span. Every take_* either advances the cursor
 * and reports success, or leaves it exactly where it was. There is no
 * "partially consumed" state to reason about, which is what makes the decoder
 * safe to write as a straight line of unchecked-looking calls followed by a
 * single error test.
 * ------------------------------------------------------------------------ */

typedef struct bs_cursor {
  bs_span s;
  size_t off;
} bs_cursor;

BS_API BS_MUST_USE bs_cursor bs_cursor_make(bs_span s);
BS_API BS_MUST_USE size_t bs_cursor_left(const bs_cursor *c);
BS_API BS_MUST_USE int bs_cursor_done(const bs_cursor *c);

BS_API BS_MUST_USE int bs_take_u8(bs_cursor *c, uint8_t *out);
BS_API BS_MUST_USE int bs_take_bytes(bs_cursor *c, size_t n, bs_span *out);

/* ---------------------------------------------------------------------------
 * Arena
 *
 * All memory used by this library comes from one caller-provided buffer.
 * There is no free: the arena is reset or discarded as a whole. Use-after-free
 * and double-free are therefore not bugs this code can express (invariant 1).
 *
 * Exhaustion is sticky. Once an allocation fails the arena stays failed, so a
 * long chain of allocations can be written without a branch after each one and
 * checked once at the end. Forgetting that final check cannot corrupt memory:
 * every failed allocation returns NULL, and NULL is never written through.
 * ------------------------------------------------------------------------ */

typedef struct bs_arena {
  uint8_t *base;
  size_t cap;
  size_t off;
  size_t peak; /* high-water mark, to size buffers from real workloads */
  int failed;  /* sticky exhaustion flag */
} bs_arena;

/* Widest scalar this library ever stores. No floating point (invariant 5),
 * so no long double, and the alignment stays 8 on every target we support. */
typedef union bs_max_align {
  long long ll;
  void *p;
  void (*fp)(void);
} bs_max_align;

#define BS_ALIGN_MAX (sizeof(bs_max_align))

/* buf may be NULL only if cap is 0, which yields an arena that fails every
 * allocation -- useful for measuring how much memory a workload would need.
 *
 * A misaligned buffer is accepted: the leading pad is absorbed and the usable
 * capacity shrinks accordingly, so carving an arena out of a larger buffer is
 * safe. On a target without uintptr_t the base cannot be inspected portably
 * and the caller must supply a BS_ALIGN_MAX-aligned buffer. */
BS_API BS_MUST_USE bs_status bs_arena_init(bs_arena *a, void *buf, size_t cap);

/* align must be a power of two and at most BS_ALIGN_MAX. Returns NULL on
 * exhaustion, on overflow, or if the arena has already failed. */
BS_API BS_MUST_USE void *bs_arena_alloc(bs_arena *a, size_t size, size_t align);

/* Zero-initialised array of n elements of the given size. Guards the
 * multiplication; a hostile count cannot wrap into a small allocation. */
BS_API BS_MUST_USE void *bs_arena_array(bs_arena *a, size_t n, size_t size,
                                        size_t align);

/* Rewind to empty. Keeps the peak, clears the failure flag. */
BS_API void bs_arena_reset(bs_arena *a);

BS_API BS_MUST_USE size_t bs_arena_used(const bs_arena *a);
BS_API BS_MUST_USE size_t bs_arena_peak(const bs_arena *a);
BS_API BS_MUST_USE int bs_arena_failed(const bs_arena *a);

/* ---------------------------------------------------------------------------
 * Tokens
 *
 * A parsed token borrows every byte from the caller's input buffer: spans
 * point into it, nothing is copied. The arena holds only the block array. So
 * a bs_token is valid exactly as long as both the input and the arena are,
 * and neither may be reused underneath it.
 * ------------------------------------------------------------------------ */

typedef enum bs_alg {
  BS_ALG_ED25519 = 0,
  BS_ALG_SECP256R1 = 1,
} bs_alg;

typedef struct bs_public_key {
  bs_alg alg;
  bs_span key;
} bs_public_key;

typedef struct bs_signed_block {
  bs_span block; /* the serialized Block, still encoded */
  bs_public_key next_key;
  bs_span signature;
  bs_span external_signature;
  bs_public_key external_key;
  int has_external;
  uint32_t version; /* signature payload version; absent means 0 */
} bs_signed_block;

typedef struct bs_token {
  bs_signed_block *blocks; /* blocks[0] is the authority block */
  size_t block_count;
  bs_span proof; /* nextSecret, or finalSignature when sealed */
  uint32_t root_key_id;
  int has_root_key_id;
  int sealed;
} bs_token;

/* Decode the container. Does not verify anything: a BS_OK here means the
 * token is well-formed, not that it is authentic.
 *
 * Returns BS_ERR_UNSUPPORTED for a token whose keys use an algorithm this
 * build does not implement, so an unverifiable token can never be confused
 * with a verified one. */
BS_API BS_MUST_USE bs_status bs_token_parse(bs_arena *a, bs_span input,
                                            bs_token *out);

/* The revocation identifier of a block: its signature, verbatim. Returns an
 * empty span for an out-of-range index. */
BS_API BS_MUST_USE bs_span bs_token_revocation_id(const bs_token *t,
                                                  size_t index);

/* ---------------------------------------------------------------------------
 * Output writer
 *
 * Rendering Datalog needs somewhere to put the bytes, and this library does
 * not allocate. The caller supplies the buffer; overflow is sticky and
 * reported once at the end rather than checked on every append.
 * ------------------------------------------------------------------------ */

typedef struct bs_writer {
  uint8_t *buf;
  size_t cap;
  size_t len;
  int overflow;
} bs_writer;

BS_API BS_MUST_USE bs_status bs_writer_init(bs_writer *w, void *buf,
                                            size_t cap);
BS_API BS_MUST_USE int bs_writer_overflow(const bs_writer *w);
BS_API BS_MUST_USE size_t bs_writer_len(const bs_writer *w);

/* ---------------------------------------------------------------------------
 * Symbol table
 *
 * Predicate names and string terms travel as indices. Indices below 1024 name
 * a well-known symbol shared by every implementation; the rest name a symbol
 * the token carries, numbered across all its blocks in order.
 *
 * `entries` is not owned: it points at spans into the token's own bytes.
 * ------------------------------------------------------------------------ */

typedef struct bs_symbols {
  const bs_span *entries; /* token-provided symbols, in block order */
  size_t count;
} bs_symbols;

/* Resolve an index to its text. Returns 0 for an index this build cannot
 * name, which includes a reserved index a future specification may define --
 * guessing would make the token read differently here than elsewhere. */
BS_API BS_MUST_USE int bs_symbol_get(const bs_symbols *s, uint64_t index,
                                     bs_span *out);

/* How many well-known symbols this build knows. */
BS_API BS_MUST_USE size_t bs_symbol_default_count(void);

/* ---------------------------------------------------------------------------
 * Datalog rendering
 * ------------------------------------------------------------------------ */

/* Render one encoded Term as Datalog source into `w`.
 *
 * `term` is the bytes of a protobuf Term message, as they appear inside a
 * block. Nesting deeper than BS_MAX_DEPTH returns BS_ERR_DEPTH rather than
 * consuming stack.
 *
 * On any error the bytes already written to `w` are undefined: the caller
 * discards the whole rendering, never a prefix of it. */
BS_API BS_MUST_USE bs_status bs_term_print(bs_writer *w, const bs_symbols *sym,
                                           bs_span term);

/* ---------------------------------------------------------------------------
 * Token-wide tables
 *
 * Symbols and public keys are referenced by index, and the indices span the
 * whole token: each block's arrays are appended in block order, authority
 * first. So they cannot be read one block at a time -- the tables are built
 * once from the parsed token, then every block is read against them.
 *
 * Like bs_token, these borrow: the spans point into the token's own bytes,
 * and only the two index arrays come from the arena.
 * ------------------------------------------------------------------------ */

typedef struct bs_tables {
  bs_symbols symbols;
  bs_public_key *public_keys;
  size_t public_key_count;
} bs_tables;

BS_API BS_MUST_USE bs_status bs_tables_build(bs_arena *a, const bs_token *t,
                                             bs_tables *out);

/* The tables of a single block, standing alone.
 *
 * Use these, not the token-wide ones, for a block carrying an external key: a
 * third-party signer never saw the rest of the token, so its indices number
 * only its own symbols and keys. Reading such a block against the token-wide
 * tables silently resolves every index to the wrong entry. */
BS_API BS_MUST_USE bs_status bs_tables_build_block(bs_arena *a, bs_span block,
                                                   bs_tables *out);

/* Render one encoded Predicate as `name(term, ...)`. */
BS_API BS_MUST_USE bs_status bs_predicate_print(bs_writer *w,
                                                const bs_tables *tab,
                                                bs_span pred);

/* Render one encoded Fact. Identical output to its predicate; the wrapper
 * exists because the wire format has one. */
BS_API BS_MUST_USE bs_status bs_fact_print(bs_writer *w, const bs_tables *tab,
                                           bs_span fact);

/* Render one encoded Scope: `authority`, `previous`, or `<alg>/<hex key>`. */
BS_API BS_MUST_USE bs_status bs_scope_print(bs_writer *w, const bs_tables *tab,
                                            bs_span scope);

/* Render one encoded Expression as Datalog source.
 *
 * Needs the arena: reconstructing the tree from the opcode stream costs one
 * node array and one stack, both sized from the expression's own length. The
 * alternative -- rendering operands to text and concatenating -- is quadratic
 * on a long chain of operators, which is a shape an attacker can choose. */
BS_API BS_MUST_USE bs_status bs_expr_print(bs_writer *w, bs_arena *a,
                                           const bs_tables *tab, bs_span expr);

/* Render one encoded Rule as `head <- body`. */
BS_API BS_MUST_USE bs_status bs_rule_print(bs_writer *w, bs_arena *a,
                                           const bs_tables *tab, bs_span rule);

/* Render one encoded Check: `check if`, `check all`, or `reject if`. */
BS_API BS_MUST_USE bs_status bs_check_print(bs_writer *w, bs_arena *a,
                                            const bs_tables *tab,
                                            bs_span check);

/* Render a whole block as Datalog source: facts, then rules, then checks.
 *
 * `block` is the serialized Block message, which is what bs_signed_block
 * carries. Returns BS_ERR_UNSUPPORTED for a block-level scope: no sample in
 * the specification carries one, so its printed form cannot be confirmed, and
 * guessing would produce output that disagrees with every other reader. */
BS_API BS_MUST_USE bs_status bs_block_print(bs_writer *w, bs_arena *a,
                                            const bs_tables *tab,
                                            bs_span block);

/* ---------------------------------------------------------------------------
 * Verification
 *
 * With BISCUITS_NO_BUNDLED_CRYPTO you supply the two primitives below; see
 * the note in the configuration section for why they take the message in
 * pieces rather than as one buffer.
 * ------------------------------------------------------------------------ */

#ifndef BS_BUNDLED_CRYPTO
bs_status bs_ed25519_verify_parts(bs_span pubkey, bs_span sig,
                                  const bs_span *parts, size_t count);
bs_status bs_ed25519_public_from_secret(bs_span seed, uint8_t out[32]);
#endif

/* Check a token's signature chain against a root public key.
 *
 * BS_OK means every block signature verifies, every third-party signature
 * verifies, and the proof at the end of the token matches -- so the token is
 * authentic and has not been truncated. Every other status means it is not
 * authentic; none of them means "probably fine".
 *
 * This says nothing about whether the token authorizes anything: that is a
 * separate question with a separate answer, and keeping them apart is what
 * stops an authentic token from being mistaken for an authorized one. */
BS_API BS_MUST_USE bs_status bs_token_verify(const bs_token *t,
                                             bs_span root_key);

/* ===========================================================================
 * 30_impl_open.inc
 * ======================================================================== */

#ifdef BISCUITS_IMPLEMENTATION

/* The entire libc surface of this library. Invariant 5.
 *
 * memcpy, memcmp and memset only: no stdio, no locale-sensitive string
 * handling, no allocation, no floating point. This is what makes the header
 * usable in a kernel module, a WASM sandbox or a bare-metal firmware without
 * a shim.
 *
 * The str* family is absent by construction, not by discipline: string
 * lengths come from sizeof at compile time, because a hand-written scan for
 * the terminator is recognised by the optimiser and rewritten into a call to
 * strlen. tools/check_invariants.py reads the undefined symbols off the
 * compiled object, which is the only place that shows. */
#include <string.h>

/* ===========================================================================
 * 40_util.inc
 * ======================================================================== */

/* ---------------------------------------------------------------------------
 * Checked size arithmetic
 *
 * Every length computed from input goes through these. A silent wrap here is
 * how a bounds check becomes a no-op, so there is no unchecked `a + b` on a
 * size derived from bytes we did not write ourselves.
 * ------------------------------------------------------------------------ */

/* Gated on the compilers that actually have these builtins rather than on
 * __GNUC__ alone: clang reports __GNUC__ as 4 regardless of its own version,
 * so a bare "__GNUC__ >= 5" would silently drop every clang build onto the
 * portable path.
 *
 * __has_builtin would be the elegant test and is not used: not every
 * preprocessor that reads this header can evaluate it -- cppcheck's cannot --
 * and a version test is just as correct here. Clang has had both builtins
 * since 3.4, GCC since 5.
 *
 * Defining BS_NO_OVERFLOW_BUILTINS selects the portable path. CI builds the
 * whole test suite that way as well, so the fallback cannot rot unnoticed. */
#ifndef BS_NO_OVERFLOW_BUILTINS
#if defined(__clang__) || (defined(__GNUC__) && __GNUC__ >= 5)
#define BS_HAS_OVERFLOW_BUILTINS 1
#endif
#endif

/* All three return 1 on success, 0 on overflow, and leave *out untouched on
 * failure so a caller that ignores the result cannot read a wrapped value. */

static int bs_size_add(size_t a, size_t b, size_t *out) {
#ifdef BS_HAS_OVERFLOW_BUILTINS
  size_t r;
  if (__builtin_add_overflow(a, b, &r)) {
    return 0;
  }
  *out = r;
  return 1;
#else
  if (b > SIZE_MAX - a) {
    return 0;
  }
  *out = a + b;
  return 1;
#endif
}

static int bs_size_mul(size_t a, size_t b, size_t *out) {
#ifdef BS_HAS_OVERFLOW_BUILTINS
  size_t r;
  if (__builtin_mul_overflow(a, b, &r)) {
    return 0;
  }
  *out = r;
  return 1;
#else
  if (a != 0 && b > SIZE_MAX / a) {
    return 0;
  }
  *out = a * b;
  return 1;
#endif
}

/* align must be a power of two; callers validate that before calling. */
static int bs_size_align_up(size_t v, size_t align, size_t *out) {
  size_t rem = v & (align - 1U);
  return bs_size_add(v, (rem == 0U) ? 0U : align - rem, out);
}

static int bs_is_pow2(size_t v) {
  return v != 0U && (v & (v - 1U)) == 0U;
}

/* ---------------------------------------------------------------------------
 * Status codes
 * ------------------------------------------------------------------------ */

BS_API const char *bs_strstatus(bs_status st) {
  /* Indexed rather than switched: a switch over an enum whose value came from
   * memory has a default case that is easy to get wrong, and -Wswitch-enum
   * would demand a case for the sentinel. A table has one bounds check. */
  static const char *const names[BS_STATUS_COUNT] = {
      "ok",
      "invalid argument",
      "arena exhausted",
      "malformed input",
      "nesting too deep",
      "arithmetic overflow",
      "evaluation limit reached",
      "unsupported by this build",
      "signature verification failed",
  };
  if ((unsigned int)st >= (unsigned int)BS_STATUS_COUNT) {
    return "unknown status";
  }
  return names[st];
}

/* ---------------------------------------------------------------------------
 * Byte ranges
 * ------------------------------------------------------------------------ */

BS_API bs_span bs_span_make(const void *p, size_t n) {
  bs_span s;
  s.p = (const uint8_t *)p;
  /* A null pointer with a nonzero length is a caller bug we normalise rather
   * than propagate: every accessor below would otherwise have to re-check. */
  s.n = (p == NULL) ? 0U : n;
  return s;
}

BS_API int bs_span_at(bs_span s, size_t i, uint8_t *out) {
  if (out == NULL || i >= s.n) {
    return 0;
  }
  *out = s.p[i];
  return 1;
}

BS_API int bs_span_slice(bs_span s, size_t off, size_t len, bs_span *out) {
  size_t end;
  if (out == NULL) {
    return 0;
  }
  if (!bs_size_add(off, len, &end) || end > s.n) {
    return 0;
  }
  /* NULL + 0 is undefined in C99, however harmless it looks -- C23 defines
   * it, this library targets C99 -- so an empty result never does the
   * arithmetic at all. */
  if (len == 0U) {
    out->p = NULL;
    out->n = 0U;
    return 1;
  }
  /* Past here the slice is non-empty, so s.n is non-zero, so s.p is non-null
   * by the invariant bs_span_make establishes. Restating it costs one compare
   * and turns an invariant the static analyser cannot derive across a struct
   * into one it can see. */
  if (s.p == NULL) {
    return 0;
  }
  out->p = s.p + off;
  out->n = len;
  return 1;
}

BS_API int bs_span_eq(bs_span a, bs_span b) {
  if (a.n != b.n) {
    return 0;
  }
  if (a.n == 0U) {
    return 1;
  }
  return memcmp(a.p, b.p, a.n) == 0;
}

/* ---------------------------------------------------------------------------
 * Cursor
 * ------------------------------------------------------------------------ */

BS_API bs_cursor bs_cursor_make(bs_span s) {
  bs_cursor c;
  c.s = s;
  c.off = 0U;
  return c;
}

BS_API size_t bs_cursor_left(const bs_cursor *c) {
  /* c->off is an invariant of the cursor, never assigned past c->s.n, so the
   * subtraction cannot wrap. The guard documents that and survives a future
   * edit that breaks the invariant. */
  if (c == NULL) {
    return 0U;
  }
  /* The cursor never advances past its span; every take_* checks first. The
   * assert states that belief so the fuzzer can falsify it, while the guard
   * below keeps a release build correct if it is ever wrong. */
  BS_ASSERT(c->off <= c->s.n);
  if (c->off > c->s.n) {
    return 0U;
  }
  return c->s.n - c->off;
}

BS_API int bs_cursor_done(const bs_cursor *c) {
  return bs_cursor_left(c) == 0U;
}

BS_API int bs_take_u8(bs_cursor *c, uint8_t *out) {
  if (c == NULL || out == NULL || bs_cursor_left(c) < 1U) {
    return 0;
  }
  *out = c->s.p[c->off];
  c->off += 1U;
  return 1;
}

BS_API int bs_take_bytes(bs_cursor *c, size_t n, bs_span *out) {
  bs_span sub;
  if (c == NULL || out == NULL || bs_cursor_left(c) < n) {
    return 0;
  }
  if (!bs_span_slice(c->s, c->off, n, &sub)) {
    return 0;
  }
  c->off += n; /* bounded by the bs_cursor_left check above */
  BS_ASSERT(c->off <= c->s.n);
  *out = sub;
  return 1;
}

/* ---------------------------------------------------------------------------
 * Arena
 * ------------------------------------------------------------------------ */

BS_API bs_status bs_arena_init(bs_arena *a, void *buf, size_t cap) {
  uint8_t *base = (uint8_t *)buf;

  if (a == NULL) {
    return BS_ERR_ARGUMENT;
  }
  if (buf == NULL && cap != 0U) {
    return BS_ERR_ARGUMENT;
  }

  /* bs_arena_alloc aligns the *offset*, so every pointer it returns inherits
   * whatever misalignment the base has. A caller carving an arena out of a
   * larger buffer -- bs_arena_init(&a, scratch + used, n) -- would otherwise
   * get struct pointers that are undefined to dereference under C99 and a
   * bus fault on ARMv7-M, SPARC or RISC-V without misaligned access.
   *
   * The leading pad is absorbed here rather than rejected: refusing the
   * buffer would push this arithmetic onto every caller, which is exactly
   * where it gets forgotten. */
#ifdef UINTPTR_MAX
  if (base != NULL) {
    size_t misalign =
        (size_t)((uintptr_t)base & (uintptr_t)(BS_ALIGN_MAX - 1U));
    size_t pad = (misalign == 0U) ? 0U : (size_t)(BS_ALIGN_MAX - misalign);
    if (pad >= cap) {
      /* Nothing usable survives the padding. An arena that fails every
       * allocation is the honest outcome, not a short one. */
      base = NULL;
      cap = 0U;
    } else {
      base += pad;
      cap -= pad;
    }
  }
#else
  /* No uintptr_t: the alignment of the base cannot be inspected portably, so
   * the caller must supply a suitably aligned buffer. Documented in the API. */
#endif

  a->base = base;
  a->cap = (base == NULL) ? 0U : cap;
  a->off = 0U;
  a->peak = 0U;
  a->failed = 0;
  return BS_OK;
}

BS_API void *bs_arena_alloc(bs_arena *a, size_t size, size_t align) {
  size_t start;
  size_t end;

  if (a == NULL || a->failed) {
    return NULL;
  }
  if (!bs_is_pow2(align) || align > BS_ALIGN_MAX) {
    a->failed = 1;
    return NULL;
  }
  /* A zero-size request still yields a distinct address, so two live objects
   * never compare equal by accident. */
  if (size == 0U) {
    size = 1U;
  }
  /* `start > end` cannot happen once bs_size_add has reported no overflow and
   * size is at least 1. It is checked anyway: the overflow builtin is opaque
   * to the static analyser, which therefore cannot relate `end` back to
   * `start`, and without that relation it must assume the returned pointer
   * may lie outside the buffer. Stating the invariant costs one comparison
   * and buys a clean bounds proof. */
  if (!bs_size_align_up(a->off, align, &start) ||
      !bs_size_add(start, size, &end) || start > end || end > a->cap) {
    a->failed = 1;
    return NULL;
  }

  BS_ASSERT(start <= end);
  BS_ASSERT(end <= a->cap);
  a->off = end;
  if (end > a->peak) {
    a->peak = end;
  }
  return a->base + start;
}

BS_API void *bs_arena_array(bs_arena *a, size_t n, size_t size, size_t align) {
  size_t total;
  void *p;
  if (!bs_size_mul(n, size, &total)) {
    if (a != NULL) {
      a->failed = 1;
    }
    return NULL;
  }
  p = bs_arena_alloc(a, total, align);
  if (p != NULL) {
    memset(p, 0, total == 0U ? 1U : total);
  }
  return p;
}

BS_API void bs_arena_reset(bs_arena *a) {
  if (a == NULL) {
    return;
  }
  a->off = 0U;
  a->failed = 0;
  /* peak is deliberately kept: it is what tells a caller how big the buffer
   * had to be across the whole workload, not just the current pass. */
}

BS_API size_t bs_arena_used(const bs_arena *a) {
  return (a == NULL) ? 0U : a->off;
}

BS_API size_t bs_arena_peak(const bs_arena *a) {
  return (a == NULL) ? 0U : a->peak;
}

BS_API int bs_arena_failed(const bs_arena *a) {
  return (a == NULL) ? 1 : a->failed;
}

/* ===========================================================================
 * 45_ed25519.inc
 * ======================================================================== */

#ifdef BS_BUNDLED_CRYPTO

/* ---------------------------------------------------------------------------
 * Ed25519 signature verification
 *
 * VENDORED CODE. The curve and hash arithmetic below is extracted from
 * TweetNaCl, which is public domain:
 *
 *   upstream:  https://tweetnacl.cr.yp.to/20140427/tweetnacl.c
 *   sha256:    02e65bc3013ff2168983365e55906bc783c4c7e0a60d8100f17bb303a17175c4
 *   extracted: the dependency closure of crypto_sign_open, minus the two
 *              functions replaced below -- so no signing, no key generation,
 *              no X25519, no secretbox, no Salsa20, no Poly1305.
 *
 * Writing new curve arithmetic for a project whose selling point is that it
 * can be audited would be a strange way to spend the trust. This is a
 * reviewed implementation, used as-is.
 *
 * Two changes were made, both mechanical and both necessary for a header:
 *
 *   1. Every symbol is prefixed bs_na_ and made static. Upstream declares
 *      file-scope identifiers named A, D, I, K, L, M, R, S, X, Y, Z, u8 and
 *      gf; in a header that a consumer includes, those are a collision
 *      waiting to happen.
 *   2. The `sv` and `FOR` macros are expanded or renamed, for the same reason.
 *
 * The extraction is checked against the RFC 8032 test vectors in
 * tests/unit/test_crypto.c, including rejection cases. If a rename had broken
 * the arithmetic, those vectors would not pass.
 *
 * What is NOT vendored: the ~20 lines that assemble the verification
 * equation, and the streaming SHA-512 around it, both in 46_verify.inc.
 * Upstream's crypto_sign_open requires the caller to hand it one buffer
 * holding signature followed by message, and copies the message out again --
 * two allocations proportional to the input, in a library whose first
 * invariant is that it never allocates. The arithmetic it calls is unchanged;
 * only the order of the calls and the shape of the buffers differ, and the
 * RFC 8032 vectors check the result.
 *
 * This code is held to upstream's style, not to this project's: reformatting
 * vendored cryptography to look tidier is how bugs get introduced. It is
 * excluded from clang-format and its warnings are suppressed locally -- the
 * suppression is scoped to this block and nothing else.
 *
 * Define BISCUITS_NO_BUNDLED_CRYPTO to omit all of it and supply your own
 * verifier through BS_ED25519_VERIFY; see 10_config.inc.
 *
 * Note what is absent: verification needs no entropy. There is no
 * randombytes() here and no CSPRNG dependency anywhere in the library, which
 * is what lets it run on a target that has no source of randomness at all.
 * ------------------------------------------------------------------------ */

/* clang-format off */
/* NOLINTBEGIN */
/* cppcheck-suppress-begin [variableScope,constParameterPointer,constVariablePointer,unreadVariable,shadowVariable,knownConditionTrueFalse,cstyleCast,invalidPointerCast,nullPointerRedundantCheck] */

#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wconversion"
#pragma GCC diagnostic ignored "-Wsign-conversion"
#pragma GCC diagnostic ignored "-Wshadow"
#pragma GCC diagnostic ignored "-Wcast-qual"
#pragma GCC diagnostic ignored "-Wsign-compare"
#endif
#if defined(__clang__)
#pragma clang diagnostic ignored "-Wimplicit-int-conversion"
#pragma clang diagnostic ignored "-Wshorten-64-to-32"
#endif

#define BS_NA_FOR(i,n) for (i = 0;i < n;++i)

typedef unsigned char bs_na_u8;
typedef unsigned long bs_na_u32;
typedef unsigned long long bs_na_u64;
typedef long long bs_na_i64;
typedef bs_na_i64 bs_na_gf[16];

static const bs_na_gf
  bs_na_gf0,
  bs_na_gf1 = {1},
  bs_na_D = {0x78a3, 0x1359, 0x4dca, 0x75eb, 0xd8ab, 0x4141, 0x0a4d, 0x0070, 0xe898, 0x7779, 0x4079, 0x8cc7, 0xfe73, 0x2b6f, 0x6cee, 0x5203},
  bs_na_D2 = {0xf159, 0x26b2, 0x9b94, 0xebd6, 0xb156, 0x8283, 0x149a, 0x00e0, 0xd130, 0xeef3, 0x80f2, 0x198e, 0xfce7, 0x56df, 0xd9dc, 0x2406},
  bs_na_X = {0xd51a, 0x8f25, 0x2d60, 0xc956, 0xa7b2, 0x9525, 0xc760, 0x692c, 0xdc5c, 0xfdd6, 0xe231, 0xc0a4, 0x53fe, 0xcd6e, 0x36d3, 0x2169},
  bs_na_Y = {0x6658, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666},
  bs_na_I = {0xa0b0, 0x4a0e, 0x1b27, 0xc4ee, 0xe478, 0xad2f, 0x1806, 0x2f43, 0xd7a7, 0x3dfb, 0x0099, 0x2b4d, 0xdf0b, 0x4fc1, 0x2480, 0x2b83};


static bs_na_u64 bs_na_dl64(const bs_na_u8 *x)
{
  bs_na_u64 i,u=0;
  BS_NA_FOR(i,8) u=(u<<8)|x[i];
  return u;
}


static void bs_na_ts64(bs_na_u8 *x,bs_na_u64 u)
{
  int i;
  for (i = 7;i >= 0;--i) { x[i] = u; u >>= 8; }
}


static int bs_na_vn(const bs_na_u8 *x,const bs_na_u8 *y,int n)
{
  bs_na_u32 i,d = 0;
  BS_NA_FOR(i,n) d |= x[i]^y[i];
  return (1 & ((d - 1) >> 8)) - 1;
}


static int bs_na_crypto_verify_32(const bs_na_u8 *x,const bs_na_u8 *y)
{
  return bs_na_vn(x,y,32);
}


static void bs_na_set25519(bs_na_gf r, const bs_na_gf a)
{
  int i;
  BS_NA_FOR(i,16) r[i]=a[i];
}

static void bs_na_car25519(bs_na_gf o)
{
  int i;
  bs_na_i64 c;
  BS_NA_FOR(i,16) {
    o[i]+=(1LL<<16);
    c=o[i]>>16;
    o[(i+1)*(i<15)]+=c-1+37*(c-1)*(i==15);
    o[i]-=c<<16;
  }
}

static void bs_na_sel25519(bs_na_gf p,bs_na_gf q,int b)
{
  bs_na_i64 t,i,c=~(b-1);
  BS_NA_FOR(i,16) {
    t= c&(p[i]^q[i]);
    p[i]^=t;
    q[i]^=t;
  }
}

static void bs_na_pack25519(bs_na_u8 *o,const bs_na_gf n)
{
  int i,j,b;
  bs_na_gf m,t;
  BS_NA_FOR(i,16) t[i]=n[i];
  bs_na_car25519(t);
  bs_na_car25519(t);
  bs_na_car25519(t);
  BS_NA_FOR(j,2) {
    m[0]=t[0]-0xffed;
    for(i=1;i<15;i++) {
      m[i]=t[i]-0xffff-((m[i-1]>>16)&1);
      m[i-1]&=0xffff;
    }
    m[15]=t[15]-0x7fff-((m[14]>>16)&1);
    b=(m[15]>>16)&1;
    m[14]&=0xffff;
    bs_na_sel25519(t,m,1-b);
  }
  BS_NA_FOR(i,16) {
    o[2*i]=t[i]&0xff;
    o[2*i+1]=t[i]>>8;
  }
}

static int bs_na_neq25519(const bs_na_gf a, const bs_na_gf b)
{
  bs_na_u8 c[32],d[32];
  bs_na_pack25519(c,a);
  bs_na_pack25519(d,b);
  return bs_na_crypto_verify_32(c,d);
}

static bs_na_u8 bs_na_par25519(const bs_na_gf a)
{
  bs_na_u8 d[32];
  bs_na_pack25519(d,a);
  return d[0]&1;
}

static void bs_na_unpack25519(bs_na_gf o, const bs_na_u8 *n)
{
  int i;
  BS_NA_FOR(i,16) o[i]=n[2*i]+((bs_na_i64)n[2*i+1]<<8);
  o[15]&=0x7fff;
}

static void bs_na_A(bs_na_gf o,const bs_na_gf a,const bs_na_gf b)
{
  int i;
  BS_NA_FOR(i,16) o[i]=a[i]+b[i];
}

static void bs_na_Z(bs_na_gf o,const bs_na_gf a,const bs_na_gf b)
{
  int i;
  BS_NA_FOR(i,16) o[i]=a[i]-b[i];
}

static void bs_na_M(bs_na_gf o,const bs_na_gf a,const bs_na_gf b)
{
  bs_na_i64 i,j,t[31];
  BS_NA_FOR(i,31) t[i]=0;
  BS_NA_FOR(i,16) BS_NA_FOR(j,16) t[i+j]+=a[i]*b[j];
  BS_NA_FOR(i,15) t[i]+=38*t[i+16];
  BS_NA_FOR(i,16) o[i]=t[i];
  bs_na_car25519(o);
  bs_na_car25519(o);
}

static void bs_na_S(bs_na_gf o,const bs_na_gf a)
{
  bs_na_M(o,a,a);
}

static void bs_na_inv25519(bs_na_gf o,const bs_na_gf i)
{
  bs_na_gf c;
  int a;
  BS_NA_FOR(a,16) c[a]=i[a];
  for(a=253;a>=0;a--) {
    bs_na_S(c,c);
    if(a!=2&&a!=4) bs_na_M(c,c,i);
  }
  BS_NA_FOR(a,16) o[a]=c[a];
}

static void bs_na_pow2523(bs_na_gf o,const bs_na_gf i)
{
  bs_na_gf c;
  int a;
  BS_NA_FOR(a,16) c[a]=i[a];
  for(a=250;a>=0;a--) {
    bs_na_S(c,c);
    if(a!=1) bs_na_M(c,c,i);
  }
  BS_NA_FOR(a,16) o[a]=c[a];
}


static bs_na_u64 bs_na_R(bs_na_u64 x,int c) { return (x >> c) | (x << (64 - c)); }
static bs_na_u64 bs_na_Ch(bs_na_u64 x,bs_na_u64 y,bs_na_u64 z) { return (x & y) ^ (~x & z); }
static bs_na_u64 bs_na_Maj(bs_na_u64 x,bs_na_u64 y,bs_na_u64 z) { return (x & y) ^ (x & z) ^ (y & z); }
static bs_na_u64 bs_na_Sigma0(bs_na_u64 x) { return bs_na_R(x,28) ^ bs_na_R(x,34) ^ bs_na_R(x,39); }
static bs_na_u64 bs_na_Sigma1(bs_na_u64 x) { return bs_na_R(x,14) ^ bs_na_R(x,18) ^ bs_na_R(x,41); }
static bs_na_u64 bs_na_sigma0(bs_na_u64 x) { return bs_na_R(x, 1) ^ bs_na_R(x, 8) ^ (x >> 7); }
static bs_na_u64 bs_na_sigma1(bs_na_u64 x) { return bs_na_R(x,19) ^ bs_na_R(x,61) ^ (x >> 6); }

static const bs_na_u64 bs_na_K[80] = 
{
  0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
  0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
  0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
  0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
  0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
  0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
  0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
  0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
  0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
  0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
  0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
  0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
  0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
  0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
  0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
  0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
  0xca273eceea26619cULL, 0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
  0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
  0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
  0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL
};


static int bs_na_crypto_hashblocks(bs_na_u8 *x,const bs_na_u8 *m,bs_na_u64 n)
{
  bs_na_u64 z[8],b[8],a[8],w[16],t;
  int i,j;

  BS_NA_FOR(i,8) z[i] = a[i] = bs_na_dl64(x + 8 * i);

  while (n >= 128) {
    BS_NA_FOR(i,16) w[i] = bs_na_dl64(m + 8 * i);

    BS_NA_FOR(i,80) {
      BS_NA_FOR(j,8) b[j] = a[j];
      t = a[7] + bs_na_Sigma1(a[4]) + bs_na_Ch(a[4],a[5],a[6]) + bs_na_K[i] + w[i%16];
      b[7] = t + bs_na_Sigma0(a[0]) + bs_na_Maj(a[0],a[1],a[2]);
      b[3] += t;
      BS_NA_FOR(j,8) a[(j+1)%8] = b[j];
      if (i%16 == 15)
	BS_NA_FOR(j,16)
	  w[j] += w[(j+9)%16] + bs_na_sigma0(w[(j+1)%16]) + bs_na_sigma1(w[(j+14)%16]);
    }

    BS_NA_FOR(i,8) { a[i] += z[i]; z[i] = a[i]; }

    m += 128;
    n -= 128;
  }

  BS_NA_FOR(i,8) bs_na_ts64(x+8*i,z[i]);

  return n;
}


static const bs_na_u8 bs_na_iv[64] = {
  0x6a,0x09,0xe6,0x67,0xf3,0xbc,0xc9,0x08,
  0xbb,0x67,0xae,0x85,0x84,0xca,0xa7,0x3b,
  0x3c,0x6e,0xf3,0x72,0xfe,0x94,0xf8,0x2b,
  0xa5,0x4f,0xf5,0x3a,0x5f,0x1d,0x36,0xf1,
  0x51,0x0e,0x52,0x7f,0xad,0xe6,0x82,0xd1,
  0x9b,0x05,0x68,0x8c,0x2b,0x3e,0x6c,0x1f,
  0x1f,0x83,0xd9,0xab,0xfb,0x41,0xbd,0x6b,
  0x5b,0xe0,0xcd,0x19,0x13,0x7e,0x21,0x79
} ;


static void bs_na_add(bs_na_gf p[4],bs_na_gf q[4])
{
  bs_na_gf a,b,c,d,t,e,f,g,h;
  
  bs_na_Z(a, p[1], p[0]);
  bs_na_Z(t, q[1], q[0]);
  bs_na_M(a, a, t);
  bs_na_A(b, p[0], p[1]);
  bs_na_A(t, q[0], q[1]);
  bs_na_M(b, b, t);
  bs_na_M(c, p[3], q[3]);
  bs_na_M(c, c, bs_na_D2);
  bs_na_M(d, p[2], q[2]);
  bs_na_A(d, d, d);
  bs_na_Z(e, b, a);
  bs_na_Z(f, d, c);
  bs_na_A(g, d, c);
  bs_na_A(h, b, a);

  bs_na_M(p[0], e, f);
  bs_na_M(p[1], h, g);
  bs_na_M(p[2], g, f);
  bs_na_M(p[3], e, h);
}

static void bs_na_cswap(bs_na_gf p[4],bs_na_gf q[4],bs_na_u8 b)
{
  int i;
  BS_NA_FOR(i,4)
    bs_na_sel25519(p[i],q[i],b);
}

static void bs_na_pack(bs_na_u8 *r,bs_na_gf p[4])
{
  bs_na_gf tx, ty, zi;
  bs_na_inv25519(zi, p[2]); 
  bs_na_M(tx, p[0], zi);
  bs_na_M(ty, p[1], zi);
  bs_na_pack25519(r, ty);
  r[31] ^= bs_na_par25519(tx) << 7;
}

static void bs_na_scalarmult(bs_na_gf p[4],bs_na_gf q[4],const bs_na_u8 *s)
{
  int i;
  bs_na_set25519(p[0],bs_na_gf0);
  bs_na_set25519(p[1],bs_na_gf1);
  bs_na_set25519(p[2],bs_na_gf1);
  bs_na_set25519(p[3],bs_na_gf0);
  for (i = 255;i >= 0;--i) {
    bs_na_u8 b = (s[i/8]>>(i&7))&1;
    bs_na_cswap(p,q,b);
    bs_na_add(q,p);
    bs_na_add(p,p);
    bs_na_cswap(p,q,b);
  }
}

static void bs_na_scalarbase(bs_na_gf p[4],const bs_na_u8 *s)
{
  bs_na_gf q[4];
  bs_na_set25519(q[0],bs_na_X);
  bs_na_set25519(q[1],bs_na_Y);
  bs_na_set25519(q[2],bs_na_gf1);
  bs_na_M(q[3],bs_na_X,bs_na_Y);
  bs_na_scalarmult(p,q,s);
}


static const bs_na_u64 bs_na_L[32] = {0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10};

static void bs_na_modL(bs_na_u8 *r,bs_na_i64 x[64])
{
  bs_na_i64 carry,i,j;
  for (i = 63;i >= 32;--i) {
    carry = 0;
    for (j = i - 32;j < i - 12;++j) {
      x[j] += carry - 16 * x[i] * bs_na_L[j - (i - 32)];
      carry = (x[j] + 128) >> 8;
      x[j] -= carry << 8;
    }
    x[j] += carry;
    x[i] = 0;
  }
  carry = 0;
  BS_NA_FOR(j,32) {
    x[j] += carry - (x[31] >> 4) * bs_na_L[j];
    carry = x[j] >> 8;
    x[j] &= 255;
  }
  BS_NA_FOR(j,32) x[j] -= carry * bs_na_L[j];
  BS_NA_FOR(i,32) {
    x[i+1] += x[i] >> 8;
    r[i] = x[i] & 255;
  }
}

static void bs_na_reduce(bs_na_u8 *r)
{
  bs_na_i64 x[64],i;
  BS_NA_FOR(i,64) x[i] = (bs_na_u64) r[i];
  BS_NA_FOR(i,64) r[i] = 0;
  bs_na_modL(r,x);
}


static int bs_na_unpackneg(bs_na_gf r[4],const bs_na_u8 p[32])
{
  bs_na_gf t, chk, num, den, den2, den4, den6;
  bs_na_set25519(r[2],bs_na_gf1);
  bs_na_unpack25519(r[1],p);
  bs_na_S(num,r[1]);
  bs_na_M(den,num,bs_na_D);
  bs_na_Z(num,num,r[2]);
  bs_na_A(den,r[2],den);

  bs_na_S(den2,den);
  bs_na_S(den4,den2);
  bs_na_M(den6,den4,den2);
  bs_na_M(t,den6,num);
  bs_na_M(t,t,den);

  bs_na_pow2523(t,t);
  bs_na_M(t,t,num);
  bs_na_M(t,t,den);
  bs_na_M(t,t,den);
  bs_na_M(r[0],t,den);

  bs_na_S(chk,r[0]);
  bs_na_M(chk,chk,den);
  if (bs_na_neq25519(chk, num)) bs_na_M(r[0],r[0],bs_na_I);

  bs_na_S(chk,r[0]);
  bs_na_M(chk,chk,den);
  if (bs_na_neq25519(chk, num)) return -1;

  if (bs_na_par25519(r[0]) == (p[31]>>7)) bs_na_Z(r[0],bs_na_gf0,r[0]);

  bs_na_M(r[3],r[0],r[1]);
  return 0;
}

#undef BS_NA_FOR

#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic pop
#endif

/* cppcheck-suppress-end [variableScope,constParameterPointer,constVariablePointer,unreadVariable,shadowVariable,knownConditionTrueFalse,cstyleCast,invalidPointerCast,nullPointerRedundantCheck] */
/* NOLINTEND */
/* clang-format on */

#endif /* BS_BUNDLED_CRYPTO */

/* ===========================================================================
 * 46_verify.inc
 * ======================================================================== */

#ifdef BS_BUNDLED_CRYPTO

/* ---------------------------------------------------------------------------
 * SHA-512, streaming, and detached Ed25519 verification
 *
 * Upstream's one-shot hash and its crypto_sign_open both want the whole input
 * in one contiguous buffer -- for verification that means signature followed
 * by message, and the message copied out again afterwards. Two buffers the
 * size of the input, in a library whose first invariant is that it never
 * allocates.
 *
 * So the hash is streamed and the verification equation is assembled here
 * instead. Every arithmetic operation below is the vendored one, called in
 * the same order upstream calls it; what changes is only where the bytes
 * live. tests/unit/test_crypto.c checks the result against the RFC 8032
 * vectors, rejection cases included, which is what makes that claim testable
 * rather than merely stated.
 * ------------------------------------------------------------------------ */

#define BS_SHA512_BLOCK 128U
#define BS_SHA512_DIGEST 64U

typedef struct bs_sha512 {
  uint8_t state[BS_SHA512_DIGEST];
  uint8_t buf[BS_SHA512_BLOCK];
  size_t buflen;
  uint64_t total; /* message length in bytes */
} bs_sha512;

static void bs_sha512_init(bs_sha512 *h) {
  size_t i;
  for (i = 0; i < BS_SHA512_DIGEST; i++) {
    h->state[i] = bs_na_iv[i];
  }
  h->buflen = 0U;
  h->total = 0U;
}

static void bs_sha512_update(bs_sha512 *h, bs_span in) {
  size_t off = 0;
  bs_span chunk;

  h->total += (uint64_t)in.n;

  /* Top up a partial block first, so the fast path below can hand whole
   * blocks straight to the compression function without copying. */
  if (h->buflen != 0U) {
    size_t want = BS_SHA512_BLOCK - h->buflen;
    size_t take = (in.n < want) ? in.n : want;
    if (!bs_span_slice(in, 0U, take, &chunk)) {
      return;
    }
    if (take != 0U) {
      memcpy(&h->buf[h->buflen], chunk.p, take);
    }
    h->buflen += take;
    off = take;
    if (h->buflen < BS_SHA512_BLOCK) {
      return;
    }
    (void)bs_na_crypto_hashblocks(h->state, h->buf, BS_SHA512_BLOCK);
    h->buflen = 0U;
  }

  {
    size_t rest = in.n - off;
    size_t whole = rest & ~(size_t)(BS_SHA512_BLOCK - 1U);
    if (whole != 0U) {
      if (!bs_span_slice(in, off, whole, &chunk)) {
        return;
      }
      (void)bs_na_crypto_hashblocks(h->state, chunk.p, whole);
      off += whole;
      rest -= whole;
    }
    if (rest != 0U) {
      if (!bs_span_slice(in, off, rest, &chunk)) {
        return;
      }
      memcpy(h->buf, chunk.p, rest);
      h->buflen = rest;
    }
  }
}

/* The padding is upstream's, transcribed: the tail, a 0x80 byte, zeroes, and
 * the bit length in the last sixteen bytes -- one extra block when the tail
 * leaves no room for the length. */
static void bs_sha512_final(bs_sha512 *h, uint8_t out[BS_SHA512_DIGEST]) {
  uint8_t x[2U * BS_SHA512_BLOCK];
  uint64_t bits = h->total;
  size_t n = h->buflen;
  size_t i;

  memset(x, 0, sizeof x);
  memcpy(x, h->buf, n);
  x[n] = 0x80U;
  n = (n < 112U) ? BS_SHA512_BLOCK : (2U * BS_SHA512_BLOCK);
  x[n - 9U] = (uint8_t)(bits >> 61U);
  bs_na_ts64(&x[n - 8U], bits << 3U);
  (void)bs_na_crypto_hashblocks(h->state, x, n);

  for (i = 0; i < BS_SHA512_DIGEST; i++) {
    out[i] = h->state[i];
  }
}

/* Is the signature's S half a canonically reduced scalar, that is S < L?
 *
 * It has to be checked, and this cost the project a real defect. L*B is the
 * identity, so S and S + k*L give the same point and both satisfy the
 * verification equation: without this check a signature is malleable, and
 * anyone holding a token can produce a different byte string that still
 * verifies.
 *
 * That is not merely untidy here. The specification defines a block's
 * revocation identifier as its signature, "as it uniquely identifies the
 * block" -- so a malleable signature is a malleable revocation identifier,
 * and a deny-list keyed on it can be stepped around by the holder of the very
 * token it names. The reference implementation checks this (ed25519-dalek's
 * verify_strict); the vendored NaCl code predates the requirement and does
 * not.
 *
 * Constant-time, in the shape libsodium uses: walking down from the most
 * significant byte, `n` stays set while every byte so far has matched, and
 * `c` latches as soon as a byte of S falls below the corresponding byte of L.
 */
static int bs_scalar_is_canonical(bs_span s) {
  unsigned int c = 0;
  unsigned int n = 1;
  size_t i = 32U;

  if (s.n != 32U) {
    return 0;
  }
  do {
    unsigned int a;
    unsigned int b;
    i--;
    a = (unsigned int)s.p[i];
    b = (unsigned int)bs_na_L[i];
    c |= ((a - b) >> 8U) & n & 1U;
    n &= (((a ^ b) - 1U) >> 8U) & 1U;
  } while (i != 0U);

  return c != 0U;
}

/* Does this point have order dividing 8?
 *
 * A small-order public key makes one signature verify every message, which
 * turns "this block was signed by that third party" into a statement with no
 * content. The reference rejects these too, via verify_strict.
 *
 * Checked by tripling the point rather than by comparing against a table of
 * known small-order encodings: three doublings cost almost nothing next to
 * the scalar multiplication already happening, and a table is a transcription
 * that can be got wrong silently. */
static int bs_point_is_small_order(const bs_na_gf *q) {
  bs_na_gf p[4];
  uint8_t enc[32];
  size_t i;
  size_t j;
  unsigned int diff;

  for (i = 0; i < 4U; i++) {
    for (j = 0; j < 16U; j++) {
      p[i][j] = q[i][j];
    }
  }
  bs_na_add(p, p); /* 2Q */
  bs_na_add(p, p); /* 4Q */
  bs_na_add(p, p); /* 8Q */
  bs_na_pack(enc, p);

  /* The identity encodes as 1. */
  diff = (unsigned int)enc[0] ^ 1U;
  for (i = 1U; i < 32U; i++) {
    diff |= (unsigned int)enc[i];
  }
  return diff == 0U;
}

/* Verify a detached Ed25519 signature.
 *
 * The equation is the one in RFC 8032 section 5.1.7: with A the public key,
 * R the first half of the signature and S the second,
 *
 *     S*B - SHA512(R || A || message) * A  ==  R
 *
 * A malformed key or a signature of the wrong width is a verification
 * failure, not a separate error: from the caller's side there is nothing to
 * distinguish "this token was not signed by you" from "this token's signature
 * could not even be parsed", and giving them different names invites a caller
 * to treat one as recoverable. */
static bs_status bs_ed25519_verify_parts(bs_span pubkey, bs_span sig,
                                         const bs_span *parts,
                                         size_t part_count) {
  bs_na_gf p[4];
  bs_na_gf q[4];
  uint8_t h[BS_SHA512_DIGEST];
  uint8_t t[32];
  bs_sha512 sha;
  bs_span r;
  bs_span s;

  if (pubkey.n != 32U || sig.n != 64U) {
    return BS_ERR_SIGNATURE;
  }
  /* The two halves, taken through the span accessors rather than by pointer
   * arithmetic, so invariant 4 holds here as everywhere else. */
  if (!bs_span_slice(sig, 0U, 32U, &r) || !bs_span_slice(sig, 32U, 32U, &s)) {
    return BS_ERR_SIGNATURE;
  }
  /* Both guards match the reference's verify_strict. Neither is optional:
   * see the notes on each. */
  if (!bs_scalar_is_canonical(s)) {
    return BS_ERR_SIGNATURE;
  }
  /* unpackneg yields -A, which is why the equation above is written with a
   * subtraction and computed here with an addition. */
  if (bs_na_unpackneg(q, pubkey.p) != 0) {
    return BS_ERR_SIGNATURE;
  }
  if (bs_point_is_small_order(q)) {
    return BS_ERR_SIGNATURE;
  }

  bs_sha512_init(&sha);
  bs_sha512_update(&sha, r);
  bs_sha512_update(&sha, pubkey);
  {
    size_t i;
    for (i = 0; i < part_count; i++) {
      bs_sha512_update(&sha, parts[i]);
    }
  }
  bs_sha512_final(&sha, h);
  bs_na_reduce(h);

  bs_na_scalarmult(p, q, h);
  bs_na_scalarbase(q, s.p);
  bs_na_add(p, q);
  bs_na_pack(t, p);

  /* Constant-time comparison, from upstream. Signatures are public data, so
   * this is belt rather than braces -- but a timing-variable memcmp here is
   * the kind of detail a reviewer should not have to wonder about. */
  if (bs_na_crypto_verify_32(r.p, t) != 0) {
    return BS_ERR_SIGNATURE;
  }
  return BS_OK;
}

/* Derive a public key from a 32-byte seed, to check that the proof at the end
 * of an unsealed token really belongs to the last block's next key. */
static bs_status bs_ed25519_public_from_secret(bs_span seed, uint8_t out[32]) {
  uint8_t h[BS_SHA512_DIGEST];
  bs_na_gf p[4];
  bs_sha512 s;

  if (seed.n != 32U) {
    return BS_ERR_SIGNATURE;
  }
  bs_sha512_init(&s);
  bs_sha512_update(&s, seed);
  bs_sha512_final(&s, h);
  /* RFC 8032 section 5.1.5 clamping. */
  h[0] &= 248U;
  h[31] &= 127U;
  h[31] |= 64U;
  bs_na_scalarbase(p, h);
  bs_na_pack(out, p);
  return BS_OK;
}

#endif /* BS_BUNDLED_CRYPTO */

/* ===========================================================================
 * 47_chain.inc
 * ======================================================================== */

/* ---------------------------------------------------------------------------
 * Signature chain
 *
 * A Biscuit is a chain: the root key signs the authority block together with
 * the key that will sign the next one, and so on. Verification walks that
 * chain from the root outwards, and finishes by proving that whoever holds
 * the token also holds the last private key -- or, for a sealed token, that
 * nobody can extend it any further.
 *
 * The payloads below are byte-exact reproductions of what the reference
 * implementation signs. They are built as a list of spans and hashed in
 * order, never concatenated: the block data is the largest thing in a token,
 * and copying it to hash it would put a buffer the size of the input into a
 * library that does not allocate.
 *
 * One divergence is worth recording. For payload version 0 the specification
 * text lists the order as data, next key, algorithm; the reference
 * implementation writes data, algorithm, next key. The code is what tokens in
 * the wild are signed with, so the code is what is reproduced here. The
 * specification's own conformance samples agree with the code.
 * ------------------------------------------------------------------------ */

/* Payload markers, spelled out rather than assembled, so they can be compared
 * against the specification by eye. The leading and trailing NUL bytes are
 * part of each marker: they are what stops a crafted block from containing
 * text that impersonates a field boundary. */
#define BS_MARK_BLOCK "\0BLOCK\0\0VERSION\0"
#define BS_MARK_PAYLOAD "\0PAYLOAD\0"
#define BS_MARK_ALGORITHM "\0ALGORITHM\0"
#define BS_MARK_NEXTKEY "\0NEXTKEY\0"
#define BS_MARK_PREVSIG "\0PREVSIG\0"
#define BS_MARK_EXTERNALSIG "\0EXTERNALSIG\0"
#define BS_MARK_EXTERNAL "\0EXTERNAL\0\0VERSION\0"

/* A marker span. sizeof - 1 drops the terminator the compiler adds, not the
 * NUL that belongs to the marker itself. */
#define BS_MARK(lit) bs_span_make("" lit, sizeof(lit) - 1U)

static void bs_le32(uint8_t out[4], uint32_t v) {
  out[0] = (uint8_t)(v & 0xFFU);
  out[1] = (uint8_t)((v >> 8U) & 0xFFU);
  out[2] = (uint8_t)((v >> 16U) & 0xFFU);
  out[3] = (uint8_t)((v >> 24U) & 0xFFU);
}

/* Build the payload a block's signature covers.
 *
 * `prev_sig` is empty for the authority block, which has no predecessor. In
 * payload version 1 that is load-bearing: the authority's payload has no
 * PREVSIG section, so an authority signature cannot be replayed in any other
 * position or any other token.
 *
 * Version 0 gives no such guarantee. There, the authority and appended
 * payloads are identical by construction -- data, algorithm, next key, with
 * nothing naming the position -- which is exactly the weakness version 1
 * exists to close. Reproduced here because tokens signed that way exist, not
 * because it is sound. */
static bs_status bs_block_payload(const bs_signed_block *b, bs_span prev_sig,
                                  int is_authority, uint8_t ver_le[4],
                                  uint8_t alg_le[4], bs_span *parts,
                                  size_t *count) {
  size_t n = 0;

  bs_le32(ver_le, b->version);
  bs_le32(alg_le, (uint32_t)b->next_key.alg);

  if (b->version == 0U) {
    /* Deprecated, and reproduced only because tokens signed this way exist.
     * Note the order: data, algorithm, next key -- see the file header. */
    parts[n++] = b->block;
    if (b->has_external) {
      parts[n++] = b->external_signature;
    }
    parts[n++] = bs_span_make(alg_le, 4U);
    parts[n++] = b->next_key.key;
    *count = n;
    return BS_OK;
  }

  if (b->version != 1U) {
    /* A version this build does not know how to hash. Refused rather than
     * guessed: a signature checked against the wrong payload is not a
     * signature check at all. */
    return BS_ERR_UNSUPPORTED;
  }

  parts[n++] = BS_MARK(BS_MARK_BLOCK);
  parts[n++] = bs_span_make(ver_le, 4U);
  parts[n++] = BS_MARK(BS_MARK_PAYLOAD);
  parts[n++] = b->block;
  parts[n++] = BS_MARK(BS_MARK_ALGORITHM);
  parts[n++] = bs_span_make(alg_le, 4U);
  parts[n++] = BS_MARK(BS_MARK_NEXTKEY);
  parts[n++] = b->next_key.key;

  if (!is_authority) {
    parts[n++] = BS_MARK(BS_MARK_PREVSIG);
    parts[n++] = prev_sig;
    if (b->has_external) {
      parts[n++] = BS_MARK(BS_MARK_EXTERNALSIG);
      parts[n++] = b->external_signature;
    }
  }

  BS_ASSERT(n <= BS_MAX_SIG_PARTS);
  *count = n;
  return BS_OK;
}

/* The payload a third-party signature covers.
 *
 * It deliberately does not name the next key: a third party signs its own
 * block and the chain position it was handed, so its signature says "I
 * authored this block, here" and nothing about what comes after. */
static bs_status bs_external_payload(const bs_signed_block *b, bs_span prev_sig,
                                     uint8_t ver_le[4], bs_span *parts,
                                     size_t *count) {
  size_t n = 0;

  if (b->version != 1U) {
    /* External signature payload v0 is withdrawn by the specification, and
     * the container decoder already refuses a third-party block that is not
     * version 1. */
    return BS_ERR_UNSUPPORTED;
  }

  bs_le32(ver_le, b->version);
  parts[n++] = BS_MARK(BS_MARK_EXTERNAL);
  parts[n++] = bs_span_make(ver_le, 4U);
  parts[n++] = BS_MARK(BS_MARK_PAYLOAD);
  parts[n++] = b->block;
  parts[n++] = BS_MARK(BS_MARK_PREVSIG);
  parts[n++] = prev_sig;

  BS_ASSERT(n <= BS_MAX_SIG_PARTS);
  *count = n;
  return BS_OK;
}

/* Verify a token's signature chain against a root public key.
 *
 * Returns BS_OK only when every block verifies, every external signature
 * verifies, and the proof at the end matches. Any other status means the
 * token is not authentic; none of them means "probably fine".
 *
 * This says nothing about whether the token authorizes anything. That is the
 * authorizer's question, and keeping the two apart is what stops a caller
 * from treating a well-formed token as an authorized one. */
BS_API bs_status bs_token_verify(const bs_token *t, bs_span root_key) {
  bs_span parts[BS_MAX_SIG_PARTS];
  uint8_t ver_le[4];
  uint8_t alg_le[4];
  bs_span current = root_key;
  bs_span prev_sig = bs_span_make(NULL, 0);
  size_t i;

  if (t == NULL || t->blocks == NULL || t->block_count == 0U) {
    return BS_ERR_ARGUMENT;
  }
  if (root_key.n != BS_ED25519_PUBKEY_LEN) {
    return BS_ERR_UNSUPPORTED;
  }

  for (i = 0; i < t->block_count; i++) {
    const bs_signed_block *b = &t->blocks[i];
    size_t count = 0;
    bs_status st;

    st =
        bs_block_payload(b, prev_sig, (i == 0U), ver_le, alg_le, parts, &count);
    if (st != BS_OK) {
      return st;
    }
    st = bs_ed25519_verify_parts(current, b->signature, parts, count);
    if (st != BS_OK) {
      return st;
    }

    if (b->has_external) {
      st = bs_external_payload(b, prev_sig, ver_le, parts, &count);
      if (st != BS_OK) {
        return st;
      }
      st = bs_ed25519_verify_parts(b->external_key.key, b->external_signature,
                                   parts, count);
      if (st != BS_OK) {
        return st;
      }
    }

    current = b->next_key.key;
    prev_sig = b->signature;
  }

  if (t->sealed) {
    /* A sealed token proves that no further block can be appended: the last
     * private key was used once more, over the last block, and then discarded.
     * The payload is the seal payload, which has no version marker. */
    const bs_signed_block *last = &t->blocks[t->block_count - 1U];
    size_t n = 0;
    bs_le32(alg_le, (uint32_t)last->next_key.alg);
    parts[n++] = last->block;
    parts[n++] = bs_span_make(alg_le, 4U);
    parts[n++] = last->next_key.key;
    parts[n++] = last->signature;
    return bs_ed25519_verify_parts(current, t->proof, parts, n);
  }

  /* An open token carries the next private key, so that the holder can
   * attenuate it. Checking that it matches the last public key is what proves
   * the token was not truncated: lopping off the final block would leave a
   * proof that belongs to a key no longer in the chain. */
  {
    uint8_t derived[BS_ED25519_PUBKEY_LEN];
    bs_status st = bs_ed25519_public_from_secret(t->proof, derived);
    if (st != BS_OK) {
      return st;
    }
    if (!bs_span_eq(bs_span_make(derived, sizeof derived), current)) {
      return BS_ERR_SIGNATURE;
    }
  }
  return BS_OK;
}

/* ===========================================================================
 * 50_pb.inc
 * ======================================================================== */

/* ---------------------------------------------------------------------------
 * Protocol Buffers wire format
 *
 * Just enough of proto2 to read the Biscuit schema, and deliberately no more.
 * There is no descriptor, no reflection and no generated code: the schema is
 * small, fixed, and read by hand in the decoders above. A generic protobuf
 * library would be larger than the whole of this one.
 *
 * This is the only code in the library that sees bytes an attacker chose. It
 * is written to be read: no state machine, no jump table, one function per
 * wire concept, and every length checked before it is trusted.
 * ------------------------------------------------------------------------ */

/* Wire types. Groups (3 and 4) were removed from proto2 long before this
 * schema existed; accepting them would mean a nesting construct with its own
 * termination rules, which is exactly the kind of surface this decoder exists
 * to not have. They are rejected. */
#define BS_PB_VARINT 0U
#define BS_PB_I64 1U
#define BS_PB_BYTES 2U
#define BS_PB_SGROUP 3U
#define BS_PB_EGROUP 4U
#define BS_PB_I32 5U

/* Field numbers are 29 bits in the wire format, and zero is not a valid one. */
#define BS_PB_MAX_FIELD 0x1FFFFFFFU

typedef struct bs_pb_field {
  uint32_t number;
  uint32_t wire;
  uint64_t varint; /* wire == VARINT, I64 or I32 */
  bs_span bytes;   /* wire == BYTES */
} bs_pb_field;

/* A base-128 varint, at most ten bytes.
 *
 * The tenth byte carries the 64th bit and nothing else, so any value above 1
 * in it would encode a number that does not fit. Protobuf writers in the wild
 * do emit non-minimal encodings (a value padded with 0x80 continuation
 * bytes), so those are accepted; what is rejected is an encoding that cannot
 * be represented at all.
 *
 * On failure the cursor is left exactly where it started. Every take_* in
 * this file keeps that property, which is what lets a decoder try a parse and
 * back out without tracking how far it got. */
static int bs_pb_varint(bs_cursor *c, uint64_t *out) {
  size_t save;
  uint64_t v = 0;
  unsigned shift = 0;
  size_t i;

  if (c == NULL || out == NULL) {
    return 0;
  }
  save = c->off;

  for (i = 0; i < 10U; i++) {
    uint8_t b;
    if (!bs_take_u8(c, &b)) {
      c->off = save;
      return 0; /* truncated mid-varint */
    }
    if (i == 9U && (b & 0x7FU) > 1U) {
      c->off = save;
      return 0; /* does not fit in 64 bits */
    }
    v |= (uint64_t)(b & 0x7FU) << shift;
    if ((b & 0x80U) == 0U) {
      *out = v;
      return 1;
    }
    shift += 7U;
  }

  c->off = save;
  return 0; /* eleventh byte: no valid varint is this long */
}

/* Read one field. Returns 1 on success, 0 at clean end of input or on a
 * malformed field; use bs_cursor_done() to tell the two apart. */
static int bs_pb_next(bs_cursor *c, bs_pb_field *f) {
  size_t save;
  uint64_t tag;
  uint64_t len;

  if (c == NULL || f == NULL || bs_cursor_done(c)) {
    return 0;
  }
  save = c->off;

  if (!bs_pb_varint(c, &tag)) {
    return 0;
  }

  f->wire = (uint32_t)(tag & 7U);
  tag >>= 3U;
  if (tag == 0U || tag > (uint64_t)BS_PB_MAX_FIELD) {
    c->off = save;
    return 0;
  }
  f->number = (uint32_t)tag;
  f->varint = 0;
  f->bytes = bs_span_make(NULL, 0);

  switch (f->wire) {
  case BS_PB_VARINT:
    if (!bs_pb_varint(c, &f->varint)) {
      c->off = save;
      return 0;
    }
    return 1;

  case BS_PB_BYTES:
    if (!bs_pb_varint(c, &len)) {
      c->off = save;
      return 0;
    }
    /* A length wider than the address space cannot be satisfied, and casting
     * it to size_t first is how a 64-bit length becomes a small one on a
     * 32-bit target. Compare before narrowing. */
    if (len > (uint64_t)bs_cursor_left(c)) {
      c->off = save;
      return 0;
    }
    if (!bs_take_bytes(c, (size_t)len, &f->bytes)) {
      c->off = save;
      return 0;
    }
    return 1;

  case BS_PB_I64:
  case BS_PB_I32: {
    size_t width = (f->wire == BS_PB_I64) ? 8U : 4U;
    bs_span raw;
    size_t i;
    if (!bs_take_bytes(c, width, &raw)) {
      c->off = save;
      return 0;
    }
    /* Little-endian, per the wire format. Assembled byte by byte rather than
     * cast, because the source is not guaranteed to be aligned and the host
     * is not guaranteed to be little-endian. */
    for (i = 0; i < width; i++) {
      f->varint |= (uint64_t)raw.p[i] << (8U * i);
    }
    return 1;
  }

  case BS_PB_SGROUP:
  case BS_PB_EGROUP:
  default:
    c->off = save;
    return 0;
  }
}

/* ===========================================================================
 * 60_token.inc
 * ======================================================================== */

/* ---------------------------------------------------------------------------
 * Token container
 *
 * Decodes the outer `Biscuit` message: the authority block, the appended
 * blocks, and the proof. The Datalog inside each block is left as bytes here
 * and decoded separately, because signature verification happens first and
 * operates on exactly these undecoded bytes.
 *
 * Nothing in this file verifies anything. A token that parses is a token that
 * is *shaped* correctly; whether it is authentic is a later question, and
 * keeping the two apart is what stops a decode error from ever being mistaken
 * for a successful verification.
 * ------------------------------------------------------------------------ */

/* Field numbers, from schema.proto. Named rather than inlined because a
 * transposed digit here is a silent misparse, not a compile error. */
#define BS_F_BISCUIT_ROOT_KEY_ID 1U
#define BS_F_BISCUIT_AUTHORITY 2U
#define BS_F_BISCUIT_BLOCKS 3U
#define BS_F_BISCUIT_PROOF 4U

#define BS_F_SIGNED_BLOCK 1U
#define BS_F_SIGNED_NEXT_KEY 2U
#define BS_F_SIGNED_SIGNATURE 3U
#define BS_F_SIGNED_EXTERNAL_SIG 4U
#define BS_F_SIGNED_VERSION 5U

#define BS_F_EXTSIG_SIGNATURE 1U
#define BS_F_EXTSIG_PUBLIC_KEY 2U

#define BS_F_PUBKEY_ALGORITHM 1U
#define BS_F_PUBKEY_KEY 2U

#define BS_F_PROOF_NEXT_SECRET 1U
#define BS_F_PROOF_FINAL_SIGNATURE 2U

static bs_status bs_pb_pubkey(bs_span in, bs_public_key *out) {
  bs_cursor c = bs_cursor_make(in);
  bs_pb_field f;
  int have_alg = 0;
  int have_key = 0;
  uint64_t alg = 0;
  bs_span key = bs_span_make(NULL, 0);

  while (!bs_cursor_done(&c)) {
    if (!bs_pb_next(&c, &f)) {
      return BS_ERR_MALFORMED;
    }
    if (f.number == BS_F_PUBKEY_ALGORITHM && f.wire == BS_PB_VARINT) {
      alg = f.varint;
      have_alg = 1;
    } else if (f.number == BS_F_PUBKEY_KEY && f.wire == BS_PB_BYTES) {
      key = f.bytes;
      have_key = 1;
    }
  }
  if (!have_alg || !have_key) {
    return BS_ERR_MALFORMED; /* both are `required` in the schema */
  }

  switch (alg) {
  case (uint64_t)BS_ALG_ED25519:
    if (key.n != BS_ED25519_PUBKEY_LEN) {
      return BS_ERR_MALFORMED;
    }
    break;
  case (uint64_t)BS_ALG_SECP256R1:
    if (key.n != BS_SECP256R1_PUBKEY_LEN ||
        (key.p[0] != 0x02U && key.p[0] != 0x03U)) {
      return BS_ERR_MALFORMED;
    }
    /* Recognised, and refused rather than ignored: a token this build cannot
     * check must never be reported as one it checked. See SECURITY.md. */
    return BS_ERR_UNSUPPORTED;
  default:
    return BS_ERR_MALFORMED;
  }

  out->alg = (bs_alg)alg;
  out->key = key;
  return BS_OK;
}

static bs_status bs_pb_external_sig(bs_span in, bs_signed_block *out) {
  bs_cursor c = bs_cursor_make(in);
  bs_pb_field f;
  int have_sig = 0;
  int have_key = 0;

  while (!bs_cursor_done(&c)) {
    if (!bs_pb_next(&c, &f)) {
      return BS_ERR_MALFORMED;
    }
    if (f.number == BS_F_EXTSIG_SIGNATURE && f.wire == BS_PB_BYTES) {
      out->external_signature = f.bytes;
      have_sig = 1;
    } else if (f.number == BS_F_EXTSIG_PUBLIC_KEY && f.wire == BS_PB_BYTES) {
      bs_status st = bs_pb_pubkey(f.bytes, &out->external_key);
      if (st != BS_OK) {
        return st;
      }
      have_key = 1;
    }
  }
  if (!have_sig || !have_key) {
    return BS_ERR_MALFORMED;
  }
  out->has_external = 1;
  return BS_OK;
}

/* `is_authority` gates the rules that apply only to block 0. The decoder
 * cannot infer it: a SignedBlock looks identical wherever it sits. */
static bs_status bs_pb_signed_block(bs_span in, bs_signed_block *out,
                                    int is_authority) {
  bs_cursor c = bs_cursor_make(in);
  bs_pb_field f;
  int have_block = 0;
  int have_next = 0;
  int have_sig = 0;

  out->block = bs_span_make(NULL, 0);
  out->signature = bs_span_make(NULL, 0);
  out->external_signature = bs_span_make(NULL, 0);
  out->has_external = 0;
  out->version = 0; /* absent means version 0, per the specification */

  while (!bs_cursor_done(&c)) {
    bs_status st;
    if (!bs_pb_next(&c, &f)) {
      return BS_ERR_MALFORMED;
    }
    switch (f.number) {
    case BS_F_SIGNED_BLOCK:
      if (f.wire != BS_PB_BYTES) {
        return BS_ERR_MALFORMED;
      }
      out->block = f.bytes;
      have_block = 1;
      break;
    case BS_F_SIGNED_NEXT_KEY:
      if (f.wire != BS_PB_BYTES) {
        return BS_ERR_MALFORMED;
      }
      st = bs_pb_pubkey(f.bytes, &out->next_key);
      if (st != BS_OK) {
        return st;
      }
      have_next = 1;
      break;
    case BS_F_SIGNED_SIGNATURE:
      if (f.wire != BS_PB_BYTES) {
        return BS_ERR_MALFORMED;
      }
      out->signature = f.bytes;
      have_sig = 1;
      break;
    case BS_F_SIGNED_EXTERNAL_SIG:
      if (f.wire != BS_PB_BYTES) {
        return BS_ERR_MALFORMED;
      }
      /* SPECIFICATIONS.md: "The authority block can't carry an external
       * signature. This is necessary to make sure an external signature
       * can't be used for any other token." The verifying procedure is
       * scoped "from 1 to n" to match. Rejected here rather than left to the
       * verifier, because the authority's own signature payload has no slot
       * for an external signature -- so an injected one is not covered by
       * the root key and would survive chain verification untouched. */
      if (is_authority) {
        return BS_ERR_MALFORMED;
      }
      st = bs_pb_external_sig(f.bytes, out);
      if (st != BS_OK) {
        return st;
      }
      break;
    case BS_F_SIGNED_VERSION:
      if (f.wire != BS_PB_VARINT || f.varint > 0xFFFFFFFFU) {
        return BS_ERR_MALFORMED;
      }
      out->version = (uint32_t)f.varint;
      break;
    default:
      break; /* unknown field: well-formed, and ignored */
    }
  }

  if (!have_block || !have_next || !have_sig) {
    return BS_ERR_MALFORMED;
  }
  /* A block's signature is made with the *previous* block's key, and the
   * authority's with the root key -- neither of which this function can see.
   * So this is not a check of the declared algorithm: it is an Ed25519-only
   * heuristic that happens to be exact while Ed25519 is the only algorithm
   * this build accepts, since bs_pb_pubkey has already refused every other
   * one. It also silently constrains the root key to Ed25519, which the
   * container genuinely cannot observe.
   *
   * When secp256r1 lands in 1.1 this must move to the verifier, which knows
   * the signing key. Until then it is what stops a truncated signature from
   * reaching the crypto at all. */
  if (out->signature.n != BS_ED25519_SIG_LEN) {
    return BS_ERR_MALFORMED;
  }
  if (out->has_external) {
    if (out->external_signature.n != BS_ED25519_SIG_LEN) {
      return BS_ERR_MALFORMED;
    }
    /* SPECIFICATIONS.md: "Signature version 1 *must* be used for third-party
     * blocks." Version 0 has no external-signature payload defined at all. */
    if (out->version != 1U) {
      return BS_ERR_MALFORMED;
    }
  }
  return BS_OK;
}

static bs_status bs_pb_proof(bs_span in, bs_token *out) {
  bs_cursor c = bs_cursor_make(in);
  bs_pb_field f;
  int have_secret = 0;
  int have_final = 0;

  while (!bs_cursor_done(&c)) {
    if (!bs_pb_next(&c, &f)) {
      return BS_ERR_MALFORMED;
    }
    if (f.wire != BS_PB_BYTES) {
      continue;
    }
    /* Repeating the *same* branch is ordinary protobuf: canonical decoders
     * take the last occurrence, and rejecting it would make this stricter
     * than every writer. Repeating the *other* branch is the dangerous case,
     * and that is what the check below catches. */
    if (f.number == BS_F_PROOF_NEXT_SECRET) {
      out->sealed = 0;
      out->proof = f.bytes;
      have_secret = 1;
    } else if (f.number == BS_F_PROOF_FINAL_SIGNATURE) {
      out->sealed = 1;
      out->proof = f.bytes;
      have_final = 1;
    }
  }

  /* The schema makes these a oneof: exactly one branch, never both, never
   * neither. A token carrying both would let a verifier pick the reading it
   * prefers -- an unsealed token and a sealed one at the same time. */
  if (have_secret == have_final) {
    return BS_ERR_MALFORMED;
  }

  /* Every other key and signature in the container has its width checked; the
   * proof was the exception. An Ed25519 secret scalar is 32 bytes and a
   * signature is 64. Like the block signatures above, this is exact only
   * while Ed25519 is the sole accepted algorithm. */
  if (out->proof.n !=
      (out->sealed ? BS_ED25519_SIG_LEN : BS_ED25519_SECRET_LEN)) {
    return BS_ERR_MALFORMED;
  }
  return BS_OK;
}

BS_API bs_status bs_token_parse(bs_arena *a, bs_span input, bs_token *out) {
  bs_cursor c;
  bs_pb_field f;
  size_t appended = 0;
  size_t total;
  size_t index;
  bs_span authority = bs_span_make(NULL, 0);
  bs_span proof = bs_span_make(NULL, 0);
  int have_authority = 0;
  int have_proof = 0;
  bs_token tok;

  if (a == NULL || out == NULL) {
    return BS_ERR_ARGUMENT;
  }

  tok.has_root_key_id = 0;
  tok.root_key_id = 0;
  tok.blocks = NULL;
  tok.block_count = 0;
  tok.sealed = 0;
  tok.proof = bs_span_make(NULL, 0);

  /* First pass: locate the top-level fields and count the appended blocks.
   * Counting before allocating is what keeps the arena free of any growth
   * strategy -- there is no realloc here because there is never a second
   * guess about how many blocks there are. */
  c = bs_cursor_make(input);
  while (!bs_cursor_done(&c)) {
    if (!bs_pb_next(&c, &f)) {
      return BS_ERR_MALFORMED;
    }
    switch (f.number) {
    case BS_F_BISCUIT_ROOT_KEY_ID:
      if (f.wire != BS_PB_VARINT || f.varint > 0xFFFFFFFFU) {
        return BS_ERR_MALFORMED;
      }
      tok.root_key_id = (uint32_t)f.varint;
      tok.has_root_key_id = 1;
      break;
    case BS_F_BISCUIT_AUTHORITY:
      /* Singular in the schema. Taking the last occurrence, as a general
       * protobuf decoder would, lets one token carry two authority blocks and
       * leaves which one is verified up to the reader. */
      if (f.wire != BS_PB_BYTES || have_authority) {
        return BS_ERR_MALFORMED;
      }
      authority = f.bytes;
      have_authority = 1;
      break;
    case BS_F_BISCUIT_BLOCKS:
      if (f.wire != BS_PB_BYTES) {
        return BS_ERR_MALFORMED;
      }
      if (!bs_size_add(appended, 1U, &appended)) {
        return BS_ERR_OVERFLOW;
      }
      break;
    case BS_F_BISCUIT_PROOF:
      if (f.wire != BS_PB_BYTES || have_proof) {
        return BS_ERR_MALFORMED;
      }
      proof = f.bytes;
      have_proof = 1;
      break;
    default:
      break;
    }
  }

  if (!have_authority || !have_proof) {
    return BS_ERR_MALFORMED;
  }
  /* Every block costs a signature verification, so the ceiling is a denial-of
   * -service bound as much as a memory one. */
  if (!bs_size_add(appended, 1U, &total)) {
    return BS_ERR_OVERFLOW;
  }
  if (total > (size_t)BS_MAX_BLOCKS) {
    return BS_ERR_LIMIT;
  }

  tok.block_count = total;
  tok.blocks = (bs_signed_block *)bs_arena_array(
      a, tok.block_count, sizeof(bs_signed_block), BS_ALIGN_MAX);
  if (tok.blocks == NULL) {
    return BS_ERR_NOMEM;
  }

  /* Second pass: decode each block in wire order. Order is load-bearing --
   * the signature chain is verified block by block from the authority
   * outwards, and a reordered token must not verify. */
  {
    bs_status st = bs_pb_signed_block(authority, &tok.blocks[0], 1);
    if (st != BS_OK) {
      return st;
    }
  }

  index = 1U;
  c = bs_cursor_make(input);
  while (!bs_cursor_done(&c)) {
    if (!bs_pb_next(&c, &f)) {
      return BS_ERR_MALFORMED; /* unreachable: the first pass validated it */
    }
    if (f.number == BS_F_BISCUIT_BLOCKS && f.wire == BS_PB_BYTES) {
      bs_status st;
      if (index >= tok.block_count) {
        return BS_ERR_MALFORMED;
      }
      BS_ASSERT(index < tok.block_count);
      st = bs_pb_signed_block(f.bytes, &tok.blocks[index], 0);
      if (st != BS_OK) {
        return st;
      }
      index++;
    }
  }
  if (index != tok.block_count) {
    return BS_ERR_MALFORMED;
  }

  {
    bs_status st = bs_pb_proof(proof, &tok);
    if (st != BS_OK) {
      return st;
    }
  }

  *out = tok;
  return BS_OK;
}

BS_API bs_span bs_token_revocation_id(const bs_token *t, size_t index) {
  if (t == NULL || t->blocks == NULL || index >= t->block_count) {
    return bs_span_make(NULL, 0);
  }
  /* The revocation identifier for a block is its signature, verbatim. */
  return t->blocks[index].signature;
}

/* ===========================================================================
 * 70_writer.inc
 * ======================================================================== */

/* ---------------------------------------------------------------------------
 * Output writer
 *
 * The printer renders Datalog into a caller-provided buffer. There is no
 * stdio and no allocation here either, so the same code runs in a signal
 * handler, a kernel module or a WASM sandbox.
 *
 * Overflow is sticky, exactly like the arena: once the buffer is full the
 * writer stays full and every later call is a no-op. A long chain of appends
 * therefore needs one check at the end rather than one per call, and the
 * failure mode of forgetting that check is truncated output -- never a write
 * past the end.
 * ------------------------------------------------------------------------ */

BS_API bs_status bs_writer_init(bs_writer *w, void *buf, size_t cap) {
  if (w == NULL) {
    return BS_ERR_ARGUMENT;
  }
  if (buf == NULL && cap != 0U) {
    return BS_ERR_ARGUMENT;
  }
  w->buf = (uint8_t *)buf;
  w->cap = (buf == NULL) ? 0U : cap;
  w->len = 0U;
  w->overflow = 0;
  return BS_OK;
}

BS_API int bs_writer_overflow(const bs_writer *w) {
  return (w == NULL) ? 1 : w->overflow;
}

BS_API size_t bs_writer_len(const bs_writer *w) {
  return (w == NULL) ? 0U : w->len;
}

static void bs_put_span(bs_writer *w, bs_span s) {
  if (w == NULL || w->overflow) {
    return;
  }
  if (s.n > w->cap - w->len) {
    w->overflow = 1;
    return;
  }
  if (s.n != 0U) {
    memcpy(w->buf + w->len, s.p, s.n);
    w->len += s.n;
  }
}

static void bs_put_byte(bs_writer *w, uint8_t b) {
  bs_put_span(w, bs_span_make(&b, 1U));
}

/* Literal text, with its length taken at compile time.
 *
 * A scan for the terminator would be the obvious implementation and is the
 * wrong one: clang recognises that loop and rewrites it into a call to
 * strlen, which puts a str* function into the shipped object and breaks
 * invariant 5. tools/check_invariants.py caught exactly that. sizeof cannot
 * be rewritten into anything. */
#define BS_PUT_LIT(w, lit)                                                     \
  bs_put_span((w), bs_span_make((lit), sizeof(lit) - 1U))

/* Signed decimal, INT64_MIN included.
 *
 * Negating INT64_MIN is undefined, so the digits are accumulated on the
 * negative side of zero, where every int64_t value is representable. */
static void bs_put_i64(bs_writer *w, int64_t v) {
  char digits[20];
  size_t n = 0;
  int64_t rest = (v < 0) ? v : -v;

  do {
    /* C99 truncates division toward zero, so this remainder is <= 0. */
    digits[n++] = (char)('0' - (int)(rest % 10));
    rest /= 10;
  } while (rest != 0);

  if (v < 0) {
    bs_put_byte(w, (uint8_t)'-');
  }
  while (n > 0U) {
    n--;
    bs_put_byte(w, (uint8_t)digits[n]);
  }
}

/* Zero-padded fixed-width decimal, for date components. */
static void bs_put_pad(bs_writer *w, uint64_t v, size_t width) {
  char digits[20];
  size_t n = 0;
  do {
    digits[n++] = (char)('0' + (int)(v % 10U));
    v /= 10U;
  } while (v != 0U);
  while (n < width) {
    bs_put_byte(w, (uint8_t)'0');
    width--;
  }
  while (n > 0U) {
    n--;
    bs_put_byte(w, (uint8_t)digits[n]);
  }
}

static void bs_put_hex(bs_writer *w, bs_span s) {
  static const char digits[] = "0123456789abcdef";
  size_t i;
  for (i = 0; i < s.n; i++) {
    unsigned int byte = s.p[i];
    bs_put_byte(w, (uint8_t)digits[byte >> 4U]);
    bs_put_byte(w, (uint8_t)digits[byte & 0x0FU]);
  }
}

/* A Datalog string literal.
 *
 * The content is emitted verbatim between quotes, with no escaping at all.
 * That is not an oversight and not a shortcut: it is what the reference
 * implementation does, and the specification's own samples encode the result.
 * test021_parsing carries a literal tab byte inside a string and expects that
 * byte back, so a printer that escaped it would fail the round trip that the
 * conformance suite exists to check.
 *
 * The consequence is worth stating plainly: a string containing a double
 * quote renders as source that cannot be parsed back. That hazard lives in
 * the specification's text format rather than here, and matching it is the
 * only way to agree with every other implementation. Anything else would be
 * a private dialect.
 *
 * UTF-8 passes through byte for byte for the same reason. */
static void bs_put_string(bs_writer *w, bs_span s) {
  bs_put_byte(w, (uint8_t)'"');
  bs_put_span(w, s);
  bs_put_byte(w, (uint8_t)'"');
}

/* An RFC 3339 timestamp in UTC, which is how the specification prints dates.
 *
 * The civil-date conversion is the standard shift-the-epoch-to-March algorithm:
 * moving the year boundary to 1 March makes the leap day the last day of the
 * year, which removes every special case from the month-length arithmetic.
 * Integer only, no division by zero, no floating point. */
static void bs_put_date(bs_writer *w, uint64_t seconds) {
  uint64_t days = seconds / 86400U;
  uint64_t rem = seconds % 86400U;
  uint64_t era;
  uint64_t doe;
  uint64_t yoe;
  uint64_t doy;
  uint64_t mp;
  uint64_t d;
  uint64_t m;
  uint64_t y;

  /* Shift the epoch from 1970-01-01 to 0000-03-01. */
  days += 719468U;
  era = days / 146097U;
  doe = days % 146097U;
  yoe = ((doe - (doe / 1460U)) + (doe / 36524U) - (doe / 146096U)) / 365U;
  y = yoe + (era * 400U);
  doy = doe - (((365U * yoe) + (yoe / 4U)) - (yoe / 100U));
  mp = ((5U * doy) + 2U) / 153U;
  d = (doy - (((153U * mp) + 2U) / 5U)) + 1U;
  m = (mp < 10U) ? (mp + 3U) : (mp - 9U);
  if (m <= 2U) {
    y += 1U;
  }

  bs_put_pad(w, y, 4U);
  bs_put_byte(w, (uint8_t)'-');
  bs_put_pad(w, m, 2U);
  bs_put_byte(w, (uint8_t)'-');
  bs_put_pad(w, d, 2U);
  bs_put_byte(w, (uint8_t)'T');
  bs_put_pad(w, rem / 3600U, 2U);
  bs_put_byte(w, (uint8_t)':');
  bs_put_pad(w, (rem / 60U) % 60U, 2U);
  bs_put_byte(w, (uint8_t)':');
  bs_put_pad(w, rem % 60U, 2U);
  bs_put_byte(w, (uint8_t)'Z');
}

/* ===========================================================================
 * 75_symbols.inc
 * ======================================================================== */

/* ---------------------------------------------------------------------------
 * Symbol table
 *
 * Predicate names and string terms are interned: the wire carries an index,
 * not the text. Indices below BS_SYMBOL_OFFSET name one of the well-known
 * symbols every implementation shares; indices at or above it name a symbol
 * the token itself carries.
 *
 * The token-provided half is the concatenation of every block's `symbols`
 * array, in block order, authority first. Getting that order wrong silently
 * renames every predicate in the token rather than failing, which is why the
 * blocks tier of the conformance suite -- decode, print, diff against the
 * expected source -- is the cheapest high-signal test in the whole project.
 * ------------------------------------------------------------------------ */

/* The gap between the two halves is not decoration: it lets the well-known
 * list grow in a later specification revision without renumbering symbols
 * inside tokens that already exist. */
#define BS_SYMBOL_OFFSET 1024U

/* Text and length together: a length taken by scanning for the terminator
 * compiles down to a call to strlen, which invariant 5 forbids. */
typedef struct bs_static_symbol {
  const char *text;
  size_t len;
} bs_static_symbol;

#define BS_SYM(s) {s, sizeof(s) - 1U}

static const bs_static_symbol BS_DEFAULT_SYMBOLS[] = {
    BS_SYM("read"),      BS_SYM("write"),     BS_SYM("resource"),
    BS_SYM("operation"), BS_SYM("right"),     BS_SYM("time"),
    BS_SYM("role"),      BS_SYM("owner"),     BS_SYM("tenant"),
    BS_SYM("namespace"), BS_SYM("user"),      BS_SYM("team"),
    BS_SYM("service"),   BS_SYM("admin"),     BS_SYM("email"),
    BS_SYM("group"),     BS_SYM("member"),    BS_SYM("ip_address"),
    BS_SYM("client"),    BS_SYM("client_ip"), BS_SYM("domain"),
    BS_SYM("path"),      BS_SYM("version"),   BS_SYM("cluster"),
    BS_SYM("node"),      BS_SYM("hostname"),  BS_SYM("nonce"),
    BS_SYM("query"),
};

#define BS_DEFAULT_SYMBOL_COUNT                                                \
  (sizeof BS_DEFAULT_SYMBOLS / sizeof BS_DEFAULT_SYMBOLS[0])

BS_API int bs_symbol_get(const bs_symbols *s, uint64_t index, bs_span *out) {
  if (out == NULL) {
    return 0;
  }

  if (index < BS_SYMBOL_OFFSET) {
    const bs_static_symbol *entry;
    if (index >= (uint64_t)BS_DEFAULT_SYMBOL_COUNT) {
      /* An index inside the reserved range but past the list this build
       * knows. A future specification may define it; this one cannot print
       * it, and guessing would produce a token that reads differently here
       * than everywhere else. */
      return 0;
    }
    entry = &BS_DEFAULT_SYMBOLS[(size_t)index];
    *out = bs_span_make(entry->text, entry->len);
    return 1;
  }

  if (s == NULL || s->entries == NULL) {
    return 0;
  }
  index -= BS_SYMBOL_OFFSET;
  if (index >= (uint64_t)s->count) {
    return 0;
  }
  *out = s->entries[(size_t)index];
  return 1;
}

BS_API size_t bs_symbol_default_count(void) {
  return (size_t)BS_DEFAULT_SYMBOL_COUNT;
}

/* ===========================================================================
 * 80_term.inc
 * ======================================================================== */

/* ---------------------------------------------------------------------------
 * Terms
 *
 * Terms are printed straight from the wire. There is no intermediate tree:
 * building one would cost an allocation per node and buy nothing, since every
 * consumer of a term either prints it or compares it, and both can be done in
 * one pass over the encoded bytes.
 *
 * Nesting is handled with an explicit frame stack (invariant 2). A frame is
 * pushed only for a container, so the depth limit counts exactly what a reader
 * would call nesting: `{"a": [1, {"b": 2}]}` is three deep. A scalar never
 * costs a frame, which is why the common case -- a flat list of strings --
 * runs at constant stack.
 * ------------------------------------------------------------------------ */

#define BS_F_TERM_VARIABLE 1U
#define BS_F_TERM_INTEGER 2U
#define BS_F_TERM_STRING 3U
#define BS_F_TERM_DATE 4U
#define BS_F_TERM_BYTES 5U
#define BS_F_TERM_BOOL 6U
#define BS_F_TERM_SET 7U
#define BS_F_TERM_NULL 8U
#define BS_F_TERM_ARRAY 9U
#define BS_F_TERM_MAP 10U

#define BS_F_MAPENTRY_KEY 1U
#define BS_F_MAPENTRY_VALUE 2U
#define BS_F_MAPKEY_INTEGER 1U
#define BS_F_MAPKEY_STRING 2U

/* Container kinds, and how each one brackets its items. Sets and maps share
 * the brace; what tells them apart when reading is the colon, which is why an
 * empty set and an empty map print identically. That ambiguity is in the
 * specification's text format, not introduced here. */
#define BS_CTR_SET 0U
#define BS_CTR_ARRAY 1U
#define BS_CTR_MAP 2U

typedef struct bs_pframe {
  bs_cursor c;   /* the container's remaining items */
  uint32_t kind; /* BS_CTR_* */
  int emitted;   /* items already written, for separator placement */
} bs_pframe;

static void bs_put_symbol(bs_writer *w, const bs_symbols *sym, uint64_t index,
                          int quoted, int *ok) {
  bs_span text;
  if (!bs_symbol_get(sym, index, &text)) {
    *ok = 0;
    return;
  }
  if (quoted) {
    bs_put_string(w, text);
  } else {
    bs_put_span(w, text);
  }
}

/* Print a term if it is a scalar, or report the container to descend into.
 *
 * Returns 0 on malformed input, 1 when the term was printed in full, and 2
 * when the caller must push a frame -- *kind and *inner then describe it.
 *
 * A Term is a protobuf oneof, so exactly one recognised field must be
 * present. Accepting several would let a token carry two readings of the same
 * value and leave it to the verifier to pick one. */
static int bs_term_step(bs_writer *w, const bs_symbols *sym, bs_span term,
                        uint32_t *kind, bs_span *inner) {
  bs_cursor c = bs_cursor_make(term);
  bs_pb_field f;
  int found = 0;
  int result = 0;
  int ok = 1;

  while (!bs_cursor_done(&c)) {
    if (!bs_pb_next(&c, &f)) {
      return 0;
    }
    switch (f.number) {
    case BS_F_TERM_VARIABLE:
      if (f.wire != BS_PB_VARINT || found++) {
        return 0;
      }
      bs_put_byte(w, (uint8_t)'$');
      bs_put_symbol(w, sym, f.varint, 0, &ok);
      result = 1;
      break;
    case BS_F_TERM_INTEGER:
      if (f.wire != BS_PB_VARINT || found++) {
        return 0;
      }
      /* proto2 int64 is two's complement in a varint, not zigzag, so a
       * negative value arrives as a ten-byte encoding and this cast is the
       * decoding. */
      bs_put_i64(w, (int64_t)f.varint);
      result = 1;
      break;
    case BS_F_TERM_STRING:
      if (f.wire != BS_PB_VARINT || found++) {
        return 0;
      }
      bs_put_symbol(w, sym, f.varint, 1, &ok);
      result = 1;
      break;
    case BS_F_TERM_DATE:
      if (f.wire != BS_PB_VARINT || found++) {
        return 0;
      }
      bs_put_date(w, f.varint);
      result = 1;
      break;
    case BS_F_TERM_BYTES:
      if (f.wire != BS_PB_BYTES || found++) {
        return 0;
      }
      BS_PUT_LIT(w, "hex:");
      bs_put_hex(w, f.bytes);
      result = 1;
      break;
    case BS_F_TERM_BOOL:
      if (f.wire != BS_PB_VARINT || found++) {
        return 0;
      }
      /* Anything other than 0 or 1 is not a bool. A token that encodes 2 here
       * would read as true in one implementation and be rejected by another. */
      if (f.varint > 1U) {
        return 0;
      }
      if (f.varint != 0U) {
        BS_PUT_LIT(w, "true");
      } else {
        BS_PUT_LIT(w, "false");
      }
      result = 1;
      break;
    case BS_F_TERM_NULL:
      if (f.wire != BS_PB_BYTES || found++) {
        return 0;
      }
      BS_PUT_LIT(w, "null");
      result = 1;
      break;
    case BS_F_TERM_SET:
    case BS_F_TERM_ARRAY:
    case BS_F_TERM_MAP:
      if (f.wire != BS_PB_BYTES || found++) {
        return 0;
      }
      *kind = (f.number == BS_F_TERM_SET)     ? BS_CTR_SET
              : (f.number == BS_F_TERM_ARRAY) ? BS_CTR_ARRAY
                                              : BS_CTR_MAP;
      *inner = f.bytes;
      result = 2;
      break;
    default:
      break; /* unknown field: parsed, then ignored */
    }
  }

  if (!found || !ok) {
    return 0;
  }
  return result;
}

/* A map key is always a scalar, so it never needs a frame. */
static int bs_mapkey_print(bs_writer *w, const bs_symbols *sym, bs_span key) {
  bs_cursor c = bs_cursor_make(key);
  bs_pb_field f;
  int found = 0;
  int ok = 1;

  while (!bs_cursor_done(&c)) {
    if (!bs_pb_next(&c, &f)) {
      return 0;
    }
    if (f.number == BS_F_MAPKEY_INTEGER && f.wire == BS_PB_VARINT) {
      if (found++) {
        return 0;
      }
      bs_put_i64(w, (int64_t)f.varint);
    } else if (f.number == BS_F_MAPKEY_STRING && f.wire == BS_PB_VARINT) {
      if (found++) {
        return 0;
      }
      bs_put_symbol(w, sym, f.varint, 1, &ok);
    }
  }
  return (found == 1 && ok) ? 1 : 0;
}

/* Split a MapEntry into its key and value. Both are required. */
static int bs_mapentry_split(bs_span entry, bs_span *key, bs_span *value) {
  bs_cursor c = bs_cursor_make(entry);
  bs_pb_field f;
  int have_key = 0;
  int have_value = 0;

  while (!bs_cursor_done(&c)) {
    if (!bs_pb_next(&c, &f)) {
      return 0;
    }
    if (f.number == BS_F_MAPENTRY_KEY && f.wire == BS_PB_BYTES) {
      *key = f.bytes;
      have_key = 1;
    } else if (f.number == BS_F_MAPENTRY_VALUE && f.wire == BS_PB_BYTES) {
      *value = f.bytes;
      have_value = 1;
    }
  }
  return (have_key && have_value) ? 1 : 0;
}

static void bs_put_open(bs_writer *w, uint32_t kind) {
  bs_put_byte(w, (uint8_t)((kind == BS_CTR_ARRAY) ? '[' : '{'));
}

/* An empty set prints as `{,}`, not `{}`.
 *
 * Sets and maps share the brace, and the colon is what tells them apart --
 * which leaves nothing to distinguish an empty one from the other. The text
 * format resolves it with a lone comma in the set. The specification's own
 * sample checks `{,}.length() === 0`, so this is required, not cosmetic. */
static void bs_put_close(bs_writer *w, uint32_t kind, int emitted) {
  if (kind == BS_CTR_SET && emitted == 0) {
    bs_put_byte(w, (uint8_t)',');
  }
  bs_put_byte(w, (uint8_t)((kind == BS_CTR_ARRAY) ? ']' : '}'));
}

/* Render one encoded Term as Datalog source. */
BS_API bs_status bs_term_print(bs_writer *w, const bs_symbols *sym,
                               bs_span term) {
  bs_pframe stack[BS_MAX_DEPTH];
  size_t depth = 0;
  uint32_t kind = 0;
  bs_span inner = bs_span_make(NULL, 0);

  switch (bs_term_step(w, sym, term, &kind, &inner)) {
  case 0:
    return BS_ERR_MALFORMED;
  case 1:
    return BS_OK; /* a scalar: no stack needed at all */
  default:
    break;
  }

  bs_put_open(w, kind);
  stack[0].c = bs_cursor_make(inner);
  stack[0].kind = kind;
  stack[0].emitted = 0;
  depth = 1;

  while (depth > 0U) {
    bs_pframe *f = &stack[depth - 1U];
    bs_pb_field item;
    bs_span value;
    int step;

    if (bs_cursor_done(&f->c)) {
      bs_put_close(w, f->kind, f->emitted);
      depth--;
      continue;
    }

    if (!bs_pb_next(&f->c, &item)) {
      return BS_ERR_MALFORMED;
    }
    /* Every container holds its items in repeated field 1. */
    if (item.number != 1U || item.wire != BS_PB_BYTES) {
      continue; /* unknown field inside a container: parsed, then ignored */
    }

    if (f->emitted++ > 0) {
      BS_PUT_LIT(w, ", ");
    }

    value = item.bytes;
    if (f->kind == BS_CTR_MAP) {
      bs_span key;
      if (!bs_mapentry_split(item.bytes, &key, &value)) {
        return BS_ERR_MALFORMED;
      }
      if (!bs_mapkey_print(w, sym, key)) {
        return BS_ERR_MALFORMED;
      }
      BS_PUT_LIT(w, ": ");
    }

    step = bs_term_step(w, sym, value, &kind, &inner);
    if (step == 0) {
      return BS_ERR_MALFORMED;
    }
    if (step == 2) {
      if (depth >= (size_t)BS_MAX_DEPTH) {
        /* Deeper than this build will walk. A clean error, never a smashed
         * stack -- which is the whole point of not recursing. */
        return BS_ERR_DEPTH;
      }
      BS_ASSERT(depth < (size_t)BS_MAX_DEPTH);
      bs_put_open(w, kind);
      stack[depth].c = bs_cursor_make(inner);
      stack[depth].kind = kind;
      stack[depth].emitted = 0;
      depth++;
    }
  }

  return bs_writer_overflow(w) ? BS_ERR_NOMEM : BS_OK;
}

/* ===========================================================================
 * 85_block.inc
 * ======================================================================== */

/* ---------------------------------------------------------------------------
 * Blocks
 *
 * A block carries the Datalog: facts, rules, checks, the scopes they trust,
 * and the symbols and public keys they refer to by index.
 *
 * Those indices are token-wide, not block-wide. The symbol table is the
 * concatenation of every block's `symbols` array in block order, authority
 * first, and the public key table works the same way. Building them is
 * therefore a whole-token operation that has to happen before any single
 * block can be read -- which is why it lives here rather than inside the
 * block decoder.
 *
 * Getting that order wrong does not fail; it silently renames every predicate
 * in the token. The blocks tier of the conformance suite catches exactly that,
 * by printing each decoded block and diffing it against the source the
 * specification says it should produce.
 * ------------------------------------------------------------------------ */

#define BS_F_BLOCK_SYMBOLS 1U
#define BS_F_BLOCK_CONTEXT 2U
#define BS_F_BLOCK_VERSION 3U
#define BS_F_BLOCK_FACTS 4U
#define BS_F_BLOCK_RULES 5U
#define BS_F_BLOCK_CHECKS 6U
#define BS_F_BLOCK_SCOPE 7U
#define BS_F_BLOCK_PUBLIC_KEYS 8U

#define BS_F_FACT_PREDICATE 1U
#define BS_F_PREDICATE_NAME 1U
#define BS_F_PREDICATE_TERMS 2U

#define BS_F_SCOPE_TYPE 1U
#define BS_F_SCOPE_PUBLIC_KEY 2U

#define BS_SCOPE_AUTHORITY 0U
#define BS_SCOPE_PREVIOUS 1U

/* Count the entries of one repeated field in a message, and optionally copy
 * their payloads out. Two passes over the same bytes is what lets the arena
 * stay a bump allocator: the count is known before anything is reserved, so
 * there is never a growth step and never a realloc. */
static bs_status bs_repeated(bs_span msg, uint32_t field, bs_span *out,
                             size_t cap, size_t *count) {
  bs_cursor c = bs_cursor_make(msg);
  bs_pb_field f;
  size_t n = 0;

  while (!bs_cursor_done(&c)) {
    if (!bs_pb_next(&c, &f)) {
      return BS_ERR_MALFORMED;
    }
    if (f.number != field || f.wire != BS_PB_BYTES) {
      continue;
    }
    if (out != NULL) {
      if (n >= cap) {
        return BS_ERR_LIMIT;
      }
      out[n] = f.bytes;
    }
    if (!bs_size_add(n, 1U, &n)) {
      return BS_ERR_OVERFLOW;
    }
  }
  *count = n;
  return BS_OK;
}

static int bs_pubkey_eq(const bs_public_key *x, const bs_public_key *y) {
  return x->alg == y->alg && bs_span_eq(x->key, y->key);
}

/* Collect the symbol and public-key tables from a run of blocks.
 *
 * `skip_external` reproduces the rule in the specification's reference
 * decoder: a block carrying an external signature contributes nothing to the
 * token-wide tables. Its symbols and keys belong to the third party that
 * signed it, who never saw the rest of the token, so folding them in would
 * shift every index that follows.
 *
 * Public keys are deduplicated on insertion -- a key already in the table
 * keeps its index rather than gaining a second one. Symbols are not: they are
 * appended as they come. */
static bs_status bs_tables_collect(bs_arena *a, const bs_signed_block *blocks,
                                   size_t block_count, int skip_external,
                                   bs_tables *out) {
  size_t total_symbols = 0;
  size_t total_keys = 0;
  size_t block;
  size_t sym_at = 0;
  size_t key_at = 0;
  /* Filled through a non-const pointer and published as const: the table is
   * read-only to everyone but its builder, and casting the qualifier away at
   * the point of use would hide that. */
  bs_span *sym_slots = NULL;

  out->symbols.entries = NULL;
  out->symbols.count = 0;
  out->public_keys = NULL;
  out->public_key_count = 0;

  for (block = 0; block < block_count; block++) {
    size_t n;
    bs_status st;
    if (skip_external && blocks[block].has_external) {
      continue;
    }
    st = bs_repeated(blocks[block].block, BS_F_BLOCK_SYMBOLS, NULL, 0U, &n);
    if (st != BS_OK) {
      return st;
    }
    if (!bs_size_add(total_symbols, n, &total_symbols)) {
      return BS_ERR_OVERFLOW;
    }
    st = bs_repeated(blocks[block].block, BS_F_BLOCK_PUBLIC_KEYS, NULL, 0U, &n);
    if (st != BS_OK) {
      return st;
    }
    if (!bs_size_add(total_keys, n, &total_keys)) {
      return BS_ERR_OVERFLOW;
    }
  }

  if (total_symbols != 0U) {
    sym_slots = (bs_span *)bs_arena_array(a, total_symbols, sizeof(bs_span),
                                          BS_ALIGN_MAX);
    if (sym_slots == NULL) {
      return BS_ERR_NOMEM;
    }
  }
  if (total_keys != 0U) {
    out->public_keys = (bs_public_key *)bs_arena_array(
        a, total_keys, sizeof(bs_public_key), BS_ALIGN_MAX);
    if (out->public_keys == NULL) {
      return BS_ERR_NOMEM;
    }
  }

  for (block = 0; block < block_count; block++) {
    bs_cursor c;
    bs_pb_field f;
    if (skip_external && blocks[block].has_external) {
      continue;
    }
    c = bs_cursor_make(blocks[block].block);
    while (!bs_cursor_done(&c)) {
      if (!bs_pb_next(&c, &f)) {
        return BS_ERR_MALFORMED;
      }
      if (f.wire != BS_PB_BYTES) {
        continue;
      }
      if (f.number == BS_F_BLOCK_SYMBOLS) {
        /* The counting pass allocated exactly as many slots as this pass will
         * fill. If the two ever disagree the input changed underneath us,
         * which cannot happen -- but saying so here is what lets the static
         * analyser see that the array is non-null and in range. */
        if (sym_slots == NULL || sym_at >= total_symbols) {
          return BS_ERR_MALFORMED;
        }
        sym_slots[sym_at] = f.bytes;
        sym_at++;
      } else if (f.number == BS_F_BLOCK_PUBLIC_KEYS) {
        bs_public_key key;
        bs_status st = bs_pb_pubkey(f.bytes, &key);
        size_t seen;
        int duplicate = 0;
        if (st != BS_OK) {
          return st;
        }
        for (seen = 0; seen < key_at && out->public_keys != NULL; seen++) {
          if (bs_pubkey_eq(&out->public_keys[seen], &key)) {
            duplicate = 1;
            break;
          }
        }
        if (!duplicate) {
          if (out->public_keys == NULL || key_at >= total_keys) {
            return BS_ERR_MALFORMED;
          }
          out->public_keys[key_at] = key;
          key_at++;
        }
      }
    }
  }

  BS_ASSERT(sym_at == total_symbols);
  BS_ASSERT(key_at <= total_keys); /* duplicates were folded away */
  out->symbols.entries = sym_slots;
  out->symbols.count = total_symbols;
  /* key_at, not total_keys: the count is of distinct keys actually written,
   * and duplicates were folded away. Publishing the pre-deduplication figure
   * would make scope indices in the gap resolve to zeroed entries and render
   * as a trust clause naming an all-zero key. */
  out->public_key_count = key_at;
  return BS_OK;
}

/* The token-wide tables: every block's symbols and keys, in block order.
 *
 * These are the tables a regular block is read against. A third-party block
 * is not -- see bs_tables_build_block. */
BS_API bs_status bs_tables_build(bs_arena *a, const bs_token *t,
                                 bs_tables *out) {
  if (a == NULL || t == NULL || out == NULL || t->blocks == NULL) {
    return BS_ERR_ARGUMENT;
  }
  return bs_tables_collect(a, t->blocks, t->block_count, 1, out);
}

/* The tables of a single block, standing alone.
 *
 * A third-party block is signed by someone who never saw the rest of the
 * token, so its indices number only its own symbols and keys. Reading it
 * against the token-wide tables resolves them to the wrong entries -- which
 * is silent, because both tables are populated and both indices are in range.
 * The specification's public-key interning sample is exactly this case, and
 * it is the reason this function exists. */
BS_API bs_status bs_tables_build_block(bs_arena *a, bs_span block,
                                       bs_tables *out) {
  bs_signed_block one;
  if (a == NULL || out == NULL) {
    return BS_ERR_ARGUMENT;
  }
  memset(&one, 0, sizeof one);
  one.block = block;
  return bs_tables_collect(a, &one, 1U, 0, out);
}

/* ---------------------------------------------------------------------------
 * Printing
 * ------------------------------------------------------------------------ */

/* A public key renders as its algorithm, a slash, and the key in hex. */
static bs_status bs_print_public_key(bs_writer *w, const bs_public_key *k) {
  if (k == NULL) {
    return BS_ERR_MALFORMED;
  }
  switch (k->alg) {
  case BS_ALG_ED25519:
    BS_PUT_LIT(w, "ed25519/");
    break;
  case BS_ALG_SECP256R1:
    BS_PUT_LIT(w, "secp256r1/");
    break;
  default:
    return BS_ERR_MALFORMED;
  }
  bs_put_hex(w, k->key);
  return BS_OK;
}

/* `authority`, `previous`, or a key from the token's public key table. */
BS_API bs_status bs_scope_print(bs_writer *w, const bs_tables *tab,
                                bs_span scope) {
  bs_cursor c = bs_cursor_make(scope);
  bs_pb_field f;
  int have_type = 0;
  int have_key = 0;
  uint64_t type = 0;
  int64_t key = 0;

  while (!bs_cursor_done(&c)) {
    if (!bs_pb_next(&c, &f)) {
      return BS_ERR_MALFORMED;
    }
    if (f.wire != BS_PB_VARINT) {
      continue;
    }
    if (f.number == BS_F_SCOPE_TYPE) {
      type = f.varint;
      have_type = 1;
    } else if (f.number == BS_F_SCOPE_PUBLIC_KEY) {
      key = (int64_t)f.varint;
      have_key = 1;
    }
  }

  /* The schema makes these a oneof: a scope names a kind or a key, never
   * both and never neither. */
  if (have_type == have_key) {
    return BS_ERR_MALFORMED;
  }

  if (have_type) {
    switch (type) {
    case BS_SCOPE_AUTHORITY:
      BS_PUT_LIT(w, "authority");
      return BS_OK;
    case BS_SCOPE_PREVIOUS:
      BS_PUT_LIT(w, "previous");
      return BS_OK;
    default:
      return BS_ERR_MALFORMED;
    }
  }

  if (tab == NULL || key < 0 ||
      (uint64_t)key >= (uint64_t)tab->public_key_count) {
    return BS_ERR_MALFORMED;
  }
  return bs_print_public_key(w, &tab->public_keys[(size_t)key]);
}

/* `name(term, term, ...)`, the shape shared by facts, rule heads and rule
 * bodies. A predicate with no terms prints as `name()`. */
BS_API bs_status bs_predicate_print(bs_writer *w, const bs_tables *tab,
                                    bs_span pred) {
  bs_cursor c;
  if (w == NULL || tab == NULL) {
    return BS_ERR_ARGUMENT;
  }
  c = bs_cursor_make(pred);
  bs_pb_field f;
  bs_span name = bs_span_make(NULL, 0);
  int have_name = 0;
  int emitted = 0;

  /* The name comes before the terms on the wire, but the schema does not
   * guarantee it, so it is resolved in a first pass. */
  while (!bs_cursor_done(&c)) {
    if (!bs_pb_next(&c, &f)) {
      return BS_ERR_MALFORMED;
    }
    if (f.number == BS_F_PREDICATE_NAME && f.wire == BS_PB_VARINT) {
      if (!bs_symbol_get(&tab->symbols, f.varint, &name)) {
        return BS_ERR_MALFORMED;
      }
      have_name = 1;
    }
  }
  if (!have_name) {
    return BS_ERR_MALFORMED;
  }

  bs_put_span(w, name);
  bs_put_byte(w, (uint8_t)'(');

  c = bs_cursor_make(pred);
  while (!bs_cursor_done(&c)) {
    bs_status st;
    if (!bs_pb_next(&c, &f)) {
      return BS_ERR_MALFORMED;
    }
    if (f.number != BS_F_PREDICATE_TERMS || f.wire != BS_PB_BYTES) {
      continue;
    }
    if (emitted++ > 0) {
      BS_PUT_LIT(w, ", ");
    }
    st = bs_term_print(w, &tab->symbols, f.bytes);
    if (st != BS_OK) {
      return st;
    }
  }

  bs_put_byte(w, (uint8_t)')');
  return BS_OK;
}

/* A Fact is a Predicate in a one-field wrapper. */
BS_API bs_status bs_fact_print(bs_writer *w, const bs_tables *tab,
                               bs_span fact) {
  bs_cursor c;
  if (w == NULL || tab == NULL) {
    return BS_ERR_ARGUMENT;
  }
  c = bs_cursor_make(fact);
  bs_pb_field f;
  int found = 0;
  bs_span pred = bs_span_make(NULL, 0);

  while (!bs_cursor_done(&c)) {
    if (!bs_pb_next(&c, &f)) {
      return BS_ERR_MALFORMED;
    }
    if (f.number == BS_F_FACT_PREDICATE && f.wire == BS_PB_BYTES) {
      if (found++) {
        return BS_ERR_MALFORMED;
      }
      pred = f.bytes;
    }
  }
  if (found != 1) {
    return BS_ERR_MALFORMED;
  }
  return bs_predicate_print(w, tab, pred);
}

/* ===========================================================================
 * 90_expr.inc
 * ======================================================================== */

/* ---------------------------------------------------------------------------
 * Expressions
 *
 * Expressions travel as a postfix opcode sequence for a stack machine. Turning
 * that back into source is the one place in this library where a naive design
 * is quadratic: rendering each operator by concatenating the text of its
 * operands copies the accumulated string once per operator, so `1+1+1+...`
 * costs O(n^2) bytes.
 *
 * So it is done in two passes instead. The first replays the stack machine but
 * pushes *node indices* rather than text, which reconstructs the tree in O(n).
 * The second walks that tree and writes straight to the output, with an
 * explicit stack and no intermediate buffers at all.
 *
 * Precedence needs no handling: the encoder emits an explicit `Parens` opcode
 * wherever the source had one, which is exactly why that opcode exists. The
 * printer therefore never adds a parenthesis and never removes one -- it
 * reproduces what the writer chose.
 * ------------------------------------------------------------------------ */

#define BS_F_EXPR_OPS 1U

#define BS_F_OP_VALUE 1U
#define BS_F_OP_UNARY 2U
#define BS_F_OP_BINARY 3U
#define BS_F_OP_CLOSURE 4U

#define BS_F_OPKIND 1U
#define BS_F_OPFFI 2U

#define BS_F_CLOSURE_PARAMS 1U
#define BS_F_CLOSURE_OPS 2U

#define BS_U_NEGATE 0U
#define BS_U_PARENS 1U
#define BS_U_LENGTH 2U
#define BS_U_TYPEOF 3U
#define BS_U_FFI 4U

#define BS_B_FFI 28U

/* How a binary operator is written.
 *
 * The specification defines the opcodes; this table defines their surface
 * syntax. Most entries come from the conformance samples, but the samples do
 * not exercise every opcode -- the eager And and Or are absent from all 38 --
 * so those were taken from the reference implementation's own printer, where
 * eager renders as `&&!` and `||!` and short-circuiting as `&&` and `||`.
 * Printing all four the same way was a real divergence that the samples could
 * not have caught. */
#define BS_OP_INFIX 0U
#define BS_OP_METHOD 1U

typedef struct bs_binop {
  uint8_t style;
  const char *text;
  size_t len;
} bs_binop;

#define BS_OP(style, lit) {style, lit, sizeof(lit) - 1U}

static const bs_binop BS_BINOPS[] = {
    BS_OP(BS_OP_INFIX, "<"),             /*  0 LessThan */
    BS_OP(BS_OP_INFIX, ">"),             /*  1 GreaterThan */
    BS_OP(BS_OP_INFIX, "<="),            /*  2 LessOrEqual */
    BS_OP(BS_OP_INFIX, ">="),            /*  3 GreaterOrEqual */
    BS_OP(BS_OP_INFIX, "==="),           /*  4 Equal */
    BS_OP(BS_OP_METHOD, "contains"),     /*  5 Contains */
    BS_OP(BS_OP_METHOD, "starts_with"),  /*  6 Prefix */
    BS_OP(BS_OP_METHOD, "ends_with"),    /*  7 Suffix */
    BS_OP(BS_OP_METHOD, "matches"),      /*  8 Regex */
    BS_OP(BS_OP_INFIX, "+"),             /*  9 Add */
    BS_OP(BS_OP_INFIX, "-"),             /* 10 Sub */
    BS_OP(BS_OP_INFIX, "*"),             /* 11 Mul */
    BS_OP(BS_OP_INFIX, "/"),             /* 12 Div */
    BS_OP(BS_OP_INFIX, "&&!"),           /* 13 And, eager */
    BS_OP(BS_OP_INFIX, "||!"),           /* 14 Or, eager */
    BS_OP(BS_OP_METHOD, "intersection"), /* 15 Intersection */
    BS_OP(BS_OP_METHOD, "union"),        /* 16 Union */
    BS_OP(BS_OP_INFIX, "&"),             /* 17 BitwiseAnd */
    BS_OP(BS_OP_INFIX, "|"),             /* 18 BitwiseOr */
    BS_OP(BS_OP_INFIX, "^"),             /* 19 BitwiseXor */
    BS_OP(BS_OP_INFIX, "!=="),           /* 20 NotEqual */
    BS_OP(BS_OP_INFIX, "=="),            /* 21 HeterogeneousEqual */
    BS_OP(BS_OP_INFIX, "!="),            /* 22 HeterogeneousNotEqual */
    BS_OP(BS_OP_INFIX, "&&"),            /* 23 LazyAnd, short-circuiting */
    BS_OP(BS_OP_INFIX, "||"),            /* 24 LazyOr, short-circuiting */
    BS_OP(BS_OP_METHOD, "all"),          /* 25 All */
    BS_OP(BS_OP_METHOD, "any"),          /* 26 Any */
    BS_OP(BS_OP_METHOD, "get"),          /* 27 Get */
    BS_OP(BS_OP_METHOD, "extern"),       /* 28 Ffi, name supplied separately */
    BS_OP(BS_OP_METHOD, "try_or"),       /* 29 TryOr */
};

#define BS_BINOP_COUNT (sizeof BS_BINOPS / sizeof BS_BINOPS[0])

#define BS_E_VALUE 0U
#define BS_E_UNARY 1U
#define BS_E_BINARY 2U
#define BS_E_CLOSURE 3U

#define BS_E_NONE 0xFFFFFFFFU

typedef struct bs_enode {
  bs_span payload; /* value: the Term bytes; closure: the Closure message */
  uint64_t ffi;    /* symbol index of an external call's name */
  uint32_t kind;   /* the unary or binary opcode */
  uint32_t a;      /* first operand, or BS_E_NONE */
  uint32_t b;      /* second operand, or BS_E_NONE */
  uint8_t tag;     /* BS_E_* */
  uint8_t has_ffi;
} bs_enode;

/* One frame of the reconstruction: an opcode list being replayed, and the
 * height of the value stack when it started. */
typedef struct bs_eframe {
  bs_cursor ops;
  bs_span closure; /* the Closure message, for its parameters */
  size_t base;
  uint32_t field; /* ops are field 1 of an Expression, field 2 of a Closure */
  int is_closure;
} bs_eframe;

/* Read an OpUnary or OpBinary: a kind, and optionally an external name. */
static bs_status bs_op_kind(bs_span msg, uint32_t *kind, uint64_t *ffi,
                            uint8_t *has_ffi) {
  bs_cursor c = bs_cursor_make(msg);
  bs_pb_field f;
  int found = 0;

  *has_ffi = 0;
  while (!bs_cursor_done(&c)) {
    if (!bs_pb_next(&c, &f)) {
      return BS_ERR_MALFORMED;
    }
    if (f.wire != BS_PB_VARINT) {
      continue;
    }
    if (f.number == BS_F_OPKIND) {
      if (found++ || f.varint > 0xFFFFFFFFU) {
        return BS_ERR_MALFORMED;
      }
      *kind = (uint32_t)f.varint;
    } else if (f.number == BS_F_OPFFI) {
      *ffi = f.varint;
      *has_ffi = 1;
    }
  }
  return (found == 1) ? BS_OK : BS_ERR_MALFORMED;
}

/* Classify one Op. Returns the oneof branch that was present, or an error if
 * the count is anything but one -- an Op that claims to be two things at once
 * would let a token mean different things to different readers. */
static bs_status bs_op_branch(bs_span op, uint32_t *branch, bs_span *body) {
  bs_cursor c = bs_cursor_make(op);
  bs_pb_field f;
  int found = 0;

  while (!bs_cursor_done(&c)) {
    if (!bs_pb_next(&c, &f)) {
      return BS_ERR_MALFORMED;
    }
    if (f.wire != BS_PB_BYTES) {
      continue;
    }
    if (f.number == BS_F_OP_VALUE || f.number == BS_F_OP_UNARY ||
        f.number == BS_F_OP_BINARY || f.number == BS_F_OP_CLOSURE) {
      if (found++) {
        return BS_ERR_MALFORMED;
      }
      *branch = f.number;
      *body = f.bytes;
    }
  }
  return (found == 1) ? BS_OK : BS_ERR_MALFORMED;
}

/* Replay the opcode stream, pushing node indices instead of values. */
static bs_status bs_expr_build(bs_arena *a, bs_span expr, bs_enode **nodes_out,
                               uint32_t **stack_out, uint32_t *root,
                               size_t *node_count) {
  bs_eframe frames[BS_MAX_DEPTH];
  bs_enode *nodes;
  uint32_t *stack;
  size_t cap;
  size_t used = 0;
  size_t sp = 0;
  size_t depth = 1;

  /* Every Op is a length-delimited field, so it costs at least two bytes in
   * its parent message. That bounds the node count by half the expression's
   * length -- an upper bound derived from the input rather than a constant,
   * which is what keeps a hostile expression's cost proportional to what the
   * attacker actually sent. */
  cap = (expr.n / 2U) + 1U;
  nodes = (bs_enode *)bs_arena_array(a, cap, sizeof(bs_enode), BS_ALIGN_MAX);
  stack = (uint32_t *)bs_arena_array(a, cap, sizeof(uint32_t), BS_ALIGN_MAX);
  if (nodes == NULL || stack == NULL) {
    return BS_ERR_NOMEM;
  }

  frames[0].ops = bs_cursor_make(expr);
  frames[0].closure = bs_span_make(NULL, 0);
  frames[0].base = 0;
  frames[0].field = BS_F_EXPR_OPS;
  frames[0].is_closure = 0;

  while (depth > 0U) {
    bs_eframe *fr = &frames[depth - 1U];
    bs_pb_field f;
    bs_span body;
    uint32_t branch = 0;
    bs_status st;

    if (bs_cursor_done(&fr->ops)) {
      if (!fr->is_closure) {
        depth--;
        continue;
      }
      /* A closure body must leave exactly one value behind, like any
       * expression. */
      if (sp != fr->base + 1U) {
        return BS_ERR_MALFORMED;
      }
      if (used >= cap) {
        return BS_ERR_LIMIT;
      }
      nodes[used].tag = (uint8_t)BS_E_CLOSURE;
      nodes[used].payload = fr->closure;
      nodes[used].a = stack[fr->base];
      nodes[used].b = BS_E_NONE;
      nodes[used].kind = 0;
      nodes[used].ffi = 0;
      nodes[used].has_ffi = 0;
      sp = fr->base;
      stack[sp++] = (uint32_t)used;
      used++;
      depth--;
      continue;
    }

    if (!bs_pb_next(&fr->ops, &f)) {
      return BS_ERR_MALFORMED;
    }
    if (f.number != fr->field || f.wire != BS_PB_BYTES) {
      continue;
    }

    st = bs_op_branch(f.bytes, &branch, &body);
    if (st != BS_OK) {
      return st;
    }
    if (used >= cap || sp >= cap) {
      return BS_ERR_LIMIT;
    }

    if (branch == BS_F_OP_CLOSURE) {
      if (depth >= (size_t)BS_MAX_DEPTH) {
        return BS_ERR_DEPTH;
      }
      frames[depth].ops = bs_cursor_make(body);
      frames[depth].closure = body;
      frames[depth].base = sp;
      frames[depth].field = BS_F_CLOSURE_OPS;
      frames[depth].is_closure = 1;
      depth++;
      continue;
    }

    nodes[used].payload = bs_span_make(NULL, 0);
    nodes[used].ffi = 0;
    nodes[used].has_ffi = 0;
    nodes[used].kind = 0;
    nodes[used].a = BS_E_NONE;
    nodes[used].b = BS_E_NONE;

    if (branch == BS_F_OP_VALUE) {
      nodes[used].tag = (uint8_t)BS_E_VALUE;
      nodes[used].payload = body;
    } else if (branch == BS_F_OP_UNARY) {
      if (sp < fr->base + 1U) {
        return BS_ERR_MALFORMED; /* not enough operands */
      }
      st = bs_op_kind(body, &nodes[used].kind, &nodes[used].ffi,
                      &nodes[used].has_ffi);
      if (st != BS_OK) {
        return st;
      }
      nodes[used].tag = (uint8_t)BS_E_UNARY;
      nodes[used].a = stack[--sp];
    } else {
      if (sp < fr->base + 2U) {
        return BS_ERR_MALFORMED;
      }
      st = bs_op_kind(body, &nodes[used].kind, &nodes[used].ffi,
                      &nodes[used].has_ffi);
      if (st != BS_OK) {
        return st;
      }
      nodes[used].tag = (uint8_t)BS_E_BINARY;
      /* The stack machine pushes the left operand first, so the top of the
       * stack is the right-hand side. */
      nodes[used].b = stack[--sp];
      nodes[used].a = stack[--sp];
    }

    stack[sp++] = (uint32_t)used;
    used++;
  }

  /* After the whole stream, exactly one value must remain. */
  if (sp != 1U) {
    return BS_ERR_MALFORMED;
  }
  *nodes_out = nodes;
  *stack_out = stack;
  *root = stack[0];
  *node_count = used;
  return BS_OK;
}

static void bs_put_extern(bs_writer *w, const bs_symbols *sym, uint64_t name,
                          int *ok) {
  BS_PUT_LIT(w, ".extern::");
  bs_put_symbol(w, sym, name, 0, ok);
  bs_put_byte(w, (uint8_t)'(');
}

/* Walk the tree and write the source. Two stages per node at most, so the
 * traversal is a flat loop over an explicit stack. */
static bs_status bs_expr_emit(bs_writer *w, const bs_tables *tab,
                              const bs_enode *nodes, size_t node_count,
                              uint32_t root, uint32_t *stack, size_t cap) {
  size_t sp = 0;
  int ok = 1;

  /* The traversal reuses the reconstruction stack, which is no longer needed
   * and is already sized to the node count. Each entry packs a node index
   * with a two-bit stage, so the index must fit in the remaining thirty bits.
   * An expression large enough to break that would have to be a gigabyte of
   * opcodes; the check costs one comparison and removes the assumption. */
  if (cap == 0U || node_count > 0x3FFFFFFFU) {
    return BS_ERR_LIMIT;
  }

  stack[sp++] = root << 2U;

  while (sp > 0U) {
    uint32_t packed = stack[sp - 1U];
    uint32_t index = packed >> 2U;
    uint32_t st = packed & 3U;
    const bs_enode *n;

    if (index >= (uint32_t)node_count) {
      return BS_ERR_MALFORMED;
    }
    n = &nodes[index];

    if (n->tag == BS_E_VALUE) {
      bs_status s = bs_term_print(w, &tab->symbols, n->payload);
      if (s != BS_OK) {
        return s;
      }
      sp--;
      continue;
    }

    if (n->tag == BS_E_UNARY) {
      if (st == 0U) {
        if (n->kind == BS_U_NEGATE) {
          bs_put_byte(w, (uint8_t)'!');
        } else if (n->kind == BS_U_PARENS) {
          bs_put_byte(w, (uint8_t)'(');
        }
        stack[sp - 1U] = (index << 2U) | 1U;
        if (sp >= cap) {
          return BS_ERR_LIMIT;
        }
        stack[sp++] = n->a << 2U;
        continue;
      }
      switch (n->kind) {
      case BS_U_NEGATE:
        break;
      case BS_U_PARENS:
        bs_put_byte(w, (uint8_t)')');
        break;
      case BS_U_LENGTH:
        BS_PUT_LIT(w, ".length()");
        break;
      case BS_U_TYPEOF:
        BS_PUT_LIT(w, ".type()");
        break;
      case BS_U_FFI:
        if (!n->has_ffi) {
          return BS_ERR_MALFORMED;
        }
        bs_put_extern(w, &tab->symbols, n->ffi, &ok);
        bs_put_byte(w, (uint8_t)')');
        break;
      default:
        return BS_ERR_MALFORMED;
      }
      sp--;
      continue;
    }

    if (n->tag == BS_E_CLOSURE) {
      if (st == 0U) {
        /* Parameters, when there are any. A zero-parameter closure is how the
         * short-circuiting operators carry their right-hand side, and it is
         * invisible in the source: `a && b`, not `a && (() -> b)`. */
        bs_cursor c = bs_cursor_make(n->payload);
        bs_pb_field f;
        int emitted = 0;
        while (!bs_cursor_done(&c)) {
          if (!bs_pb_next(&c, &f)) {
            return BS_ERR_MALFORMED;
          }
          if (f.number != BS_F_CLOSURE_PARAMS || f.wire != BS_PB_VARINT) {
            continue;
          }
          if (emitted++ > 0) {
            BS_PUT_LIT(w, ", ");
          }
          bs_put_byte(w, (uint8_t)'$');
          bs_put_symbol(w, &tab->symbols, f.varint, 0, &ok);
        }
        if (emitted > 0) {
          BS_PUT_LIT(w, " -> ");
        }
        stack[sp - 1U] = (index << 2U) | 1U;
        if (sp >= cap) {
          return BS_ERR_LIMIT;
        }
        stack[sp++] = n->a << 2U;
        continue;
      }
      sp--;
      continue;
    }

    /* Binary. */
    if (n->kind >= (uint32_t)BS_BINOP_COUNT) {
      return BS_ERR_MALFORMED;
    }
    if (st == 0U) {
      stack[sp - 1U] = (index << 2U) | 1U;
      if (sp >= cap) {
        return BS_ERR_LIMIT;
      }
      stack[sp++] = n->a << 2U;
      continue;
    }
    if (st == 1U) {
      const bs_binop *op = &BS_BINOPS[n->kind];
      if (n->kind == BS_B_FFI) {
        if (!n->has_ffi) {
          return BS_ERR_MALFORMED;
        }
        bs_put_extern(w, &tab->symbols, n->ffi, &ok);
      } else if (op->style == BS_OP_INFIX) {
        bs_put_byte(w, (uint8_t)' ');
        bs_put_span(w, bs_span_make(op->text, op->len));
        bs_put_byte(w, (uint8_t)' ');
      } else {
        bs_put_byte(w, (uint8_t)'.');
        bs_put_span(w, bs_span_make(op->text, op->len));
        bs_put_byte(w, (uint8_t)'(');
      }
      stack[sp - 1U] = (index << 2U) | 2U;
      if (sp >= cap) {
        return BS_ERR_LIMIT;
      }
      stack[sp++] = n->b << 2U;
      continue;
    }

    if (n->kind == BS_B_FFI || BS_BINOPS[n->kind].style == BS_OP_METHOD) {
      bs_put_byte(w, (uint8_t)')');
    }
    sp--;
  }

  if (!ok) {
    return BS_ERR_MALFORMED;
  }
  return bs_writer_overflow(w) ? BS_ERR_NOMEM : BS_OK;
}

/* Render one encoded Expression as Datalog source. */
BS_API bs_status bs_expr_print(bs_writer *w, bs_arena *a, const bs_tables *tab,
                               bs_span expr) {
  bs_enode *nodes = NULL;
  uint32_t *stack = NULL;
  uint32_t root = 0;
  size_t count = 0;
  bs_status st;

  if (w == NULL || a == NULL || tab == NULL) {
    return BS_ERR_ARGUMENT;
  }
  st = bs_expr_build(a, expr, &nodes, &stack, &root, &count);
  if (st != BS_OK) {
    return st;
  }
  return bs_expr_emit(w, tab, nodes, count, root, stack, (expr.n / 2U) + 1U);
}

/* ===========================================================================
 * 95_datalog.inc
 * ======================================================================== */

/* ---------------------------------------------------------------------------
 * Rules, checks, and whole blocks
 *
 * This is where the pieces meet: a rule is a head, a body of predicates, a
 * list of expressions and the scopes it trusts, and a check is one or more
 * rules with a kind. The block is those in a fixed order -- facts, then rules,
 * then checks -- which is the order the reference implementation prints and
 * therefore the order the conformance suite expects.
 * ------------------------------------------------------------------------ */

#define BS_F_RULE_HEAD 1U
#define BS_F_RULE_BODY 2U
#define BS_F_RULE_EXPRESSIONS 3U
#define BS_F_RULE_SCOPE 4U

#define BS_F_CHECK_QUERIES 1U
#define BS_F_CHECK_KIND 2U

#define BS_CHECK_ONE 0U
#define BS_CHECK_ALL 1U
#define BS_CHECK_REJECT 2U

/* Render a rule's body: its predicates, then its expressions, comma
 * separated, then the scopes it trusts.
 *
 * A check prints only this part; a rule prints its head and an arrow first.
 * They are the same message, and which half is shown is the only difference
 * between the two forms. */
static bs_status bs_rule_body_print(bs_writer *w, bs_arena *a,
                                    const bs_tables *tab, bs_span rule) {
  bs_cursor c;
  bs_pb_field f;
  int emitted = 0;
  int scopes = 0;
  bs_status st;

  c = bs_cursor_make(rule);
  while (!bs_cursor_done(&c)) {
    if (!bs_pb_next(&c, &f)) {
      return BS_ERR_MALFORMED;
    }
    if (f.number != BS_F_RULE_BODY || f.wire != BS_PB_BYTES) {
      continue;
    }
    if (emitted++ > 0) {
      BS_PUT_LIT(w, ", ");
    }
    st = bs_predicate_print(w, tab, f.bytes);
    if (st != BS_OK) {
      return st;
    }
  }

  c = bs_cursor_make(rule);
  while (!bs_cursor_done(&c)) {
    if (!bs_pb_next(&c, &f)) {
      return BS_ERR_MALFORMED;
    }
    if (f.number != BS_F_RULE_EXPRESSIONS || f.wire != BS_PB_BYTES) {
      continue;
    }
    if (emitted++ > 0) {
      BS_PUT_LIT(w, ", ");
    }
    st = bs_expr_print(w, a, tab, f.bytes);
    if (st != BS_OK) {
      return st;
    }
  }

  c = bs_cursor_make(rule);
  while (!bs_cursor_done(&c)) {
    if (!bs_pb_next(&c, &f)) {
      return BS_ERR_MALFORMED;
    }
    if (f.number != BS_F_RULE_SCOPE || f.wire != BS_PB_BYTES) {
      continue;
    }
    if (scopes++ == 0) {
      BS_PUT_LIT(w, " trusting ");
    } else {
      BS_PUT_LIT(w, ", ");
    }
    st = bs_scope_print(w, tab, f.bytes);
    if (st != BS_OK) {
      return st;
    }
  }
  return BS_OK;
}

/* `head <- body`. */
BS_API bs_status bs_rule_print(bs_writer *w, bs_arena *a, const bs_tables *tab,
                               bs_span rule) {
  bs_cursor c = bs_cursor_make(rule);
  bs_pb_field f;
  bs_span head = bs_span_make(NULL, 0);
  int found = 0;
  bs_status st;

  if (w == NULL || a == NULL || tab == NULL) {
    return BS_ERR_ARGUMENT;
  }

  while (!bs_cursor_done(&c)) {
    if (!bs_pb_next(&c, &f)) {
      return BS_ERR_MALFORMED;
    }
    if (f.number == BS_F_RULE_HEAD && f.wire == BS_PB_BYTES) {
      if (found++) {
        return BS_ERR_MALFORMED;
      }
      head = f.bytes;
    }
  }
  if (found != 1) {
    return BS_ERR_MALFORMED;
  }

  st = bs_predicate_print(w, tab, head);
  if (st != BS_OK) {
    return st;
  }
  BS_PUT_LIT(w, " <- ");
  return bs_rule_body_print(w, a, tab, rule);
}

/* `check if q`, `check all q`, or `reject if q`, with several queries joined
 * by ` or `. The head of each query is a synthetic predicate the writer never
 * printed, so it is not printed here either. */
BS_API bs_status bs_check_print(bs_writer *w, bs_arena *a, const bs_tables *tab,
                                bs_span check) {
  bs_cursor c;
  bs_pb_field f;
  uint64_t kind = BS_CHECK_ONE;
  int emitted = 0;
  bs_status st;

  if (w == NULL || a == NULL || tab == NULL) {
    return BS_ERR_ARGUMENT;
  }

  c = bs_cursor_make(check);
  while (!bs_cursor_done(&c)) {
    if (!bs_pb_next(&c, &f)) {
      return BS_ERR_MALFORMED;
    }
    if (f.number == BS_F_CHECK_KIND && f.wire == BS_PB_VARINT) {
      kind = f.varint;
    }
  }

  switch (kind) {
  case BS_CHECK_ONE:
    BS_PUT_LIT(w, "check if ");
    break;
  case BS_CHECK_ALL:
    BS_PUT_LIT(w, "check all ");
    break;
  case BS_CHECK_REJECT:
    BS_PUT_LIT(w, "reject if ");
    break;
  default:
    return BS_ERR_MALFORMED;
  }

  c = bs_cursor_make(check);
  while (!bs_cursor_done(&c)) {
    if (!bs_pb_next(&c, &f)) {
      return BS_ERR_MALFORMED;
    }
    if (f.number != BS_F_CHECK_QUERIES || f.wire != BS_PB_BYTES) {
      continue;
    }
    if (emitted++ > 0) {
      BS_PUT_LIT(w, " or ");
    }
    st = bs_rule_body_print(w, a, tab, f.bytes);
    if (st != BS_OK) {
      return st;
    }
  }
  if (emitted == 0) {
    return BS_ERR_MALFORMED; /* a check with no query cannot mean anything */
  }
  return BS_OK;
}

/* Render a whole block as Datalog source: facts, then rules, then checks,
 * each terminated by a semicolon and a newline. That order is not arbitrary --
 * it is what the reference implementation emits, and the conformance suite
 * compares text. */
BS_API bs_status bs_block_print(bs_writer *w, bs_arena *a, const bs_tables *tab,
                                bs_span block) {
  static const uint32_t sections[3] = {
      BS_F_BLOCK_FACTS,
      BS_F_BLOCK_RULES,
      BS_F_BLOCK_CHECKS,
  };
  size_t i;

  if (w == NULL || a == NULL || tab == NULL) {
    return BS_ERR_ARGUMENT;
  }

  /* A block-level scope would apply to everything in the block. No sample in
   * the specification's suite carries one, so its printed form cannot be
   * confirmed against anything -- and inventing a syntax that later turns out
   * to differ would be worse than refusing. Refused explicitly rather than
   * ignored: a block whose trust boundary this build cannot render must not
   * be reported as one it rendered. */
  {
    bs_cursor c = bs_cursor_make(block);
    bs_pb_field f;
    while (!bs_cursor_done(&c)) {
      if (!bs_pb_next(&c, &f)) {
        return BS_ERR_MALFORMED;
      }
      if (f.number == BS_F_BLOCK_SCOPE && f.wire == BS_PB_BYTES) {
        return BS_ERR_UNSUPPORTED;
      }
    }
  }

  for (i = 0; i < 3U; i++) {
    bs_cursor c = bs_cursor_make(block);
    bs_pb_field f;
    while (!bs_cursor_done(&c)) {
      bs_status st;
      if (!bs_pb_next(&c, &f)) {
        return BS_ERR_MALFORMED;
      }
      if (f.number != sections[i] || f.wire != BS_PB_BYTES) {
        continue;
      }
      if (sections[i] == BS_F_BLOCK_FACTS) {
        st = bs_fact_print(w, tab, f.bytes);
      } else if (sections[i] == BS_F_BLOCK_RULES) {
        st = bs_rule_print(w, a, tab, f.bytes);
      } else {
        st = bs_check_print(w, a, tab, f.bytes);
      }
      if (st != BS_OK) {
        return st;
      }
      BS_PUT_LIT(w, ";\n");
    }
  }

  return bs_writer_overflow(w) ? BS_ERR_NOMEM : BS_OK;
}

/* ===========================================================================
 * 99_epilogue.inc
 * ======================================================================== */

#endif /* BISCUITS_IMPLEMENTATION */

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* BISCUITS_H_INCLUDED */
