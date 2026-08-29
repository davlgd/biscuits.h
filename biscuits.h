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
 * travelled. Each block costs a signature verification.
 *
 * Sixty-three and not sixty-four: origins are a 64-bit set and the top bit is
 * the authorizer's, so blocks own bits 0..62 and nothing else may. A block
 * holding bit 63 would be indistinguishable from the authorizer, and since
 * every authorizer rule trusts the authorizer by default, the last block of a
 * full-length token would have been trusted as though the application had
 * stated its facts itself. */
#ifndef BS_MAX_BLOCKS
#define BS_MAX_BLOCKS 63
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
  BS_ERR_ARGUMENT,  /* caller passed a null or nonsensical argument */
  BS_ERR_NOMEM,     /* the caller-provided arena is exhausted */
  BS_ERR_MALFORMED, /* input violates the wire format, truncation included */
  BS_ERR_DEPTH,     /* nesting deeper than BS_MAX_DEPTH */
  BS_ERR_OVERFLOW,  /* an arithmetic operation overflowed */
  BS_ERR_LIMIT,     /* a configured evaluation limit was reached */
  BS_ERR_TYPE,      /* an operation applied to an operand of the wrong type */
  BS_ERR_SHADOWED, /* a closure parameter shadows a variable already in scope */
  BS_ERR_UNSUPPORTED, /* well-formed, but this build cannot handle it */
  BS_ERR_SIGNATURE,   /* a signature did not verify */
  BS_ERR_UNBOUND,     /* a rule's head names a variable its body never binds */
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

/* Decode a token from its text form -- URL-safe base64, with an optional
 * `biscuit:` prefix -- and parse it. The decoded bytes come from the arena, so
 * the arena rather than the text is what must outlive the token. */
BS_API BS_MUST_USE bs_status bs_token_parse_text(bs_arena *a, bs_span text,
                                                 bs_token *out);

/* Decode URL-safe base64 into arena memory.
 *
 * Strict: padding must be canonical, the bits a partial final group leaves
 * over must be zero, and whitespace is not skipped. A lenient decoder accepts
 * several strings for one token, which turns "have I seen this token before?"
 * into a question with more than one answer -- and any cache, rate limiter or
 * deny-list keyed on the string form is then wrong in a way nobody notices
 * until it matters. */
BS_API BS_MUST_USE bs_status bs_base64url_decode(bs_arena *a, bs_span text,
                                                 bs_span *out);

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

/* ---------------------------------------------------------------------------
 * The world
 *
 * Everything so far has read the wire format in place: decode a span, print
 * it, never build anything. That works for printing and it does not work for
 * evaluation, because Datalog generates facts that were never on any wire,
 * and because it has to compare facts that arrived from different blocks.
 *
 * So this is the in-memory form, and it is deliberately flat. Terms, ops,
 * predicates, facts and rules each live in one arena-allocated pool, and
 * everything refers to everything else by index rather than by pointer. Three
 * reasons, in order of how much they matter:
 *
 *   - Comparing two facts is comparing two runs of a pool, which is what the
 *     fixpoint loop does more than anything else.
 *   - An index is stable when a pool is refilled; a pointer is not.
 *   - There is nothing to free, which is the whole arena story, and nothing
 *     that can dangle.
 *
 * The cost is that reading this code means holding "index into which pool?"
 * in your head. The pools are named for what they hold, and every index field
 * says which pool it indexes.
 * ------------------------------------------------------------------------ */

/* Term kinds, matching the wire format's oneof but numbered independently:
 * the wire numbers are field tags and would tie this representation to the
 * encoding it is meant to be free of. */
#define BS_T_VARIABLE 0U
#define BS_T_INTEGER 1U
#define BS_T_STRING 2U
#define BS_T_DATE 3U
#define BS_T_BYTES 4U
#define BS_T_BOOL 5U
#define BS_T_SET 6U
#define BS_T_NULL 7U
#define BS_T_ARRAY 8U
#define BS_T_MAP 9U

/* Internal only: a closure sitting on the evaluation stack, waiting for the
 * operator that will decide whether to run it. Never encoded, never decoded,
 * and numbered past every kind the wire format can express. */
#define BS_T_CLOSURE 10U

typedef struct bs_term {
  uint8_t kind;
  union {
    uint64_t sym; /* BS_T_VARIABLE, BS_T_STRING: a symbol table index */
    int64_t integer;
    uint64_t date; /* seconds since the epoch, unsigned per the specification */
    bs_span bytes; /* borrowed from the token, never copied */
    int boolean;
    /* SET, ARRAY: a run in the term pool. MAP: a run of key/value pairs,
     * stored adjacently, so count is always even. */
    struct {
      uint32_t at;
      uint32_t count;
    } list;
  } as;
} bs_term;

/* `name(t0, t1, ...)`, with the terms in a run of the term pool. */
typedef struct bs_predicate {
  uint64_t name; /* symbol table index */
  uint32_t at;   /* into the term pool */
  uint32_t count;
} bs_predicate;

/* Which blocks a fact came from.
 *
 * A fact stated in block n has origin {n}. A fact a rule produced has the
 * union of the rule's block and the origins of every fact it matched. That
 * union is what `trusting` filters on, and getting it wrong does not fail --
 * it silently authorizes things.
 *
 * A bitset, because a union is then one OR. Bits 0..62 are blocks and bit
 * 63 is the authorizer, which is why BS_MAX_BLOCKS is 63 rather than 64. */
typedef uint64_t bs_origin;

#define BS_ORIGIN_NONE ((bs_origin)0)
#define BS_ORIGIN_ONE(block) ((bs_origin)1 << (block))

/* The authorizer's own facts and rules are not in any block. They are given
 * the highest bit, which keeps `origin` a single word and keeps "authorizer"
 * expressible in a trust mask like any other source. No block may hold this
 * bit: see BS_MAX_BLOCKS. */
#define BS_ORIGIN_AUTHORIZER BS_ORIGIN_ONE(63U)

typedef struct bs_fact {
  bs_predicate pred;
  bs_origin origin;
} bs_fact;

/* An expression, as a run of the op pool. Ops are postfix, exactly as the
 * wire format carries them -- and exactly what the text parser will produce,
 * so the evaluator has one input shape rather than two. */
typedef struct bs_expr {
  uint32_t at;
  uint32_t count;
} bs_expr;

#define BS_OP_VALUE 0U
#define BS_OP_UNARY 1U
#define BS_OP_BINARY 2U
#define BS_OP_CLOSURE 3U

typedef struct bs_op {
  uint8_t tag;   /* BS_OP_* */
  uint32_t kind; /* the unary or binary opcode */
  union {
    uint32_t term; /* BS_OP_VALUE: into the term pool */
    uint64_t ffi;  /* BS_OP_UNARY, BS_OP_BINARY: an external call's name */
    struct {
      uint32_t at;    /* parameters, into the symbol run pool */
      uint32_t count; /* parameter count */
      bs_expr body;   /* the closure's own ops, once placed */
      bs_span src;    /* the encoded ops, while the body is still pending */
    } closure;
  } as;
} bs_op;

typedef struct bs_rule {
  bs_predicate head;
  /* A check's queries live in this pool too, and must not take part in the
   * fixpoint: a query is asked once, when the check is evaluated, and does
   * not add its head to the world. */
  uint8_t is_query;
  uint32_t body_at; /* into the predicate pool */
  uint32_t body_count;
  uint32_t expr_at; /* into the expression pool */
  uint32_t expr_count;
  bs_origin trust; /* which blocks this rule's premises may come from */
  uint32_t block;  /* the block that stated it */
} bs_rule;

#define BS_CHECK_KIND_ONE 0U
#define BS_CHECK_KIND_ALL 1U
#define BS_CHECK_KIND_REJECT 2U

typedef struct bs_check {
  uint32_t query_at; /* into the rule pool: one rule per query */
  uint32_t query_count;
  uint8_t kind;
  uint32_t block; /* the block that stated it, for reporting */
  /* How to render this check when it fails. A block's check is printed from
   * its own encoding, by the printer the `blocks` conformance tier already
   * exercises; the authorizer's is echoed back from the source the
   * application wrote, because that is the text its author will recognise. */
  bs_span src;
  uint8_t from_text;
} bs_check;

#define BS_POLICY_ALLOW 0U
#define BS_POLICY_DENY 1U

typedef struct bs_policy {
  uint32_t query_at;
  uint32_t query_count;
  uint8_t kind;
} bs_policy;

/* The pools.
 *
 * Sized once from the caller's arena and never grown: the counting pass that
 * fills each capacity runs before anything is allocated, which is what lets
 * the arena stay a bump allocator with no growth strategy anywhere.
 *
 * Every `*_count` is how much is used; every `*_cap` is how much was
 * reserved. Running out is BS_ERR_NOMEM, and it is the caller's arena that
 * ran out, not the library's. */
typedef struct bs_world {
  bs_term *terms;
  size_t term_count;
  size_t term_cap;

  bs_op *ops;
  size_t op_count;
  size_t op_cap;

  bs_expr *exprs;
  size_t expr_count;
  size_t expr_cap;

  bs_predicate *preds; /* rule bodies */
  size_t pred_count;
  size_t pred_cap;

  uint64_t *syms; /* closure parameter runs */
  size_t sym_count;
  size_t sym_cap;

  bs_fact *facts;
  size_t fact_count;
  size_t fact_cap;

  bs_rule *rules;
  size_t rule_count;
  size_t rule_cap;

  bs_check *checks;
  size_t check_count;
  size_t check_cap;

  bs_policy *policies;
  size_t policy_count;
  size_t policy_cap;

  const bs_tables *tables; /* symbols and public keys, borrowed */
  size_t block_count;
} bs_world;

/* ---------------------------------------------------------------------------
 * Interning table
 *
 * Reading a token needs one symbol table; evaluating one needs a different
 * table. A third-party block numbers its symbols from its own array, because
 * whoever signed it never saw the rest of the token -- fine for printing,
 * wrong for evaluation, where two facts spelled the same way must be the same
 * fact whichever block stated them.
 *
 * So the engine interns: seeded with the token-wide symbols, so ordinary
 * blocks keep their indices unchanged, then extended with whatever the
 * third-party blocks and the authorizer introduce. Entries are borrowed
 * spans, never copies. */
typedef struct bs_symtab {
  bs_span *entries;
  size_t count;
  size_t cap;
} bs_symtab;

/* Reserve room for the seed plus `extra` new symbols. */
BS_API BS_MUST_USE bs_status bs_symtab_init(bs_symtab *t, bs_arena *a,
                                            const bs_symbols *seed,
                                            size_t extra);

/* Resolve an index to its text. Returns 0 for an index this table cannot
 * name. */
BS_API BS_MUST_USE int bs_symtab_get(const bs_symtab *t, uint64_t index,
                                     bs_span *out);

/* Find `text`, appending it if absent, and report its index. */
BS_API BS_MUST_USE bs_status bs_symtab_intern(bs_symtab *t, bs_span text,
                                              uint64_t *out);

/* Translate an index from a block's own numbering into this table's. Safe to
 * call for an ordinary block too, where it returns the index unchanged. */
BS_API BS_MUST_USE bs_status bs_symtab_translate(bs_symtab *t,
                                                 const bs_symbols *from,
                                                 uint64_t index, uint64_t *out);

/* Reserve every pool in one go.
 *
 * The capacities are the caller's to choose because only the caller knows
 * what it is willing to spend. A gateway with a 64 KB scratch buffer and a
 * batch job with a megabyte want different answers, and a library that picks
 * for them is wrong for one of them. */
typedef struct bs_limits {
  size_t max_terms;
  size_t max_ops;
  size_t max_exprs;
  size_t max_preds;
  size_t max_syms;
  size_t max_facts;
  size_t max_rules;
  size_t max_checks;
  size_t max_policies;
  size_t
      max_iterations; /* fixpoint rounds, per the specification's run limits */
} bs_limits;

/* Defaults sized for the tokens the specification's own suite contains, with
 * room to spare. A starting point, not a recommendation: measure with
 * bs_arena_peak() against your own traffic. */
BS_API BS_MUST_USE bs_limits bs_limits_default(void);

/* Reserve the pools from the arena. Everything the evaluator will need is
 * allocated here and never grown, so an arena that survives this call is an
 * arena that cannot run out later. */
BS_API BS_MUST_USE bs_status bs_world_init(bs_world *w, bs_arena *a,
                                           const bs_tables *tab,
                                           size_t block_count,
                                           const bs_limits *lim);

/* Load every fact a block states into the world, tagged with that block as
 * its origin.
 *
 * `from` is the symbol table the block's indices are numbered against: its
 * own for a third-party block, the token-wide one otherwise. Supplying the
 * wrong one does not fail, it renames every predicate in the block, so the
 * caller that knows the difference is the one that passes it. */
BS_API BS_MUST_USE bs_status bs_world_load_facts(bs_world *w, bs_symtab *syms,
                                                 const bs_symbols *from,
                                                 bs_span block,
                                                 size_t block_index);

/* Load every rule and check a block states.
 *
 * Scope annotations are resolved to block-id sets here rather than during
 * evaluation, so the fixpoint loop compares two bitmasks and nothing else.
 * The token and its tables are needed because a scope may name a public key,
 * which means "every block carrying an external signature by that key". */
BS_API BS_MUST_USE bs_status bs_world_load_logic(
    bs_world *w, bs_symtab *syms, const bs_symbols *from, const bs_token *t,
    const bs_tables *tab, bs_span block, size_t block_index);

/* ---------------------------------------------------------------------------
 * Expression evaluation
 * ------------------------------------------------------------------------ */

/* A variable's value for the duration of one evaluation, taken from the
 * predicates a rule matched. */
typedef struct bs_binding {
  uint64_t sym;
  bs_term value;
} bs_binding;

/* Evaluate one expression to a boolean.
 *
 * Failure modes are distinct on purpose: an overflow, a type error and a
 * malformed opcode stream are different outcomes, and the specification's own
 * conformance suite tells them apart. */
BS_API BS_MUST_USE bs_status bs_expr_evaluate(bs_world *w, bs_symtab *syms,
                                              bs_arena *a, bs_expr expr,
                                              const bs_binding *bindings,
                                              size_t binding_count, int *out);

/* ---------------------------------------------------------------------------
 * Evaluation
 * ------------------------------------------------------------------------ */

/* Run every rule to a fixpoint, appending what they derive.
 *
 * Bounded by iterations rather than by time, as the specification's own run
 * limits are: a token cannot buy itself an unbounded evaluation, and reaching
 * the bound is BS_ERR_LIMIT rather than a hang. Pass 0 for the default. */
/* Parse Datalog source into the world.
 *
 * `block` is which block the statements belong to, or BS_MAX_BLOCKS for the
 * authorizer, which sits outside the chain: it trusts the authority and
 * itself, and its facts carry BS_ORIGIN_AUTHORIZER.
 *
 * `token` and `tables` are needed only to resolve a `trusting ed25519/...`
 * annotation to the blocks that key signed; both may be NULL when the source
 * names no public key. */
BS_API BS_MUST_USE bs_status bs_world_parse(bs_world *w, bs_symtab *syms,
                                            bs_arena *a, bs_span source,
                                            size_t block, const bs_token *token,
                                            const bs_tables *tab);

/* --------------------------------------------------------------------------
 * Authorization
 * ----------------------------------------------------------------------- */

#define BS_VERDICT_ALLOW 0U
#define BS_VERDICT_DENY 1U
#define BS_VERDICT_NO_POLICY 2U

/* A check that did not hold, and enough to say which one. */
typedef struct bs_failed_check {
  uint32_t block; /* the block that stated it, or BS_MAX_BLOCKS: authorizer */
  uint32_t index; /* which check within that block */
  bs_span src;
  uint8_t from_text; /* whether `src` is source text or an encoded check */
} bs_failed_check;

typedef struct bs_verdict {
  uint8_t kind;    /* BS_VERDICT_* */
  uint32_t policy; /* which policy decided, when one did */
  uint8_t has_policy;
  size_t failed_count;
  const bs_failed_check *failed;
} bs_verdict;

/* Run the world to a fixpoint, evaluate every check, then every policy.
 *
 * A token is authorized when a policy allows it *and* no check failed. Those
 * are separate conditions and both are reported: a caller that only looks at
 * the policy will authorize a token whose checks all failed.
 *
 * The verdict's `failed` array is allocated from `a` and lives as long as the
 * arena does. */
BS_API BS_MUST_USE bs_status bs_authorize(bs_world *w, bs_symtab *syms,
                                          bs_arena *a, size_t max_iterations,
                                          bs_verdict *out);

/* Render a failed check as the text its author would recognise. */
BS_API BS_MUST_USE bs_status bs_failed_check_print(bs_writer *wr, bs_arena *a,
                                                   const bs_tables *tab,
                                                   const bs_failed_check *f);

BS_API BS_MUST_USE bs_status bs_world_run(bs_world *w, bs_symtab *syms,
                                          bs_arena *a, size_t max_iterations);

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
      "type error",
      "shadowed variable",
      "unsupported by this build",
      "signature verification failed",
      "rule head variable not bound by its body",
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

/* A scoped rewind, for scratch that is provably dead.
 *
 * This is not free() and it does not weaken invariant 1: nothing is ever
 * released individually, and no object outlives the arena. What it allows is
 * a function to give back memory it allocated and finished with, before
 * returning -- a stack discipline, not a heap one.
 *
 * The rule for using it is narrow, and there is exactly one caller: nothing
 * allocated after the mark may still be reachable when the rewind happens.
 * The expression printer qualifies because its node array and traversal stack
 * are dead the moment the rendering is written, and nothing it publishes
 * points into them.
 *
 * Without this, a block with many expressions accumulates scratch it will
 * never touch again, and a caller sizing an arena from one expression finds
 * it too small for ten. */
static size_t bs_arena_mark(const bs_arena *a) {
  return (a == NULL) ? 0U : a->off;
}

static void bs_arena_rewind(bs_arena *a, size_t mark) {
  if (a == NULL || mark > a->off) {
    return;
  }
  a->off = mark;
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
 * 55_base64.inc
 * ======================================================================== */

/* ---------------------------------------------------------------------------
 * base64url
 *
 * How a token travels. The specification says a Biscuit is serialized to a
 * URL-safe base64 string, optionally prefixed with `biscuit:` when the
 * context does not already say what it is.
 *
 * The decoder here is strict, and that is a deliberate choice with a cost.
 * Padding must be canonical, the bits a final partial group leaves over must
 * be zero, and whitespace is not skipped. A lenient decoder would accept
 * several distinct strings for the same token, which turns "have I seen this
 * token before?" into a question with more than one answer -- and any cache,
 * rate limiter or deny-list keyed on the string form would be wrong in a way
 * nobody notices until it matters.
 *
 * The cost is that a token some other tool encoded sloppily is rejected here.
 * That is the trade this library makes everywhere else too.
 * ------------------------------------------------------------------------ */

#define BS_TOKEN_PREFIX "biscuit:"

/* Reverse alphabet: value for a valid character, 0xFF for everything else.
 * A table rather than a chain of range comparisons, so decoding one character
 * takes the same work regardless of which character it is -- token bytes are
 * public, but a uniform table is also simply smaller and easier to check. */
static const uint8_t BS_B64URL[256] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 62U,  0xFF, 0xFF,
    52U,  53U,  54U,  55U,  56U,  57U,  58U,  59U,  60U,  61U,  0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0U,   1U,   2U,   3U,   4U,   5U,   6U,
    7U,   8U,   9U,   10U,  11U,  12U,  13U,  14U,  15U,  16U,  17U,  18U,
    19U,  20U,  21U,  22U,  23U,  24U,  25U,  0xFF, 0xFF, 0xFF, 0xFF, 63U,
    0xFF, 26U,  27U,  28U,  29U,  30U,  31U,  32U,  33U,  34U,  35U,  36U,
    37U,  38U,  39U,  40U,  41U,  42U,  43U,  44U,  45U,  46U,  47U,  48U,
    49U,  50U,  51U,  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
};

/* Length of the optional `biscuit:` prefix, or zero.
 *
 * Returns an offset rather than a re-based span deliberately. Slicing would
 * hand back a pointer into the middle of the caller's buffer, and every index
 * afterwards would be relative to a base the reader has to track separately.
 * One origin, one set of indices. */
static size_t bs_prefix_len(bs_span text) {
  bs_span head;
  bs_span want = bs_span_make("" BS_TOKEN_PREFIX, sizeof BS_TOKEN_PREFIX - 1U);

  if (!bs_span_slice(text, 0U, want.n, &head) || !bs_span_eq(head, want)) {
    return 0U;
  }
  return want.n;
}

BS_API bs_status bs_base64url_decode(bs_arena *a, bs_span text, bs_span *out) {
  size_t start;
  size_t stop; /* one past the last character of the encoded body */
  size_t len;
  size_t groups;
  size_t tail;
  size_t capacity;
  uint8_t *buf;
  size_t written = 0;

  if (a == NULL || out == NULL) {
    return BS_ERR_ARGUMENT;
  }

  /* Everything below indexes `text` directly, between `start` and `stop`.
   * There is one buffer and one origin throughout. */
  start = bs_prefix_len(text);
  stop = text.n;

  /* Padding, which may only be the last one or two characters. */
  tail = 0;
  while (tail < 2U && stop > start) {
    uint8_t c = 0;
    if (!bs_span_at(text, stop - 1U, &c) || c != (uint8_t)'=') {
      break;
    }
    stop--;
    tail++;
  }
  BS_ASSERT(stop >= start);
  len = stop - start;

  /* With padding present the encoding is a whole number of four-character
   * groups; without it, a final group of two or three characters is allowed.
   * A final group of one is not: it carries no complete byte. */
  if (tail != 0U && ((len + tail) % 4U) != 0U) {
    return BS_ERR_MALFORMED;
  }
  if ((len % 4U) == 1U) {
    return BS_ERR_MALFORMED;
  }
  if (tail == 1U && (len % 4U) != 3U) {
    return BS_ERR_MALFORMED;
  }
  if (tail == 2U && (len % 4U) != 2U) {
    return BS_ERR_MALFORMED;
  }

  groups = len / 4U;
  capacity = groups * 3U;
  switch (len % 4U) {
  case 2U:
    capacity += 1U;
    break;
  case 3U:
    capacity += 2U;
    break;
  default:
    break;
  }

  buf = (uint8_t *)bs_arena_alloc(a, (capacity == 0U) ? 1U : capacity, 1U);
  if (buf == NULL) {
    return BS_ERR_NOMEM;
  }

  {
    uint32_t acc = 0;
    unsigned int bits = 0;
    size_t i;
    for (i = start; i < stop; i++) {
      uint8_t c = 0;
      uint8_t v;
      if (!bs_span_at(text, i, &c)) {
        return BS_ERR_MALFORMED;
      }
      v = BS_B64URL[c];
      if (v == 0xFFU) {
        /* Whitespace included: a decoder that skips it accepts several
         * strings for one token. */
        return BS_ERR_MALFORMED;
      }
      acc = (acc << 6U) | v;
      bits += 6U;
      if (bits >= 8U) {
        bits -= 8U;
        if (written >= capacity) {
          return BS_ERR_MALFORMED;
        }
        buf[written++] = (uint8_t)((acc >> bits) & 0xFFU);
      }
    }
    /* The bits a partial final group leaves over must be zero. Otherwise two
     * different strings decode to the same bytes, and the token has more than
     * one canonical form. */
    if (bits != 0U && (acc & ((1U << bits) - 1U)) != 0U) {
      return BS_ERR_MALFORMED;
    }
  }

  BS_ASSERT(written == capacity);
  *out = bs_span_make(buf, written);
  return BS_OK;
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

/* Decode a token from its text form and parse it.
 *
 * This is how a Biscuit actually arrives: URL-safe base64, sometimes with a
 * `biscuit:` prefix when the surrounding context does not already say what it
 * is. The decoded bytes are allocated from the arena, so the returned token's
 * spans point into arena memory rather than into the caller's string -- which
 * means the arena, not the text, is what must outlive the token. */
BS_API bs_status bs_token_parse_text(bs_arena *a, bs_span text, bs_token *out) {
  bs_span raw;
  bs_status st;

  if (a == NULL || out == NULL) {
    return BS_ERR_ARGUMENT;
  }
  st = bs_base64url_decode(a, text, &raw);
  if (st != BS_OK) {
    return st;
  }
  return bs_token_parse(a, raw, out);
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
  size_t mark;
  bs_status st;

  if (w == NULL || a == NULL || tab == NULL) {
    return BS_ERR_ARGUMENT;
  }

  /* The node array and the traversal stack are scratch: they are dead the
   * moment the rendering is written, and nothing published outward points
   * into them -- bs_enode.payload spans point at the token's own bytes, never
   * at the arena. So the arena is rewound on the way out.
   *
   * The bound is generous by design (half the expression's length, where a
   * typical expression needs a tenth of that), which is fine for one
   * expression and would not be for the twenty in a block. */
  mark = bs_arena_mark(a);
  st = bs_expr_build(a, expr, &nodes, &stack, &root, &count);
  if (st == BS_OK) {
    st = bs_expr_emit(w, tab, nodes, count, root, stack, (expr.n / 2U) + 1U);
  }
  bs_arena_rewind(a, mark);
  return st;
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
 * 100_world.inc
 * ======================================================================== */

/* ---------------------------------------------------------------------------
 * The world -- pool allocation
 *
 * The types live in the API section; what is here is the one function that
 * reserves them. See the commentary there for why everything is an index into
 * a flat pool rather than a pointer.
 * ------------------------------------------------------------------------ */

BS_API bs_limits bs_limits_default(void) {
  bs_limits l;
  l.max_terms = 4096U;
  l.max_ops = 4096U;
  l.max_exprs = 512U;
  l.max_preds = 1024U;
  l.max_syms = 512U;
  l.max_facts = 1024U;
  l.max_rules = 256U;
  l.max_checks = 256U;
  l.max_policies = 64U;
  l.max_iterations = 100U;
  return l;
}

BS_API bs_status bs_world_init(bs_world *w, bs_arena *a, const bs_tables *tab,
                               size_t block_count, const bs_limits *lim) {
  bs_limits l;

  if (w == NULL || a == NULL || tab == NULL) {
    return BS_ERR_ARGUMENT;
  }
  if (block_count > (size_t)BS_MAX_BLOCKS) {
    return BS_ERR_LIMIT;
  }
  l = (lim == NULL) ? bs_limits_default() : *lim;

  memset(w, 0, sizeof *w);
  w->tables = tab;
  w->block_count = block_count;

  w->terms =
      (bs_term *)bs_arena_array(a, l.max_terms, sizeof(bs_term), BS_ALIGN_MAX);
  w->ops = (bs_op *)bs_arena_array(a, l.max_ops, sizeof(bs_op), BS_ALIGN_MAX);
  w->exprs =
      (bs_expr *)bs_arena_array(a, l.max_exprs, sizeof(bs_expr), BS_ALIGN_MAX);
  w->preds = (bs_predicate *)bs_arena_array(a, l.max_preds,
                                            sizeof(bs_predicate), BS_ALIGN_MAX);
  w->syms =
      (uint64_t *)bs_arena_array(a, l.max_syms, sizeof(uint64_t), BS_ALIGN_MAX);
  w->facts =
      (bs_fact *)bs_arena_array(a, l.max_facts, sizeof(bs_fact), BS_ALIGN_MAX);
  w->rules =
      (bs_rule *)bs_arena_array(a, l.max_rules, sizeof(bs_rule), BS_ALIGN_MAX);
  w->checks = (bs_check *)bs_arena_array(a, l.max_checks, sizeof(bs_check),
                                         BS_ALIGN_MAX);
  w->policies = (bs_policy *)bs_arena_array(a, l.max_policies,
                                            sizeof(bs_policy), BS_ALIGN_MAX);

  if (w->terms == NULL || w->ops == NULL || w->exprs == NULL ||
      w->preds == NULL || w->syms == NULL || w->facts == NULL ||
      w->rules == NULL || w->checks == NULL || w->policies == NULL) {
    return BS_ERR_NOMEM;
  }

  w->term_cap = l.max_terms;
  w->op_cap = l.max_ops;
  w->expr_cap = l.max_exprs;
  w->pred_cap = l.max_preds;
  w->sym_cap = l.max_syms;
  w->fact_cap = l.max_facts;
  w->rule_cap = l.max_rules;
  w->check_cap = l.max_checks;
  w->policy_cap = l.max_policies;
  return BS_OK;
}

/* Does every variable in the head appear somewhere in the body?
 *
 * The specification calls a rule that fails this invalid, and it is invalid
 * on sight rather than on use: a rule whose body happens to match nothing
 * would otherwise pass silently and become an error only once some later
 * token supplied the missing fact. Checking at load time makes the verdict a
 * property of the rule. */
static bs_status bs_rule_bound(const bs_world *w, const bs_rule *r) {
  uint32_t i;

  for (i = 0; i < r->head.count; i++) {
    bs_term t = w->terms[r->head.at + i];
    uint32_t j;
    int found = 0;

    if (t.kind != (uint8_t)BS_T_VARIABLE) {
      continue;
    }
    for (j = 0; j < r->body_count && !found; j++) {
      const bs_predicate *p = &w->preds[r->body_at + j];
      uint32_t k;
      for (k = 0; k < p->count; k++) {
        bs_term b = w->terms[p->at + k];
        if (b.kind == (uint8_t)BS_T_VARIABLE && b.as.sym == t.as.sym) {
          found = 1;
          break;
        }
      }
    }
    if (!found) {
      return BS_ERR_UNBOUND;
    }
  }
  return BS_OK;
}

/* ===========================================================================
 * 105_symtab.inc
 * ======================================================================== */

/* ---------------------------------------------------------------------------
 * Interning table
 *
 * Reading a token needs one symbol table. Evaluating one needs a different
 * table, and the difference is the whole reason this file exists.
 *
 * A third-party block numbers its symbols from its own array, because whoever
 * signed it never saw the rest of the token. That is fine for printing -- the
 * printer just uses the block's own table -- and it is not fine for
 * evaluation, because the engine compares facts from different blocks against
 * each other. Two facts spelled `group("admin")` must be the same fact
 * whichever block stated them, and they will not be if one block's index 1024
 * means "admin" while another's means "read".
 *
 * So the engine builds one table by interning: seeded with the token-wide
 * symbols so that ordinary blocks keep their existing indices unchanged, then
 * extended with whatever the third-party blocks and the authorizer text
 * introduce. Every symbol index the engine handles is an index into this
 * table, and every index that arrives from a block is translated on the way
 * in.
 *
 * Interning is a linear scan. Tokens carry tens of symbols, not thousands,
 * and a hash table here would be more code, more state and more to get wrong
 * for a saving nobody would measure.
 * ------------------------------------------------------------------------ */

BS_API bs_status bs_symtab_init(bs_symtab *t, bs_arena *a,
                                const bs_symbols *seed, size_t extra) {
  size_t total;

  if (t == NULL || a == NULL) {
    return BS_ERR_ARGUMENT;
  }
  t->entries = NULL;
  t->count = 0;
  t->cap = 0;

  total = (seed == NULL) ? 0U : seed->count;
  if (!bs_size_add(total, extra, &total)) {
    return BS_ERR_OVERFLOW;
  }
  if (total == 0U) {
    return BS_OK;
  }

  t->entries =
      (bs_span *)bs_arena_array(a, total, sizeof(bs_span), BS_ALIGN_MAX);
  if (t->entries == NULL) {
    return BS_ERR_NOMEM;
  }
  t->cap = total;

  /* Seeded in order, so a symbol index that came off the wire in an ordinary
   * block still names the same text after interning. Nothing is renumbered. */
  if (seed != NULL) {
    size_t i;
    for (i = 0; i < seed->count; i++) {
      t->entries[i] = seed->entries[i];
    }
    t->count = seed->count;
  }
  return BS_OK;
}

/* Resolve an index to its text. The well-known half is shared by every
 * implementation; the rest is what this table holds. */
BS_API int bs_symtab_get(const bs_symtab *t, uint64_t index, bs_span *out) {
  bs_symbols view;
  if (t == NULL) {
    return 0;
  }
  view.entries = t->entries;
  view.count = t->count;
  return bs_symbol_get(&view, index, out);
}

/* Find `text`, appending it if absent, and report its index.
 *
 * The well-known symbols are checked first so that a token which spells out
 * "read" gets index 0 rather than a fresh one -- otherwise two facts that
 * should be identical would differ. */
BS_API bs_status bs_symtab_intern(bs_symtab *t, bs_span text, uint64_t *out) {
  size_t i;
  size_t defaults;

  if (t == NULL || out == NULL) {
    return BS_ERR_ARGUMENT;
  }

  defaults = bs_symbol_default_count();
  for (i = 0; i < defaults; i++) {
    bs_span known;
    if (bs_symbol_get(NULL, (uint64_t)i, &known) && bs_span_eq(known, text)) {
      *out = (uint64_t)i;
      return BS_OK;
    }
  }

  for (i = 0; i < t->count; i++) {
    if (bs_span_eq(t->entries[i], text)) {
      *out = (uint64_t)BS_SYMBOL_OFFSET + (uint64_t)i;
      return BS_OK;
    }
  }

  if (t->count >= t->cap) {
    return BS_ERR_NOMEM;
  }
  t->entries[t->count] = text;
  *out = (uint64_t)BS_SYMBOL_OFFSET + (uint64_t)t->count;
  t->count++;
  return BS_OK;
}

/* Translate an index from a block's own numbering into this table's.
 *
 * `from` is the block's table: its own for a third-party block, the
 * token-wide one otherwise. Call it on every index rather than only on
 * third-party ones, because it is not the identity even for an ordinary
 * block: a token is free to carry its own copy of a well-known symbol, and
 * interning collapses that copy onto the shared index. Two blocks writing
 * owner("alice") must state one fact whichever spelling each used, and this
 * is where that happens. */
BS_API bs_status bs_symtab_translate(bs_symtab *t, const bs_symbols *from,
                                     uint64_t index, uint64_t *out) {
  bs_span text;
  if (t == NULL || out == NULL) {
    return BS_ERR_ARGUMENT;
  }
  if (!bs_symbol_get(from, index, &text)) {
    /* An index the source table cannot name. Refused rather than passed
     * through: a fact whose predicate has no name is not a fact. */
    return BS_ERR_MALFORMED;
  }
  return bs_symtab_intern(t, text, out);
}

/* ===========================================================================
 * 110_load.inc
 * ======================================================================== */

/* ---------------------------------------------------------------------------
 * Loading: wire format into the world
 *
 * The printers read the wire in place. The engine cannot: it generates facts
 * that were never encoded, and it compares facts across blocks whose symbol
 * numbering differs. So blocks are decoded into the pools, once, with every
 * symbol index translated through the interning table on the way in.
 *
 * Nested terms are the interesting part, because invariant 2 forbids
 * recursion and a container's children have to end up contiguous in the pool.
 *
 * The trick is to expand breadth-first, in the pool itself. A container is
 * first written as *pending*, holding the source bytes it was decoded from.
 * Then a single forward scan walks the pool: each pending term reserves a run
 * for its children at the current end, writes its scalars, and leaves its own
 * container children pending further along. Because expansion only ever
 * appends, the scan never revisits and never needs a worklist -- the pool is
 * the worklist.
 *
 * Depth falls out of the same walk: everything appended while expanding one
 * level forms the next, so tracking where each level ends counts nesting
 * without a stack.
 * ------------------------------------------------------------------------ */

/* A container whose children have not been placed yet. The source span lives
 * in the `bytes` variant, which is free because a pending term is never a
 * bytes term. */
#define BS_T_PENDING 0x80U

static bs_status bs_pool_reserve_terms(bs_world *w, size_t n, uint32_t *at) {
  size_t end;
  if (!bs_size_add(w->term_count, n, &end) || end > w->term_cap) {
    return BS_ERR_NOMEM;
  }
  if (end > 0xFFFFFFFFU) {
    return BS_ERR_LIMIT;
  }
  *at = (uint32_t)w->term_count;
  w->term_count = end;
  return BS_OK;
}

/* Decode one Term message into `out`, translating its symbol if it has one.
 * A container is left pending: its children are placed by the caller's scan. */
static bs_status bs_term_load_shallow(bs_symtab *syms, const bs_symbols *from,
                                      bs_span term, bs_term *out) {
  bs_cursor c = bs_cursor_make(term);
  bs_pb_field f;
  int found = 0;

  while (!bs_cursor_done(&c)) {
    bs_status st;
    if (!bs_pb_next(&c, &f)) {
      return BS_ERR_MALFORMED;
    }
    switch (f.number) {
    case BS_F_TERM_VARIABLE:
    case BS_F_TERM_STRING:
      if (f.wire != BS_PB_VARINT || found++) {
        return BS_ERR_MALFORMED;
      }
      out->kind = (f.number == BS_F_TERM_VARIABLE) ? (uint8_t)BS_T_VARIABLE
                                                   : (uint8_t)BS_T_STRING;
      st = bs_symtab_translate(syms, from, f.varint, &out->as.sym);
      if (st != BS_OK) {
        return st;
      }
      break;
    case BS_F_TERM_INTEGER:
      if (f.wire != BS_PB_VARINT || found++) {
        return BS_ERR_MALFORMED;
      }
      out->kind = (uint8_t)BS_T_INTEGER;
      out->as.integer = (int64_t)f.varint;
      break;
    case BS_F_TERM_DATE:
      if (f.wire != BS_PB_VARINT || found++) {
        return BS_ERR_MALFORMED;
      }
      out->kind = (uint8_t)BS_T_DATE;
      out->as.date = f.varint;
      break;
    case BS_F_TERM_BYTES:
      if (f.wire != BS_PB_BYTES || found++) {
        return BS_ERR_MALFORMED;
      }
      out->kind = (uint8_t)BS_T_BYTES;
      out->as.bytes = f.bytes;
      break;
    case BS_F_TERM_BOOL:
      if (f.wire != BS_PB_VARINT || found++ || f.varint > 1U) {
        return BS_ERR_MALFORMED;
      }
      out->kind = (uint8_t)BS_T_BOOL;
      out->as.boolean = (f.varint != 0U);
      break;
    case BS_F_TERM_NULL:
      if (f.wire != BS_PB_BYTES || found++) {
        return BS_ERR_MALFORMED;
      }
      out->kind = (uint8_t)BS_T_NULL;
      break;
    case BS_F_TERM_SET:
    case BS_F_TERM_ARRAY:
    case BS_F_TERM_MAP:
      if (f.wire != BS_PB_BYTES || found++) {
        return BS_ERR_MALFORMED;
      }
      out->kind = (uint8_t)(BS_T_PENDING |
                            ((f.number == BS_F_TERM_SET)     ? BS_T_SET
                             : (f.number == BS_F_TERM_ARRAY) ? BS_T_ARRAY
                                                             : BS_T_MAP));
      out->as.bytes = f.bytes;
      break;
    default:
      break; /* unknown field: parsed, then ignored */
    }
  }
  return (found == 1) ? BS_OK : BS_ERR_MALFORMED;
}

/* A map key is an integer or a string, never a container. */
static bs_status bs_mapkey_load(bs_symtab *syms, const bs_symbols *from,
                                bs_span key, bs_term *out) {
  bs_cursor c = bs_cursor_make(key);
  bs_pb_field f;
  int found = 0;

  while (!bs_cursor_done(&c)) {
    if (!bs_pb_next(&c, &f)) {
      return BS_ERR_MALFORMED;
    }
    if (f.wire != BS_PB_VARINT) {
      continue;
    }
    if (f.number == BS_F_MAPKEY_INTEGER) {
      if (found++) {
        return BS_ERR_MALFORMED;
      }
      out->kind = (uint8_t)BS_T_INTEGER;
      out->as.integer = (int64_t)f.varint;
    } else if (f.number == BS_F_MAPKEY_STRING) {
      bs_status st;
      if (found++) {
        return BS_ERR_MALFORMED;
      }
      out->kind = (uint8_t)BS_T_STRING;
      st = bs_symtab_translate(syms, from, f.varint, &out->as.sym);
      if (st != BS_OK) {
        return st;
      }
    }
  }
  return (found == 1) ? BS_OK : BS_ERR_MALFORMED;
}

/* Count the items of a container body: repeated field 1, whatever the kind.
 * A map entry counts as one item here and becomes two terms below. */
static bs_status bs_container_count(bs_span body, size_t *out) {
  return bs_repeated(body, 1U, NULL, 0U, out);
}

/* Place the children of every pending container, breadth-first, until none
 * are left. See the file header for why this needs no worklist. */
static bs_status bs_terms_expand(bs_world *w, bs_symtab *syms,
                                 const bs_symbols *from, uint32_t start) {
  size_t i = (size_t)start;
  size_t level_end = w->term_count;
  size_t depth = 1;

  while (i < w->term_count) {
    bs_term *t;
    uint8_t kind;
    bs_span body;
    size_t items;
    size_t placed = 0;
    uint32_t at = 0;
    bs_cursor c;
    bs_pb_field f;
    bs_status st;

    if (i >= level_end) {
      /* Everything appended while expanding the previous level is the next
       * one. Counting levels this way needs no stack at all. */
      depth++;
      level_end = w->term_count;
      if (depth > (size_t)BS_MAX_DEPTH) {
        return BS_ERR_DEPTH;
      }
    }

    t = &w->terms[i];
    if ((t->kind & BS_T_PENDING) == 0U) {
      i++;
      continue;
    }
    kind = (uint8_t)(t->kind & (uint8_t)~BS_T_PENDING);
    body = t->as.bytes;

    st = bs_container_count(body, &items);
    if (st != BS_OK) {
      return st;
    }
    /* A map stores its key and value adjacently, so it needs two slots per
     * entry rather than one. */
    if (kind == BS_T_MAP) {
      if (!bs_size_add(items, items, &items)) {
        return BS_ERR_OVERFLOW;
      }
    }
    st = bs_pool_reserve_terms(w, items, &at);
    if (st != BS_OK) {
      return st;
    }
    /* The pool is fixed and never moves, so `t` is still valid -- but it is
     * re-taken anyway, because a reader should not have to know that to trust
     * the next three lines. */
    t = &w->terms[i];
    t->kind = kind;
    t->as.list.at = at;
    t->as.list.count = (uint32_t)items;

    c = bs_cursor_make(body);
    while (!bs_cursor_done(&c)) {
      if (!bs_pb_next(&c, &f)) {
        return BS_ERR_MALFORMED;
      }
      if (f.number != 1U || f.wire != BS_PB_BYTES) {
        continue;
      }
      if (kind == BS_T_MAP) {
        bs_span key;
        bs_span value;
        if (!bs_mapentry_split(f.bytes, &key, &value)) {
          return BS_ERR_MALFORMED;
        }
        if (placed + 2U > items) {
          return BS_ERR_MALFORMED;
        }
        st = bs_mapkey_load(syms, from, key, &w->terms[at + placed]);
        if (st != BS_OK) {
          return st;
        }
        placed++;
        st = bs_term_load_shallow(syms, from, value, &w->terms[at + placed]);
        if (st != BS_OK) {
          return st;
        }
        placed++;
      } else {
        if (placed >= items) {
          return BS_ERR_MALFORMED;
        }
        st = bs_term_load_shallow(syms, from, f.bytes, &w->terms[at + placed]);
        if (st != BS_OK) {
          return st;
        }
        placed++;
      }
    }
    if (placed != items) {
      return BS_ERR_MALFORMED;
    }
    i++;
  }
  return BS_OK;
}

/* ---------------------------------------------------------------------------
 * Predicates and facts
 * ------------------------------------------------------------------------ */

/* `name(t0, ...)`. The terms are placed contiguously, which is what lets a
 * later comparison be a run-against-run walk rather than a chase. */
static bs_status bs_predicate_load(bs_world *w, bs_symtab *syms,
                                   const bs_symbols *from, bs_span pred,
                                   bs_predicate *out) {
  bs_cursor c;
  bs_pb_field f;
  size_t count = 0;
  size_t placed = 0;
  uint32_t at = 0;
  int have_name = 0;
  bs_status st;

  /* The name first, in its own pass: the schema does not promise field order,
   * and a predicate with no name is not a predicate. */
  c = bs_cursor_make(pred);
  while (!bs_cursor_done(&c)) {
    if (!bs_pb_next(&c, &f)) {
      return BS_ERR_MALFORMED;
    }
    if (f.number == BS_F_PREDICATE_NAME && f.wire == BS_PB_VARINT) {
      if (have_name++) {
        return BS_ERR_MALFORMED;
      }
      st = bs_symtab_translate(syms, from, f.varint, &out->name);
      if (st != BS_OK) {
        return st;
      }
    }
  }
  if (have_name != 1) {
    return BS_ERR_MALFORMED;
  }

  st = bs_repeated(pred, BS_F_PREDICATE_TERMS, NULL, 0U, &count);
  if (st != BS_OK) {
    return st;
  }
  st = bs_pool_reserve_terms(w, count, &at);
  if (st != BS_OK) {
    return st;
  }
  out->at = at;
  out->count = (uint32_t)count;

  c = bs_cursor_make(pred);
  while (!bs_cursor_done(&c)) {
    if (!bs_pb_next(&c, &f)) {
      return BS_ERR_MALFORMED;
    }
    if (f.number != BS_F_PREDICATE_TERMS || f.wire != BS_PB_BYTES) {
      continue;
    }
    if (placed >= count) {
      return BS_ERR_MALFORMED;
    }
    st = bs_term_load_shallow(syms, from, f.bytes, &w->terms[at + placed]);
    if (st != BS_OK) {
      return st;
    }
    placed++;
  }
  if (placed != count) {
    return BS_ERR_MALFORMED;
  }
  /* One expansion pass for the whole predicate, rather than one per term:
   * the scan picks up every pending container the loop above left behind. */
  return bs_terms_expand(w, syms, from, at);
}

/* Load every fact a block states, tagged with that block as its origin.
 *
 * `from` is the table the block's own indices are numbered against: its own
 * for a third-party block, the token-wide one otherwise. Passing the wrong
 * one does not fail -- it renames every predicate in the block -- which is
 * why the caller that knows the difference is the one that supplies it. */
BS_API bs_status bs_world_load_facts(bs_world *w, bs_symtab *syms,
                                     const bs_symbols *from, bs_span block,
                                     size_t block_index) {
  bs_cursor c;
  bs_pb_field f;

  if (w == NULL || syms == NULL) {
    return BS_ERR_ARGUMENT;
  }
  if (block_index >= (size_t)BS_MAX_BLOCKS) {
    return BS_ERR_LIMIT;
  }

  c = bs_cursor_make(block);
  while (!bs_cursor_done(&c)) {
    bs_cursor inner;
    bs_pb_field g;
    int found = 0;
    bs_span pred = bs_span_make(NULL, 0);
    bs_status st;

    if (!bs_pb_next(&c, &f)) {
      return BS_ERR_MALFORMED;
    }
    if (f.number != BS_F_BLOCK_FACTS || f.wire != BS_PB_BYTES) {
      continue;
    }

    inner = bs_cursor_make(f.bytes);
    while (!bs_cursor_done(&inner)) {
      if (!bs_pb_next(&inner, &g)) {
        return BS_ERR_MALFORMED;
      }
      if (g.number == BS_F_FACT_PREDICATE && g.wire == BS_PB_BYTES) {
        if (found++) {
          return BS_ERR_MALFORMED;
        }
        pred = g.bytes;
      }
    }
    if (found != 1) {
      return BS_ERR_MALFORMED;
    }

    if (w->fact_count >= w->fact_cap) {
      return BS_ERR_NOMEM;
    }
    st = bs_predicate_load(w, syms, from, pred, &w->facts[w->fact_count].pred);
    if (st != BS_OK) {
      return st;
    }
    w->facts[w->fact_count].origin = BS_ORIGIN_ONE(block_index);
    w->fact_count++;
  }
  return BS_OK;
}

/* ---------------------------------------------------------------------------
 * Expressions
 *
 * Ops are loaded into the pool in the same postfix order the wire carries
 * them, and a closure keeps its body as a separate run so the evaluator can
 * decline to run it -- which is the whole point of a short-circuiting
 * operator.
 *
 * A closure's body has to be contiguous, and its own nested closures would
 * otherwise land in the middle of it. Same answer as for nested terms: mark
 * the closure pending, holding its source bytes, and let a forward scan place
 * each body at the current end. Appending only, so the scan never revisits.
 * ------------------------------------------------------------------------ */

#define BS_OP_PENDING 0x80U

static bs_status bs_pool_reserve_ops(bs_world *w, size_t n, uint32_t *at) {
  size_t end;
  if (!bs_size_add(w->op_count, n, &end) || end > w->op_cap) {
    return BS_ERR_NOMEM;
  }
  if (end > 0xFFFFFFFFU) {
    return BS_ERR_LIMIT;
  }
  *at = (uint32_t)w->op_count;
  w->op_count = end;
  return BS_OK;
}

/* One Op, with a container's contents left for the scan below. */
static bs_status bs_op_load(bs_world *w, bs_symtab *syms,
                            const bs_symbols *from, bs_span op, bs_op *out) {
  bs_span body = bs_span_make(NULL, 0);
  uint32_t branch = 0;
  bs_status st = bs_op_branch(op, &branch, &body);

  if (st != BS_OK) {
    return st;
  }

  out->kind = 0;
  switch (branch) {
  case BS_F_OP_VALUE: {
    uint32_t at;
    st = bs_pool_reserve_terms(w, 1U, &at);
    if (st != BS_OK) {
      return st;
    }
    st = bs_term_load_shallow(syms, from, body, &w->terms[at]);
    if (st != BS_OK) {
      return st;
    }
    st = bs_terms_expand(w, syms, from, at);
    if (st != BS_OK) {
      return st;
    }
    out->tag = (uint8_t)BS_OP_VALUE;
    out->as.term = at;
    return BS_OK;
  }
  case BS_F_OP_UNARY:
  case BS_F_OP_BINARY: {
    uint64_t ffi = 0;
    uint8_t has_ffi = 0;
    st = bs_op_kind(body, &out->kind, &ffi, &has_ffi);
    if (st != BS_OK) {
      return st;
    }
    out->tag =
        (uint8_t)((branch == BS_F_OP_UNARY) ? BS_OP_UNARY : BS_OP_BINARY);
    out->as.ffi = 0;
    if (has_ffi) {
      /* The external call's name is a symbol like any other, so it goes
       * through the same translation: a third-party block naming a function
       * numbers it in its own table. */
      st = bs_symtab_translate(syms, from, ffi, &out->as.ffi);
      if (st != BS_OK) {
        return st;
      }
    }
    return BS_OK;
  }
  default:
    out->tag = (uint8_t)(BS_OP_PENDING | BS_OP_CLOSURE);
    out->as.closure.at = 0;
    out->as.closure.count = 0;
    out->as.closure.body.at = 0;
    out->as.closure.body.count = 0;
    out->as.closure.src = body;
    return BS_OK;
  }
}

/* Load one run of ops -- an Expression's or a Closure's -- leaving nested
 * closures pending. `field` is 1 inside an Expression and 2 inside a Closure.
 */
static bs_status bs_ops_load_run(bs_world *w, bs_symtab *syms,
                                 const bs_symbols *from, bs_span msg,
                                 uint32_t field, bs_expr *out) {
  size_t count = 0;
  size_t placed = 0;
  uint32_t at = 0;
  bs_cursor c;
  bs_pb_field f;
  bs_status st = bs_repeated(msg, field, NULL, 0U, &count);

  if (st != BS_OK) {
    return st;
  }
  st = bs_pool_reserve_ops(w, count, &at);
  if (st != BS_OK) {
    return st;
  }
  out->at = at;
  out->count = (uint32_t)count;

  c = bs_cursor_make(msg);
  while (!bs_cursor_done(&c)) {
    if (!bs_pb_next(&c, &f)) {
      return BS_ERR_MALFORMED;
    }
    if (f.number != field || f.wire != BS_PB_BYTES) {
      continue;
    }
    if (placed >= count) {
      return BS_ERR_MALFORMED;
    }
    st = bs_op_load(w, syms, from, f.bytes, &w->ops[at + placed]);
    if (st != BS_OK) {
      return st;
    }
    placed++;
  }
  return (placed == count) ? BS_OK : BS_ERR_MALFORMED;
}

/* Place the body of every pending closure, breadth-first. */
static bs_status bs_ops_expand(bs_world *w, bs_symtab *syms,
                               const bs_symbols *from, uint32_t start) {
  size_t i = (size_t)start;
  size_t level_end = w->op_count;
  size_t depth = 1;

  while (i < w->op_count) {
    bs_op *o;
    bs_span src;
    bs_expr body;
    bs_cursor c;
    bs_pb_field f;
    size_t params = 0;
    uint32_t sym_at = 0;
    bs_status st;

    if (i >= level_end) {
      depth++;
      level_end = w->op_count;
      if (depth > (size_t)BS_MAX_DEPTH) {
        return BS_ERR_DEPTH;
      }
    }

    o = &w->ops[i];
    if ((o->tag & BS_OP_PENDING) == 0U) {
      i++;
      continue;
    }
    src = o->as.closure.src;

    /* Parameters first: symbol indices in the closure's own numbering,
     * translated like everything else. Counted by hand rather than with
     * bs_repeated, which only counts length-delimited fields and these are
     * varints. */
    params = 0;
    c = bs_cursor_make(src);
    while (!bs_cursor_done(&c)) {
      if (!bs_pb_next(&c, &f)) {
        return BS_ERR_MALFORMED;
      }
      if (f.number == BS_F_CLOSURE_PARAMS && f.wire == BS_PB_VARINT) {
        params++;
      }
    }
    if (params > 0U) {
      size_t end;
      if (!bs_size_add(w->sym_count, params, &end) || end > w->sym_cap) {
        return BS_ERR_NOMEM;
      }
      sym_at = (uint32_t)w->sym_count;
      w->sym_count = end;
      {
        size_t k = 0;
        c = bs_cursor_make(src);
        while (!bs_cursor_done(&c)) {
          if (!bs_pb_next(&c, &f)) {
            return BS_ERR_MALFORMED;
          }
          if (f.number != BS_F_CLOSURE_PARAMS || f.wire != BS_PB_VARINT) {
            continue;
          }
          st = bs_symtab_translate(syms, from, f.varint, &w->syms[sym_at + k]);
          if (st != BS_OK) {
            return st;
          }
          k++;
        }
      }
    }

    st = bs_ops_load_run(w, syms, from, src, BS_F_CLOSURE_OPS, &body);
    if (st != BS_OK) {
      return st;
    }

    o = &w->ops[i];
    o->tag = (uint8_t)BS_OP_CLOSURE;
    o->as.closure.at = sym_at;
    o->as.closure.count = (uint32_t)params;
    o->as.closure.body = body;
    o->as.closure.src = bs_span_make(NULL, 0);
    i++;
  }
  return BS_OK;
}

static bs_status bs_expr_load(bs_world *w, bs_symtab *syms,
                              const bs_symbols *from, bs_span expr,
                              bs_expr *out) {
  bs_status st = bs_ops_load_run(w, syms, from, expr, BS_F_EXPR_OPS, out);
  if (st != BS_OK) {
    return st;
  }
  return bs_ops_expand(w, syms, from, out->at);
}

/* ---------------------------------------------------------------------------
 * Scopes, rules and checks
 *
 * A scope annotation names which blocks a rule may draw its premises from,
 * and it is resolved to a set of block ids here, once, rather than consulted
 * during evaluation.
 *
 * The specification is exact about the default and about what is always
 * included: "By default, only the current block, the authority block and the
 * authorizer are trusted", and "the current block and the authorizer are
 * always trusted" whatever annotations are present. Both are why the two bits
 * below are set before anything else is considered.
 *
 * The matching rule is worth stating too, because it is stricter than it
 * looks: "Only facts whose origin is a subset of these trusted origins are
 * matched." A fact derived from blocks {0, 2} is invisible to a rule trusting
 * only {0}, even though it partly comes from a block that rule trusts.
 * ------------------------------------------------------------------------ */

static bs_status bs_pool_reserve_preds(bs_world *w, size_t n, uint32_t *at) {
  size_t end;
  if (!bs_size_add(w->pred_count, n, &end) || end > w->pred_cap) {
    return BS_ERR_NOMEM;
  }
  if (end > 0xFFFFFFFFU) {
    return BS_ERR_LIMIT;
  }
  *at = (uint32_t)w->pred_count;
  w->pred_count = end;
  return BS_OK;
}

static bs_status bs_pool_reserve_exprs(bs_world *w, size_t n, uint32_t *at) {
  size_t end;
  if (!bs_size_add(w->expr_count, n, &end) || end > w->expr_cap) {
    return BS_ERR_NOMEM;
  }
  if (end > 0xFFFFFFFFU) {
    return BS_ERR_LIMIT;
  }
  *at = (uint32_t)w->expr_count;
  w->expr_count = end;
  return BS_OK;
}

/* Which blocks one scope annotation adds. */
static bs_status bs_scope_resolve(const bs_token *t, const bs_tables *tab,
                                  size_t block_index, bs_span scope,
                                  bs_origin *add) {
  bs_cursor c = bs_cursor_make(scope);
  bs_pb_field f;
  int have_type = 0;
  int have_key = 0;
  uint64_t type = 0;
  int64_t key = 0;
  size_t i;

  *add = BS_ORIGIN_NONE;

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
  if (have_type == have_key) {
    return BS_ERR_MALFORMED; /* a oneof: one branch, never both or neither */
  }

  if (have_type) {
    if (type == BS_SCOPE_AUTHORITY) {
      *add = BS_ORIGIN_ONE(0U);
      return BS_OK;
    }
    if (type == BS_SCOPE_PREVIOUS) {
      /* Every block up to and including this one. In the authorizer this
       * annotation is meaningless and the specification says to ignore it;
       * the authorizer never reaches here with a block index. */
      for (i = 0; i <= block_index && i < (size_t)BS_MAX_BLOCKS; i++) {
        *add |= BS_ORIGIN_ONE(i);
      }
      return BS_OK;
    }
    return BS_ERR_MALFORMED;
  }

  if (tab == NULL || t == NULL || key < 0 ||
      (uint64_t)key >= (uint64_t)tab->public_key_count) {
    return BS_ERR_MALFORMED;
  }
  /* A public key names every block carrying an external signature by it.
   * Naming a key nobody signed with is not an error -- it trusts nothing,
   * which is the honest reading of "the blocks verified by this key" when
   * there are none. */
  for (i = 0; i < t->block_count; i++) {
    if (t->blocks[i].has_external &&
        t->blocks[i].external_key.alg == tab->public_keys[key].alg &&
        bs_span_eq(t->blocks[i].external_key.key, tab->public_keys[key].key)) {
      *add |= BS_ORIGIN_ONE(i);
    }
  }
  return BS_OK;
}

/* The trust set of a rule: the always-trusted pair, plus whatever its scope
 * annotations add, or the authority block when there are none. */
static bs_status bs_trust_load(const bs_token *t, const bs_tables *tab,
                               size_t block_index, bs_span msg, uint32_t field,
                               bs_origin *out) {
  bs_cursor c = bs_cursor_make(msg);
  bs_pb_field f;
  int annotated = 0;
  bs_origin trust = BS_ORIGIN_AUTHORIZER | BS_ORIGIN_ONE(block_index);

  while (!bs_cursor_done(&c)) {
    bs_origin add = BS_ORIGIN_NONE;
    bs_status st;
    if (!bs_pb_next(&c, &f)) {
      return BS_ERR_MALFORMED;
    }
    if (f.number != field || f.wire != BS_PB_BYTES) {
      continue;
    }
    st = bs_scope_resolve(t, tab, block_index, f.bytes, &add);
    if (st != BS_OK) {
      return st;
    }
    /* Multiple annotations are added, not intersected. */
    trust |= add;
    annotated = 1;
  }
  if (!annotated) {
    trust |= BS_ORIGIN_ONE(0U);
  }
  *out = trust;
  return BS_OK;
}

static bs_status bs_rule_load(bs_world *w, bs_symtab *syms,
                              const bs_symbols *from, const bs_token *t,
                              const bs_tables *tab, size_t block_index,
                              bs_span rule, bs_rule *out) {
  bs_cursor c;
  bs_pb_field f;
  size_t body_count = 0;
  size_t expr_count = 0;
  size_t placed = 0;
  int have_head = 0;
  bs_status st;

  c = bs_cursor_make(rule);
  while (!bs_cursor_done(&c)) {
    if (!bs_pb_next(&c, &f)) {
      return BS_ERR_MALFORMED;
    }
    if (f.number == BS_F_RULE_HEAD && f.wire == BS_PB_BYTES) {
      if (have_head++) {
        return BS_ERR_MALFORMED;
      }
      st = bs_predicate_load(w, syms, from, f.bytes, &out->head);
      if (st != BS_OK) {
        return st;
      }
    }
  }
  if (have_head != 1) {
    return BS_ERR_MALFORMED;
  }

  st = bs_repeated(rule, BS_F_RULE_BODY, NULL, 0U, &body_count);
  if (st != BS_OK) {
    return st;
  }
  st = bs_pool_reserve_preds(w, body_count, &out->body_at);
  if (st != BS_OK) {
    return st;
  }
  out->body_count = (uint32_t)body_count;

  c = bs_cursor_make(rule);
  while (!bs_cursor_done(&c)) {
    if (!bs_pb_next(&c, &f)) {
      return BS_ERR_MALFORMED;
    }
    if (f.number != BS_F_RULE_BODY || f.wire != BS_PB_BYTES) {
      continue;
    }
    if (placed >= body_count) {
      return BS_ERR_MALFORMED;
    }
    st = bs_predicate_load(w, syms, from, f.bytes,
                           &w->preds[out->body_at + placed]);
    if (st != BS_OK) {
      return st;
    }
    placed++;
  }
  if (placed != body_count) {
    return BS_ERR_MALFORMED;
  }

  st = bs_repeated(rule, BS_F_RULE_EXPRESSIONS, NULL, 0U, &expr_count);
  if (st != BS_OK) {
    return st;
  }
  st = bs_pool_reserve_exprs(w, expr_count, &out->expr_at);
  if (st != BS_OK) {
    return st;
  }
  out->expr_count = (uint32_t)expr_count;

  placed = 0;
  c = bs_cursor_make(rule);
  while (!bs_cursor_done(&c)) {
    if (!bs_pb_next(&c, &f)) {
      return BS_ERR_MALFORMED;
    }
    if (f.number != BS_F_RULE_EXPRESSIONS || f.wire != BS_PB_BYTES) {
      continue;
    }
    if (placed >= expr_count) {
      return BS_ERR_MALFORMED;
    }
    st = bs_expr_load(w, syms, from, f.bytes, &w->exprs[out->expr_at + placed]);
    if (st != BS_OK) {
      return st;
    }
    placed++;
  }
  if (placed != expr_count) {
    return BS_ERR_MALFORMED;
  }

  out->block = (uint32_t)block_index;
  return bs_trust_load(t, tab, block_index, rule, BS_F_RULE_SCOPE, &out->trust);
}

/* Load every rule and check a block states. */
BS_API bs_status bs_world_load_logic(bs_world *w, bs_symtab *syms,
                                     const bs_symbols *from, const bs_token *t,
                                     const bs_tables *tab, bs_span block,
                                     size_t block_index) {
  bs_cursor c;
  bs_pb_field f;
  bs_status st;

  if (w == NULL || syms == NULL) {
    return BS_ERR_ARGUMENT;
  }
  if (block_index >= (size_t)BS_MAX_BLOCKS) {
    return BS_ERR_LIMIT;
  }

  c = bs_cursor_make(block);
  while (!bs_cursor_done(&c)) {
    if (!bs_pb_next(&c, &f)) {
      return BS_ERR_MALFORMED;
    }
    if (f.number != BS_F_BLOCK_RULES || f.wire != BS_PB_BYTES) {
      continue;
    }
    if (w->rule_count >= w->rule_cap) {
      return BS_ERR_NOMEM;
    }
    st = bs_rule_load(w, syms, from, t, tab, block_index, f.bytes,
                      &w->rules[w->rule_count]);
    if (st != BS_OK) {
      return st;
    }
    /* Invalid on sight, not on use: a rule whose head names a variable its
     * body never binds is rejected here rather than when it first fires. */
    st = bs_rule_bound(w, &w->rules[w->rule_count]);
    if (st != BS_OK) {
      return st;
    }
    w->rule_count++;
  }

  c = bs_cursor_make(block);
  while (!bs_cursor_done(&c)) {
    bs_cursor inner;
    bs_pb_field g;
    uint64_t kind = BS_CHECK_KIND_ONE;
    size_t queries = 0;
    uint32_t at;

    if (!bs_pb_next(&c, &f)) {
      return BS_ERR_MALFORMED;
    }
    if (f.number != BS_F_BLOCK_CHECKS || f.wire != BS_PB_BYTES) {
      continue;
    }

    inner = bs_cursor_make(f.bytes);
    while (!bs_cursor_done(&inner)) {
      if (!bs_pb_next(&inner, &g)) {
        return BS_ERR_MALFORMED;
      }
      if (g.number == BS_F_CHECK_KIND && g.wire == BS_PB_VARINT) {
        kind = g.varint;
      }
    }
    if (kind > (uint64_t)BS_CHECK_KIND_REJECT) {
      return BS_ERR_MALFORMED;
    }

    st = bs_repeated(f.bytes, BS_F_CHECK_QUERIES, NULL, 0U, &queries);
    if (st != BS_OK) {
      return st;
    }
    if (queries == 0U) {
      return BS_ERR_MALFORMED; /* a check with no query cannot mean anything */
    }
    {
      size_t end;
      if (!bs_size_add(w->rule_count, queries, &end) || end > w->rule_cap) {
        return BS_ERR_NOMEM;
      }
      at = (uint32_t)w->rule_count;
    }

    inner = bs_cursor_make(f.bytes);
    while (!bs_cursor_done(&inner)) {
      if (!bs_pb_next(&inner, &g)) {
        return BS_ERR_MALFORMED;
      }
      if (g.number != BS_F_CHECK_QUERIES || g.wire != BS_PB_BYTES) {
        continue;
      }
      if (w->rule_count >= w->rule_cap) {
        return BS_ERR_NOMEM;
      }
      st = bs_rule_load(w, syms, from, t, tab, block_index, g.bytes,
                        &w->rules[w->rule_count]);
      if (st != BS_OK) {
        return st;
      }
      w->rules[w->rule_count].is_query = 1;
      w->rule_count++;
    }

    if (w->check_count >= w->check_cap) {
      return BS_ERR_NOMEM;
    }
    w->checks[w->check_count].query_at = at;
    w->checks[w->check_count].query_count = (uint32_t)queries;
    w->checks[w->check_count].kind = (uint8_t)kind;
    w->checks[w->check_count].block = (uint32_t)block_index;
    /* Its own encoding, so a failure can be reported through the same
     * printer the `blocks` tier already holds to the reference's output. */
    w->checks[w->check_count].src = f.bytes;
    w->checks[w->check_count].from_text = 0;
    w->check_count++;
  }
  return BS_OK;
}

/* ===========================================================================
 * 125_regex.inc
 * ======================================================================== */

/* ---------------------------------------------------------------------------
 * Regular expressions
 *
 * `.matches()` is the one operator whose argument is a small program written
 * by whoever made the token, run against text that also came from the token.
 * A backtracking matcher would be far less code and would be the wrong
 * answer: `(a+)+b` against a string of a's is exponential, and both halves of
 * that are attacker-chosen. So this is a Thompson simulation -- every thread
 * advanced in lockstep, one pass over the input, no backtracking -- which is
 * linear in the product of pattern and input length whatever either contains.
 *
 * The compiler is two passes, both iterative because invariant 2 forbids the
 * recursive descent this would normally be written as. First the pattern is
 * tokenised into atoms and operators with the implicit concatenations made
 * explicit; then shunting-yard turns that into postfix; then a fragment stack
 * assembles the program. Groups and alternation cost a stack entry each
 * rather than a call frame.
 *
 * Supported: literals, `.`, `[...]` with ranges and negation, `*`, `+`, `?`,
 * `|`, `(...)`, `^`, `$`, and backslash escapes.
 *
 * Not supported, and refused rather than approximated: repetition counts
 * (`{n,m}`), backreferences, lookaround, named classes (`\d`, `\w`). A
 * pattern using one of those is BS_ERR_UNSUPPORTED, never a silent mismatch,
 * because an expression that quietly answers "no" is a check that quietly
 * passes.
 *
 * One divergence to record: `.` and the classes match a *byte*, where the
 * reference implementation matches a Unicode scalar. For an ASCII pattern the
 * two agree exactly; for a pattern with a multi-byte character in a class, or
 * a `.` expected to consume one accented character, they do not. Every
 * pattern in the specification's own suite is ASCII.
 * ------------------------------------------------------------------------ */

#ifndef BS_RE_MAX_INSTS
#define BS_RE_MAX_INSTS 256
#endif

#ifndef BS_RE_MAX_CLASSES
#define BS_RE_MAX_CLASSES 16
#endif

#define BS_RE_CHAR 0U
#define BS_RE_ANY 1U
#define BS_RE_CLASS 2U
#define BS_RE_SPLIT 3U
#define BS_RE_JMP 4U
#define BS_RE_MATCH 5U
#define BS_RE_BOL 6U
#define BS_RE_EOL 7U

typedef struct bs_re_inst {
  uint8_t op;
  uint8_t ch;  /* BS_RE_CHAR */
  uint8_t cls; /* BS_RE_CLASS: which bitmap */
  uint32_t x;  /* next, or the first branch of a split */
  uint32_t y;  /* the second branch of a split */
} bs_re_inst;

/* --------------------------------------------------------------------------
 * Tokens and fragments
 * ----------------------------------------------------------------------- */

#define BS_RE_T_ATOM 0U /* a literal, `.`, or a class */
#define BS_RE_T_CONCAT 1U
#define BS_RE_T_ALT 2U
#define BS_RE_T_STAR 3U
#define BS_RE_T_PLUS 4U
#define BS_RE_T_OPT 5U
#define BS_RE_T_LPAREN 6U
#define BS_RE_T_RPAREN 7U
#define BS_RE_T_BOL 8U
#define BS_RE_T_EOL 9U

typedef struct bs_re_tok {
  uint8_t kind;
  uint8_t op; /* for atoms: BS_RE_CHAR, BS_RE_ANY or BS_RE_CLASS */
  uint8_t ch;
  uint8_t cls;
} bs_re_tok;

#ifndef BS_RE_MAX_TOKENS
#define BS_RE_MAX_TOKENS 256
#endif

/* A fragment: an entry point, and the list of instruction slots that still
 * need to be told where to go next. The dangling slots are threaded through
 * the instructions themselves, as in Thompson's original construction. */
typedef struct bs_re_frag {
  uint32_t start;
  uint32_t out; /* head of the patch list, or BS_RE_NONE */
} bs_re_frag;

#define BS_RE_NONE 0xFFFFFFFFU
/* A patch entry names an instruction and which of its two successors is the
 * hole: the low bit says x or y, the rest is the index. */
#define BS_RE_PATCH(i, is_y) (((i) << 1U) | (is_y))

/* The compiled program and everything the simulation needs to run it.
 *
 * The thread lists live here rather than as locals because a library that
 * advertises a bounded, small stack cannot spend three kilobytes of it on one
 * operator. This object comes from the evaluation arena, where its size is
 * the caller's choice rather than the C stack's. */
typedef struct bs_regex {
  bs_re_inst prog[BS_RE_MAX_INSTS];
  uint8_t classes[BS_RE_MAX_CLASSES][32]; /* 256 bits each */
  size_t count;
  size_t class_count;
  /* Simulation state. */
  uint32_t cur[BS_RE_MAX_INSTS];
  uint32_t next[BS_RE_MAX_INSTS];
  uint32_t work[BS_RE_MAX_INSTS]; /* the epsilon-closure walk */
  uint8_t seen[BS_RE_MAX_INSTS];
  /* Compilation scratch. Here for the same reason as the thread lists: as
   * locals they cost five kilobytes of stack, and the stack bound is a
   * documented number this project is measured against. */
  bs_re_tok toks[BS_RE_MAX_TOKENS];
  bs_re_tok post[BS_RE_MAX_TOKENS];
  bs_re_tok opstack[BS_RE_MAX_TOKENS];
  bs_re_frag frags[BS_RE_MAX_TOKENS];
} bs_regex;

/* --------------------------------------------------------------------------
 * Tokenising
 * ----------------------------------------------------------------------- */

/* Read a character class, `[` already consumed. */
static bs_status bs_re_class(bs_regex *re, bs_span p, size_t *i, uint8_t *out) {
  uint8_t *set;
  int negate = 0;
  size_t k;
  int first = 1;

  if (re->class_count >= (size_t)BS_RE_MAX_CLASSES) {
    return BS_ERR_LIMIT;
  }
  set = re->classes[re->class_count];
  for (k = 0; k < 32U; k++) {
    set[k] = 0;
  }

  if (*i < p.n && p.p[*i] == (uint8_t)'^') {
    negate = 1;
    (*i)++;
  }

  while (*i < p.n) {
    uint8_t lo;
    uint8_t hi;

    if (p.p[*i] == (uint8_t)']' && !first) {
      (*i)++;
      if (negate) {
        for (k = 0; k < 32U; k++) {
          set[k] = (uint8_t)~set[k];
        }
      }
      *out = (uint8_t)re->class_count;
      re->class_count++;
      return BS_OK;
    }
    first = 0;

    lo = p.p[*i];
    if (lo == (uint8_t)'\\') {
      (*i)++;
      if (*i >= p.n) {
        return BS_ERR_MALFORMED;
      }
      lo = p.p[*i];
    }
    (*i)++;

    hi = lo;
    /* A range, unless the `-` is the last character before the bracket. */
    if (*i + 1U < p.n && p.p[*i] == (uint8_t)'-' &&
        p.p[*i + 1U] != (uint8_t)']') {
      (*i)++;
      hi = p.p[*i];
      if (hi == (uint8_t)'\\') {
        (*i)++;
        if (*i >= p.n) {
          return BS_ERR_MALFORMED;
        }
        hi = p.p[*i];
      }
      (*i)++;
      if (hi < lo) {
        return BS_ERR_MALFORMED;
      }
    }

    for (k = (size_t)lo; k <= (size_t)hi; k++) {
      set[k >> 3U] |= (uint8_t)(1U << (k & 7U));
    }
  }
  return BS_ERR_MALFORMED; /* unterminated class */
}

/* Tokenise, inserting the concatenations the syntax leaves implicit. */
static bs_status bs_re_tokenise(bs_regex *re, bs_span p, bs_re_tok *out,
                                size_t *count) {
  size_t i = 0;
  size_t n = 0;
  int prev_atom = 0; /* whether a concatenation may precede the next token */

  while (i < p.n) {
    uint8_t c = p.p[i];
    bs_re_tok t;
    int is_atom = 0;

    t.op = 0;
    t.ch = 0;
    t.cls = 0;

    switch (c) {
    case (uint8_t)'(':
      t.kind = (uint8_t)BS_RE_T_LPAREN;
      is_atom = 1;
      i++;
      break;
    case (uint8_t)')':
      t.kind = (uint8_t)BS_RE_T_RPAREN;
      i++;
      prev_atom = 1;
      goto emit;
    case (uint8_t)'|':
      t.kind = (uint8_t)BS_RE_T_ALT;
      i++;
      prev_atom = 0;
      goto emit;
    case (uint8_t)'*':
    case (uint8_t)'+':
    case (uint8_t)'?':
      t.kind = (c == (uint8_t)'*')   ? (uint8_t)BS_RE_T_STAR
               : (c == (uint8_t)'+') ? (uint8_t)BS_RE_T_PLUS
                                     : (uint8_t)BS_RE_T_OPT;
      i++;
      prev_atom = 1;
      goto emit;
    case (uint8_t)'{':
      /* Repetition counts are not implemented. Refused, so a pattern using
       * one is an error rather than a mismatch. */
      return BS_ERR_UNSUPPORTED;
    case (uint8_t)'^':
      t.kind = (uint8_t)BS_RE_T_BOL;
      is_atom = 1;
      i++;
      break;
    case (uint8_t)'$':
      t.kind = (uint8_t)BS_RE_T_EOL;
      is_atom = 1;
      i++;
      break;
    case (uint8_t)'.':
      t.kind = (uint8_t)BS_RE_T_ATOM;
      t.op = (uint8_t)BS_RE_ANY;
      is_atom = 1;
      i++;
      break;
    case (uint8_t)'[': {
      bs_status st;
      i++;
      t.kind = (uint8_t)BS_RE_T_ATOM;
      t.op = (uint8_t)BS_RE_CLASS;
      st = bs_re_class(re, p, &i, &t.cls);
      if (st != BS_OK) {
        return st;
      }
      is_atom = 1;
      break;
    }
    case (uint8_t)'\\':
      i++;
      if (i >= p.n) {
        return BS_ERR_MALFORMED;
      }
      /* Only literal escapes. A named class such as \\d would need Unicode
       * tables to match the reference, so it is refused. */
      if ((p.p[i] >= (uint8_t)'a' && p.p[i] <= (uint8_t)'z') ||
          (p.p[i] >= (uint8_t)'A' && p.p[i] <= (uint8_t)'Z')) {
        return BS_ERR_UNSUPPORTED;
      }
      t.kind = (uint8_t)BS_RE_T_ATOM;
      t.op = (uint8_t)BS_RE_CHAR;
      t.ch = p.p[i];
      is_atom = 1;
      i++;
      break;
    default:
      t.kind = (uint8_t)BS_RE_T_ATOM;
      t.op = (uint8_t)BS_RE_CHAR;
      t.ch = c;
      is_atom = 1;
      i++;
      break;
    }

    /* Two adjacent atoms are a concatenation, and the grammar never writes
     * the operator down. */
    if (is_atom && prev_atom) {
      if (n >= (size_t)BS_RE_MAX_TOKENS) {
        return BS_ERR_LIMIT;
      }
      out[n].kind = (uint8_t)BS_RE_T_CONCAT;
      out[n].op = 0;
      out[n].ch = 0;
      out[n].cls = 0;
      n++;
    }
    prev_atom = (t.kind != (uint8_t)BS_RE_T_LPAREN);

  emit:
    if (n >= (size_t)BS_RE_MAX_TOKENS) {
      return BS_ERR_LIMIT;
    }
    out[n] = t;
    n++;
  }
  *count = n;
  return BS_OK;
}

/* --------------------------------------------------------------------------
 * Shunting-yard, then assembly
 * ----------------------------------------------------------------------- */

static unsigned int bs_re_prec(uint8_t kind) {
  switch (kind) {
  case BS_RE_T_ALT:
    return 1U;
  case BS_RE_T_CONCAT:
    return 2U;
  default:
    return 3U; /* the postfix repetitions bind tightest */
  }
}

static bs_status bs_re_emit(bs_regex *re, uint8_t op, uint8_t ch, uint8_t cls,
                            uint32_t *at) {
  if (re->count >= (size_t)BS_RE_MAX_INSTS) {
    return BS_ERR_LIMIT;
  }
  re->prog[re->count].op = op;
  re->prog[re->count].ch = ch;
  re->prog[re->count].cls = cls;
  re->prog[re->count].x = 0;
  re->prog[re->count].y = 0;
  *at = (uint32_t)re->count;
  re->count++;
  return BS_OK;
}

static uint32_t *bs_re_slot(bs_regex *re, uint32_t patch) {
  bs_re_inst *in = &re->prog[patch >> 1U];
  return ((patch & 1U) != 0U) ? &in->y : &in->x;
}

static void bs_re_patch(bs_regex *re, uint32_t list, uint32_t target) {
  while (list != BS_RE_NONE) {
    uint32_t *slot = bs_re_slot(re, list);
    uint32_t next = *slot;
    *slot = target;
    list = next;
  }
}

static uint32_t bs_re_append(bs_regex *re, uint32_t a, uint32_t b) {
  uint32_t head = a;
  uint32_t cur;
  if (a == BS_RE_NONE) {
    return b;
  }
  cur = a;
  for (;;) {
    uint32_t *slot = bs_re_slot(re, cur);
    if (*slot == BS_RE_NONE) {
      *slot = b;
      return head;
    }
    cur = *slot;
  }
}

static bs_status bs_re_build(bs_regex *re, const bs_re_tok *post, size_t n) {
  bs_re_frag *stack = re->frags;
  size_t sp = 0;
  size_t i;
  bs_status st;
  uint32_t at;

  for (i = 0; i < n; i++) {
    const bs_re_tok *t = &post[i];
    bs_re_frag a;
    bs_re_frag b;

    switch (t->kind) {
    case BS_RE_T_ATOM:
      st = bs_re_emit(re, t->op, t->ch, t->cls, &at);
      if (st != BS_OK) {
        return st;
      }
      re->prog[at].x = BS_RE_NONE;
      stack[sp].start = at;
      stack[sp].out = BS_RE_PATCH(at, 0U);
      sp++;
      break;

    case BS_RE_T_BOL:
    case BS_RE_T_EOL:
      st = bs_re_emit(re,
                      (t->kind == (uint8_t)BS_RE_T_BOL) ? (uint8_t)BS_RE_BOL
                                                        : (uint8_t)BS_RE_EOL,
                      0, 0, &at);
      if (st != BS_OK) {
        return st;
      }
      re->prog[at].x = BS_RE_NONE;
      stack[sp].start = at;
      stack[sp].out = BS_RE_PATCH(at, 0U);
      sp++;
      break;

    case BS_RE_T_CONCAT:
      if (sp < 2U) {
        return BS_ERR_MALFORMED;
      }
      b = stack[--sp];
      a = stack[--sp];
      bs_re_patch(re, a.out, b.start);
      stack[sp].start = a.start;
      stack[sp].out = b.out;
      sp++;
      break;

    case BS_RE_T_ALT:
      if (sp < 2U) {
        return BS_ERR_MALFORMED;
      }
      b = stack[--sp];
      a = stack[--sp];
      st = bs_re_emit(re, (uint8_t)BS_RE_SPLIT, 0, 0, &at);
      if (st != BS_OK) {
        return st;
      }
      re->prog[at].x = a.start;
      re->prog[at].y = b.start;
      stack[sp].start = at;
      stack[sp].out = bs_re_append(re, a.out, b.out);
      sp++;
      break;

    case BS_RE_T_STAR:
    case BS_RE_T_PLUS:
    case BS_RE_T_OPT:
      if (sp < 1U) {
        return BS_ERR_MALFORMED;
      }
      a = stack[--sp];
      st = bs_re_emit(re, (uint8_t)BS_RE_SPLIT, 0, 0, &at);
      if (st != BS_OK) {
        return st;
      }
      re->prog[at].x = a.start;
      re->prog[at].y = BS_RE_NONE;
      if (t->kind == (uint8_t)BS_RE_T_STAR) {
        bs_re_patch(re, a.out, at);
        stack[sp].start = at;
        stack[sp].out = BS_RE_PATCH(at, 1U);
      } else if (t->kind == (uint8_t)BS_RE_T_PLUS) {
        bs_re_patch(re, a.out, at);
        stack[sp].start = a.start;
        stack[sp].out = BS_RE_PATCH(at, 1U);
      } else {
        stack[sp].start = at;
        stack[sp].out = bs_re_append(re, a.out, BS_RE_PATCH(at, 1U));
      }
      sp++;
      break;

    default:
      return BS_ERR_MALFORMED;
    }
  }

  if (sp == 0U) {
    /* An empty pattern matches everywhere. */
    st = bs_re_emit(re, (uint8_t)BS_RE_MATCH, 0, 0, &at);
    return st;
  }
  if (sp != 1U) {
    return BS_ERR_MALFORMED;
  }
  st = bs_re_emit(re, (uint8_t)BS_RE_MATCH, 0, 0, &at);
  if (st != BS_OK) {
    return st;
  }
  bs_re_patch(re, stack[0].out, at);
  /* The program's entry point is the fragment's start, which the simulation
   * below reads from prog[0].x of a synthesised jump so that entry is always
   * instruction zero's target. */
  if (re->count >= (size_t)BS_RE_MAX_INSTS) {
    return BS_ERR_LIMIT;
  }
  re->prog[re->count].op = (uint8_t)BS_RE_JMP;
  re->prog[re->count].ch = 0;
  re->prog[re->count].cls = 0;
  re->prog[re->count].x = stack[0].start;
  re->prog[re->count].y = 0;
  re->count++;
  return BS_OK;
}

static bs_status bs_re_compile(bs_regex *re, bs_span pattern) {
  bs_re_tok *toks = re->toks;
  bs_re_tok *post = re->post;
  bs_re_tok *ops = re->opstack;
  size_t ntok = 0;
  size_t npost = 0;
  size_t nops = 0;
  size_t i;
  bs_status st;

  re->count = 0;
  re->class_count = 0;

  st = bs_re_tokenise(re, pattern, toks, &ntok);
  if (st != BS_OK) {
    return st;
  }

  /* Shunting-yard: operators to a stack, atoms straight out, parentheses
   * flushing back to the matching opener. */
  for (i = 0; i < ntok; i++) {
    bs_re_tok t = toks[i];
    if (t.kind == (uint8_t)BS_RE_T_ATOM || t.kind == (uint8_t)BS_RE_T_BOL ||
        t.kind == (uint8_t)BS_RE_T_EOL) {
      post[npost] = t;
      npost++;
      continue;
    }
    if (t.kind == (uint8_t)BS_RE_T_LPAREN) {
      ops[nops] = t;
      nops++;
      continue;
    }
    if (t.kind == (uint8_t)BS_RE_T_RPAREN) {
      while (nops > 0U && ops[nops - 1U].kind != (uint8_t)BS_RE_T_LPAREN) {
        nops--;
        post[npost] = ops[nops];
        npost++;
      }
      if (nops == 0U) {
        return BS_ERR_MALFORMED; /* unbalanced */
      }
      nops--; /* discard the opener */
      continue;
    }
    while (nops > 0U && ops[nops - 1U].kind != (uint8_t)BS_RE_T_LPAREN &&
           bs_re_prec(ops[nops - 1U].kind) >= bs_re_prec(t.kind)) {
      nops--;
      post[npost] = ops[nops];
      npost++;
    }
    ops[nops] = t;
    nops++;
  }
  while (nops > 0U) {
    nops--;
    if (ops[nops].kind == (uint8_t)BS_RE_T_LPAREN) {
      return BS_ERR_MALFORMED;
    }
    post[npost] = ops[nops];
    npost++;
  }

  return bs_re_build(re, post, npost);
}

/* --------------------------------------------------------------------------
 * Simulation
 * ----------------------------------------------------------------------- */

/* Add a thread and everything reachable from it without consuming input.
 * `seen` keeps each instruction to one thread per position, which is what
 * bounds the work and removes backtracking entirely. */
static void bs_re_add(bs_regex *re, uint32_t pc, uint32_t *list, size_t *n,
                      uint8_t *seen, size_t pos, size_t len) {
  uint32_t *stack = re->work;
  size_t sp = 0;

  stack[sp] = pc;
  sp++;
  while (sp > 0U) {
    const bs_re_inst *in;
    sp--;
    pc = stack[sp];
    if (pc == BS_RE_NONE || (size_t)pc >= re->count || seen[pc]) {
      continue;
    }
    seen[pc] = 1;
    in = &re->prog[pc];
    if (in->op == (uint8_t)BS_RE_SPLIT || in->op == (uint8_t)BS_RE_JMP) {
      if (in->op == (uint8_t)BS_RE_SPLIT && sp < (size_t)BS_RE_MAX_INSTS) {
        stack[sp] = in->y;
        sp++;
      }
      if (sp < (size_t)BS_RE_MAX_INSTS) {
        stack[sp] = in->x;
        sp++;
      }
      continue;
    }
    if (in->op == (uint8_t)BS_RE_BOL) {
      if (pos == 0U && sp < (size_t)BS_RE_MAX_INSTS) {
        stack[sp] = in->x;
        sp++;
      }
      continue;
    }
    if (in->op == (uint8_t)BS_RE_EOL) {
      if (pos == len && sp < (size_t)BS_RE_MAX_INSTS) {
        stack[sp] = in->x;
        sp++;
      }
      continue;
    }
    list[*n] = pc;
    (*n)++;
  }
}

/* Does the pattern match anywhere in `text`?
 *
 * Unanchored, like the reference: a new thread starts at every position, all
 * of them advanced together. One pass, no backtracking, and the work is
 * bounded by pattern length times input length however hostile either is. */
static bs_status bs_re_search(bs_regex *re, bs_span text, int *out) {
  uint32_t *cur = re->cur;
  uint32_t *next = re->next;
  uint8_t *seen = re->seen;
  size_t ncur = 0;
  size_t nnext;
  size_t pos;
  size_t k;
  uint32_t entry;

  if (re->count == 0U) {
    return BS_ERR_MALFORMED;
  }
  entry = re->prog[re->count - 1U].x;

  for (k = 0; k < re->count; k++) {
    seen[k] = 0;
  }
  bs_re_add(re, entry, cur, &ncur, seen, 0U, text.n);
  for (k = 0; k < ncur; k++) {
    if (re->prog[cur[k]].op == (uint8_t)BS_RE_MATCH) {
      *out = 1;
      return BS_OK;
    }
  }

  for (pos = 0; pos < text.n; pos++) {
    uint8_t c = text.p[pos];
    size_t j;

    nnext = 0;
    for (k = 0; k < re->count; k++) {
      seen[k] = 0;
    }

    for (j = 0; j < ncur; j++) {
      const bs_re_inst *in = &re->prog[cur[j]];
      int hit = 0;
      switch (in->op) {
      case BS_RE_CHAR:
        hit = (c == in->ch);
        break;
      case BS_RE_ANY:
        /* As in the reference, `.` does not cross a newline. */
        hit = (c != (uint8_t)'\n');
        break;
      case BS_RE_CLASS:
        hit =
            ((re->classes[in->cls][c >> 3U] & (uint8_t)(1U << (c & 7U))) != 0U);
        break;
      default:
        break;
      }
      if (hit) {
        bs_re_add(re, in->x, next, &nnext, seen, pos + 1U, text.n);
      }
    }

    /* Unanchored: a match may start here too. */
    bs_re_add(re, entry, next, &nnext, seen, pos + 1U, text.n);

    for (k = 0; k < nnext; k++) {
      cur[k] = next[k];
      if (re->prog[next[k]].op == (uint8_t)BS_RE_MATCH) {
        *out = 1;
        return BS_OK;
      }
    }
    ncur = nnext;
  }

  *out = 0;
  return BS_OK;
}

/* Compile and run in one call.
 *
 * The compiled program is a few kilobytes -- an instruction array and the
 * class bitmaps -- which is more than belongs on the stack in a library that
 * advertises a bounded one. It comes from the evaluation arena instead, and
 * goes back with everything else when the expression finishes.
 *
 * Nothing is cached between calls. A rule evaluated against a thousand facts
 * recompiles its pattern a thousand times, which is the honest trade for now:
 * a cache is state, and state that outlives one expression is the thing this
 * design has been avoiding everywhere else. */
static bs_status bs_re_match(const bs_symtab *syms, bs_arena *arena,
                             bs_term subject, bs_term pattern, int *out) {
  bs_span text;
  bs_span pat;
  bs_regex *re;
  bs_status st;

  if (!bs_symtab_get(syms, subject.as.sym, &text) ||
      !bs_symtab_get(syms, pattern.as.sym, &pat)) {
    return BS_ERR_TYPE;
  }
  re = (bs_regex *)bs_arena_alloc(arena, sizeof(bs_regex), BS_ALIGN_MAX);
  if (re == NULL) {
    return BS_ERR_NOMEM;
  }
  st = bs_re_compile(re, pat);
  if (st != BS_OK) {
    return st;
  }
  return bs_re_search(re, text, out);
}

/* ===========================================================================
 * 120_eval.inc
 * ======================================================================== */

/* ---------------------------------------------------------------------------
 * Expression evaluation
 *
 * The same postfix opcode stream the printer renders, actually executed. A
 * value stack, one pass, no allocation beyond what the world's pools already
 * hold -- and every intermediate value discarded afterwards, because an
 * expression must leave exactly one boolean behind and nothing else it built
 * along the way can be referred to again.
 *
 * Three semantics from the specification are easy to get subtly wrong, and
 * each one changes authorization outcomes rather than merely erroring:
 *
 *   - Integer arithmetic must *fail* on overflow, not wrap. A token that
 *     computes its way past INT64_MAX does not get a smaller number; the
 *     expression is an error and the check that contained it fails.
 *   - Strict equality (===) is a type error across types. Lenient equality
 *     (==) is simply false across types. Confusing them turns a check that
 *     should have failed loudly into one that quietly returns false, or the
 *     reverse.
 *   - Comparison is defined on integers and dates, and on nothing else.
 *     `"a" < "b"` is not false, it is a type error.
 * ------------------------------------------------------------------------ */

/* The stack an expression may use. The specification bounds expressions
 * through the run limits rather than by depth, so this is a structural
 * ceiling: an opcode stream that needs more is refused, never accommodated. */
#ifndef BS_MAX_EVAL_STACK
#define BS_MAX_EVAL_STACK 32
#endif

typedef struct bs_eval {
  bs_world *w;
  bs_symtab *syms;
  bs_arena *arena; /* scratch for values an operator builds, rewound after */
  const bs_binding *bindings;
  size_t binding_count;
  bs_term stack[BS_MAX_EVAL_STACK];
  size_t sp;
} bs_eval;

static bs_status bs_push(bs_eval *e, bs_term v) {
  if (e->sp >= (size_t)BS_MAX_EVAL_STACK) {
    return BS_ERR_LIMIT;
  }
  e->stack[e->sp] = v;
  e->sp++;
  return BS_OK;
}

static bs_status bs_pop(bs_eval *e, bs_term *out) {
  if (e->sp == 0U) {
    return BS_ERR_MALFORMED; /* the opcode stream underflows its own stack */
  }
  e->sp--;
  *out = e->stack[e->sp];
  return BS_OK;
}

/* Resolve a variable to its binding, or report that it has none. */
static bs_status bs_resolve(const bs_eval *e, bs_term in, bs_term *out) {
  size_t i;
  if (in.kind != (uint8_t)BS_T_VARIABLE) {
    *out = in;
    return BS_OK;
  }
  for (i = 0; i < e->binding_count; i++) {
    if (e->bindings[i].sym == in.as.sym) {
      *out = e->bindings[i].value;
      return BS_OK;
    }
  }
  /* An unbound variable in an expression. The specification requires every
   * variable in an expression to appear in a predicate of the same rule, so
   * reaching here means the rule was accepted when it should not have been. */
  return BS_ERR_TYPE;
}

static bs_term bs_bool(int b) {
  bs_term t;
  t.kind = (uint8_t)BS_T_BOOL;
  t.as.boolean = (b != 0);
  return t;
}

static bs_term bs_int(int64_t v) {
  bs_term t;
  t.kind = (uint8_t)BS_T_INTEGER;
  t.as.integer = v;
  return t;
}

/* Equality, without recursion.
 *
 * Comparing two nested terms is naturally a tree walk, and a tree walk is
 * naturally recursive -- which invariant 2 forbids, and for a good reason
 * here: the terms come off the wire, so their nesting is chosen by whoever
 * sent the token.
 *
 * So the walk carries an explicit frame stack. Each frame is one pending
 * comparison; `last` carries a finished frame's answer back to its parent,
 * which is what a return value would do. Arrays and maps compare position by
 * position. Sets compare as sets -- same size and every element of one present
 * in the other -- because the specification treats them as deduplicated
 * collections, so two encodings of the same set must be equal.
 */
typedef struct bs_eqframe {
  bs_term a;
  bs_term b;
  uint32_t i; /* position in a */
  uint32_t j; /* position in b, while searching for a match for a[i] */
  uint8_t mode;
} bs_eqframe;

static int bs_term_eq(const bs_world *w, bs_term a, bs_term b) {
  bs_eqframe st[BS_MAX_DEPTH + 2];
  size_t d = 1;
  int last = 1;

  st[0].a = a;
  st[0].b = b;
  st[0].i = 0;
  st[0].j = 0;

  while (d > 0U) {
    bs_eqframe *f = &st[d - 1U];

    if (f->a.kind != f->b.kind) {
      last = 0;
      d--;
      continue;
    }

    switch (f->a.kind) {
    case BS_T_VARIABLE:
    case BS_T_STRING:
      last = (f->a.as.sym == f->b.as.sym);
      d--;
      continue;
    case BS_T_INTEGER:
      last = (f->a.as.integer == f->b.as.integer);
      d--;
      continue;
    case BS_T_DATE:
      last = (f->a.as.date == f->b.as.date);
      d--;
      continue;
    case BS_T_BYTES:
      last = bs_span_eq(f->a.as.bytes, f->b.as.bytes);
      d--;
      continue;
    case BS_T_BOOL:
      last = (f->a.as.boolean == f->b.as.boolean);
      d--;
      continue;
    case BS_T_NULL:
      last = 1; /* null is always equal to itself */
      d--;
      continue;
    default:
      break;
    }

    if (f->a.as.list.count != f->b.as.list.count) {
      last = 0;
      d--;
      continue;
    }
    if (d >= sizeof st / sizeof st[0]) {
      /* Deeper than the loader would have accepted, so unreachable through
       * the public API -- and answering "unequal" rather than reading past
       * the stack is the right answer if it ever is reached. */
      BS_ASSERT(0);
      return 0;
    }

    if (f->a.kind == (uint8_t)BS_T_SET) {
      /* Searching b for a match for a[i]. */
      if (f->j > 0U && last) {
        f->i++;
        f->j = 0;
      }
      if (f->i >= f->a.as.list.count) {
        last = 1;
        d--;
        continue;
      }
      if (f->j >= f->b.as.list.count) {
        last = 0; /* a[i] is in no position of b */
        d--;
        continue;
      }
      st[d].a = w->terms[f->a.as.list.at + f->i];
      st[d].b = w->terms[f->b.as.list.at + f->j];
      st[d].i = 0;
      st[d].j = 0;
      f->j++;
      d++;
      continue;
    }

    /* Arrays, and maps whose keys and values sit adjacently, compare
     * position by position. */
    if (f->i > 0U && !last) {
      d--;
      continue;
    }
    if (f->i >= f->a.as.list.count) {
      last = 1;
      d--;
      continue;
    }
    st[d].a = w->terms[f->a.as.list.at + f->i];
    st[d].b = w->terms[f->b.as.list.at + f->i];
    st[d].i = 0;
    st[d].j = 0;
    f->i++;
    d++;
  }
  return last;
}

static int bs_run_contains(const bs_world *w, uint32_t at, uint32_t count,
                           bs_term needle) {
  uint32_t i = 0;
  for (; i < count; i++) {
    if (bs_term_eq(w, w->terms[at + i], needle)) {
      return 1;
    }
  }
  return 0;
}

/* `<`, `>`, `<=`, `>=`: integers and dates only. Anything else is a type
 * error rather than false, because "is this string less than that date" has
 * no answer and pretending it is `false` hides a mistake in the token. */
static bs_status bs_compare(bs_term a, bs_term b, int *out) {
  if (a.kind != b.kind) {
    return BS_ERR_TYPE;
  }
  if (a.kind == (uint8_t)BS_T_INTEGER) {
    *out = (a.as.integer < b.as.integer) ? -1 : (a.as.integer > b.as.integer);
    return BS_OK;
  }
  if (a.kind == (uint8_t)BS_T_DATE) {
    *out = (a.as.date < b.as.date) ? -1 : (a.as.date > b.as.date);
    return BS_OK;
  }
  return BS_ERR_TYPE;
}

/* Integer arithmetic, checked. The specification is explicit: "Integer
 * operations must have overflow checks. If it overflows, the expression
 * fails." Wrapping would let a token compute its way to a smaller number and
 * satisfy a bound it should not. */
static bs_status bs_arith(uint32_t op, int64_t x, int64_t y, int64_t *out) {
#ifdef BS_HAS_OVERFLOW_BUILTINS
  switch (op) {
  case 9U:
    return __builtin_add_overflow(x, y, out) ? BS_ERR_OVERFLOW : BS_OK;
  case 10U:
    return __builtin_sub_overflow(x, y, out) ? BS_ERR_OVERFLOW : BS_OK;
  case 11U:
    return __builtin_mul_overflow(x, y, out) ? BS_ERR_OVERFLOW : BS_OK;
  default:
    break;
  }
#else
  switch (op) {
  case 9U:
    if ((y > 0 && x > INT64_MAX - y) || (y < 0 && x < INT64_MIN - y)) {
      return BS_ERR_OVERFLOW;
    }
    *out = x + y;
    return BS_OK;
  case 10U:
    if ((y < 0 && x > INT64_MAX + y) || (y > 0 && x < INT64_MIN + y)) {
      return BS_ERR_OVERFLOW;
    }
    *out = x - y;
    return BS_OK;
  case 11U:
    if (x != 0 && y != 0) {
      int64_t r = x * y;
      if (r / x != y) {
        return BS_ERR_OVERFLOW;
      }
      *out = r;
    } else {
      *out = 0;
    }
    return BS_OK;
  default:
    break;
  }
#endif
  /* Division. Zero is an error, and so is INT64_MIN / -1, whose result has no
   * representation -- on most machines it traps rather than wrapping. */
  if (y == 0) {
    return BS_ERR_OVERFLOW;
  }
  if (x == INT64_MIN && y == -1) {
    return BS_ERR_OVERFLOW;
  }
  *out = x / y;
  return BS_OK;
}

/* The name `.type()` returns for each kind, interned on demand so the result
 * is an ordinary string term and comparisons against it are ordinary symbol
 * comparisons. */
static bs_status bs_typeof(bs_eval *e, bs_term v, bs_term *out) {
  /* Lengths from sizeof, not from a scan: a hand-written walk to the
   * terminator is an idiom the optimiser rewrites into a call to strlen,
   * which would put a str* function into the shipped object. That is not
   * hypothetical -- it is what tools/check_invariants.py caught here. */
  static const bs_static_symbol NAMES[] = {
      BS_SYM("variable"), BS_SYM("integer"), BS_SYM("string"), BS_SYM("date"),
      BS_SYM("bytes"),    BS_SYM("bool"),    BS_SYM("set"),    BS_SYM("null"),
      BS_SYM("array"),    BS_SYM("map"),
  };

  if (v.kind == (uint8_t)BS_T_VARIABLE ||
      v.kind >= (uint8_t)(sizeof NAMES / sizeof NAMES[0])) {
    /* A variable has no type of its own: it is resolved before it gets
     * here, and reaching this means it was never bound. */
    return BS_ERR_TYPE;
  }
  out->kind = (uint8_t)BS_T_STRING;
  return bs_symtab_intern(e->syms,
                          bs_span_make(NAMES[v.kind].text, NAMES[v.kind].len),
                          &out->as.sym);
}

/* `.length()`: bytes for a string, elements for a container. The
 * specification counts UTF-8 bytes rather than characters, deliberately --
 * counting grapheme clusters would give different answers in different
 * languages, which is not something an authorization decision can afford. */
static bs_status bs_length(const bs_eval *e, bs_term v, int64_t *out) {
  bs_span text;
  switch (v.kind) {
  case BS_T_STRING:
    if (!bs_symtab_get(e->syms, v.as.sym, &text)) {
      return BS_ERR_TYPE;
    }
    *out = (int64_t)text.n;
    return BS_OK;
  case BS_T_BYTES:
    *out = (int64_t)v.as.bytes.n;
    return BS_OK;
  case BS_T_SET:
  case BS_T_ARRAY:
    *out = (int64_t)v.as.list.count;
    return BS_OK;
  case BS_T_MAP:
    /* Keys and values are stored adjacently; the length of a map is its
     * number of entries, not its number of slots. */
    *out = (int64_t)(v.as.list.count / 2U);
    return BS_OK;
  default:
    return BS_ERR_TYPE;
  }
}

/* `.contains()`: membership for a container, superset for two sets, and a
 * substring test between two strings. */
static bs_status bs_contains(const bs_eval *e, bs_term hay, bs_term needle,
                             int *out) {
  uint32_t i;

  if (hay.kind == (uint8_t)BS_T_SET && needle.kind == (uint8_t)BS_T_SET) {
    /* Between two sets, whether the first is a superset of the second. */
    for (i = 0; i < needle.as.list.count; i++) {
      if (!bs_run_contains(e->w, hay.as.list.at, hay.as.list.count,
                           e->w->terms[needle.as.list.at + i])) {
        *out = 0;
        return BS_OK;
      }
    }
    *out = 1;
    return BS_OK;
  }

  switch (hay.kind) {
  case BS_T_SET:
  case BS_T_ARRAY:
    *out = bs_run_contains(e->w, hay.as.list.at, hay.as.list.count, needle);
    return BS_OK;
  case BS_T_MAP:
    /* For a map, whether the argument is one of its keys. Keys sit at even
     * offsets. Anything that is not an integer or a string cannot be a key,
     * and the answer is false rather than an error. */
    *out = 0;
    if (needle.kind != (uint8_t)BS_T_INTEGER &&
        needle.kind != (uint8_t)BS_T_STRING) {
      return BS_OK;
    }
    for (i = 0; i + 1U < hay.as.list.count; i += 2U) {
      if (bs_term_eq(e->w, e->w->terms[hay.as.list.at + i], needle)) {
        *out = 1;
        return BS_OK;
      }
    }
    return BS_OK;
  case BS_T_STRING: {
    bs_span h;
    bs_span n;
    size_t i2;
    if (needle.kind != (uint8_t)BS_T_STRING) {
      return BS_ERR_TYPE;
    }
    if (!bs_symtab_get(e->syms, hay.as.sym, &h) ||
        !bs_symtab_get(e->syms, needle.as.sym, &n)) {
      return BS_ERR_TYPE;
    }
    *out = 0;
    if (n.n > h.n) {
      return BS_OK;
    }
    for (i2 = 0; i2 + n.n <= h.n; i2++) {
      bs_span window;
      if (bs_span_slice(h, i2, n.n, &window) && bs_span_eq(window, n)) {
        *out = 1;
        return BS_OK;
      }
    }
    return BS_OK;
  }
  default:
    return BS_ERR_TYPE;
  }
}

/* Prefix and suffix, on strings and on arrays.
 *
 * The array case compares element by element rather than by run, because two
 * arrays holding equal values may hold them at different pool offsets. */
static bs_status bs_affix(const bs_eval *e, bs_term whole, bs_term part,
                          int suffix, int *out) {
  if (whole.kind != part.kind) {
    return BS_ERR_TYPE;
  }
  if (whole.kind == (uint8_t)BS_T_STRING) {
    bs_span h;
    bs_span n;
    bs_span window;
    if (!bs_symtab_get(e->syms, whole.as.sym, &h) ||
        !bs_symtab_get(e->syms, part.as.sym, &n)) {
      return BS_ERR_TYPE;
    }
    if (n.n > h.n) {
      *out = 0;
      return BS_OK;
    }
    *out = bs_span_slice(h, suffix ? (h.n - n.n) : 0U, n.n, &window) &&
           bs_span_eq(window, n);
    return BS_OK;
  }
  if (whole.kind == (uint8_t)BS_T_ARRAY) {
    uint32_t i;
    uint32_t off;
    if (part.as.list.count > whole.as.list.count) {
      *out = 0;
      return BS_OK;
    }
    off = suffix ? (whole.as.list.count - part.as.list.count) : 0U;
    for (i = 0; i < part.as.list.count; i++) {
      if (!bs_term_eq(e->w, e->w->terms[whole.as.list.at + off + i],
                      e->w->terms[part.as.list.at + i])) {
        *out = 0;
        return BS_OK;
      }
    }
    *out = 1;
    return BS_OK;
  }
  return BS_ERR_TYPE;
}

/* String concatenation.
 *
 * The result is a string, and strings are symbol indices, so the joined text
 * has to live somewhere and then be interned. It goes in the evaluation
 * arena, which is rewound when the expression finishes -- along with the
 * symbol table, so a symbol invented mid-expression does not outlive it and
 * leave the table holding a span into reclaimed scratch. */
static bs_status bs_str_concat(bs_eval *e, bs_term a, bs_term b, bs_term *out) {
  bs_span x;
  bs_span y;
  size_t total;
  uint8_t *buf;

  if (a.kind != (uint8_t)BS_T_STRING || b.kind != (uint8_t)BS_T_STRING) {
    return BS_ERR_TYPE;
  }
  if (!bs_symtab_get(e->syms, a.as.sym, &x) ||
      !bs_symtab_get(e->syms, b.as.sym, &y)) {
    return BS_ERR_TYPE;
  }
  if (!bs_size_add(x.n, y.n, &total)) {
    return BS_ERR_OVERFLOW;
  }
  buf = (uint8_t *)bs_arena_alloc(e->arena, (total == 0U) ? 1U : total, 1U);
  if (buf == NULL) {
    return BS_ERR_NOMEM;
  }
  if (x.n != 0U) {
    memcpy(buf, x.p, x.n);
  }
  if (y.n != 0U) {
    memcpy(&buf[x.n], y.p, y.n);
  }
  out->kind = (uint8_t)BS_T_STRING;
  return bs_symtab_intern(e->syms, bs_span_make(buf, total), &out->as.sym);
}

/* Intersection and union, which build a new set in the term pool.
 *
 * Both deduplicate as they go, because a set is a deduplicated collection and
 * a result that repeated an element would not compare equal to the same set
 * written by hand. */
static bs_status bs_set_op(bs_eval *e, bs_term a, bs_term b, int is_union,
                           bs_term *out) {
  uint32_t start;
  uint32_t i;

  if (a.kind != (uint8_t)BS_T_SET || b.kind != (uint8_t)BS_T_SET) {
    return BS_ERR_TYPE;
  }
  start = (uint32_t)e->w->term_count;

  for (i = 0; i < a.as.list.count; i++) {
    bs_term v = e->w->terms[a.as.list.at + i];
    int keep =
        is_union ? 1 : bs_run_contains(e->w, b.as.list.at, b.as.list.count, v);
    if (!keep ||
        bs_run_contains(e->w, start, (uint32_t)e->w->term_count - start, v)) {
      continue;
    }
    if (e->w->term_count >= e->w->term_cap) {
      return BS_ERR_NOMEM;
    }
    e->w->terms[e->w->term_count] = v;
    e->w->term_count++;
  }

  if (is_union) {
    for (i = 0; i < b.as.list.count; i++) {
      bs_term v = e->w->terms[b.as.list.at + i];
      if (bs_run_contains(e->w, start, (uint32_t)e->w->term_count - start, v)) {
        continue;
      }
      if (e->w->term_count >= e->w->term_cap) {
        return BS_ERR_NOMEM;
      }
      e->w->terms[e->w->term_count] = v;
      e->w->term_count++;
    }
  }

  out->kind = (uint8_t)BS_T_SET;
  out->as.list.at = start;
  out->as.list.count = (uint32_t)e->w->term_count - start;
  return BS_OK;
}

/* `.get()`: an element of an array by position, or a value of a map by key.
 * Out of range is `null` rather than an error, which is what makes `get`
 * usable without a length check in front of it. */
static bs_status bs_get(const bs_eval *e, bs_term container, bs_term key,
                        bs_term *out) {
  out->kind = (uint8_t)BS_T_NULL;
  if (container.kind == (uint8_t)BS_T_ARRAY) {
    if (key.kind != (uint8_t)BS_T_INTEGER) {
      return BS_ERR_TYPE;
    }
    if (key.as.integer < 0 ||
        (uint64_t)key.as.integer >= (uint64_t)container.as.list.count) {
      return BS_OK;
    }
    *out = e->w->terms[container.as.list.at + (uint32_t)key.as.integer];
    return BS_OK;
  }
  if (container.kind == (uint8_t)BS_T_MAP) {
    uint32_t i;
    if (key.kind != (uint8_t)BS_T_INTEGER && key.kind != (uint8_t)BS_T_STRING) {
      return BS_ERR_TYPE;
    }
    for (i = 0; i + 1U < container.as.list.count; i += 2U) {
      if (bs_term_eq(e->w, e->w->terms[container.as.list.at + i], key)) {
        *out = e->w->terms[container.as.list.at + i + 1U];
        return BS_OK;
      }
    }
    return BS_OK;
  }
  return BS_ERR_TYPE;
}

/* ---------------------------------------------------------------------------
 * The machine
 *
 * Postfix opcodes over a value stack. What makes this more than a loop is
 * closures: `a && b` encodes b as a zero-parameter closure so it can be
 * skipped, and `.all()` runs its closure once per element. Evaluating a
 * closure body from inside the evaluator would be recursion, which invariant
 * 2 forbids -- and forbids for a reason, since the nesting is chosen by
 * whoever sent the token.
 *
 * So the evaluator carries an explicit frame stack. A frame is one opcode run
 * being executed, plus at most one *pending* operator: the one that asked for
 * a closure body to be run and is waiting for its result. When a body frame
 * finishes, its value is on the stack and the parent's pending operator picks
 * it up -- exactly what a return value and a resumed call would do, laid out
 * where it can be bounded.
 * ------------------------------------------------------------------------ */

#define BS_PEND_NONE 0U
#define BS_PEND_LAZY 1U
#define BS_PEND_ALL 2U
#define BS_PEND_ANY 3U
#define BS_PEND_TRY 4U

#ifndef BS_MAX_EVAL_FRAMES
#define BS_MAX_EVAL_FRAMES 16
#endif

#ifndef BS_MAX_BINDINGS
#define BS_MAX_BINDINGS 32
#endif

typedef struct bs_frame {
  bs_expr expr;
  uint32_t pc;
  size_t bind_base; /* bindings above this belong to this frame */
  size_t sp_base;   /* value stack height when the pending child was entered */
  uint8_t pending;  /* the operator waiting on this frame's child */
  bs_term subject;  /* the container being walked, for all and any */
  bs_term fallback; /* what try_or returns when its closure fails */
  uint32_t index;   /* position in `subject` */
  uint32_t closure; /* the closure op being applied */
} bs_frame;

typedef struct bs_machine {
  bs_frame frames[BS_MAX_EVAL_FRAMES];
  bs_binding binds[BS_MAX_BINDINGS];
  size_t depth;
  size_t bind_count;
} bs_machine;

/* Push a frame for a closure's body, binding its parameter when it takes one.
 */
/* How many elements a container has, and what the nth one is.
 *
 * A map is walked as key-value pairs, and its keys and values already sit
 * adjacently in the term pool -- so the pair a closure receives is an array
 * term pointing at those two, costing nothing to build and nothing to free.
 * This is why the run holds them adjacently rather than in two runs. */
static uint32_t bs_iter_count(bs_term subject) {
  return (subject.kind == (uint8_t)BS_T_MAP) ? (subject.as.list.count / 2U)
                                             : subject.as.list.count;
}

static bs_term bs_iter_at(const bs_world *w, bs_term subject, uint32_t index) {
  bs_term out;
  if (subject.kind != (uint8_t)BS_T_MAP) {
    return w->terms[subject.as.list.at + index];
  }
  out.kind = (uint8_t)BS_T_ARRAY;
  out.as.list.at = subject.as.list.at + (2U * index);
  out.as.list.count = 2U;
  return out;
}

static bs_status bs_enter_closure(bs_eval *e, bs_machine *m,
                                  uint32_t closure_op, const bs_term *arg) {
  const bs_op *op;
  size_t base = m->bind_count;

  if (m->depth >= (size_t)BS_MAX_EVAL_FRAMES) {
    return BS_ERR_DEPTH;
  }
  if ((size_t)closure_op >= e->w->op_count) {
    return BS_ERR_MALFORMED;
  }
  op = &e->w->ops[closure_op];
  if (op->tag != (uint8_t)BS_OP_CLOSURE) {
    return BS_ERR_MALFORMED;
  }

  if (arg != NULL) {
    uint64_t sym;
    size_t i;
    if (op->as.closure.count != 1U) {
      return BS_ERR_MALFORMED; /* all and any pass exactly one element */
    }
    if ((size_t)op->as.closure.at >= e->w->sym_count) {
      return BS_ERR_MALFORMED;
    }
    if (m->bind_count >= (size_t)BS_MAX_BINDINGS) {
      return BS_ERR_LIMIT;
    }
    sym = e->w->syms[op->as.closure.at];
    /* "Shadowing (defining a parameter with the same name as a variable
     * already in scope) is not allowed and should be rejected before starting
     * the evaluation." */
    for (i = 0; i < m->bind_count; i++) {
      if (m->binds[i].sym == sym) {
        return BS_ERR_SHADOWED;
      }
    }
    m->binds[m->bind_count].sym = sym;
    m->binds[m->bind_count].value = *arg;
    m->bind_count++;
  } else if (op->as.closure.count != 0U) {
    /* A short-circuiting operator's right-hand side takes no parameters. */
    return BS_ERR_MALFORMED;
  }

  m->frames[m->depth].expr = op->as.closure.body;
  m->frames[m->depth].pc = 0;
  m->frames[m->depth].bind_base = base;
  m->frames[m->depth].pending = (uint8_t)BS_PEND_NONE;
  m->frames[m->depth].index = 0;
  m->frames[m->depth].closure = 0;
  m->depth++;
  e->bindings = m->binds;
  e->binding_count = m->bind_count;
  return BS_OK;
}

/* Evaluate one expression to a boolean. */
static bs_status bs_expr_eval(bs_eval *e, bs_expr expr, int *out) {
  bs_machine m;
  size_t i;
  bs_status st;

  if (e->binding_count > (size_t)BS_MAX_BINDINGS) {
    st = BS_ERR_LIMIT;
    goto failed;
  }
  /* The caller's bindings sit at the bottom, visible to every frame. */
  for (i = 0; i < e->binding_count; i++) {
    m.binds[i] = e->bindings[i];
  }
  m.bind_count = e->binding_count;
  m.depth = 1;
  e->sp = 0;
  e->bindings = m.binds;
  e->binding_count = m.bind_count;

  m.frames[0].expr = expr;
  m.frames[0].pc = 0;
  m.frames[0].bind_base = m.bind_count;
  m.frames[0].pending = (uint8_t)BS_PEND_NONE;
  m.frames[0].sp_base = 0;
  m.frames[0].index = 0;
  m.frames[0].closure = 0;

again:
  while (m.depth > 0U) {
    bs_frame *f = &m.frames[m.depth - 1U];
    const bs_op *op;
    bs_term a;
    bs_term b;
    bs_term result;
    int flag = 0;
    int cmp = 0;
    int64_t n = 0;

    /* A closure body has finished; its value is on the stack, and the
     * operator that asked for it decides what that means. */
    if (f->pending != (uint8_t)BS_PEND_NONE) {
      uint8_t pend = f->pending;
      st = bs_pop(e, &a);
      if (st != BS_OK) {
        goto failed;
      }
      m.bind_count = f->bind_base;
      e->binding_count = m.bind_count;

      if (pend == (uint8_t)BS_PEND_LAZY || pend == (uint8_t)BS_PEND_TRY) {
        if (pend == (uint8_t)BS_PEND_LAZY && a.kind != (uint8_t)BS_T_BOOL) {
          st = BS_ERR_TYPE;
          goto failed;
        }
        f->pending = (uint8_t)BS_PEND_NONE;
        st = bs_push(e, a);
        if (st != BS_OK) {
          goto failed;
        }
        continue;
      }

      if (a.kind != (uint8_t)BS_T_BOOL) {
        st = BS_ERR_TYPE;
        goto failed;
      }
      if ((pend == (uint8_t)BS_PEND_ALL && !a.as.boolean) ||
          (pend == (uint8_t)BS_PEND_ANY && a.as.boolean)) {
        /* Decided: the rest of the container cannot change the answer. */
        f->pending = (uint8_t)BS_PEND_NONE;
        st = bs_push(e, bs_bool(pend == (uint8_t)BS_PEND_ANY));
        if (st != BS_OK) {
          goto failed;
        }
        continue;
      }
      f->index++;
      if (f->index >= bs_iter_count(f->subject)) {
        f->pending = (uint8_t)BS_PEND_NONE;
        st = bs_push(e, bs_bool(pend == (uint8_t)BS_PEND_ALL));
        if (st != BS_OK) {
          goto failed;
        }
        continue;
      }
      {
        bs_term item = bs_iter_at(e->w, f->subject, f->index);
        st = bs_enter_closure(e, &m, f->closure, &item);
      }
      if (st != BS_OK) {
        goto failed;
      }
      continue;
    }

    if (f->pc >= f->expr.count) {
      m.depth--;
      continue;
    }
    if ((size_t)f->expr.at + (size_t)f->pc >= e->w->op_count) {
      st = BS_ERR_MALFORMED;
      goto failed;
    }
    op = &e->w->ops[f->expr.at + f->pc];
    f->pc++;

    if (op->tag == (uint8_t)BS_OP_VALUE) {
      if ((size_t)op->as.term >= e->w->term_count) {
        st = BS_ERR_MALFORMED;
        goto failed;
      }
      st = bs_resolve(e, e->w->terms[op->as.term], &a);
      if (st != BS_OK) {
        goto failed;
      }
      st = bs_push(e, a);
      if (st != BS_OK) {
        goto failed;
      }
      continue;
    }

    if (op->tag == (uint8_t)BS_OP_CLOSURE) {
      /* A closure is a value until an operator decides what to do with it. */
      result.kind = (uint8_t)BS_T_CLOSURE;
      result.as.list.at = (uint32_t)((size_t)f->expr.at + (size_t)f->pc - 1U);
      result.as.list.count = op->as.closure.count;
      st = bs_push(e, result);
      if (st != BS_OK) {
        goto failed;
      }
      continue;
    }

    if (op->tag == (uint8_t)BS_OP_UNARY) {
      st = bs_pop(e, &a);
      if (st != BS_OK) {
        goto failed;
      }
      switch (op->kind) {
      case BS_U_NEGATE:
        if (a.kind != (uint8_t)BS_T_BOOL) {
          st = BS_ERR_TYPE;
          goto failed;
        }
        st = bs_push(e, bs_bool(!a.as.boolean));
        break;
      case BS_U_PARENS:
        st = bs_push(e, a);
        break;
      case BS_U_LENGTH:
        st = bs_length(e, a, &n);
        if (st == BS_OK) {
          st = bs_push(e, bs_int(n));
        }
        break;
      case BS_U_TYPEOF:
        st = bs_typeof(e, a, &result);
        if (st == BS_OK) {
          st = bs_push(e, result);
        }
        break;
      default:
        st = BS_ERR_UNSUPPORTED;
        goto failed; /* external calls */
      }
      if (st != BS_OK) {
        goto failed;
      }
      continue;
    }

    /* Binary. The right-hand side was pushed last. */
    st = bs_pop(e, &b);
    if (st != BS_OK) {
      goto failed;
    }
    st = bs_pop(e, &a);
    if (st != BS_OK) {
      goto failed;
    }

    switch (op->kind) {
    case 0U:
    case 1U:
    case 2U:
    case 3U:
      st = bs_compare(a, b, &cmp);
      if (st != BS_OK) {
        goto failed;
      }
      flag = (op->kind == 0U)   ? (cmp < 0)
             : (op->kind == 1U) ? (cmp > 0)
             : (op->kind == 2U) ? (cmp <= 0)
                                : (cmp >= 0);
      st = bs_push(e, bs_bool(flag));
      break;

    case 4U:
    case 20U:
      /* Strict: comparing different types is an error, not false. */
      if (a.kind != b.kind) {
        st = BS_ERR_TYPE;
        goto failed;
      }
      flag = bs_term_eq(e->w, a, b);
      st = bs_push(e, bs_bool((op->kind == 4U) ? flag : !flag));
      break;

    case 21U:
    case 22U:
      /* Lenient: different types are simply unequal. */
      flag = (a.kind == b.kind) && bs_term_eq(e->w, a, b);
      st = bs_push(e, bs_bool((op->kind == 21U) ? flag : !flag));
      break;

    case 5U:
      st = bs_contains(e, a, b, &flag);
      if (st == BS_OK) {
        st = bs_push(e, bs_bool(flag));
      }
      break;

    case 8U: /* .matches() */
      if (a.kind != (uint8_t)BS_T_STRING || b.kind != (uint8_t)BS_T_STRING) {
        st = BS_ERR_TYPE;
        goto failed;
      }
      st = bs_re_match(e->syms, e->arena, a, b, &flag);
      if (st == BS_OK) {
        st = bs_push(e, bs_bool(flag));
      }
      break;

    case 6U: /* .starts_with() */
    case 7U: /* .ends_with() */
      st = bs_affix(e, a, b, (op->kind == 7U), &flag);
      if (st == BS_OK) {
        st = bs_push(e, bs_bool(flag));
      }
      break;

    case 15U: /* .intersection() */
    case 16U: /* .union() */
      st = bs_set_op(e, a, b, (op->kind == 16U), &result);
      if (st == BS_OK) {
        st = bs_push(e, result);
      }
      break;

    case 9U:
    case 10U:
    case 11U:
    case 12U:
      if (op->kind == 9U && a.kind == (uint8_t)BS_T_STRING) {
        /* `+` joins strings as well as adding integers. */
        st = bs_str_concat(e, a, b, &result);
        if (st == BS_OK) {
          st = bs_push(e, result);
        }
        break;
      }
      if (a.kind != (uint8_t)BS_T_INTEGER || b.kind != (uint8_t)BS_T_INTEGER) {
        /* A plain `return` here would step around the try_or unwinding
         * below, which is exactly what an error inside a try_or must not do. */
        st = BS_ERR_TYPE;
        goto failed;
      }
      st = bs_arith(op->kind, a.as.integer, b.as.integer, &n);
      if (st == BS_OK) {
        st = bs_push(e, bs_int(n));
      }
      break;

    case 13U:
    case 14U:
      if (a.kind != (uint8_t)BS_T_BOOL || b.kind != (uint8_t)BS_T_BOOL) {
        st = BS_ERR_TYPE;
        goto failed;
      }
      flag = (op->kind == 13U) ? (a.as.boolean && b.as.boolean)
                               : (a.as.boolean || b.as.boolean);
      st = bs_push(e, bs_bool(flag));
      break;

    case 17U:
    case 18U:
    case 19U:
      if (a.kind != (uint8_t)BS_T_INTEGER || b.kind != (uint8_t)BS_T_INTEGER) {
        st = BS_ERR_TYPE;
        goto failed;
      }
      {
        uint64_t x = (uint64_t)a.as.integer;
        uint64_t y = (uint64_t)b.as.integer;
        uint64_t r = (op->kind == 17U)   ? (x & y)
                     : (op->kind == 18U) ? (x | y)
                                         : (x ^ y);
        st = bs_push(e, bs_int((int64_t)r));
      }
      break;

    case 23U: /* && short-circuiting */
    case 24U: /* || short-circuiting */
      if (a.kind != (uint8_t)BS_T_BOOL || b.kind != (uint8_t)BS_T_CLOSURE) {
        st = BS_ERR_TYPE;
        goto failed;
      }
      /* The whole point: the right-hand side is not evaluated when the left
       * already decides the answer. */
      if ((op->kind == 23U && !a.as.boolean) ||
          (op->kind == 24U && a.as.boolean)) {
        st = bs_push(e, a);
        break;
      }
      f->pending = (uint8_t)BS_PEND_LAZY;
      f->bind_base = m.bind_count;
      f->sp_base = e->sp;
      st = bs_enter_closure(e, &m, b.as.list.at, NULL);
      break;

    case 25U: /* .all() */
    case 26U: /* .any() */
      if (b.kind != (uint8_t)BS_T_CLOSURE) {
        st = BS_ERR_TYPE;
        goto failed;
      }
      if (a.kind != (uint8_t)BS_T_SET && a.kind != (uint8_t)BS_T_ARRAY &&
          a.kind != (uint8_t)BS_T_MAP) {
        st = BS_ERR_TYPE;
        goto failed;
      }
      if (bs_iter_count(a) == 0U) {
        /* Vacuously true for all, vacuously false for any. */
        st = bs_push(e, bs_bool(op->kind == 25U));
        break;
      }
      f->pending =
          (op->kind == 25U) ? (uint8_t)BS_PEND_ALL : (uint8_t)BS_PEND_ANY;
      f->subject = a;
      f->index = 0;
      f->closure = b.as.list.at;
      f->bind_base = m.bind_count;
      f->sp_base = e->sp;
      {
        bs_term item = bs_iter_at(e->w, a, 0U);
        st = bs_enter_closure(e, &m, b.as.list.at, &item);
      }
      break;

    case 27U:
      st = bs_get(e, a, b, &result);
      if (st == BS_OK) {
        st = bs_push(e, result);
      }
      break;

    case 29U: /* .try_or() */
      /* The closure is the left operand and the fallback the right, so the
       * fallback is already evaluated when we get here -- which is fine,
       * since it is a value and cannot fail. */
      if (a.kind != (uint8_t)BS_T_CLOSURE) {
        st = BS_ERR_TYPE;
        goto failed;
      }
      f->pending = (uint8_t)BS_PEND_TRY;
      f->fallback = b;
      f->bind_base = m.bind_count;
      f->sp_base = e->sp;
      st = bs_enter_closure(e, &m, a.as.list.at, NULL);
      break;

    default:
      /* String operations, set algebra and external calls. Refused rather
       * than approximated: an operator that silently returns false is a check
       * that silently passes. */
      st = BS_ERR_UNSUPPORTED;
      goto failed;
    }
    if (st != BS_OK) {
      goto failed;
    }
  }

  if (e->sp != 1U) {
    st = BS_ERR_MALFORMED;
    goto failed;
  }
  if (e->stack[0].kind != (uint8_t)BS_T_BOOL) {
    /* "After executing, the stack must contain only one value, of the boolean
     * type." An expression that leaves an integer is not false; it is wrong. */
    st = BS_ERR_TYPE;
    goto failed;
  }
  *out = e->stack[0].as.boolean;
  return BS_OK;

failed:
  /* `try_or` is the one operator that turns a failure into a value. Unwind to
   * the nearest frame waiting on one, restore the stack to where that frame
   * left it, and hand it the fallback -- the closure's own error goes no
   * further. Without a try_or in scope the failure is the answer. */
  while (m.depth > 0U) {
    bs_frame *g = &m.frames[m.depth - 1U];
    if (g->pending == (uint8_t)BS_PEND_TRY) {
      g->pending = (uint8_t)BS_PEND_NONE;
      m.bind_count = g->bind_base;
      e->binding_count = m.bind_count;
      e->sp = g->sp_base;
      if (bs_push(e, g->fallback) != BS_OK) {
        return BS_ERR_LIMIT;
      }
      goto again;
    }
    m.depth--;
  }
  return st;
}

/* Evaluate one expression of the world, with the given variable bindings. */
BS_API bs_status bs_expr_evaluate(bs_world *w, bs_symtab *syms, bs_arena *a,
                                  bs_expr expr, const bs_binding *bindings,
                                  size_t binding_count, int *out) {
  bs_eval e;
  size_t term_mark;
  size_t sym_mark;
  size_t arena_mark;
  bs_status st;

  if (w == NULL || syms == NULL || a == NULL || out == NULL) {
    return BS_ERR_ARGUMENT;
  }
  e.w = w;
  e.syms = syms;
  e.arena = a;
  e.bindings = bindings;
  e.binding_count = binding_count;
  e.sp = 0;

  /* An expression leaves exactly one boolean behind, so every value it built
   * on the way -- a joined string, an intersected set, the symbol either of
   * them needed -- is unreachable the moment it returns. Giving all of it
   * back here is what stops a block with twenty expressions from costing
   * twenty times what one costs.
   *
   * The symbol table is rewound with the rest, and it has to be: its entries
   * are spans, and a symbol interned from arena scratch would otherwise
   * outlive the bytes it points at. */
  term_mark = w->term_count;
  sym_mark = syms->count;
  arena_mark = bs_arena_mark(a);

  st = bs_expr_eval(&e, expr, out);

  /* cppcheck-suppress redundantAssignment ; only redundant for an expression
   * that built nothing. One that intersects two sets or joins two strings
   * moves both counters, and cppcheck cannot see that path from here. */
  w->term_count = term_mark;
  /* cppcheck-suppress redundantAssignment ; as above */
  syms->count = sym_mark;
  bs_arena_rewind(a, arena_mark);
  return st;
}

/* ===========================================================================
 * 130_engine.inc
 * ======================================================================== */

/* ---------------------------------------------------------------------------
 * Datalog evaluation
 *
 * Repeatedly apply every rule to every combination of facts it can match,
 * until a round produces nothing new. That is the whole algorithm; what makes
 * it worth explaining is the two constraints around it.
 *
 * The first is origin. Every fact carries the set of blocks that allowed it to
 * exist, and a derived fact's origin is the union of the rule's own block and
 * the origins of every fact it matched. A rule only sees facts whose origin is
 * a *subset* of what it trusts -- not merely overlapping. A fact derived from
 * blocks {0, 2} is invisible to a rule trusting only {0}, even though part of
 * it came from a block that rule accepts. This is the whole mechanism that
 * stops an appended block from granting itself rights, and getting it wrong
 * does not fail: it silently authorizes.
 *
 * The second is that matching N body predicates is N nested loops, and the
 * depth is a property of the rule rather than of this code -- so it cannot be
 * written as nested loops, and invariant 2 forbids writing it as recursion.
 * It is an explicit backtracking walk instead: one frame per body position,
 * each remembering which fact it is trying and how many bindings it made, so
 * undoing a choice is truncating a list.
 * ------------------------------------------------------------------------ */

/* Predicates in one rule body. Thirty-two rather than sixteen because
 * test022 writes a check naming all twenty-eight default symbols in a single
 * body, and a limit the specification's own samples exceed is a bug rather
 * than a bound. */
#ifndef BS_MAX_BODY
#define BS_MAX_BODY 32
#endif

typedef struct bs_matchframe {
  size_t fact;      /* the candidate being tried at this body position */
  size_t bind_mark; /* how many bindings existed before it bound any */
  bs_origin origin; /* origins accumulated through this position */
} bs_matchframe;

/* Do two facts state the same thing? Origins are compared too: the same
 * sentence derived through different blocks is a different fact, because
 * scoping asks where it came from. */
static int bs_fact_same(const bs_world *w, const bs_fact *a, const bs_fact *b) {
  uint32_t i;
  if (a->pred.name != b->pred.name || a->pred.count != b->pred.count ||
      a->origin != b->origin) {
    return 0;
  }
  for (i = 0; i < a->pred.count; i++) {
    if (!bs_term_eq(w, w->terms[a->pred.at + i], w->terms[b->pred.at + i])) {
      return 0;
    }
  }
  return 1;
}

/* Match one predicate against one fact, extending `binds`.
 *
 * A variable already bound must match what it is bound to; an unbound one
 * takes the fact's value. Anything else must be equal outright. On failure
 * the caller truncates the binding list back to its mark, which is why
 * nothing needs undoing here. */
static int bs_unify(const bs_world *w, const bs_predicate *p, const bs_fact *f,
                    bs_binding *binds, size_t *count, size_t cap) {
  uint32_t i;

  if (p->name != f->pred.name || p->count != f->pred.count) {
    return 0;
  }
  for (i = 0; i < p->count; i++) {
    bs_term pt = w->terms[p->at + i];
    bs_term ft = w->terms[f->pred.at + i];

    if (pt.kind == (uint8_t)BS_T_VARIABLE) {
      size_t k;
      int bound = 0;
      for (k = 0; k < *count; k++) {
        if (binds[k].sym == pt.as.sym) {
          if (!bs_term_eq(w, binds[k].value, ft)) {
            return 0;
          }
          bound = 1;
          break;
        }
      }
      if (!bound) {
        if (*count >= cap) {
          return 0; /* more distinct variables than this build will bind */
        }
        binds[*count].sym = pt.as.sym;
        binds[*count].value = ft;
        (*count)++;
      }
      continue;
    }
    if (!bs_term_eq(w, pt, ft)) {
      return 0;
    }
  }
  return 1;
}

/* Build the fact a rule's head states, substituting the bindings. */
static bs_status bs_head_instantiate(bs_world *w, const bs_rule *r,
                                     const bs_binding *binds, size_t count,
                                     bs_origin origin, bs_fact *out) {
  uint32_t at;
  uint32_t i;
  bs_status st = bs_pool_reserve_terms(w, r->head.count, &at);

  if (st != BS_OK) {
    return st;
  }
  for (i = 0; i < r->head.count; i++) {
    bs_term t = w->terms[r->head.at + i];
    if (t.kind == (uint8_t)BS_T_VARIABLE) {
      size_t k;
      int bound = 0;
      for (k = 0; k < count; k++) {
        if (binds[k].sym == t.as.sym) {
          t = binds[k].value;
          bound = 1;
          break;
        }
      }
      if (!bound) {
        /* Unreachable in practice: bs_rule_bound rejects such a rule when it
         * is loaded, which is what the specification asks for -- an invalid
         * rule is invalid whether or not its body happens to match. Kept as
         * a guard because a fact with a hole in it is not a fact. */
        return BS_ERR_UNBOUND;
      }
    }
    w->terms[at + i] = t;
  }
  out->pred.name = r->head.name;
  out->pred.at = at;
  out->pred.count = r->head.count;
  out->origin = origin;
  return BS_OK;
}

/* The origin bit a rule's own block stands for. The authorizer has a bit
 * reserved rather than a position, so its index is never shifted. */
static bs_origin bs_rule_origin(const bs_rule *r) {
  return ((size_t)r->block >= (size_t)BS_MAX_BLOCKS) ? BS_ORIGIN_AUTHORIZER
                                                     : BS_ORIGIN_ONE(r->block);
}

/* The backtracking walk, as a resumable iterator.
 *
 * A rule and a query ask the same question -- which combinations of facts
 * match this body -- and differ only in what they do with each answer. One
 * machine yields the answers; the callers decide. Written as a callback it
 * would be an indirect call, which the stack measurement cannot follow, so it
 * is resumable state instead: `bs_solver_next` picks up exactly where the
 * previous answer left off. */
typedef struct bs_solver {
  bs_matchframe frames[BS_MAX_BODY];
  bs_binding binds[BS_MAX_BINDINGS];
  size_t bind_count;
  size_t level;
  size_t base_facts; /* facts that existed when the walk started */
  int started;
  int done;
} bs_solver;

static bs_status bs_solver_init(bs_solver *s, const bs_world *w,
                                const bs_rule *r) {
  if (r->body_count > (size_t)BS_MAX_BODY) {
    return BS_ERR_LIMIT;
  }
  s->bind_count = 0;
  s->level = 0;
  /* Only facts that existed when this walk started are candidates: a rule
   * must not consume what it produced in the same pass, or a recursive rule
   * would run away inside one round instead of converging over several. */
  s->base_facts = w->fact_count;
  s->started = 0;
  s->done = 0;
  s->frames[0].fact = 0;
  s->frames[0].bind_mark = 0;
  s->frames[0].origin = bs_rule_origin(r);
  return BS_OK;
}

/* Advance to the next combination matching the body. `*found` is 0 when
 * there are none left; the bindings are then meaningless. */
static void bs_solver_next(const bs_world *w, const bs_rule *r, bs_solver *s,
                           int *found) {
  *found = 0;
  if (s->done) {
    return;
  }
  if (s->started) {
    /* Resume by undoing the last answer's final choice. */
    if (s->level == 0U) {
      s->done = 1;
      return;
    }
    s->level--;
    s->bind_count = s->frames[s->level].bind_mark;
    s->frames[s->level].fact++;
  }
  s->started = 1;

  for (;;) {
    const bs_predicate *p;
    bs_origin prev;
    int matched = 0;

    if (s->level == r->body_count) {
      *found = 1;
      return;
    }

    p = &w->preds[r->body_at + s->level];
    prev =
        (s->level == 0U) ? bs_rule_origin(r) : s->frames[s->level - 1U].origin;

    while (s->frames[s->level].fact < s->base_facts) {
      const bs_fact *f = &w->facts[s->frames[s->level].fact];
      size_t mark = s->bind_count;

      /* "Only facts whose origin is a subset of these trusted origins are
       * matched." A subset, not an overlap. */
      if ((f->origin & ~r->trust) != BS_ORIGIN_NONE) {
        s->frames[s->level].fact++;
        continue;
      }
      if (!bs_unify(w, p, f, s->binds, &s->bind_count,
                    (size_t)BS_MAX_BINDINGS)) {
        s->bind_count = mark;
        s->frames[s->level].fact++;
        continue;
      }
      s->frames[s->level].bind_mark = mark;
      s->frames[s->level].origin = prev | f->origin;
      matched = 1;
      break;
    }

    if (!matched) {
      if (s->level == 0U) {
        s->done = 1;
        return;
      }
      s->level--;
      s->bind_count = s->frames[s->level].bind_mark;
      s->frames[s->level].fact++;
      continue;
    }

    s->level++;
    if (s->level < r->body_count) {
      s->frames[s->level].fact = 0;
      s->frames[s->level].bind_mark = s->bind_count;
    }
  }
}

/* The origin of the answer the solver is currently sitting on. */
static bs_origin bs_solver_origin(const bs_solver *s, const bs_rule *r) {
  return (r->body_count == 0U) ? bs_rule_origin(r)
                               : s->frames[r->body_count - 1U].origin;
}

/* Do this answer's expressions all hold? */
static bs_status bs_solver_expressions(bs_world *w, bs_symtab *syms,
                                       bs_arena *a, const bs_rule *r,
                                       const bs_solver *s, int *keep) {
  uint32_t k;

  *keep = 1;
  for (k = 0; k < r->expr_count && *keep; k++) {
    int v = 0;
    /* An expression that errors is not a failed match: the specification
     * reports overflow, type errors and shadowing as execution failures of
     * the whole evaluation. */
    bs_status st = bs_expr_evaluate(w, syms, a, w->exprs[r->expr_at + k],
                                    s->binds, s->bind_count, &v);
    if (st != BS_OK) {
      return st;
    }
    *keep = v;
  }
  return BS_OK;
}

/* Apply one rule to everything currently known, appending what it derives.
 *
 * `produced` counts the facts that were not already present, which is what
 * tells the fixpoint loop whether anything changed. */
static bs_status bs_rule_apply(bs_world *w, bs_symtab *syms, bs_arena *a,
                               const bs_rule *r, bs_solver *sv,
                               size_t *produced) {
  bs_status st = bs_solver_init(sv, w, r);

  if (st != BS_OK) {
    return st;
  }
  for (;;) {
    int found = 0;
    int keep = 0;
    bs_fact candidate;
    size_t term_mark;
    size_t i;
    int seen = 0;

    bs_solver_next(w, r, sv, &found);
    if (!found) {
      return BS_OK;
    }
    st = bs_solver_expressions(w, syms, a, r, sv, &keep);
    if (st != BS_OK) {
      return st;
    }
    if (!keep) {
      continue;
    }

    term_mark = w->term_count;
    st = bs_head_instantiate(w, r, sv->binds, sv->bind_count,
                             bs_solver_origin(sv, r), &candidate);
    if (st != BS_OK) {
      return st;
    }
    for (i = 0; i < w->fact_count; i++) {
      if (bs_fact_same(w, &w->facts[i], &candidate)) {
        seen = 1;
        break;
      }
    }
    if (seen) {
      /* Already known. Give back the terms the instantiation reserved, or a
       * rule that fires a thousand times costs a thousand copies of the same
       * fact. */
      w->term_count = term_mark;
      continue;
    }
    if (w->fact_count >= w->fact_cap) {
      return BS_ERR_NOMEM;
    }
    w->facts[w->fact_count] = candidate;
    w->fact_count++;
    (*produced)++;
  }
}

/* Run every rule to a fixpoint, with a solver the caller owns.
 *
 * The solver holds one frame per body position and one slot per binding --
 * something over a kilobyte -- so it lives in the arena and is passed down
 * rather than declared at each level. Two of them on one call path was most
 * of a stack budget for no reason: they are never live at the same time.
 *
 * Bounded by iterations rather than by time, which is what the specification's
 * own run limits do: a token cannot buy itself an unbounded evaluation, and
 * hitting the bound is a clean error rather than a hang. */
static bs_status bs_world_run_with(bs_world *w, bs_symtab *syms, bs_arena *a,
                                   size_t max_iterations, bs_solver *sv) {
  size_t round;

  if (max_iterations == 0U) {
    max_iterations = bs_limits_default().max_iterations;
  }

  for (round = 0; round < max_iterations; round++) {
    size_t produced = 0;
    size_t i;

    for (i = 0; i < w->rule_count; i++) {
      bs_status st;
      if (w->rules[i].is_query) {
        continue; /* a check's query is asked later, not derived from */
      }
      st = bs_rule_apply(w, syms, a, &w->rules[i], sv, &produced);
      if (st != BS_OK) {
        return st;
      }
    }
    if (produced == 0U) {
      return BS_OK; /* nothing changed: the fixpoint */
    }
  }
  return BS_ERR_LIMIT;
}

static bs_solver *bs_solver_new(bs_arena *a) {
  return (bs_solver *)bs_arena_alloc(a, sizeof(bs_solver), BS_ALIGN_MAX);
}

BS_API bs_status bs_world_run(bs_world *w, bs_symtab *syms, bs_arena *a,
                              size_t max_iterations) {
  bs_solver *sv;

  if (w == NULL || syms == NULL || a == NULL) {
    return BS_ERR_ARGUMENT;
  }
  sv = bs_solver_new(a);
  if (sv == NULL) {
    return BS_ERR_NOMEM;
  }
  return bs_world_run_with(w, syms, a, max_iterations, sv);
}

/* ===========================================================================
 * 135_lex.inc
 * ======================================================================== */

/* ---------------------------------------------------------------------------
 * Lexing Datalog source
 *
 * The authorizer's rules, checks and policies arrive as text -- from a
 * configuration file, a request handler, or whatever the embedding decides.
 * That text is trusted rather more than a token is, but only rather: it is
 * still the last thing between a caller's intent and an authorization
 * decision, so it is read strictly and refused loudly.
 *
 * The lexer produces one pass of tokens over a caller-owned buffer. Nothing
 * is copied: every identifier and string is a span into the source, which is
 * why the source has to outlive the parse.
 * ------------------------------------------------------------------------ */

#define BS_TK_EOF 0U
#define BS_TK_IDENT 1U    /* a name, possibly with a `::` namespace */
#define BS_TK_VARIABLE 2U /* `$name` */
#define BS_TK_STRING 3U
#define BS_TK_INTEGER 4U
#define BS_TK_DATE 5U
#define BS_TK_BYTES 6U /* `hex:...` */
#define BS_TK_KEY 7U   /* `ed25519/...` */
#define BS_TK_PUNCT 8U /* everything spelled with symbols */

/* Punctuation and operators, as one enumeration so the parser can switch on
 * a single value rather than re-examining text. */
#define BS_P_LPAREN 1U
#define BS_P_RPAREN 2U
#define BS_P_LBRACKET 3U
#define BS_P_RBRACKET 4U
#define BS_P_LBRACE 5U
#define BS_P_RBRACE 6U
#define BS_P_COMMA 7U
#define BS_P_SEMI 8U
#define BS_P_COLON 9U
#define BS_P_DOT 10U
#define BS_P_ARROW 11U
#define BS_P_LEFTARROW 12U /* `<-` */
#define BS_P_BANG 13U
#define BS_P_LT 14U
#define BS_P_GT 15U
#define BS_P_LE 16U
#define BS_P_GE 17U
#define BS_P_EQ3 18U  /* === */
#define BS_P_NEQ3 19U /* !== */
#define BS_P_EQ2 20U  /* == */
#define BS_P_NEQ2 21U /* != */
#define BS_P_PLUS 22U
#define BS_P_MINUS 23U
#define BS_P_STAR 24U
#define BS_P_SLASH 25U
#define BS_P_AND2 26U  /* && */
#define BS_P_OR2 27U   /* || */
#define BS_P_AND2E 28U /* &&! eager */
#define BS_P_OR2E 29U  /* ||! eager */
#define BS_P_AMP 30U
#define BS_P_PIPE 31U
#define BS_P_CARET 32U

typedef struct bs_token_t {
  uint8_t kind;
  uint8_t punct;   /* BS_P_*, when kind is BS_TK_PUNCT */
  bs_span text;    /* identifiers, variables, strings: the bytes themselves */
  int64_t integer; /* BS_TK_INTEGER */
  uint64_t date;   /* BS_TK_DATE, seconds since the epoch */
  size_t at;       /* offset in the source, for reporting */
} bs_token_t;

typedef struct bs_lexer {
  bs_span src;
  size_t pos;
} bs_lexer;

static int bs_is_space(uint8_t c) {
  return c == (uint8_t)' ' || c == (uint8_t)'\t' || c == (uint8_t)'\n' ||
         c == (uint8_t)'\r';
}

static int bs_is_digit(uint8_t c) {
  return c >= (uint8_t)'0' && c <= (uint8_t)'9';
}

static int bs_is_name_start(uint8_t c) {
  return (c >= (uint8_t)'a' && c <= (uint8_t)'z') ||
         (c >= (uint8_t)'A' && c <= (uint8_t)'Z') || c == (uint8_t)'_';
}

static int bs_is_name(uint8_t c) {
  return bs_is_name_start(c) || bs_is_digit(c);
}

static int bs_hex_digit(uint8_t c, uint8_t *out) {
  if (bs_is_digit(c)) {
    *out = (uint8_t)(c - (uint8_t)'0');
    return 1;
  }
  if (c >= (uint8_t)'a' && c <= (uint8_t)'f') {
    *out = (uint8_t)(c - (uint8_t)'a' + 10U);
    return 1;
  }
  if (c >= (uint8_t)'A' && c <= (uint8_t)'F') {
    *out = (uint8_t)(c - (uint8_t)'A' + 10U);
    return 1;
  }
  return 0;
}

/* Skip whitespace and `//` comments. */
static void bs_lex_skip(bs_lexer *l) {
  for (;;) {
    uint8_t c = 0;
    if (!bs_span_at(l->src, l->pos, &c)) {
      return;
    }
    if (bs_is_space(c)) {
      l->pos++;
      continue;
    }
    if (c == (uint8_t)'/') {
      uint8_t d = 0;
      if (bs_span_at(l->src, l->pos + 1U, &d) && d == (uint8_t)'/') {
        while (bs_span_at(l->src, l->pos, &c) && c != (uint8_t)'\n') {
          l->pos++;
        }
        continue;
      }
    }
    return;
  }
}

/* An RFC 3339 timestamp, which is what a date looks like in the source.
 *
 * Only the UTC form the printer emits is accepted. Offsets would need a
 * timezone conversion, and a library that never links a time function has no
 * business inventing one. */
static bs_status bs_lex_date(const bs_lexer *l, size_t start, uint64_t *out,
                             size_t *end) {
  uint64_t part[6];
  size_t widths[6];
  size_t k;
  size_t p = start;
  uint64_t days;
  uint64_t y;
  uint64_t m;
  uint64_t era;
  uint64_t yoe;
  uint64_t doy;

  widths[0] = 4U;
  widths[1] = 2U;
  widths[2] = 2U;
  widths[3] = 2U;
  widths[4] = 2U;
  widths[5] = 2U;

  for (k = 0; k < 6U; k++) {
    size_t d;
    part[k] = 0;
    for (d = 0; d < widths[k]; d++) {
      uint8_t c = 0;
      if (!bs_span_at(l->src, p, &c) || !bs_is_digit(c)) {
        return BS_ERR_MALFORMED;
      }
      part[k] = (part[k] * 10U) + (uint64_t)(c - (uint8_t)'0');
      p++;
    }
    if (k < 5U) {
      uint8_t sep = 0;
      uint8_t want = (k < 2U)    ? (uint8_t)'-'
                     : (k == 2U) ? (uint8_t)'T'
                                 : (uint8_t)':';
      if (!bs_span_at(l->src, p, &sep) || sep != want) {
        return BS_ERR_MALFORMED;
      }
      p++;
    }
  }
  {
    uint8_t z = 0;
    if (!bs_span_at(l->src, p, &z) ||
        (z != (uint8_t)'Z' && z != (uint8_t)'z')) {
      return BS_ERR_MALFORMED;
    }
    p++;
  }

  if (part[1] < 1U || part[1] > 12U || part[2] < 1U || part[2] > 31U ||
      part[3] > 23U || part[4] > 59U || part[5] > 60U) {
    return BS_ERR_MALFORMED;
  }
  /* Dates are unsigned seconds since the epoch, so nothing before 1970 is
   * expressible and refusing is the only honest answer. */
  if (part[0] < 1970U) {
    return BS_ERR_MALFORMED;
  }

  /* The inverse of the printer's conversion: shift the year to start in
   * March so the leap day is the last day of the year. */
  y = part[0];
  m = part[1];
  y -= (m <= 2U) ? 1U : 0U;
  era = y / 400U;
  yoe = y - (era * 400U);
  doy = (((153U * ((m > 2U) ? (m - 3U) : (m + 9U))) + 2U) / 5U) + part[2] - 1U;
  days = (era * 146097U) + ((yoe * 365U) + (yoe / 4U) - (yoe / 100U)) + doy;
  days -= 719468U;

  *out = (days * 86400U) + (part[3] * 3600U) + (part[4] * 60U) + part[5];
  *end = p;
  return BS_OK;
}

static bs_status bs_lex_next(bs_lexer *l, bs_token_t *t) {
  uint8_t c = 0;
  uint8_t d = 0;
  size_t start;

  bs_lex_skip(l);
  t->kind = (uint8_t)BS_TK_EOF;
  t->punct = 0;
  t->text = bs_span_make(NULL, 0);
  t->integer = 0;
  t->date = 0;
  t->at = l->pos;

  if (!bs_span_at(l->src, l->pos, &c)) {
    return BS_OK;
  }
  start = l->pos;

  /* A variable. */
  if (c == (uint8_t)'$') {
    l->pos++;
    while (bs_span_at(l->src, l->pos, &c) && bs_is_name(c)) {
      l->pos++;
    }
    if (l->pos == start + 1U) {
      return BS_ERR_MALFORMED; /* `$` with no name */
    }
    t->kind = (uint8_t)BS_TK_VARIABLE;
    return bs_span_slice(l->src, start + 1U, l->pos - start - 1U, &t->text)
               ? BS_OK
               : BS_ERR_MALFORMED;
  }

  /* A string. Escapes match what the printer does *not* emit, so they exist
   * for hand-written source rather than for round-tripping. */
  if (c == (uint8_t)'"') {
    l->pos++;
    start = l->pos;
    while (bs_span_at(l->src, l->pos, &c)) {
      if (c == (uint8_t)'"') {
        t->kind = (uint8_t)BS_TK_STRING;
        if (!bs_span_slice(l->src, start, l->pos - start, &t->text)) {
          return BS_ERR_MALFORMED;
        }
        l->pos++;
        return BS_OK;
      }
      if (c == (uint8_t)'\\') {
        l->pos++;
        if (!bs_span_at(l->src, l->pos, &c)) {
          return BS_ERR_MALFORMED;
        }
      }
      l->pos++;
    }
    return BS_ERR_MALFORMED; /* unterminated */
  }

  /* A number, or a date, which starts like one. */
  if (bs_is_digit(c) ||
      (c == (uint8_t)'-' && bs_span_at(l->src, l->pos + 1U, &d) &&
       bs_is_digit(d))) {
    int negative = (c == (uint8_t)'-');
    size_t digits = 0;
    uint64_t value = 0;
    size_t probe = l->pos + (negative ? 1U : 0U);

    /* Four digits then a dash is a date, not a subtraction. */
    if (!negative) {
      uint8_t sep = 0;
      if (bs_span_at(l->src, l->pos + 4U, &sep) && sep == (uint8_t)'-') {
        size_t end = l->pos;
        bs_status st = bs_lex_date(l, l->pos, &t->date, &end);
        if (st == BS_OK) {
          t->kind = (uint8_t)BS_TK_DATE;
          /* bs_lex_date reads without advancing, and reports where it
           * stopped: the length of a date is its business, not the caller's,
           * and two places agreeing on 20 is one place too many. */
          l->pos = end;
          return BS_OK;
        }
      }
    }

    while (bs_span_at(l->src, probe, &c) && bs_is_digit(c)) {
      uint64_t digit = (uint64_t)(c - (uint8_t)'0');
      /* Checked before the multiply rather than after. Comparing the product
       * against what it came from catches most wraps and not all of them,
       * and "most" is not a bound. */
      if (value > (UINT64_MAX - digit) / 10U) {
        return BS_ERR_OVERFLOW;
      }
      value = (value * 10U) + digit;
      probe++;
      digits++;
    }
    if (digits == 0U) {
      return BS_ERR_MALFORMED;
    }
    /* INT64_MIN is one past what the positive range holds, so it is built on
     * the negative side rather than negated. */
    if (negative) {
      if (value > (uint64_t)INT64_MAX + 1U) {
        return BS_ERR_OVERFLOW;
      }
      t->integer =
          (value == (uint64_t)INT64_MAX + 1U) ? INT64_MIN : -(int64_t)value;
    } else {
      if (value > (uint64_t)INT64_MAX) {
        return BS_ERR_OVERFLOW;
      }
      t->integer = (int64_t)value;
    }
    l->pos = probe;
    t->kind = (uint8_t)BS_TK_INTEGER;
    return BS_OK;
  }

  /* A name, which may turn out to be `hex:`, a key, or a namespaced
   * predicate. */
  if (bs_is_name_start(c)) {
    size_t name_end;
    while (bs_span_at(l->src, l->pos, &c) && bs_is_name(c)) {
      l->pos++;
    }
    name_end = l->pos;

    if (bs_span_at(l->src, l->pos, &c) && c == (uint8_t)':') {
      uint8_t next = 0;
      if (bs_span_at(l->src, l->pos + 1U, &next) && next == (uint8_t)':') {
        /* A namespace: keep reading, the whole thing is one name. */
        l->pos += 2U;
        while (bs_span_at(l->src, l->pos, &c) && bs_is_name(c)) {
          l->pos++;
        }
        t->kind = (uint8_t)BS_TK_IDENT;
        return bs_span_slice(l->src, start, l->pos - start, &t->text)
                   ? BS_OK
                   : BS_ERR_MALFORMED;
      }
      /* `hex:` introduces a byte string. */
      {
        bs_span word;
        if (bs_span_slice(l->src, start, name_end - start, &word) &&
            bs_span_eq(word, bs_span_make("hex", 3U))) {
          size_t digits_start;
          l->pos++;
          digits_start = l->pos;
          while (bs_span_at(l->src, l->pos, &c) && bs_hex_digit(c, &d)) {
            l->pos++;
          }
          if (((l->pos - digits_start) % 2U) != 0U) {
            return BS_ERR_MALFORMED; /* half a byte */
          }
          t->kind = (uint8_t)BS_TK_BYTES;
          return bs_span_slice(l->src, digits_start, l->pos - digits_start,
                               &t->text)
                     ? BS_OK
                     : BS_ERR_MALFORMED;
        }
      }
    }

    if (bs_span_at(l->src, l->pos, &c) && c == (uint8_t)'/') {
      /* An algorithm followed by a slash is a public key. */
      bs_span word;
      if (bs_span_slice(l->src, start, name_end - start, &word) &&
          (bs_span_eq(word, bs_span_make("ed25519", 7U)) ||
           bs_span_eq(word, bs_span_make("secp256r1", 9U)))) {
        l->pos++;
        while (bs_span_at(l->src, l->pos, &c) && bs_hex_digit(c, &d)) {
          l->pos++;
        }
        t->kind = (uint8_t)BS_TK_KEY;
        return bs_span_slice(l->src, start, l->pos - start, &t->text)
                   ? BS_OK
                   : BS_ERR_MALFORMED;
      }
    }

    t->kind = (uint8_t)BS_TK_IDENT;
    return bs_span_slice(l->src, start, l->pos - start, &t->text)
               ? BS_OK
               : BS_ERR_MALFORMED;
  }

  /* Punctuation. The longest match wins, so `===` is never read as `==`
   * followed by `=`. */
  t->kind = (uint8_t)BS_TK_PUNCT;
  (void)bs_span_at(l->src, l->pos + 1U, &d);
  switch (c) {
  case (uint8_t)'(':
    t->punct = (uint8_t)BS_P_LPAREN;
    l->pos++;
    return BS_OK;
  case (uint8_t)')':
    t->punct = (uint8_t)BS_P_RPAREN;
    l->pos++;
    return BS_OK;
  case (uint8_t)'[':
    t->punct = (uint8_t)BS_P_LBRACKET;
    l->pos++;
    return BS_OK;
  case (uint8_t)']':
    t->punct = (uint8_t)BS_P_RBRACKET;
    l->pos++;
    return BS_OK;
  case (uint8_t)'{':
    t->punct = (uint8_t)BS_P_LBRACE;
    l->pos++;
    return BS_OK;
  case (uint8_t)'}':
    t->punct = (uint8_t)BS_P_RBRACE;
    l->pos++;
    return BS_OK;
  case (uint8_t)',':
    t->punct = (uint8_t)BS_P_COMMA;
    l->pos++;
    return BS_OK;
  case (uint8_t)';':
    t->punct = (uint8_t)BS_P_SEMI;
    l->pos++;
    return BS_OK;
  case (uint8_t)':':
    t->punct = (uint8_t)BS_P_COLON;
    l->pos++;
    return BS_OK;
  case (uint8_t)'.':
    t->punct = (uint8_t)BS_P_DOT;
    l->pos++;
    return BS_OK;
  case (uint8_t)'^':
    t->punct = (uint8_t)BS_P_CARET;
    l->pos++;
    return BS_OK;
  case (uint8_t)'*':
    t->punct = (uint8_t)BS_P_STAR;
    l->pos++;
    return BS_OK;
  case (uint8_t)'/':
    t->punct = (uint8_t)BS_P_SLASH;
    l->pos++;
    return BS_OK;
  case (uint8_t)'+':
    t->punct = (uint8_t)BS_P_PLUS;
    l->pos++;
    return BS_OK;
  case (uint8_t)'-':
    if (d == (uint8_t)'>') {
      t->punct = (uint8_t)BS_P_ARROW;
      l->pos += 2U;
      return BS_OK;
    }
    t->punct = (uint8_t)BS_P_MINUS;
    l->pos++;
    return BS_OK;
  case (uint8_t)'<':
    if (d == (uint8_t)'-') {
      t->punct = (uint8_t)BS_P_LEFTARROW;
      l->pos += 2U;
      return BS_OK;
    }
    if (d == (uint8_t)'=') {
      t->punct = (uint8_t)BS_P_LE;
      l->pos += 2U;
      return BS_OK;
    }
    t->punct = (uint8_t)BS_P_LT;
    l->pos++;
    return BS_OK;
  case (uint8_t)'>':
    if (d == (uint8_t)'=') {
      t->punct = (uint8_t)BS_P_GE;
      l->pos += 2U;
      return BS_OK;
    }
    t->punct = (uint8_t)BS_P_GT;
    l->pos++;
    return BS_OK;
  case (uint8_t)'=': {
    uint8_t e = 0;
    (void)bs_span_at(l->src, l->pos + 2U, &e);
    if (d == (uint8_t)'=' && e == (uint8_t)'=') {
      t->punct = (uint8_t)BS_P_EQ3;
      l->pos += 3U;
      return BS_OK;
    }
    if (d == (uint8_t)'=') {
      t->punct = (uint8_t)BS_P_EQ2;
      l->pos += 2U;
      return BS_OK;
    }
    return BS_ERR_MALFORMED; /* a lone `=` means nothing */
  }
  case (uint8_t)'!': {
    uint8_t e = 0;
    (void)bs_span_at(l->src, l->pos + 2U, &e);
    if (d == (uint8_t)'=' && e == (uint8_t)'=') {
      t->punct = (uint8_t)BS_P_NEQ3;
      l->pos += 3U;
      return BS_OK;
    }
    if (d == (uint8_t)'=') {
      t->punct = (uint8_t)BS_P_NEQ2;
      l->pos += 2U;
      return BS_OK;
    }
    t->punct = (uint8_t)BS_P_BANG;
    l->pos++;
    return BS_OK;
  }
  case (uint8_t)'&': {
    uint8_t e = 0;
    (void)bs_span_at(l->src, l->pos + 2U, &e);
    if (d == (uint8_t)'&') {
      /* `&&!` is the eager form: it evaluates both sides. */
      t->punct = (e == (uint8_t)'!') ? (uint8_t)BS_P_AND2E : (uint8_t)BS_P_AND2;
      l->pos += (e == (uint8_t)'!') ? 3U : 2U;
      return BS_OK;
    }
    t->punct = (uint8_t)BS_P_AMP;
    l->pos++;
    return BS_OK;
  }
  case (uint8_t)'|': {
    uint8_t e = 0;
    (void)bs_span_at(l->src, l->pos + 2U, &e);
    if (d == (uint8_t)'|') {
      t->punct = (e == (uint8_t)'!') ? (uint8_t)BS_P_OR2E : (uint8_t)BS_P_OR2;
      l->pos += (e == (uint8_t)'!') ? 3U : 2U;
      return BS_OK;
    }
    t->punct = (uint8_t)BS_P_PIPE;
    l->pos++;
    return BS_OK;
  }
  default:
    return BS_ERR_MALFORMED;
  }
}

/* ===========================================================================
 * 140_parse.inc
 * ======================================================================== */

/* ---------------------------------------------------------------------------
 * Parsing Datalog source
 *
 * Facts, rules, checks and policies, from text into the same pools the wire
 * format loads into. One representation, two front ends: the evaluator never
 * learns where anything came from.
 *
 * This is written without recursion, and the first draft was not. A parser is
 * the place where recursive descent is so natural that it takes an effort of
 * will to write anything else -- which is exactly why the invariant is worth
 * having, and why an exception "just for the parser" would have been the
 * beginning of the end of it. Nesting here comes from the source text, and
 * while that text is the application's rather than the token's, a stack bound
 * that holds for one input and not another is not a bound.
 *
 * Two explicit stacks do the work:
 *
 *   - Terms: a stack of container frames. A `[` or `{` opens one; the closing
 *     bracket pops it, assembles the run in the term pool, and hands the
 *     finished container back as the value the enclosing frame was waiting
 *     for.
 *
 *   - Expressions: shunting-yard, with `(`, method calls and closures pushed
 *     onto the operator stack as markers rather than becoming calls. Output
 *     is postfix, which is the order the opcode pool already wants.
 *
 * A closure's body has to be a contiguous run of its own. At the `)` that
 * closes it, its opcodes are exactly the suffix of the output buffer since the
 * marker, so they move to the pool in one copy and the buffer truncates back.
 * Nested closures work out because the inner one closes first.
 *
 * The precedence table is the reference implementation's, read rather than
 * guessed, and it is not C's: `&` binds tighter than `|`, which binds tighter
 * than `^`, and comparisons do not chain.
 * ------------------------------------------------------------------------ */

#ifndef BS_PARSE_SCRATCH
#define BS_PARSE_SCRATCH 128
#endif

typedef struct bs_parser {
  bs_lexer lex;
  bs_token_t tok; /* one token of lookahead */
  bs_world *w;
  bs_symtab *syms;
  const bs_token *token; /* for a scope naming a public key */
  const bs_tables *tables;
  bs_arena *arena; /* for byte literals */
  bs_op *scratch;  /* the expression under construction */
  /* Two term buffers, because a predicate's argument list and a container
   * literal inside it fill at the same moment. They live in the arena rather
   * than on the stack: at a hundred-odd terms each they would otherwise be
   * most of this build's stack budget. */
  bs_term *tscratch; /* bs_p_term */
  bs_term *pscratch; /* bs_p_predicate */
  size_t scratch_cap;
  size_t block;            /* which block these statements belong to */
  bs_origin default_trust; /* what a statement with no annotation trusts */
} bs_parser;

static bs_status bs_p_advance(bs_parser *p) {
  return bs_lex_next(&p->lex, &p->tok);
}

static int bs_p_is_punct(const bs_parser *p, uint8_t punct) {
  return p->tok.kind == (uint8_t)BS_TK_PUNCT && p->tok.punct == punct;
}

static int bs_p_is_word(const bs_parser *p, const char *word, size_t n) {
  return p->tok.kind == (uint8_t)BS_TK_IDENT &&
         bs_span_eq(p->tok.text, bs_span_make(word, n));
}

#define BS_WORD(p, lit) bs_p_is_word((p), "" lit, sizeof(lit) - 1U)

static bs_status bs_p_expect(bs_parser *p, uint8_t punct) {
  if (!bs_p_is_punct(p, punct)) {
    return BS_ERR_MALFORMED;
  }
  return bs_p_advance(p);
}

/* --------------------------------------------------------------------------
 * Terms
 * ----------------------------------------------------------------------- */

/* Hex digit pairs into bytes. The lexer has already checked that every
 * character is a digit and that there is an even number of them, so this
 * only has to pack them. */
static int bs_p_unhex(bs_span text, uint8_t *out, size_t cap) {
  size_t n = text.n / 2U;
  size_t i;
  if (n > cap) {
    return 0;
  }
  for (i = 0; i < n; i++) {
    uint8_t hi = 0;
    uint8_t lo = 0;
    (void)bs_hex_digit(text.p[2U * i], &hi);
    (void)bs_hex_digit(text.p[(2U * i) + 1U], &lo);
    out[i] = (uint8_t)(((unsigned int)hi << 4U) | (unsigned int)lo);
  }
  return 1;
}

/* A scalar: everything that is not a container. */
static bs_status bs_p_scalar(bs_parser *p, bs_term *out) {
  bs_status st;

  switch (p->tok.kind) {
  case BS_TK_STRING:
    out->kind = (uint8_t)BS_T_STRING;
    st = bs_symtab_intern(p->syms, p->tok.text, &out->as.sym);
    return (st == BS_OK) ? bs_p_advance(p) : st;
  case BS_TK_VARIABLE:
    out->kind = (uint8_t)BS_T_VARIABLE;
    st = bs_symtab_intern(p->syms, p->tok.text, &out->as.sym);
    return (st == BS_OK) ? bs_p_advance(p) : st;
  case BS_TK_INTEGER:
    out->kind = (uint8_t)BS_T_INTEGER;
    out->as.integer = p->tok.integer;
    return bs_p_advance(p);
  case BS_TK_DATE:
    out->kind = (uint8_t)BS_T_DATE;
    out->as.date = p->tok.date;
    return bs_p_advance(p);
  case BS_TK_BYTES: {
    size_t n = p->tok.text.n / 2U;
    uint8_t *buf = (uint8_t *)bs_arena_alloc(p->arena, (n == 0U) ? 1U : n, 1U);
    if (buf == NULL) {
      return BS_ERR_NOMEM;
    }
    if (!bs_p_unhex(p->tok.text, buf, n)) {
      return BS_ERR_MALFORMED;
    }
    out->kind = (uint8_t)BS_T_BYTES;
    out->as.bytes = bs_span_make(buf, n);
    return bs_p_advance(p);
  }
  case BS_TK_IDENT:
    if (BS_WORD(p, "true")) {
      out->kind = (uint8_t)BS_T_BOOL;
      out->as.boolean = 1;
      return bs_p_advance(p);
    }
    if (BS_WORD(p, "false")) {
      out->kind = (uint8_t)BS_T_BOOL;
      out->as.boolean = 0;
      return bs_p_advance(p);
    }
    if (BS_WORD(p, "null")) {
      out->kind = (uint8_t)BS_T_NULL;
      return bs_p_advance(p);
    }
    return BS_ERR_MALFORMED;
  default:
    return BS_ERR_MALFORMED;
  }
}

/* A container kind that is not yet known: `{` opens either a set or a map,
 * and only the colon after the first element tells them apart. */
#define BS_T_UNKNOWN 0xFEU

typedef struct bs_termframe {
  uint8_t kind;  /* BS_T_ARRAY, BS_T_SET, BS_T_MAP, or BS_T_UNKNOWN */
  uint8_t close; /* the punctuation that ends it */
  size_t base;   /* where this frame's elements start in the shared buffer */
} bs_termframe;

/* One term, containers and all. */
static bs_status bs_p_term(bs_parser *p, bs_term *out) {
  bs_termframe frames[BS_MAX_DEPTH];
  bs_term *items = p->tscratch;
  size_t nitems = 0;
  size_t depth = 0;
  bs_term value;
  bs_status st;

  for (;;) {
    /* Open as many containers as the source opens, then read one scalar. */
    for (;;) {
      uint8_t close;
      uint8_t kind;
      if (bs_p_is_punct(p, (uint8_t)BS_P_LBRACKET)) {
        close = (uint8_t)BS_P_RBRACKET;
        kind = (uint8_t)BS_T_ARRAY;
      } else if (bs_p_is_punct(p, (uint8_t)BS_P_LBRACE)) {
        close = (uint8_t)BS_P_RBRACE;
        kind = (uint8_t)BS_T_UNKNOWN;
      } else {
        break;
      }
      if (depth >= (size_t)BS_MAX_DEPTH) {
        return BS_ERR_DEPTH;
      }
      st = bs_p_advance(p);
      if (st != BS_OK) {
        return st;
      }
      frames[depth].kind = kind;
      frames[depth].close = close;
      frames[depth].base = nitems;
      depth++;

      /* The empty spellings. `{}` is a map and `{,}` is a set: with no
       * element to disambiguate them, the comma is the whole difference. */
      if (kind == (uint8_t)BS_T_UNKNOWN &&
          bs_p_is_punct(p, (uint8_t)BS_P_COMMA)) {
        st = bs_p_advance(p);
        if (st != BS_OK) {
          return st;
        }
        if (!bs_p_is_punct(p, close)) {
          return BS_ERR_MALFORMED;
        }
        kind = (uint8_t)BS_T_SET;
      } else if (kind == (uint8_t)BS_T_UNKNOWN && bs_p_is_punct(p, close)) {
        kind = (uint8_t)BS_T_MAP;
      } else if (!bs_p_is_punct(p, close)) {
        continue;
      }
      value.kind = kind;
      value.as.list.at = (uint32_t)p->w->term_count;
      value.as.list.count = 0;
      st = bs_p_advance(p);
      if (st != BS_OK) {
        return st;
      }
      depth--;
      goto have_value;
    }

    st = bs_p_scalar(p, &value);
    if (st != BS_OK) {
      return st;
    }

  have_value:
    if (depth == 0U) {
      *out = value;
      return BS_OK;
    }

    if (nitems >= (size_t)BS_PARSE_SCRATCH) {
      return BS_ERR_LIMIT;
    }
    items[nitems] = value;
    nitems++;

    {
      bs_termframe *f = &frames[depth - 1U];
      size_t placed = nitems - f->base;

      if (f->kind == (uint8_t)BS_T_UNKNOWN) {
        /* Decided by what follows the first element. */
        f->kind = bs_p_is_punct(p, (uint8_t)BS_P_COLON) ? (uint8_t)BS_T_MAP
                                                        : (uint8_t)BS_T_SET;
      }

      if (f->kind == (uint8_t)BS_T_MAP && (placed % 2U) == 1U) {
        /* A key was just placed; its value follows the colon, and keys and
         * values sit adjacently in the run. */
        st = bs_p_expect(p, (uint8_t)BS_P_COLON);
        if (st != BS_OK) {
          return st;
        }
        continue;
      }

      if (bs_p_is_punct(p, (uint8_t)BS_P_COMMA)) {
        st = bs_p_advance(p);
        if (st != BS_OK) {
          return st;
        }
        if (!bs_p_is_punct(p, f->close)) {
          continue;
        }
        /* A trailing comma. `{,}` is how an empty set is written, and it has
         * already placed no elements, so the frame closes as a set. */
        if (placed == 0U) {
          f->kind = (uint8_t)BS_T_SET;
        }
      }
    }

    /* Close the innermost frame and hand its container to the frame outside,
     * or to the caller. */
    {
      const bs_termframe *f = &frames[depth - 1U];
      size_t n = nitems - f->base;
      uint32_t at;
      size_t i;

      st = bs_p_expect(p, f->close);
      if (st != BS_OK) {
        return st;
      }
      if (f->kind == (uint8_t)BS_T_MAP && (n % 2U) != 0U) {
        return BS_ERR_MALFORMED; /* a key with no value */
      }
      st = bs_pool_reserve_terms(p->w, n, &at);
      if (st != BS_OK) {
        return st;
      }
      for (i = 0; i < n; i++) {
        p->w->terms[at + i] = items[f->base + i];
      }
      value.kind = f->kind;
      value.as.list.at = at;
      value.as.list.count = (uint32_t)n;
      nitems = f->base;
      depth--;
      goto have_value;
    }
  }
}

/* --------------------------------------------------------------------------
 * Expressions
 * ----------------------------------------------------------------------- */

/* Lowest binds loosest; 0 means "not a binary operator". Prefix `!` sits
 * above every binary so that `!a && b` negates `a` and not the conjunction,
 * while method calls, which bind tighter still, are applied inline. */
#define BS_PREC_UNARY 9U

static unsigned int bs_p_prec(uint8_t punct) {
  switch (punct) {
  case BS_P_OR2:
  case BS_P_OR2E:
    return 1U;
  case BS_P_AND2:
  case BS_P_AND2E:
    return 2U;
  case BS_P_LT:
  case BS_P_GT:
  case BS_P_LE:
  case BS_P_GE:
  case BS_P_EQ3:
  case BS_P_NEQ3:
  case BS_P_EQ2:
  case BS_P_NEQ2:
    return 3U;
  case BS_P_CARET:
    return 4U;
  case BS_P_PIPE:
    return 5U;
  case BS_P_AMP:
    return 6U;
  case BS_P_PLUS:
  case BS_P_MINUS:
    return 7U;
  case BS_P_STAR:
  case BS_P_SLASH:
    return 8U;
  default:
    return 0U;
  }
}

static uint32_t bs_p_binop(uint8_t punct) {
  switch (punct) {
  case BS_P_LT:
    return 0U;
  case BS_P_GT:
    return 1U;
  case BS_P_LE:
    return 2U;
  case BS_P_GE:
    return 3U;
  case BS_P_EQ3:
    return 4U;
  case BS_P_PLUS:
    return 9U;
  case BS_P_MINUS:
    return 10U;
  case BS_P_STAR:
    return 11U;
  case BS_P_SLASH:
    return 12U;
  case BS_P_AND2E:
    return 13U;
  case BS_P_OR2E:
    return 14U;
  case BS_P_AMP:
    return 17U;
  case BS_P_PIPE:
    return 18U;
  case BS_P_CARET:
    return 19U;
  case BS_P_NEQ3:
    return 20U;
  case BS_P_EQ2:
    return 21U;
  case BS_P_NEQ2:
    return 22U;
  case BS_P_AND2:
    return 23U;
  default:
    return 24U; /* BS_P_OR2 */
  }
}

/* The methods this build knows, and which of them take no argument. */
static int bs_p_method(bs_span name, uint32_t *kind, int *nullary) {
  static const struct {
    const char *text;
    size_t len;
    uint32_t kind;
    int nullary;
  } METHODS[] = {
      {"contains", 8U, 5U, 0},
      {"starts_with", 11U, 6U, 0},
      {"ends_with", 9U, 7U, 0},
      {"matches", 7U, 8U, 0},
      {"intersection", 12U, 15U, 0},
      {"union", 5U, 16U, 0},
      {"all", 3U, 25U, 0},
      {"any", 3U, 26U, 0},
      {"get", 3U, 27U, 0},
      {"try_or", 6U, 29U, 0},
      {"length", 6U, BS_U_LENGTH, 1},
      {"type", 4U, BS_U_TYPEOF, 1},
  };
  size_t i;
  for (i = 0; i < sizeof METHODS / sizeof METHODS[0]; i++) {
    if (bs_span_eq(name, bs_span_make(METHODS[i].text, METHODS[i].len))) {
      *kind = METHODS[i].kind;
      *nullary = METHODS[i].nullary;
      return 1;
    }
  }
  return 0;
}

/* What sits on the operator stack. Three of the five are not operators at
 * all but the open brackets of a construct, kept here so that closing one is
 * a pop rather than a return. */
#define BS_S_BINARY 0U
#define BS_S_UNARY 1U
#define BS_S_PAREN 2U
#define BS_S_METHOD 3U
#define BS_S_CLOSURE 4U

typedef struct bs_opstack {
  uint8_t what;
  uint8_t punct; /* BS_S_BINARY */
  uint32_t kind; /* BS_S_METHOD */
  /* Where in the output this entry's operand begins. Three constructs need
   * it: a lazy connective, whose right-hand side becomes a closure so that it
   * can go unevaluated; `try_or`, whose receiver becomes one for the same
   * reason; and a closure written as such. */
  size_t out;
  uint64_t param; /* BS_S_CLOSURE: the bound variable */
} bs_opstack;

/* Is this connective one that must not evaluate its right-hand side unless
 * the left fails to decide? */
static int bs_p_is_lazy(uint8_t punct) {
  return punct == (uint8_t)BS_P_AND2 || punct == (uint8_t)BS_P_OR2;
}

/* Move ops[from..*n) into the pool as a closure body, and put a closure in
 * their place. `param` is the bound variable, or `count` 0 for the anonymous
 * closures the lazy connectives and `try_or` are built from. */
static bs_status bs_p_close_over(bs_parser *p, bs_op *out, size_t *n,
                                 size_t cap, size_t from, uint32_t count,
                                 uint64_t param);

static bs_status bs_p_emit(bs_op *out, size_t *n, size_t cap, bs_op op) {
  if (*n >= cap) {
    return BS_ERR_LIMIT;
  }
  out[*n] = op;
  (*n)++;
  return BS_OK;
}

static bs_status bs_p_emit_op(bs_op *out, size_t *n, size_t cap, uint8_t tag,
                              uint32_t kind) {
  bs_op op;
  op.tag = tag;
  op.kind = kind;
  op.as.ffi = 0;
  return bs_p_emit(out, n, cap, op);
}

static bs_status bs_p_close_over(bs_parser *p, bs_op *out, size_t *n,
                                 size_t cap, size_t from, uint32_t count,
                                 uint64_t param) {
  size_t body_n = *n - from;
  uint32_t at;
  size_t i;
  bs_op op;
  bs_status st;

  st = bs_pool_reserve_ops(p->w, body_n, &at);
  if (st != BS_OK) {
    return st;
  }
  for (i = 0; i < body_n; i++) {
    p->w->ops[at + i] = out[from + i];
  }
  *n = from;
  op.tag = (uint8_t)BS_OP_CLOSURE;
  op.kind = 0;
  op.as.closure.count = count;
  op.as.closure.body.at = at;
  op.as.closure.body.count = (uint32_t)body_n;
  op.as.closure.src = bs_span_make(NULL, 0);
  op.as.closure.at = (uint32_t)p->w->sym_count;
  if (count > 0U) {
    if (p->w->sym_count >= p->w->sym_cap) {
      return BS_ERR_NOMEM;
    }
    p->w->syms[p->w->sym_count] = param;
    p->w->sym_count++;
  }
  return bs_p_emit(out, n, cap, op);
}

/* Apply one stack entry, turning it into the opcode it stands for. */
static bs_status bs_p_apply(bs_parser *p, const bs_opstack *e, bs_op *out,
                            size_t *n, size_t cap) {
  if (e->what == (uint8_t)BS_S_UNARY) {
    return bs_p_emit_op(out, n, cap, (uint8_t)BS_OP_UNARY, BS_U_NEGATE);
  }
  if (bs_p_is_lazy(e->punct)) {
    /* `a && b` is stored as `a` and a closure over `b`, which is what lets
     * the evaluator skip `b` when `a` already decides the answer. */
    bs_status st = bs_p_close_over(p, out, n, cap, e->out, 0U, 0U);
    if (st != BS_OK) {
      return st;
    }
  }
  return bs_p_emit_op(out, n, cap, (uint8_t)BS_OP_BINARY, bs_p_binop(e->punct));
}

/* One expression, from the current token up to whatever does not continue it.
 *
 * `out` is the caller's buffer; the finished run is copied into the op pool
 * at the end, so that closure bodies -- which reach the pool first, as they
 * complete -- stay contiguous runs of their own. */
static bs_status bs_p_expression(bs_parser *p, bs_op *out, size_t cap,
                                 bs_expr *result) {
  bs_opstack stack[BS_MAX_DEPTH];
  size_t depth = 0;
  size_t n = 0;
  /* Where the operand a method call would attach to begins. `try_or` needs
   * it, because the receiver rather than the argument is what must not be
   * evaluated eagerly. */
  size_t operand_at = 0;
  unsigned int last_prec = 0;
  int want_operand = 1;
  bs_status st;

  for (;;) {
    if (want_operand) {
      if (bs_p_is_punct(p, (uint8_t)BS_P_BANG)) {
        if (depth >= (size_t)BS_MAX_DEPTH) {
          return BS_ERR_DEPTH;
        }
        stack[depth].what = (uint8_t)BS_S_UNARY;
        depth++;
        st = bs_p_advance(p);
        if (st != BS_OK) {
          return st;
        }
        continue;
      }
      if (bs_p_is_punct(p, (uint8_t)BS_P_LPAREN)) {
        if (depth >= (size_t)BS_MAX_DEPTH) {
          return BS_ERR_DEPTH;
        }
        stack[depth].what = (uint8_t)BS_S_PAREN;
        stack[depth].out = n;
        depth++;
        last_prec = 0;
        st = bs_p_advance(p);
        if (st != BS_OK) {
          return st;
        }
        continue;
      }
      /* A closure, if the variable is followed by an arrow. Deciding needs
       * one token more than the lexer holds, so the lexer's position is
       * saved and put back when it turns out to be an ordinary variable. */
      if (p->tok.kind == (uint8_t)BS_TK_VARIABLE) {
        bs_lexer save_lex = p->lex;
        bs_token_t save_tok = p->tok;
        bs_span param = p->tok.text;
        st = bs_p_advance(p);
        if (st != BS_OK) {
          return st;
        }
        if (bs_p_is_punct(p, (uint8_t)BS_P_ARROW)) {
          uint64_t sym = 0;
          if (depth >= (size_t)BS_MAX_DEPTH) {
            return BS_ERR_DEPTH;
          }
          st = bs_symtab_intern(p->syms, param, &sym);
          if (st != BS_OK) {
            return st;
          }
          stack[depth].what = (uint8_t)BS_S_CLOSURE;
          stack[depth].out = n;
          stack[depth].param = sym;
          depth++;
          last_prec = 0;
          st = bs_p_advance(p);
          if (st != BS_OK) {
            return st;
          }
          continue;
        }
        p->lex = save_lex;
        p->tok = save_tok;
      }
      {
        bs_term t;
        uint32_t at;
        bs_op op;
        operand_at = n;
        st = bs_p_term(p, &t);
        if (st != BS_OK) {
          return st;
        }
        st = bs_pool_reserve_terms(p->w, 1U, &at);
        if (st != BS_OK) {
          return st;
        }
        p->w->terms[at] = t;
        op.tag = (uint8_t)BS_OP_VALUE;
        op.kind = 0;
        op.as.term = at;
        st = bs_p_emit(out, &n, cap, op);
        if (st != BS_OK) {
          return st;
        }
      }
      want_operand = 0;
      continue;
    }

    /* A method call binds to the operand just produced. */
    if (bs_p_is_punct(p, (uint8_t)BS_P_DOT)) {
      uint32_t kind = 0;
      int nullary = 0;
      bs_span name;

      st = bs_p_advance(p);
      if (st != BS_OK) {
        return st;
      }
      if (p->tok.kind != (uint8_t)BS_TK_IDENT) {
        return BS_ERR_MALFORMED;
      }
      name = p->tok.text;
      if (!bs_p_method(name, &kind, &nullary)) {
        /* External calls are implementation-defined and this build defines
         * none, so one is refused rather than quietly ignored. */
        return BS_ERR_UNSUPPORTED;
      }
      st = bs_p_advance(p);
      if (st != BS_OK) {
        return st;
      }
      st = bs_p_expect(p, (uint8_t)BS_P_LPAREN);
      if (st != BS_OK) {
        return st;
      }
      if (nullary) {
        st = bs_p_expect(p, (uint8_t)BS_P_RPAREN);
        if (st != BS_OK) {
          return st;
        }
        st = bs_p_emit_op(out, &n, cap, (uint8_t)BS_OP_UNARY, kind);
        if (st != BS_OK) {
          return st;
        }
        continue;
      }
      if (depth >= (size_t)BS_MAX_DEPTH) {
        return BS_ERR_DEPTH;
      }
      if (kind == 29U) {
        /* `x.try_or(y)` catches a failure in `x`, so it is `x` that must be
         * held back unevaluated -- the receiver, not the argument. */
        st = bs_p_close_over(p, out, &n, cap, operand_at, 0U, 0U);
        if (st != BS_OK) {
          return st;
        }
      }
      stack[depth].what = (uint8_t)BS_S_METHOD;
      stack[depth].kind = kind;
      stack[depth].out = operand_at;
      depth++;
      want_operand = 1;
      last_prec = 0;
      continue;
    }

    if (bs_p_is_punct(p, (uint8_t)BS_P_RPAREN)) {
      /* Close whatever the innermost bracket was. A closure and the method
       * call holding it are closed by the same `)`, which is why this pops
       * more than once. */
      int closed = 0;
      while (!closed) {
        while (depth > 0U && stack[depth - 1U].what <= (uint8_t)BS_S_UNARY) {
          depth--;
          st = bs_p_apply(p, &stack[depth], out, &n, cap);
          if (st != BS_OK) {
            return st;
          }
        }
        if (depth == 0U) {
          return BS_ERR_MALFORMED; /* a `)` that opens nothing */
        }
        depth--;
        operand_at = stack[depth].out;
        if (stack[depth].what == (uint8_t)BS_S_PAREN) {
          st = bs_p_emit_op(out, &n, cap, (uint8_t)BS_OP_UNARY, BS_U_PARENS);
          if (st != BS_OK) {
            return st;
          }
          closed = 1;
        } else if (stack[depth].what == (uint8_t)BS_S_METHOD) {
          st = bs_p_emit_op(out, &n, cap, (uint8_t)BS_OP_BINARY,
                            stack[depth].kind);
          if (st != BS_OK) {
            return st;
          }
          closed = 1;
        } else {
          /* A closure. Its opcodes are exactly the suffix produced since the
           * marker, so they move to the pool in one copy. Round again after
           * it, to close the method call it was an argument to. */
          st = bs_p_close_over(p, out, &n, cap, stack[depth].out, 1U,
                               stack[depth].param);
          if (st != BS_OK) {
            return st;
          }
        }
      }
      st = bs_p_advance(p);
      if (st != BS_OK) {
        return st;
      }
      last_prec = 0;
      continue;
    }

    {
      unsigned int prec;
      if (p->tok.kind != (uint8_t)BS_TK_PUNCT) {
        break;
      }
      prec = bs_p_prec(p->tok.punct);
      if (prec == 0U) {
        break;
      }
      /* Comparisons do not chain: `a < b < c` is refused rather than read as
       * something its author did not mean. */
      if (prec == 3U && last_prec == 3U) {
        return BS_ERR_MALFORMED;
      }
      while (depth > 0U && stack[depth - 1U].what <= (uint8_t)BS_S_UNARY) {
        unsigned int top = (stack[depth - 1U].what == (uint8_t)BS_S_UNARY)
                               ? BS_PREC_UNARY
                               : bs_p_prec(stack[depth - 1U].punct);
        if (top < prec) {
          break;
        }
        depth--;
        st = bs_p_apply(p, &stack[depth], out, &n, cap);
        if (st != BS_OK) {
          return st;
        }
      }
      if (depth >= (size_t)BS_MAX_DEPTH) {
        return BS_ERR_DEPTH;
      }
      stack[depth].what = (uint8_t)BS_S_BINARY;
      stack[depth].punct = p->tok.punct;
      stack[depth].out = n;
      depth++;
      last_prec = prec;
      want_operand = 1;
      st = bs_p_advance(p);
      if (st != BS_OK) {
        return st;
      }
    }
  }

  while (depth > 0U) {
    depth--;
    if (stack[depth].what > (uint8_t)BS_S_UNARY) {
      return BS_ERR_MALFORMED; /* a bracket nothing closed */
    }
    st = bs_p_apply(p, &stack[depth], out, &n, cap);
    if (st != BS_OK) {
      return st;
    }
  }

  {
    uint32_t at;
    size_t i;
    st = bs_pool_reserve_ops(p->w, n, &at);
    if (st != BS_OK) {
      return st;
    }
    for (i = 0; i < n; i++) {
      p->w->ops[at + i] = out[i];
    }
    result->at = at;
    result->count = (uint32_t)n;
  }
  return BS_OK;
}

/* --------------------------------------------------------------------------
 * Predicates, scopes and statements
 * ----------------------------------------------------------------------- */

static bs_status bs_p_predicate(bs_parser *p, bs_predicate *out) {
  bs_term *items = p->pscratch;
  size_t n = 0;
  uint64_t name = 0;
  uint32_t at;
  size_t i;
  bs_status st;

  if (p->tok.kind != (uint8_t)BS_TK_IDENT) {
    return BS_ERR_MALFORMED;
  }
  st = bs_symtab_intern(p->syms, p->tok.text, &name);
  if (st != BS_OK) {
    return st;
  }
  st = bs_p_advance(p);
  if (st != BS_OK) {
    return st;
  }
  st = bs_p_expect(p, (uint8_t)BS_P_LPAREN);
  if (st != BS_OK) {
    return st;
  }
  if (!bs_p_is_punct(p, (uint8_t)BS_P_RPAREN)) {
    for (;;) {
      if (n >= (size_t)BS_PARSE_SCRATCH) {
        return BS_ERR_LIMIT;
      }
      st = bs_p_term(p, &items[n]);
      if (st != BS_OK) {
        return st;
      }
      n++;
      if (!bs_p_is_punct(p, (uint8_t)BS_P_COMMA)) {
        break;
      }
      st = bs_p_advance(p);
      if (st != BS_OK) {
        return st;
      }
    }
  }
  st = bs_p_expect(p, (uint8_t)BS_P_RPAREN);
  if (st != BS_OK) {
    return st;
  }
  st = bs_pool_reserve_terms(p->w, n, &at);
  if (st != BS_OK) {
    return st;
  }
  for (i = 0; i < n; i++) {
    p->w->terms[at + i] = items[i];
  }
  out->name = name;
  out->at = at;
  out->count = (uint32_t)n;
  return BS_OK;
}

/* The origin bit a statement's own position stands for. The authorizer sits
 * outside the chain and has a bit reserved for it rather than a position, so
 * its index is never shifted. */
static bs_origin bs_p_self(const bs_parser *p) {
  return (p->block >= (size_t)BS_MAX_BLOCKS) ? BS_ORIGIN_AUTHORIZER
                                             : BS_ORIGIN_ONE(p->block);
}

/* One scope annotation: `authority`, `previous`, or a public key. */
static bs_status bs_p_scope(bs_parser *p, bs_origin *add) {
  size_t i;

  *add = BS_ORIGIN_NONE;

  if (BS_WORD(p, "authority")) {
    *add = BS_ORIGIN_ONE(0U);
    return bs_p_advance(p);
  }
  if (BS_WORD(p, "previous")) {
    /* Every block up to and including the one that said this. The authorizer
     * has no position in the chain, so for it the annotation means every
     * block there is. */
    size_t last =
        (p->block >= (size_t)BS_MAX_BLOCKS) ? p->w->block_count : p->block + 1U;
    for (i = 0; i < last && i < (size_t)BS_MAX_BLOCKS; i++) {
      *add |= BS_ORIGIN_ONE(i);
    }
    return bs_p_advance(p);
  }
  if (p->tok.kind == (uint8_t)BS_TK_KEY) {
    uint8_t key[32];
    bs_span hex;

    /* The token spans the algorithm too, so the digits start after the
     * slash. Only Ed25519 keys are resolved here; a secp256r1 scope parses
     * and matches nothing, because no block in this build carries one. */
    if (!bs_span_slice(p->tok.text, 0U, 8U, &hex) ||
        !bs_span_eq(hex, bs_span_make("ed25519/", 8U)) ||
        !bs_span_slice(p->tok.text, 8U, p->tok.text.n - 8U, &hex)) {
      return BS_ERR_UNSUPPORTED;
    }
    if (hex.n != 2U * sizeof key || !bs_p_unhex(hex, key, sizeof key)) {
      return BS_ERR_MALFORMED;
    }
    /* A key names every block carrying an external signature by it. Naming
     * one nobody signed with trusts nothing, which is the honest reading
     * rather than an error. */
    if (p->token != NULL) {
      for (i = 0; i < p->token->block_count; i++) {
        if (p->token->blocks[i].has_external &&
            p->token->blocks[i].external_key.alg == BS_ALG_ED25519 &&
            bs_span_eq(p->token->blocks[i].external_key.key,
                       bs_span_make(key, sizeof key))) {
          *add |= BS_ORIGIN_ONE(i);
        }
      }
    }
    return bs_p_advance(p);
  }
  return BS_ERR_MALFORMED;
}

/* An optional `trusting` clause. Without one, a statement trusts what its
 * position in the chain implies and nothing more. */
static bs_status bs_p_trusting(bs_parser *p, bs_origin *trust) {
  bs_status st;

  *trust = p->default_trust;
  if (!BS_WORD(p, "trusting")) {
    return BS_OK;
  }
  st = bs_p_advance(p);
  if (st != BS_OK) {
    return st;
  }
  /* An annotation replaces the default rather than adding to it, and the
   * authority is part of the default. Only the current block and the
   * authorizer are always trusted -- so `trusting ed25519/...` does *not*
   * keep seeing the authority, which is the difference between denying a
   * policy and granting it. */
  *trust = BS_ORIGIN_AUTHORIZER | bs_p_self(p);
  for (;;) {
    bs_origin add = BS_ORIGIN_NONE;
    st = bs_p_scope(p, &add);
    if (st != BS_OK) {
      return st;
    }
    *trust |= add;
    if (!bs_p_is_punct(p, (uint8_t)BS_P_COMMA)) {
      return BS_OK;
    }
    st = bs_p_advance(p);
    if (st != BS_OK) {
      return st;
    }
  }
}

/* Does an identifier here open a predicate rather than a term? Only a name
 * immediately followed by `(` does, which is one token further than the
 * lexer holds -- so the position is saved and put back. */
static bs_status bs_p_starts_predicate(bs_parser *p, int *yes) {
  bs_lexer save_lex;
  bs_token_t save_tok;
  bs_status st;

  *yes = 0;
  if (p->tok.kind != (uint8_t)BS_TK_IDENT) {
    return BS_OK;
  }
  if (BS_WORD(p, "true") || BS_WORD(p, "false") || BS_WORD(p, "null")) {
    return BS_OK;
  }
  save_lex = p->lex;
  save_tok = p->tok;
  st = bs_p_advance(p);
  if (st != BS_OK) {
    return st;
  }
  *yes = bs_p_is_punct(p, (uint8_t)BS_P_LPAREN);
  p->lex = save_lex;
  p->tok = save_tok;
  return BS_OK;
}

/* A rule body: predicates and expressions, comma-separated, with an optional
 * trust annotation at the end. Used for rules, for a check's queries and for
 * a policy's. */
static bs_status bs_p_body(bs_parser *p, bs_rule *out) {
  bs_predicate preds[BS_MAX_BODY];
  bs_expr exprs[BS_MAX_BODY];
  size_t npred = 0;
  size_t nexpr = 0;
  uint32_t at;
  size_t i;
  bs_status st;

  for (;;) {
    int is_pred = 0;
    st = bs_p_starts_predicate(p, &is_pred);
    if (st != BS_OK) {
      return st;
    }
    if (is_pred) {
      if (npred >= (size_t)BS_MAX_BODY) {
        return BS_ERR_LIMIT;
      }
      st = bs_p_predicate(p, &preds[npred]);
      if (st != BS_OK) {
        return st;
      }
      npred++;
    } else {
      if (nexpr >= (size_t)BS_MAX_BODY) {
        return BS_ERR_LIMIT;
      }
      st = bs_p_expression(p, p->scratch, p->scratch_cap, &exprs[nexpr]);
      if (st != BS_OK) {
        return st;
      }
      nexpr++;
    }
    if (!bs_p_is_punct(p, (uint8_t)BS_P_COMMA)) {
      break;
    }
    st = bs_p_advance(p);
    if (st != BS_OK) {
      return st;
    }
  }

  st = bs_p_trusting(p, &out->trust);
  if (st != BS_OK) {
    return st;
  }
  st = bs_pool_reserve_preds(p->w, npred, &at);
  if (st != BS_OK) {
    return st;
  }
  for (i = 0; i < npred; i++) {
    p->w->preds[at + i] = preds[i];
  }
  out->body_at = at;
  out->body_count = (uint32_t)npred;

  st = bs_pool_reserve_exprs(p->w, nexpr, &at);
  if (st != BS_OK) {
    return st;
  }
  for (i = 0; i < nexpr; i++) {
    p->w->exprs[at + i] = exprs[i];
  }
  out->expr_at = at;
  out->expr_count = (uint32_t)nexpr;
  out->block = (uint32_t)p->block;
  return BS_OK;
}

/* One or more queries joined by `or`, appended to the rule pool as one run.
 * A query is a rule with no head: it is asked, never fired. */
static bs_status bs_p_queries(bs_parser *p, uint32_t *at, uint32_t *count) {
  size_t n = 0;

  *at = (uint32_t)p->w->rule_count;
  for (;;) {
    bs_rule r;
    uint32_t slot;
    bs_status st;

    memset(&r, 0, sizeof r);
    r.is_query = 1;
    r.head.name = 0;
    r.head.at = 0;
    r.head.count = 0;
    st = bs_p_body(p, &r);
    if (st != BS_OK) {
      return st;
    }
    if (p->w->rule_count >= p->w->rule_cap) {
      return BS_ERR_NOMEM;
    }
    slot = (uint32_t)p->w->rule_count;
    p->w->rules[slot] = r;
    p->w->rule_count++;
    n++;

    if (!BS_WORD(p, "or")) {
      break;
    }
    st = bs_p_advance(p);
    if (st != BS_OK) {
      return st;
    }
  }
  *count = (uint32_t)n;
  return BS_OK;
}

/* The source a statement occupies, without the whitespace that followed it.
 * The check printer works from an encoding; the authorizer has none, so a
 * failing check is reported in the words its author wrote. */
static bs_span bs_p_since(const bs_parser *p, size_t start) {
  size_t end = p->tok.at;
  bs_span out = bs_span_make(NULL, 0);

  while (end > start) {
    uint8_t c = 0;
    if (!bs_span_at(p->lex.src, end - 1U, &c) || !bs_is_space(c)) {
      break;
    }
    end--;
  }
  (void)bs_span_slice(p->lex.src, start, end - start, &out);
  return out;
}

static bs_status bs_p_statement(bs_parser *p) {
  size_t start = p->tok.at;
  bs_status st;

  /* check if ... / check all ... / reject if ... */
  if (BS_WORD(p, "check") || BS_WORD(p, "reject")) {
    uint8_t kind = (uint8_t)BS_CHECK_KIND_ONE;
    int is_reject = BS_WORD(p, "reject");

    st = bs_p_advance(p);
    if (st != BS_OK) {
      return st;
    }
    if (is_reject) {
      if (!BS_WORD(p, "if")) {
        return BS_ERR_MALFORMED;
      }
      kind = (uint8_t)BS_CHECK_KIND_REJECT;
    } else if (BS_WORD(p, "if")) {
      kind = (uint8_t)BS_CHECK_KIND_ONE;
    } else if (BS_WORD(p, "all")) {
      kind = (uint8_t)BS_CHECK_KIND_ALL;
    } else {
      return BS_ERR_MALFORMED;
    }
    st = bs_p_advance(p);
    if (st != BS_OK) {
      return st;
    }
    {
      bs_check c;
      st = bs_p_queries(p, &c.query_at, &c.query_count);
      if (st != BS_OK) {
        return st;
      }
      c.kind = kind;
      c.block = (uint32_t)p->block;
      c.src = bs_p_since(p, start);
      c.from_text = 1;
      if (p->w->check_count >= p->w->check_cap) {
        return BS_ERR_NOMEM;
      }
      p->w->checks[p->w->check_count] = c;
      p->w->check_count++;
    }
    return BS_OK;
  }

  /* allow if ... / deny if ... */
  if (BS_WORD(p, "allow") || BS_WORD(p, "deny")) {
    uint8_t kind = BS_WORD(p, "allow") ? (uint8_t)BS_POLICY_ALLOW
                                       : (uint8_t)BS_POLICY_DENY;
    bs_policy pol;

    st = bs_p_advance(p);
    if (st != BS_OK) {
      return st;
    }
    if (!BS_WORD(p, "if")) {
      return BS_ERR_MALFORMED;
    }
    st = bs_p_advance(p);
    if (st != BS_OK) {
      return st;
    }
    st = bs_p_queries(p, &pol.query_at, &pol.query_count);
    if (st != BS_OK) {
      return st;
    }
    pol.kind = kind;
    if (p->w->policy_count >= p->w->policy_cap) {
      return BS_ERR_NOMEM;
    }
    p->w->policies[p->w->policy_count] = pol;
    p->w->policy_count++;
    return BS_OK;
  }

  /* Otherwise a head: a fact on its own, or a rule if an arrow follows. */
  {
    bs_predicate head;
    st = bs_p_predicate(p, &head);
    if (st != BS_OK) {
      return st;
    }
    if (bs_p_is_punct(p, (uint8_t)BS_P_LEFTARROW)) {
      bs_rule r;
      st = bs_p_advance(p);
      if (st != BS_OK) {
        return st;
      }
      memset(&r, 0, sizeof r);
      r.head = head;
      r.is_query = 0;
      st = bs_p_body(p, &r);
      if (st != BS_OK) {
        return st;
      }
      if (p->w->rule_count >= p->w->rule_cap) {
        return BS_ERR_NOMEM;
      }
      p->w->rules[p->w->rule_count] = r;
      st = bs_rule_bound(p->w, &p->w->rules[p->w->rule_count]);
      if (st != BS_OK) {
        return st;
      }
      p->w->rule_count++;
      return BS_OK;
    }
    {
      bs_fact f;
      uint32_t i;
      /* A fact states something outright, so nothing in it may be a
       * variable: there would be nothing to bind it to. */
      for (i = 0; i < head.count; i++) {
        if (p->w->terms[head.at + i].kind == (uint8_t)BS_T_VARIABLE) {
          return BS_ERR_MALFORMED;
        }
      }
      f.pred = head;
      f.origin = bs_p_self(p);
      if (p->w->fact_count >= p->w->fact_cap) {
        return BS_ERR_NOMEM;
      }
      p->w->facts[p->w->fact_count] = f;
      p->w->fact_count++;
      return BS_OK;
    }
  }
}

/* Parse a whole source into the world.
 *
 * `block` is the block these statements belong to, or BS_MAX_BLOCKS for the
 * authorizer, which sits outside the chain and trusts only the authority and
 * itself. */
BS_API bs_status bs_world_parse(bs_world *w, bs_symtab *syms, bs_arena *a,
                                bs_span source, size_t block,
                                const bs_token *token, const bs_tables *tab) {
  bs_parser p;
  bs_status st;

  if (w == NULL || syms == NULL || a == NULL || source.p == NULL) {
    return BS_ERR_ARGUMENT;
  }
  if (block > (size_t)BS_MAX_BLOCKS) {
    return BS_ERR_ARGUMENT;
  }

  memset(&p, 0, sizeof p);
  p.w = w;
  p.syms = syms;
  p.arena = a;
  p.token = token;
  p.tables = tab;
  p.block = block;
  p.default_trust = BS_ORIGIN_AUTHORIZER | BS_ORIGIN_ONE(0U) | bs_p_self(&p);
  p.scratch_cap = (size_t)BS_PARSE_SCRATCH;
  p.scratch =
      (bs_op *)bs_arena_array(a, p.scratch_cap, sizeof(bs_op), BS_ALIGN_MAX);
  p.tscratch = (bs_term *)bs_arena_array(a, p.scratch_cap, sizeof(bs_term),
                                         BS_ALIGN_MAX);
  p.pscratch = (bs_term *)bs_arena_array(a, p.scratch_cap, sizeof(bs_term),
                                         BS_ALIGN_MAX);
  if (p.scratch == NULL || p.tscratch == NULL || p.pscratch == NULL) {
    return BS_ERR_NOMEM;
  }

  p.lex.src = source;
  p.lex.pos = 0;
  st = bs_p_advance(&p);
  if (st != BS_OK) {
    return st;
  }

  while (p.tok.kind != (uint8_t)BS_TK_EOF) {
    st = bs_p_statement(&p);
    if (st != BS_OK) {
      return st;
    }
    /* A semicolon ends a statement. The last one may leave it out. */
    if (bs_p_is_punct(&p, (uint8_t)BS_P_SEMI)) {
      st = bs_p_advance(&p);
      if (st != BS_OK) {
        return st;
      }
      continue;
    }
    if (p.tok.kind != (uint8_t)BS_TK_EOF) {
      return BS_ERR_MALFORMED;
    }
  }
  return BS_OK;
}

/* ===========================================================================
 * 145_authorize.inc
 * ======================================================================== */

/* ---------------------------------------------------------------------------
 * Authorization
 *
 * Everything above produces facts; this decides what they mean. Run the world
 * to a fixpoint, ask every check whether it holds, then walk the policies in
 * order until one matches.
 *
 * The part worth stating plainly is that a policy and a check answer
 * different questions. A policy says what the application will allow; a check
 * says what the token's own blocks insisted on. An implementation that
 * consults only the policy authorizes a token whose every check failed --
 * which is to say it ignores attenuation entirely, silently, while appearing
 * to work. So both are evaluated, always, and both are reported.
 * ------------------------------------------------------------------------ */

/* Does this query have at least one answer that satisfies its expressions? */
static bs_status bs_query_any(bs_world *w, bs_symtab *syms, bs_arena *a,
                              const bs_rule *r, bs_solver *sv, int *yes) {
  bs_status st = bs_solver_init(sv, w, r);

  *yes = 0;
  if (st != BS_OK) {
    return st;
  }
  for (;;) {
    int found = 0;
    int keep = 0;

    bs_solver_next(w, r, sv, &found);
    if (!found) {
      return BS_OK;
    }
    st = bs_solver_expressions(w, syms, a, r, sv, &keep);
    if (st != BS_OK) {
      return st;
    }
    if (keep) {
      *yes = 1;
      return BS_OK;
    }
  }
}

/* Do *all* of this query's answers satisfy its expressions?
 *
 * And is there at least one. The specification's wording -- "all the sets of
 * facts that match the body also succeed the expression" -- reads as
 * vacuously true when the body matches nothing, but test025's "no matches"
 * case expects a failure, so an empty body is a failure here. The samples
 * settle what the prose leaves open. */
static bs_status bs_query_all(bs_world *w, bs_symtab *syms, bs_arena *a,
                              const bs_rule *r, bs_solver *sv, int *yes) {
  bs_status st = bs_solver_init(sv, w, r);
  int any = 0;

  *yes = 0;
  if (st != BS_OK) {
    return st;
  }
  for (;;) {
    int found = 0;
    int keep = 0;

    bs_solver_next(w, r, sv, &found);
    if (!found) {
      *yes = any;
      return BS_OK;
    }
    any = 1;
    st = bs_solver_expressions(w, syms, a, r, sv, &keep);
    if (st != BS_OK) {
      return st;
    }
    if (!keep) {
      *yes = 0;
      return BS_OK;
    }
  }
}

/* Does a check hold?
 *
 * A check carries several queries joined by `or` and succeeds if any of them
 * succeeds -- except `reject if`, which fails if any of them matches. What
 * "succeeds" means for one query is the check's kind. */
static bs_status bs_check_holds(bs_world *w, bs_symtab *syms, bs_arena *a,
                                const bs_check *c, bs_solver *sv, int *holds) {
  uint32_t i;

  *holds = (c->kind == (uint8_t)BS_CHECK_KIND_REJECT) ? 1 : 0;

  for (i = 0; i < c->query_count; i++) {
    const bs_rule *r = &w->rules[c->query_at + i];
    int yes = 0;
    bs_status st;

    if (c->kind == (uint8_t)BS_CHECK_KIND_ALL) {
      st = bs_query_all(w, syms, a, r, sv, &yes);
    } else {
      st = bs_query_any(w, syms, a, r, sv, &yes);
    }
    if (st != BS_OK) {
      return st;
    }
    if (c->kind == (uint8_t)BS_CHECK_KIND_REJECT) {
      if (yes) {
        *holds = 0; /* something matched, and matching is the rejection */
        return BS_OK;
      }
      continue;
    }
    if (yes) {
      *holds = 1;
      return BS_OK;
    }
  }
  return BS_OK;
}

/* Does a policy's condition match? Its queries are joined by `or` too. */
static bs_status bs_policy_matches(bs_world *w, bs_symtab *syms, bs_arena *a,
                                   const bs_policy *pol, bs_solver *sv,
                                   int *yes) {
  uint32_t i;

  *yes = 0;
  for (i = 0; i < pol->query_count; i++) {
    bs_status st =
        bs_query_any(w, syms, a, &w->rules[pol->query_at + i], sv, yes);
    if (st != BS_OK) {
      return st;
    }
    if (*yes) {
      return BS_OK;
    }
  }
  return BS_OK;
}

BS_API bs_status bs_authorize(bs_world *w, bs_symtab *syms, bs_arena *a,
                              size_t max_iterations, bs_verdict *out) {
  bs_failed_check *failed;
  bs_solver *sv;
  size_t nfailed = 0;
  size_t i;
  bs_status st;

  if (w == NULL || syms == NULL || a == NULL || out == NULL) {
    return BS_ERR_ARGUMENT;
  }

  memset(out, 0, sizeof *out);
  out->kind = (uint8_t)BS_VERDICT_NO_POLICY;

  /* One solver for the whole decision: the fixpoint finishes before any
   * check is asked, so nothing here is ever using two at once. */
  sv = bs_solver_new(a);
  if (sv == NULL) {
    return BS_ERR_NOMEM;
  }
  st = bs_world_run_with(w, syms, a, max_iterations, sv);
  if (st != BS_OK) {
    return st;
  }

  failed = (bs_failed_check *)bs_arena_array(
      a, (w->check_count == 0U) ? 1U : w->check_count, sizeof(bs_failed_check),
      BS_ALIGN_MAX);
  if (failed == NULL) {
    return BS_ERR_NOMEM;
  }

  /* Every check is evaluated, not just up to the first failure: an
   * application that logs why a token was refused wants all the reasons, and
   * stopping early would make the report depend on evaluation order. */
  {
    uint32_t per_block = 0;
    uint32_t block = 0xFFFFFFFFU;

    for (i = 0; i < w->check_count; i++) {
      int holds = 0;

      if (w->checks[i].block != block) {
        block = w->checks[i].block;
        per_block = 0;
      }
      st = bs_check_holds(w, syms, a, &w->checks[i], sv, &holds);
      if (st != BS_OK) {
        return st;
      }
      if (!holds) {
        failed[nfailed].block = w->checks[i].block;
        failed[nfailed].index = per_block;
        failed[nfailed].src = w->checks[i].src;
        failed[nfailed].from_text = w->checks[i].from_text;
        nfailed++;
      }
      per_block++;
    }
  }

  for (i = 0; i < w->policy_count; i++) {
    int matched = 0;
    st = bs_policy_matches(w, syms, a, &w->policies[i], sv, &matched);
    if (st != BS_OK) {
      return st;
    }
    if (!matched) {
      continue;
    }
    out->policy = (uint32_t)i;
    out->has_policy = 1;
    /* A deny that matches denies; an allow that matches only allows if
     * nothing the token itself demanded went unmet. */
    out->kind = (w->policies[i].kind == (uint8_t)BS_POLICY_DENY || nfailed > 0U)
                    ? (uint8_t)BS_VERDICT_DENY
                    : (uint8_t)BS_VERDICT_ALLOW;
    break;
  }

  out->failed_count = nfailed;
  out->failed = failed;
  return BS_OK;
}

BS_API bs_status bs_failed_check_print(bs_writer *wr, bs_arena *a,
                                       const bs_tables *tab,
                                       const bs_failed_check *f) {
  if (wr == NULL || f == NULL) {
    return BS_ERR_ARGUMENT;
  }
  if (f->from_text) {
    bs_put_span(wr, f->src);
    return bs_writer_overflow(wr) ? BS_ERR_NOMEM : BS_OK;
  }
  return bs_check_print(wr, a, tab, f->src);
}

/* ===========================================================================
 * 99_epilogue.inc
 * ======================================================================== */

#endif /* BISCUITS_IMPLEMENTATION */

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* BISCUITS_H_INCLUDED */
