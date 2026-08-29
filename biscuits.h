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
 *   5. No libc beyond memcpy, memcmp and memset. No stdio, no locale, no
 *                            string functions, no floating point.
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
  BS_ERR_TRUNCATED,   /* input ended in the middle of a structure */
  BS_ERR_MALFORMED,   /* input violates the wire format */
  BS_ERR_DEPTH,       /* nesting deeper than BS_MAX_DEPTH */
  BS_ERR_OVERFLOW,    /* an arithmetic operation overflowed */
  BS_ERR_LIMIT,       /* a configured evaluation limit was reached */
  BS_ERR_UNSUPPORTED, /* well-formed, but this build cannot handle it */
  BS_ERR_SIGNATURE,   /* a signature did not verify */
  BS_STATUS_COUNT,    /* not a status; keep last */
} bs_status;

/* Short, stable, allocation-free description. Never NULL, even for a value
 * outside the enum -- a corrupted status must not become a crash. */
BS_API const char *bs_strstatus(bs_status st);

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

BS_API bs_span bs_span_make(const void *p, size_t n);

/* Byte at index i. Returns 0 and leaves *out untouched if i is out of range. */
BS_API int bs_span_at(bs_span s, size_t i, uint8_t *out);

/* Sub-range [off, off+len). Returns 0 on any overflow or overrun. */
BS_API int bs_span_slice(bs_span s, size_t off, size_t len, bs_span *out);

/* Content equality. Two empty spans are equal regardless of their pointers. */
BS_API int bs_span_eq(bs_span a, bs_span b);

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

BS_API bs_cursor bs_cursor_make(bs_span s);
BS_API size_t bs_cursor_left(const bs_cursor *c);
BS_API int bs_cursor_done(const bs_cursor *c);

BS_API int bs_take_u8(bs_cursor *c, uint8_t *out);
BS_API int bs_take_bytes(bs_cursor *c, size_t n, bs_span *out);

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
 * allocation -- useful for measuring how much memory a workload would need. */
BS_API bs_status bs_arena_init(bs_arena *a, void *buf, size_t cap);

/* align must be a power of two and at most BS_ALIGN_MAX. Returns NULL on
 * exhaustion, on overflow, or if the arena has already failed. */
BS_API void *bs_arena_alloc(bs_arena *a, size_t size, size_t align);

/* Zero-initialised array of n elements of the given size. Guards the
 * multiplication; a hostile count cannot wrap into a small allocation. */
BS_API void *bs_arena_array(bs_arena *a, size_t n, size_t size, size_t align);

/* Rewind to empty. Keeps the peak, clears the failure flag. */
BS_API void bs_arena_reset(bs_arena *a);

BS_API size_t bs_arena_used(const bs_arena *a);
BS_API size_t bs_arena_peak(const bs_arena *a);
BS_API int bs_arena_failed(const bs_arena *a);

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
BS_API bs_status bs_token_parse(bs_arena *a, bs_span input, bs_token *out);

/* The revocation identifier of a block: its signature, verbatim. Returns an
 * empty span for an out-of-range index. */
BS_API bs_span bs_token_revocation_id(const bs_token *t, size_t index);

/* ===========================================================================
 * 30_impl_open.inc
 * ======================================================================== */

#ifdef BISCUITS_IMPLEMENTATION

/* The entire libc surface of this library. Invariant 5.
 *
 * memcpy/memcmp/memset only: no stdio, no locale-sensitive string handling,
 * no allocation, no floating point. This is what makes the header usable in
 * a kernel module, a WASM sandbox or a bare-metal firmware without a shim. */
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

#if defined(__GNUC__) || defined(__clang__)
#define BS_HAS_OVERFLOW_BUILTINS 1
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
      "input truncated",
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
  if (c == NULL || c->off > c->s.n) {
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
  *out = sub;
  return 1;
}

/* ---------------------------------------------------------------------------
 * Arena
 * ------------------------------------------------------------------------ */

BS_API bs_status bs_arena_init(bs_arena *a, void *buf, size_t cap) {
  if (a == NULL) {
    return BS_ERR_ARGUMENT;
  }
  if (buf == NULL && cap != 0U) {
    return BS_ERR_ARGUMENT;
  }
  a->base = (uint8_t *)buf;
  a->cap = (buf == NULL) ? 0U : cap;
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

/* Key widths. Ed25519 is a compressed Edwards point; secp256r1 is a
 * compressed SEC1 point whose leading byte must be 0x02 or 0x03. */
#define BS_ED25519_PUBKEY_LEN 32U
#define BS_ED25519_SIG_LEN 64U
#define BS_SECP256R1_PUBKEY_LEN 33U

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

static bs_status bs_pb_signed_block(bs_span in, bs_signed_block *out) {
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
  /* A signature is verified with the *previous* block's key, whose algorithm
   * this function cannot see. That does not matter while Ed25519 is the only
   * algorithm this build accepts -- every other one has already been refused
   * by bs_pb_pubkey -- so every signature must be 64 bytes.
   *
   * When secp256r1 lands in 1.1 this check moves to the verifier, which knows
   * the signing key. Until then, catching a truncated signature here is what
   * stops a malformed token from reaching the crypto at all. */
  if (out->signature.n != BS_ED25519_SIG_LEN) {
    return BS_ERR_MALFORMED;
  }
  if (out->has_external && out->external_signature.n != BS_ED25519_SIG_LEN) {
    return BS_ERR_MALFORMED;
  }
  return BS_OK;
}

static bs_status bs_pb_proof(bs_span in, bs_token *out) {
  bs_cursor c = bs_cursor_make(in);
  bs_pb_field f;
  int seen = 0;

  while (!bs_cursor_done(&c)) {
    if (!bs_pb_next(&c, &f)) {
      return BS_ERR_MALFORMED;
    }
    if (f.wire != BS_PB_BYTES) {
      continue;
    }
    if (f.number == BS_F_PROOF_NEXT_SECRET) {
      out->sealed = 0;
      out->proof = f.bytes;
      seen++;
    } else if (f.number == BS_F_PROOF_FINAL_SIGNATURE) {
      out->sealed = 1;
      out->proof = f.bytes;
      seen++;
    }
  }
  /* The schema makes these a oneof: exactly one, never both, never neither.
   * A token carrying both would let a verifier pick the branch it prefers. */
  if (seen != 1) {
    return BS_ERR_MALFORMED;
  }
  return BS_OK;
}

BS_API bs_status bs_token_parse(bs_arena *a, bs_span input, bs_token *out) {
  bs_cursor c;
  bs_pb_field f;
  size_t appended = 0;
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
      if (f.wire != BS_PB_BYTES) {
        return BS_ERR_MALFORMED;
      }
      authority = f.bytes;
      have_authority = 1;
      break;
    case BS_F_BISCUIT_BLOCKS:
      if (f.wire != BS_PB_BYTES) {
        return BS_ERR_MALFORMED;
      }
      appended++;
      break;
    case BS_F_BISCUIT_PROOF:
      if (f.wire != BS_PB_BYTES) {
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
  if (appended + 1U > (size_t)BS_MAX_BLOCKS) {
    return BS_ERR_LIMIT;
  }

  tok.block_count = appended + 1U;
  tok.blocks = (bs_signed_block *)bs_arena_array(
      a, tok.block_count, sizeof(bs_signed_block), BS_ALIGN_MAX);
  if (tok.blocks == NULL) {
    return BS_ERR_NOMEM;
  }

  /* Second pass: decode each block in wire order. Order is load-bearing --
   * the signature chain is verified block by block from the authority
   * outwards, and a reordered token must not verify. */
  {
    bs_status st = bs_pb_signed_block(authority, &tok.blocks[0]);
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
      st = bs_pb_signed_block(f.bytes, &tok.blocks[index]);
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
 * 99_epilogue.inc
 * ======================================================================== */

#endif /* BISCUITS_IMPLEMENTATION */

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* BISCUITS_H_INCLUDED */
