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
  if (!bs_size_align_up(a->off, align, &start) ||
      !bs_size_add(start, size, &end) || end > a->cap) {
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
 * 99_epilogue.inc
 * ======================================================================== */

#endif /* BISCUITS_IMPLEMENTATION */

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* BISCUITS_H_INCLUDED */
