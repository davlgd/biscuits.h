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
#define BS_ED25519_SECRET_LEN 32U
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
      if (!bs_size_add(appended, 1U, &appended)) {
        return BS_ERR_OVERFLOW;
      }
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
 * UTF-8 passes through untouched: the specification's own samples contain
 * multi-byte characters printed verbatim, and re-encoding them would break
 * the round-trip the conformance suite checks. Only the characters that would
 * terminate or reinterpret the literal are escaped. */
static void bs_put_string(bs_writer *w, bs_span s) {
  size_t i;
  bs_put_byte(w, (uint8_t)'"');
  for (i = 0; i < s.n; i++) {
    uint8_t c = s.p[i];
    switch (c) {
    case (uint8_t)'"':
      BS_PUT_LIT(w, "\\\"");
      break;
    case (uint8_t)'\\':
      BS_PUT_LIT(w, "\\\\");
      break;
    case (uint8_t)'\n':
      BS_PUT_LIT(w, "\\n");
      break;
    case (uint8_t)'\t':
      BS_PUT_LIT(w, "\\t");
      break;
    case (uint8_t)'\r':
      BS_PUT_LIT(w, "\\r");
      break;
    default:
      bs_put_byte(w, c);
      break;
    }
  }
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

static void bs_put_close(bs_writer *w, uint32_t kind) {
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
      bs_put_close(w, f->kind);
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
 * 99_epilogue.inc
 * ======================================================================== */

#endif /* BISCUITS_IMPLEMENTATION */

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* BISCUITS_H_INCLUDED */
