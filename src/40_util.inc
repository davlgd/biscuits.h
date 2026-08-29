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
