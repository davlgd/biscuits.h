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
