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

/* Strip the optional `biscuit:` prefix. */
static bs_span bs_strip_prefix(bs_span text) {
  bs_span head;
  bs_span rest;
  bs_span want = bs_span_make("" BS_TOKEN_PREFIX, sizeof BS_TOKEN_PREFIX - 1U);

  if (!bs_span_slice(text, 0U, want.n, &head) || !bs_span_eq(head, want)) {
    return text;
  }
  if (!bs_span_slice(text, want.n, text.n - want.n, &rest)) {
    return text;
  }
  return rest;
}

BS_API bs_status bs_base64url_decode(bs_arena *a, bs_span text, bs_span *out) {
  bs_span body;
  size_t groups;
  size_t tail;
  size_t capacity;
  uint8_t *buf;
  size_t written = 0;
  size_t i;

  if (a == NULL || out == NULL) {
    return BS_ERR_ARGUMENT;
  }

  body = bs_strip_prefix(text);

  /* Count the padding, which may only appear as the last one or two
   * characters of the last group. */
  tail = 0;
  while (tail < 2U && body.n > tail) {
    uint8_t c = 0;
    if (!bs_span_at(body, body.n - tail - 1U, &c) || c != (uint8_t)'=') {
      break;
    }
    tail++;
  }
  if (body.n < tail) {
    return BS_ERR_MALFORMED;
  }
  body.n -= tail;

  /* With padding present the encoding is a whole number of four-character
   * groups; without it, a final group of two or three characters is allowed.
   * A final group of one is not: it carries no complete byte. */
  if (tail != 0U && ((body.n + tail) % 4U) != 0U) {
    return BS_ERR_MALFORMED;
  }
  if ((body.n % 4U) == 1U) {
    return BS_ERR_MALFORMED;
  }
  if (tail == 1U && (body.n % 4U) != 3U) {
    return BS_ERR_MALFORMED;
  }
  if (tail == 2U && (body.n % 4U) != 2U) {
    return BS_ERR_MALFORMED;
  }

  groups = body.n / 4U;
  capacity = groups * 3U;
  switch (body.n % 4U) {
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
    for (i = 0; i < body.n; i++) {
      uint8_t c = 0;
      uint8_t v;
      (void)bs_span_at(body, i, &c);
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
