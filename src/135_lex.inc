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
  /* Whether the token just consumed was an operand. `-` is the sign of a
   * number literal or the subtraction operator, and nothing about the
   * character says which: the grammar makes the space optional, so `3-2` is
   * a subtraction while `f(-2)` is a negative literal. Only the parser knows
   * which it is expecting, so it says. */
  int after_operand;
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

  if (part[1] < 1U || part[1] > 12U || part[2] < 1U || part[3] > 23U ||
      part[4] > 59U || part[5] > 60U) {
    return BS_ERR_MALFORMED;
  }
  {
    /* Days per month, with February decided by the year. A flat 1..31 bound
     * would accept the 31st of February, and the conversion below would then
     * silently normalise it into a different instant rather than refusing --
     * two spellings for one moment, one of which nobody wrote on purpose. */
    static const uint64_t DAYS[12] = {
        31U, 28U, 31U, 30U, 31U, 30U, 31U, 31U, 30U, 31U, 30U, 31U,
    };
    uint64_t limit = DAYS[part[1] - 1U];
    if (part[1] == 2U && (part[0] % 4U) == 0U &&
        ((part[0] % 100U) != 0U || (part[0] % 400U) == 0U)) {
      limit = 29U;
    }
    if (part[2] > limit) {
      return BS_ERR_MALFORMED;
    }
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

  /* A number, or a date, which starts like one. A leading `-` is part of the
   * number only where an operand is expected; after one it is subtraction. */
  if (bs_is_digit(c) ||
      (c == (uint8_t)'-' && !l->after_operand &&
       bs_span_at(l->src, l->pos + 1U, &d) && bs_is_digit(d))) {
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
