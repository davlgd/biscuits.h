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
