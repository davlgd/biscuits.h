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

static const char *const BS_DEFAULT_SYMBOLS[] = {
    "read",    "write",     "resource", "operation", "right",   "time",
    "role",    "owner",     "tenant",   "namespace", "user",    "team",
    "service", "admin",     "email",    "group",     "member",  "ip_address",
    "client",  "client_ip", "domain",   "path",      "version", "cluster",
    "node",    "hostname",  "nonce",    "query",
};

#define BS_DEFAULT_SYMBOL_COUNT                                                \
  (sizeof BS_DEFAULT_SYMBOLS / sizeof BS_DEFAULT_SYMBOLS[0])

static size_t bs_cstr_len(const char *s) {
  size_t n = 0;
  while (s[n] != '\0') {
    n++;
  }
  return n;
}

BS_API int bs_symbol_get(const bs_symbols *s, uint64_t index, bs_span *out) {
  if (out == NULL) {
    return 0;
  }

  if (index < BS_SYMBOL_OFFSET) {
    const char *text;
    if (index >= (uint64_t)BS_DEFAULT_SYMBOL_COUNT) {
      /* An index inside the reserved range but past the list this build
       * knows. A future specification may define it; this one cannot print
       * it, and guessing would produce a token that reads differently here
       * than everywhere else. */
      return 0;
    }
    text = BS_DEFAULT_SYMBOLS[(size_t)index];
    *out = bs_span_make(text, bs_cstr_len(text));
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
