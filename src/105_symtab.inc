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
