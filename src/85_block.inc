/* ---------------------------------------------------------------------------
 * Blocks
 *
 * A block carries the Datalog: facts, rules, checks, the scopes they trust,
 * and the symbols and public keys they refer to by index.
 *
 * Those indices are token-wide, not block-wide. The symbol table is the
 * concatenation of every block's `symbols` array in block order, authority
 * first, and the public key table works the same way. Building them is
 * therefore a whole-token operation that has to happen before any single
 * block can be read -- which is why it lives here rather than inside the
 * block decoder.
 *
 * Getting that order wrong does not fail; it silently renames every predicate
 * in the token. The blocks tier of the conformance suite catches exactly that,
 * by printing each decoded block and diffing it against the source the
 * specification says it should produce.
 * ------------------------------------------------------------------------ */

#define BS_F_BLOCK_SYMBOLS 1U
#define BS_F_BLOCK_CONTEXT 2U
#define BS_F_BLOCK_VERSION 3U
#define BS_F_BLOCK_FACTS 4U
#define BS_F_BLOCK_RULES 5U
#define BS_F_BLOCK_CHECKS 6U
#define BS_F_BLOCK_SCOPE 7U
#define BS_F_BLOCK_PUBLIC_KEYS 8U

#define BS_F_FACT_PREDICATE 1U
#define BS_F_PREDICATE_NAME 1U
#define BS_F_PREDICATE_TERMS 2U

#define BS_F_SCOPE_TYPE 1U
#define BS_F_SCOPE_PUBLIC_KEY 2U

#define BS_SCOPE_AUTHORITY 0U
#define BS_SCOPE_PREVIOUS 1U

/* Count the entries of one repeated field in a message, and optionally copy
 * their payloads out. Two passes over the same bytes is what lets the arena
 * stay a bump allocator: the count is known before anything is reserved, so
 * there is never a growth step and never a realloc. */
static bs_status bs_repeated(bs_span msg, uint32_t field, bs_span *out,
                             size_t cap, size_t *count) {
  bs_cursor c = bs_cursor_make(msg);
  bs_pb_field f;
  size_t n = 0;

  while (!bs_cursor_done(&c)) {
    if (!bs_pb_next(&c, &f)) {
      return BS_ERR_MALFORMED;
    }
    if (f.number != field || f.wire != BS_PB_BYTES) {
      continue;
    }
    if (out != NULL) {
      if (n >= cap) {
        return BS_ERR_LIMIT;
      }
      out[n] = f.bytes;
    }
    if (!bs_size_add(n, 1U, &n)) {
      return BS_ERR_OVERFLOW;
    }
  }
  *count = n;
  return BS_OK;
}

static int bs_pubkey_eq(const bs_public_key *x, const bs_public_key *y) {
  return x->alg == y->alg && bs_span_eq(x->key, y->key);
}

/* Collect the symbol and public-key tables from a run of blocks.
 *
 * `skip_external` reproduces the rule in the specification's reference
 * decoder: a block carrying an external signature contributes nothing to the
 * token-wide tables. Its symbols and keys belong to the third party that
 * signed it, who never saw the rest of the token, so folding them in would
 * shift every index that follows.
 *
 * Public keys are deduplicated on insertion -- a key already in the table
 * keeps its index rather than gaining a second one. Symbols are not: they are
 * appended as they come. */
static bs_status bs_tables_collect(bs_arena *a, const bs_signed_block *blocks,
                                   size_t block_count, int skip_external,
                                   bs_tables *out) {
  size_t total_symbols = 0;
  size_t total_keys = 0;
  size_t block;
  size_t sym_at = 0;
  size_t key_at = 0;
  /* Filled through a non-const pointer and published as const: the table is
   * read-only to everyone but its builder, and casting the qualifier away at
   * the point of use would hide that. */
  bs_span *sym_slots = NULL;

  out->symbols.entries = NULL;
  out->symbols.count = 0;
  out->public_keys = NULL;
  out->public_key_count = 0;

  for (block = 0; block < block_count; block++) {
    size_t n;
    bs_status st;
    if (skip_external && blocks[block].has_external) {
      continue;
    }
    st = bs_repeated(blocks[block].block, BS_F_BLOCK_SYMBOLS, NULL, 0U, &n);
    if (st != BS_OK) {
      return st;
    }
    if (!bs_size_add(total_symbols, n, &total_symbols)) {
      return BS_ERR_OVERFLOW;
    }
    st = bs_repeated(blocks[block].block, BS_F_BLOCK_PUBLIC_KEYS, NULL, 0U, &n);
    if (st != BS_OK) {
      return st;
    }
    if (!bs_size_add(total_keys, n, &total_keys)) {
      return BS_ERR_OVERFLOW;
    }
  }

  if (total_symbols != 0U) {
    sym_slots = (bs_span *)bs_arena_array(a, total_symbols, sizeof(bs_span),
                                          BS_ALIGN_MAX);
    if (sym_slots == NULL) {
      return BS_ERR_NOMEM;
    }
  }
  if (total_keys != 0U) {
    out->public_keys = (bs_public_key *)bs_arena_array(
        a, total_keys, sizeof(bs_public_key), BS_ALIGN_MAX);
    if (out->public_keys == NULL) {
      return BS_ERR_NOMEM;
    }
  }

  for (block = 0; block < block_count; block++) {
    bs_cursor c;
    bs_pb_field f;
    if (skip_external && blocks[block].has_external) {
      continue;
    }
    c = bs_cursor_make(blocks[block].block);
    while (!bs_cursor_done(&c)) {
      if (!bs_pb_next(&c, &f)) {
        return BS_ERR_MALFORMED;
      }
      if (f.wire != BS_PB_BYTES) {
        continue;
      }
      if (f.number == BS_F_BLOCK_SYMBOLS) {
        /* The counting pass allocated exactly as many slots as this pass will
         * fill. If the two ever disagree the input changed underneath us,
         * which cannot happen -- but saying so here is what lets the static
         * analyser see that the array is non-null and in range. */
        if (sym_slots == NULL || sym_at >= total_symbols) {
          return BS_ERR_MALFORMED;
        }
        sym_slots[sym_at] = f.bytes;
        sym_at++;
      } else if (f.number == BS_F_BLOCK_PUBLIC_KEYS) {
        bs_public_key key;
        bs_status st = bs_pb_pubkey(f.bytes, &key);
        size_t seen;
        int duplicate = 0;
        if (st != BS_OK) {
          return st;
        }
        for (seen = 0; seen < key_at && out->public_keys != NULL; seen++) {
          if (bs_pubkey_eq(&out->public_keys[seen], &key)) {
            duplicate = 1;
            break;
          }
        }
        if (!duplicate) {
          if (out->public_keys == NULL || key_at >= total_keys) {
            return BS_ERR_MALFORMED;
          }
          out->public_keys[key_at] = key;
          key_at++;
        }
      }
    }
  }

  BS_ASSERT(sym_at == total_symbols);
  BS_ASSERT(key_at <= total_keys); /* duplicates were folded away */
  out->symbols.entries = sym_slots;
  out->symbols.count = total_symbols;
  out->public_key_count = total_keys;
  return BS_OK;
}

/* The token-wide tables: every block's symbols and keys, in block order.
 *
 * These are the tables a regular block is read against. A third-party block
 * is not -- see bs_tables_build_block. */
BS_API bs_status bs_tables_build(bs_arena *a, const bs_token *t,
                                 bs_tables *out) {
  if (a == NULL || t == NULL || out == NULL || t->blocks == NULL) {
    return BS_ERR_ARGUMENT;
  }
  return bs_tables_collect(a, t->blocks, t->block_count, 1, out);
}

/* The tables of a single block, standing alone.
 *
 * A third-party block is signed by someone who never saw the rest of the
 * token, so its indices number only its own symbols and keys. Reading it
 * against the token-wide tables resolves them to the wrong entries -- which
 * is silent, because both tables are populated and both indices are in range.
 * The specification's public-key interning sample is exactly this case, and
 * it is the reason this function exists. */
BS_API bs_status bs_tables_build_block(bs_arena *a, bs_span block,
                                       bs_tables *out) {
  bs_signed_block one;
  if (a == NULL || out == NULL) {
    return BS_ERR_ARGUMENT;
  }
  memset(&one, 0, sizeof one);
  one.block = block;
  return bs_tables_collect(a, &one, 1U, 0, out);
}

/* ---------------------------------------------------------------------------
 * Printing
 * ------------------------------------------------------------------------ */

/* A public key renders as its algorithm, a slash, and the key in hex. */
static bs_status bs_print_public_key(bs_writer *w, const bs_public_key *k) {
  if (k == NULL) {
    return BS_ERR_MALFORMED;
  }
  switch (k->alg) {
  case BS_ALG_ED25519:
    BS_PUT_LIT(w, "ed25519/");
    break;
  case BS_ALG_SECP256R1:
    BS_PUT_LIT(w, "secp256r1/");
    break;
  default:
    return BS_ERR_MALFORMED;
  }
  bs_put_hex(w, k->key);
  return BS_OK;
}

/* `authority`, `previous`, or a key from the token's public key table. */
BS_API bs_status bs_scope_print(bs_writer *w, const bs_tables *tab,
                                bs_span scope) {
  bs_cursor c = bs_cursor_make(scope);
  bs_pb_field f;
  int have_type = 0;
  int have_key = 0;
  uint64_t type = 0;
  int64_t key = 0;

  while (!bs_cursor_done(&c)) {
    if (!bs_pb_next(&c, &f)) {
      return BS_ERR_MALFORMED;
    }
    if (f.wire != BS_PB_VARINT) {
      continue;
    }
    if (f.number == BS_F_SCOPE_TYPE) {
      type = f.varint;
      have_type = 1;
    } else if (f.number == BS_F_SCOPE_PUBLIC_KEY) {
      key = (int64_t)f.varint;
      have_key = 1;
    }
  }

  /* The schema makes these a oneof: a scope names a kind or a key, never
   * both and never neither. */
  if (have_type == have_key) {
    return BS_ERR_MALFORMED;
  }

  if (have_type) {
    switch (type) {
    case BS_SCOPE_AUTHORITY:
      BS_PUT_LIT(w, "authority");
      return BS_OK;
    case BS_SCOPE_PREVIOUS:
      BS_PUT_LIT(w, "previous");
      return BS_OK;
    default:
      return BS_ERR_MALFORMED;
    }
  }

  if (tab == NULL || key < 0 ||
      (uint64_t)key >= (uint64_t)tab->public_key_count) {
    return BS_ERR_MALFORMED;
  }
  return bs_print_public_key(w, &tab->public_keys[(size_t)key]);
}

/* `name(term, term, ...)`, the shape shared by facts, rule heads and rule
 * bodies. A predicate with no terms prints as `name()`. */
BS_API bs_status bs_predicate_print(bs_writer *w, const bs_tables *tab,
                                    bs_span pred) {
  bs_cursor c = bs_cursor_make(pred);
  bs_pb_field f;
  bs_span name = bs_span_make(NULL, 0);
  int have_name = 0;
  int emitted = 0;

  /* The name comes before the terms on the wire, but the schema does not
   * guarantee it, so it is resolved in a first pass. */
  while (!bs_cursor_done(&c)) {
    if (!bs_pb_next(&c, &f)) {
      return BS_ERR_MALFORMED;
    }
    if (f.number == BS_F_PREDICATE_NAME && f.wire == BS_PB_VARINT) {
      if (!bs_symbol_get(&tab->symbols, f.varint, &name)) {
        return BS_ERR_MALFORMED;
      }
      have_name = 1;
    }
  }
  if (!have_name) {
    return BS_ERR_MALFORMED;
  }

  bs_put_span(w, name);
  bs_put_byte(w, (uint8_t)'(');

  c = bs_cursor_make(pred);
  while (!bs_cursor_done(&c)) {
    bs_status st;
    if (!bs_pb_next(&c, &f)) {
      return BS_ERR_MALFORMED;
    }
    if (f.number != BS_F_PREDICATE_TERMS || f.wire != BS_PB_BYTES) {
      continue;
    }
    if (emitted++ > 0) {
      BS_PUT_LIT(w, ", ");
    }
    st = bs_term_print(w, &tab->symbols, f.bytes);
    if (st != BS_OK) {
      return st;
    }
  }

  bs_put_byte(w, (uint8_t)')');
  return BS_OK;
}

/* A Fact is a Predicate in a one-field wrapper. */
BS_API bs_status bs_fact_print(bs_writer *w, const bs_tables *tab,
                               bs_span fact) {
  bs_cursor c = bs_cursor_make(fact);
  bs_pb_field f;
  int found = 0;
  bs_span pred = bs_span_make(NULL, 0);

  while (!bs_cursor_done(&c)) {
    if (!bs_pb_next(&c, &f)) {
      return BS_ERR_MALFORMED;
    }
    if (f.number == BS_F_FACT_PREDICATE && f.wire == BS_PB_BYTES) {
      if (found++) {
        return BS_ERR_MALFORMED;
      }
      pred = f.bytes;
    }
  }
  if (found != 1) {
    return BS_ERR_MALFORMED;
  }
  return bs_predicate_print(w, tab, pred);
}
