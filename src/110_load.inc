/* ---------------------------------------------------------------------------
 * Loading: wire format into the world
 *
 * The printers read the wire in place. The engine cannot: it generates facts
 * that were never encoded, and it compares facts across blocks whose symbol
 * numbering differs. So blocks are decoded into the pools, once, with every
 * symbol index translated through the interning table on the way in.
 *
 * Nested terms are the interesting part, because invariant 2 forbids
 * recursion and a container's children have to end up contiguous in the pool.
 *
 * The trick is to expand breadth-first, in the pool itself. A container is
 * first written as *pending*, holding the source bytes it was decoded from.
 * Then a single forward scan walks the pool: each pending term reserves a run
 * for its children at the current end, writes its scalars, and leaves its own
 * container children pending further along. Because expansion only ever
 * appends, the scan never revisits and never needs a worklist -- the pool is
 * the worklist.
 *
 * Depth falls out of the same walk: everything appended while expanding one
 * level forms the next, so tracking where each level ends counts nesting
 * without a stack.
 * ------------------------------------------------------------------------ */

/* A container whose children have not been placed yet. The source span lives
 * in the `bytes` variant, which is free because a pending term is never a
 * bytes term. */
#define BS_T_PENDING 0x80U

static bs_status bs_pool_reserve_terms(bs_world *w, size_t n, uint32_t *at) {
  size_t end;
  if (!bs_size_add(w->term_count, n, &end) || end > w->term_cap) {
    return BS_ERR_NOMEM;
  }
  if (end > 0xFFFFFFFFU) {
    return BS_ERR_LIMIT;
  }
  *at = (uint32_t)w->term_count;
  w->term_count = end;
  return BS_OK;
}

/* Decode one Term message into `out`, translating its symbol if it has one.
 * A container is left pending: its children are placed by the caller's scan. */
static bs_status bs_term_load_shallow(bs_symtab *syms, const bs_symbols *from,
                                      bs_span term, bs_term *out) {
  bs_cursor c = bs_cursor_make(term);
  bs_pb_field f;
  int found = 0;

  while (!bs_cursor_done(&c)) {
    bs_status st;
    if (!bs_pb_next(&c, &f)) {
      return BS_ERR_MALFORMED;
    }
    switch (f.number) {
    case BS_F_TERM_VARIABLE:
    case BS_F_TERM_STRING:
      if (f.wire != BS_PB_VARINT || found++) {
        return BS_ERR_MALFORMED;
      }
      out->kind = (f.number == BS_F_TERM_VARIABLE) ? (uint8_t)BS_T_VARIABLE
                                                   : (uint8_t)BS_T_STRING;
      st = bs_symtab_translate(syms, from, f.varint, &out->as.sym);
      if (st != BS_OK) {
        return st;
      }
      break;
    case BS_F_TERM_INTEGER:
      if (f.wire != BS_PB_VARINT || found++) {
        return BS_ERR_MALFORMED;
      }
      out->kind = (uint8_t)BS_T_INTEGER;
      out->as.integer = (int64_t)f.varint;
      break;
    case BS_F_TERM_DATE:
      if (f.wire != BS_PB_VARINT || found++) {
        return BS_ERR_MALFORMED;
      }
      out->kind = (uint8_t)BS_T_DATE;
      out->as.date = f.varint;
      break;
    case BS_F_TERM_BYTES:
      if (f.wire != BS_PB_BYTES || found++) {
        return BS_ERR_MALFORMED;
      }
      out->kind = (uint8_t)BS_T_BYTES;
      out->as.bytes = f.bytes;
      break;
    case BS_F_TERM_BOOL:
      if (f.wire != BS_PB_VARINT || found++ || f.varint > 1U) {
        return BS_ERR_MALFORMED;
      }
      out->kind = (uint8_t)BS_T_BOOL;
      out->as.boolean = (f.varint != 0U);
      break;
    case BS_F_TERM_NULL:
      if (f.wire != BS_PB_BYTES || found++) {
        return BS_ERR_MALFORMED;
      }
      out->kind = (uint8_t)BS_T_NULL;
      break;
    case BS_F_TERM_SET:
    case BS_F_TERM_ARRAY:
    case BS_F_TERM_MAP:
      if (f.wire != BS_PB_BYTES || found++) {
        return BS_ERR_MALFORMED;
      }
      out->kind = (uint8_t)(BS_T_PENDING |
                            ((f.number == BS_F_TERM_SET)     ? BS_T_SET
                             : (f.number == BS_F_TERM_ARRAY) ? BS_T_ARRAY
                                                             : BS_T_MAP));
      out->as.bytes = f.bytes;
      break;
    default:
      break; /* unknown field: parsed, then ignored */
    }
  }
  return (found == 1) ? BS_OK : BS_ERR_MALFORMED;
}

/* A map key is an integer or a string, never a container. */
static bs_status bs_mapkey_load(bs_symtab *syms, const bs_symbols *from,
                                bs_span key, bs_term *out) {
  bs_cursor c = bs_cursor_make(key);
  bs_pb_field f;
  int found = 0;

  while (!bs_cursor_done(&c)) {
    if (!bs_pb_next(&c, &f)) {
      return BS_ERR_MALFORMED;
    }
    if (f.wire != BS_PB_VARINT) {
      continue;
    }
    if (f.number == BS_F_MAPKEY_INTEGER) {
      if (found++) {
        return BS_ERR_MALFORMED;
      }
      out->kind = (uint8_t)BS_T_INTEGER;
      out->as.integer = (int64_t)f.varint;
    } else if (f.number == BS_F_MAPKEY_STRING) {
      bs_status st;
      if (found++) {
        return BS_ERR_MALFORMED;
      }
      out->kind = (uint8_t)BS_T_STRING;
      st = bs_symtab_translate(syms, from, f.varint, &out->as.sym);
      if (st != BS_OK) {
        return st;
      }
    }
  }
  return (found == 1) ? BS_OK : BS_ERR_MALFORMED;
}

/* Count the items of a container body: repeated field 1, whatever the kind.
 * A map entry counts as one item here and becomes two terms below. */
static bs_status bs_container_count(bs_span body, size_t *out) {
  return bs_repeated(body, 1U, NULL, 0U, out);
}

/* Place the children of every pending container, breadth-first, until none
 * are left. See the file header for why this needs no worklist. */
static bs_status bs_terms_expand(bs_world *w, bs_symtab *syms,
                                 const bs_symbols *from, uint32_t start) {
  size_t i = (size_t)start;
  size_t level_end = w->term_count;
  size_t depth = 1;

  while (i < w->term_count) {
    bs_term *t;
    uint8_t kind;
    bs_span body;
    size_t items;
    size_t placed = 0;
    uint32_t at = 0;
    bs_cursor c;
    bs_pb_field f;
    bs_status st;

    if (i >= level_end) {
      /* Everything appended while expanding the previous level is the next
       * one. Counting levels this way needs no stack at all. */
      depth++;
      level_end = w->term_count;
      if (depth > (size_t)BS_MAX_DEPTH) {
        return BS_ERR_DEPTH;
      }
    }

    t = &w->terms[i];
    if ((t->kind & BS_T_PENDING) == 0U) {
      i++;
      continue;
    }
    kind = (uint8_t)(t->kind & (uint8_t)~BS_T_PENDING);
    body = t->as.bytes;

    st = bs_container_count(body, &items);
    if (st != BS_OK) {
      return st;
    }
    /* A map stores its key and value adjacently, so it needs two slots per
     * entry rather than one. */
    if (kind == BS_T_MAP) {
      if (!bs_size_add(items, items, &items)) {
        return BS_ERR_OVERFLOW;
      }
    }
    st = bs_pool_reserve_terms(w, items, &at);
    if (st != BS_OK) {
      return st;
    }
    /* The pool is fixed and never moves, so `t` is still valid -- but it is
     * re-taken anyway, because a reader should not have to know that to trust
     * the next three lines. */
    t = &w->terms[i];
    t->kind = kind;
    t->as.list.at = at;
    t->as.list.count = (uint32_t)items;

    c = bs_cursor_make(body);
    while (!bs_cursor_done(&c)) {
      if (!bs_pb_next(&c, &f)) {
        return BS_ERR_MALFORMED;
      }
      if (f.number != 1U || f.wire != BS_PB_BYTES) {
        continue;
      }
      if (kind == BS_T_MAP) {
        bs_span key;
        bs_span value;
        if (!bs_mapentry_split(f.bytes, &key, &value)) {
          return BS_ERR_MALFORMED;
        }
        if (placed + 2U > items) {
          return BS_ERR_MALFORMED;
        }
        st = bs_mapkey_load(syms, from, key, &w->terms[at + placed]);
        if (st != BS_OK) {
          return st;
        }
        placed++;
        st = bs_term_load_shallow(syms, from, value, &w->terms[at + placed]);
        if (st != BS_OK) {
          return st;
        }
        placed++;
      } else {
        if (placed >= items) {
          return BS_ERR_MALFORMED;
        }
        st = bs_term_load_shallow(syms, from, f.bytes, &w->terms[at + placed]);
        if (st != BS_OK) {
          return st;
        }
        placed++;
      }
    }
    if (placed != items) {
      return BS_ERR_MALFORMED;
    }
    i++;
  }
  return BS_OK;
}

/* ---------------------------------------------------------------------------
 * Predicates and facts
 * ------------------------------------------------------------------------ */

/* `name(t0, ...)`. The terms are placed contiguously, which is what lets a
 * later comparison be a run-against-run walk rather than a chase. */
static bs_status bs_predicate_load(bs_world *w, bs_symtab *syms,
                                   const bs_symbols *from, bs_span pred,
                                   bs_predicate *out) {
  bs_cursor c;
  bs_pb_field f;
  size_t count = 0;
  size_t placed = 0;
  uint32_t at = 0;
  int have_name = 0;
  bs_status st;

  /* The name first, in its own pass: the schema does not promise field order,
   * and a predicate with no name is not a predicate. */
  c = bs_cursor_make(pred);
  while (!bs_cursor_done(&c)) {
    if (!bs_pb_next(&c, &f)) {
      return BS_ERR_MALFORMED;
    }
    if (f.number == BS_F_PREDICATE_NAME && f.wire == BS_PB_VARINT) {
      if (have_name++) {
        return BS_ERR_MALFORMED;
      }
      st = bs_symtab_translate(syms, from, f.varint, &out->name);
      if (st != BS_OK) {
        return st;
      }
    }
  }
  if (have_name != 1) {
    return BS_ERR_MALFORMED;
  }

  st = bs_repeated(pred, BS_F_PREDICATE_TERMS, NULL, 0U, &count);
  if (st != BS_OK) {
    return st;
  }
  st = bs_pool_reserve_terms(w, count, &at);
  if (st != BS_OK) {
    return st;
  }
  out->at = at;
  out->count = (uint32_t)count;

  c = bs_cursor_make(pred);
  while (!bs_cursor_done(&c)) {
    if (!bs_pb_next(&c, &f)) {
      return BS_ERR_MALFORMED;
    }
    if (f.number != BS_F_PREDICATE_TERMS || f.wire != BS_PB_BYTES) {
      continue;
    }
    if (placed >= count) {
      return BS_ERR_MALFORMED;
    }
    st = bs_term_load_shallow(syms, from, f.bytes, &w->terms[at + placed]);
    if (st != BS_OK) {
      return st;
    }
    placed++;
  }
  if (placed != count) {
    return BS_ERR_MALFORMED;
  }
  /* One expansion pass for the whole predicate, rather than one per term:
   * the scan picks up every pending container the loop above left behind. */
  return bs_terms_expand(w, syms, from, at);
}

/* Load every fact a block states, tagged with that block as its origin.
 *
 * `from` is the table the block's own indices are numbered against: its own
 * for a third-party block, the token-wide one otherwise. Passing the wrong
 * one does not fail -- it renames every predicate in the block -- which is
 * why the caller that knows the difference is the one that supplies it. */
BS_API bs_status bs_world_load_facts(bs_world *w, bs_symtab *syms,
                                     const bs_symbols *from, bs_span block,
                                     size_t block_index) {
  bs_cursor c;
  bs_pb_field f;

  if (w == NULL || syms == NULL) {
    return BS_ERR_ARGUMENT;
  }
  if (block_index >= (size_t)BS_MAX_BLOCKS) {
    return BS_ERR_LIMIT;
  }

  c = bs_cursor_make(block);
  while (!bs_cursor_done(&c)) {
    bs_cursor inner;
    bs_pb_field g;
    int found = 0;
    bs_span pred = bs_span_make(NULL, 0);
    bs_status st;

    if (!bs_pb_next(&c, &f)) {
      return BS_ERR_MALFORMED;
    }
    if (f.number != BS_F_BLOCK_FACTS || f.wire != BS_PB_BYTES) {
      continue;
    }

    inner = bs_cursor_make(f.bytes);
    while (!bs_cursor_done(&inner)) {
      if (!bs_pb_next(&inner, &g)) {
        return BS_ERR_MALFORMED;
      }
      if (g.number == BS_F_FACT_PREDICATE && g.wire == BS_PB_BYTES) {
        if (found++) {
          return BS_ERR_MALFORMED;
        }
        pred = g.bytes;
      }
    }
    if (found != 1) {
      return BS_ERR_MALFORMED;
    }

    if (w->fact_count >= w->fact_cap) {
      return BS_ERR_NOMEM;
    }
    st = bs_predicate_load(w, syms, from, pred, &w->facts[w->fact_count].pred);
    if (st != BS_OK) {
      return st;
    }
    w->facts[w->fact_count].origin = BS_ORIGIN_ONE(block_index);
    w->fact_count++;
  }
  return BS_OK;
}
