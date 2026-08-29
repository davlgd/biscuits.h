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

/* ---------------------------------------------------------------------------
 * Expressions
 *
 * Ops are loaded into the pool in the same postfix order the wire carries
 * them, and a closure keeps its body as a separate run so the evaluator can
 * decline to run it -- which is the whole point of a short-circuiting
 * operator.
 *
 * A closure's body has to be contiguous, and its own nested closures would
 * otherwise land in the middle of it. Same answer as for nested terms: mark
 * the closure pending, holding its source bytes, and let a forward scan place
 * each body at the current end. Appending only, so the scan never revisits.
 * ------------------------------------------------------------------------ */

#define BS_OP_PENDING 0x80U

static bs_status bs_pool_reserve_ops(bs_world *w, size_t n, uint32_t *at) {
  size_t end;
  if (!bs_size_add(w->op_count, n, &end) || end > w->op_cap) {
    return BS_ERR_NOMEM;
  }
  if (end > 0xFFFFFFFFU) {
    return BS_ERR_LIMIT;
  }
  *at = (uint32_t)w->op_count;
  w->op_count = end;
  return BS_OK;
}

/* One Op, with a container's contents left for the scan below. */
static bs_status bs_op_load(bs_world *w, bs_symtab *syms,
                            const bs_symbols *from, bs_span op, bs_op *out) {
  bs_span body = bs_span_make(NULL, 0);
  uint32_t branch = 0;
  bs_status st = bs_op_branch(op, &branch, &body);

  if (st != BS_OK) {
    return st;
  }

  out->kind = 0;
  switch (branch) {
  case BS_F_OP_VALUE: {
    uint32_t at;
    st = bs_pool_reserve_terms(w, 1U, &at);
    if (st != BS_OK) {
      return st;
    }
    st = bs_term_load_shallow(syms, from, body, &w->terms[at]);
    if (st != BS_OK) {
      return st;
    }
    st = bs_terms_expand(w, syms, from, at);
    if (st != BS_OK) {
      return st;
    }
    out->tag = (uint8_t)BS_OP_VALUE;
    out->as.term = at;
    return BS_OK;
  }
  case BS_F_OP_UNARY:
  case BS_F_OP_BINARY: {
    uint64_t ffi = 0;
    uint8_t has_ffi = 0;
    st = bs_op_kind(body, &out->kind, &ffi, &has_ffi);
    if (st != BS_OK) {
      return st;
    }
    out->tag =
        (uint8_t)((branch == BS_F_OP_UNARY) ? BS_OP_UNARY : BS_OP_BINARY);
    out->as.ffi = 0;
    if (has_ffi) {
      /* The external call's name is a symbol like any other, so it goes
       * through the same translation: a third-party block naming a function
       * numbers it in its own table. */
      st = bs_symtab_translate(syms, from, ffi, &out->as.ffi);
      if (st != BS_OK) {
        return st;
      }
    }
    return BS_OK;
  }
  default:
    out->tag = (uint8_t)(BS_OP_PENDING | BS_OP_CLOSURE);
    out->as.closure.at = 0;
    out->as.closure.count = 0;
    out->as.closure.body.at = 0;
    out->as.closure.body.count = 0;
    out->as.closure.src = body;
    return BS_OK;
  }
}

/* Load one run of ops -- an Expression's or a Closure's -- leaving nested
 * closures pending. `field` is 1 inside an Expression and 2 inside a Closure.
 */
static bs_status bs_ops_load_run(bs_world *w, bs_symtab *syms,
                                 const bs_symbols *from, bs_span msg,
                                 uint32_t field, bs_expr *out) {
  size_t count = 0;
  size_t placed = 0;
  uint32_t at = 0;
  bs_cursor c;
  bs_pb_field f;
  bs_status st = bs_repeated(msg, field, NULL, 0U, &count);

  if (st != BS_OK) {
    return st;
  }
  st = bs_pool_reserve_ops(w, count, &at);
  if (st != BS_OK) {
    return st;
  }
  out->at = at;
  out->count = (uint32_t)count;

  c = bs_cursor_make(msg);
  while (!bs_cursor_done(&c)) {
    if (!bs_pb_next(&c, &f)) {
      return BS_ERR_MALFORMED;
    }
    if (f.number != field || f.wire != BS_PB_BYTES) {
      continue;
    }
    if (placed >= count) {
      return BS_ERR_MALFORMED;
    }
    st = bs_op_load(w, syms, from, f.bytes, &w->ops[at + placed]);
    if (st != BS_OK) {
      return st;
    }
    placed++;
  }
  return (placed == count) ? BS_OK : BS_ERR_MALFORMED;
}

/* Place the body of every pending closure, breadth-first. */
static bs_status bs_ops_expand(bs_world *w, bs_symtab *syms,
                               const bs_symbols *from, uint32_t start) {
  size_t i = (size_t)start;
  size_t level_end = w->op_count;
  size_t depth = 1;

  while (i < w->op_count) {
    bs_op *o;
    bs_span src;
    bs_expr body;
    bs_cursor c;
    bs_pb_field f;
    size_t params = 0;
    uint32_t sym_at = 0;
    bs_status st;

    if (i >= level_end) {
      depth++;
      level_end = w->op_count;
      if (depth > (size_t)BS_MAX_DEPTH) {
        return BS_ERR_DEPTH;
      }
    }

    o = &w->ops[i];
    if ((o->tag & BS_OP_PENDING) == 0U) {
      i++;
      continue;
    }
    src = o->as.closure.src;

    /* Parameters first: symbol indices in the closure's own numbering,
     * translated like everything else. Counted by hand rather than with
     * bs_repeated, which only counts length-delimited fields and these are
     * varints. */
    params = 0;
    c = bs_cursor_make(src);
    while (!bs_cursor_done(&c)) {
      if (!bs_pb_next(&c, &f)) {
        return BS_ERR_MALFORMED;
      }
      if (f.number == BS_F_CLOSURE_PARAMS && f.wire == BS_PB_VARINT) {
        params++;
      }
    }
    if (params > 0U) {
      size_t end;
      if (!bs_size_add(w->sym_count, params, &end) || end > w->sym_cap) {
        return BS_ERR_NOMEM;
      }
      sym_at = (uint32_t)w->sym_count;
      w->sym_count = end;
      {
        size_t k = 0;
        c = bs_cursor_make(src);
        while (!bs_cursor_done(&c)) {
          if (!bs_pb_next(&c, &f)) {
            return BS_ERR_MALFORMED;
          }
          if (f.number != BS_F_CLOSURE_PARAMS || f.wire != BS_PB_VARINT) {
            continue;
          }
          st = bs_symtab_translate(syms, from, f.varint, &w->syms[sym_at + k]);
          if (st != BS_OK) {
            return st;
          }
          k++;
        }
      }
    }

    st = bs_ops_load_run(w, syms, from, src, BS_F_CLOSURE_OPS, &body);
    if (st != BS_OK) {
      return st;
    }

    o = &w->ops[i];
    o->tag = (uint8_t)BS_OP_CLOSURE;
    o->as.closure.at = sym_at;
    o->as.closure.count = (uint32_t)params;
    o->as.closure.body = body;
    o->as.closure.src = bs_span_make(NULL, 0);
    i++;
  }
  return BS_OK;
}

static bs_status bs_expr_load(bs_world *w, bs_symtab *syms,
                              const bs_symbols *from, bs_span expr,
                              bs_expr *out) {
  bs_status st = bs_ops_load_run(w, syms, from, expr, BS_F_EXPR_OPS, out);
  if (st != BS_OK) {
    return st;
  }
  return bs_ops_expand(w, syms, from, out->at);
}

/* ---------------------------------------------------------------------------
 * Scopes, rules and checks
 *
 * A scope annotation names which blocks a rule may draw its premises from,
 * and it is resolved to a set of block ids here, once, rather than consulted
 * during evaluation.
 *
 * The specification is exact about the default and about what is always
 * included: "By default, only the current block, the authority block and the
 * authorizer are trusted", and "the current block and the authorizer are
 * always trusted" whatever annotations are present. Both are why the two bits
 * below are set before anything else is considered.
 *
 * The matching rule is worth stating too, because it is stricter than it
 * looks: "Only facts whose origin is a subset of these trusted origins are
 * matched." A fact derived from blocks {0, 2} is invisible to a rule trusting
 * only {0}, even though it partly comes from a block that rule trusts.
 * ------------------------------------------------------------------------ */

static bs_status bs_pool_reserve_preds(bs_world *w, size_t n, uint32_t *at) {
  size_t end;
  if (!bs_size_add(w->pred_count, n, &end) || end > w->pred_cap) {
    return BS_ERR_NOMEM;
  }
  if (end > 0xFFFFFFFFU) {
    return BS_ERR_LIMIT;
  }
  *at = (uint32_t)w->pred_count;
  w->pred_count = end;
  return BS_OK;
}

static bs_status bs_pool_reserve_exprs(bs_world *w, size_t n, uint32_t *at) {
  size_t end;
  if (!bs_size_add(w->expr_count, n, &end) || end > w->expr_cap) {
    return BS_ERR_NOMEM;
  }
  if (end > 0xFFFFFFFFU) {
    return BS_ERR_LIMIT;
  }
  *at = (uint32_t)w->expr_count;
  w->expr_count = end;
  return BS_OK;
}

/* Which blocks one scope annotation adds. */
static bs_status bs_scope_resolve(const bs_token *t, const bs_tables *tab,
                                  size_t block_index, bs_span scope,
                                  bs_origin *add) {
  bs_cursor c = bs_cursor_make(scope);
  bs_pb_field f;
  int have_type = 0;
  int have_key = 0;
  uint64_t type = 0;
  int64_t key = 0;
  size_t i;

  *add = BS_ORIGIN_NONE;

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
  if (have_type == have_key) {
    return BS_ERR_MALFORMED; /* a oneof: one branch, never both or neither */
  }

  if (have_type) {
    if (type == BS_SCOPE_AUTHORITY) {
      *add = BS_ORIGIN_ONE(0U);
      return BS_OK;
    }
    if (type == BS_SCOPE_PREVIOUS) {
      /* Every block up to and including this one. In the authorizer this
       * annotation is meaningless and the specification says to ignore it;
       * the authorizer never reaches here with a block index. */
      for (i = 0; i <= block_index && i < (size_t)BS_MAX_BLOCKS; i++) {
        *add |= BS_ORIGIN_ONE(i);
      }
      return BS_OK;
    }
    return BS_ERR_MALFORMED;
  }

  if (tab == NULL || t == NULL || key < 0 ||
      (uint64_t)key >= (uint64_t)tab->public_key_count) {
    return BS_ERR_MALFORMED;
  }
  /* A public key names every block carrying an external signature by it.
   * Naming a key nobody signed with is not an error -- it trusts nothing,
   * which is the honest reading of "the blocks verified by this key" when
   * there are none. */
  for (i = 0; i < t->block_count; i++) {
    if (t->blocks[i].has_external &&
        t->blocks[i].external_key.alg == tab->public_keys[key].alg &&
        bs_span_eq(t->blocks[i].external_key.key, tab->public_keys[key].key)) {
      *add |= BS_ORIGIN_ONE(i);
    }
  }
  return BS_OK;
}

/* The trust set of a rule: the always-trusted pair, plus whatever its scope
 * annotations add, or the authority block when there are none. */
static bs_status bs_trust_load(const bs_token *t, const bs_tables *tab,
                               size_t block_index, bs_span msg, uint32_t field,
                               bs_origin *out) {
  bs_cursor c = bs_cursor_make(msg);
  bs_pb_field f;
  int annotated = 0;
  bs_origin trust = BS_ORIGIN_AUTHORIZER | BS_ORIGIN_ONE(block_index);

  while (!bs_cursor_done(&c)) {
    bs_origin add = BS_ORIGIN_NONE;
    bs_status st;
    if (!bs_pb_next(&c, &f)) {
      return BS_ERR_MALFORMED;
    }
    if (f.number != field || f.wire != BS_PB_BYTES) {
      continue;
    }
    st = bs_scope_resolve(t, tab, block_index, f.bytes, &add);
    if (st != BS_OK) {
      return st;
    }
    /* Multiple annotations are added, not intersected. */
    trust |= add;
    annotated = 1;
  }
  if (!annotated) {
    trust |= BS_ORIGIN_ONE(0U);
  }
  *out = trust;
  return BS_OK;
}

static bs_status bs_rule_load(bs_world *w, bs_symtab *syms,
                              const bs_symbols *from, const bs_token *t,
                              const bs_tables *tab, size_t block_index,
                              bs_span rule, bs_rule *out) {
  bs_cursor c;
  bs_pb_field f;
  size_t body_count = 0;
  size_t expr_count = 0;
  size_t placed = 0;
  int have_head = 0;
  bs_status st;

  c = bs_cursor_make(rule);
  while (!bs_cursor_done(&c)) {
    if (!bs_pb_next(&c, &f)) {
      return BS_ERR_MALFORMED;
    }
    if (f.number == BS_F_RULE_HEAD && f.wire == BS_PB_BYTES) {
      if (have_head++) {
        return BS_ERR_MALFORMED;
      }
      st = bs_predicate_load(w, syms, from, f.bytes, &out->head);
      if (st != BS_OK) {
        return st;
      }
    }
  }
  if (have_head != 1) {
    return BS_ERR_MALFORMED;
  }

  st = bs_repeated(rule, BS_F_RULE_BODY, NULL, 0U, &body_count);
  if (st != BS_OK) {
    return st;
  }
  st = bs_pool_reserve_preds(w, body_count, &out->body_at);
  if (st != BS_OK) {
    return st;
  }
  out->body_count = (uint32_t)body_count;

  c = bs_cursor_make(rule);
  while (!bs_cursor_done(&c)) {
    if (!bs_pb_next(&c, &f)) {
      return BS_ERR_MALFORMED;
    }
    if (f.number != BS_F_RULE_BODY || f.wire != BS_PB_BYTES) {
      continue;
    }
    if (placed >= body_count) {
      return BS_ERR_MALFORMED;
    }
    st = bs_predicate_load(w, syms, from, f.bytes,
                           &w->preds[out->body_at + placed]);
    if (st != BS_OK) {
      return st;
    }
    placed++;
  }
  if (placed != body_count) {
    return BS_ERR_MALFORMED;
  }

  st = bs_repeated(rule, BS_F_RULE_EXPRESSIONS, NULL, 0U, &expr_count);
  if (st != BS_OK) {
    return st;
  }
  st = bs_pool_reserve_exprs(w, expr_count, &out->expr_at);
  if (st != BS_OK) {
    return st;
  }
  out->expr_count = (uint32_t)expr_count;

  placed = 0;
  c = bs_cursor_make(rule);
  while (!bs_cursor_done(&c)) {
    if (!bs_pb_next(&c, &f)) {
      return BS_ERR_MALFORMED;
    }
    if (f.number != BS_F_RULE_EXPRESSIONS || f.wire != BS_PB_BYTES) {
      continue;
    }
    if (placed >= expr_count) {
      return BS_ERR_MALFORMED;
    }
    st = bs_expr_load(w, syms, from, f.bytes, &w->exprs[out->expr_at + placed]);
    if (st != BS_OK) {
      return st;
    }
    placed++;
  }
  if (placed != expr_count) {
    return BS_ERR_MALFORMED;
  }

  out->block = (uint32_t)block_index;
  return bs_trust_load(t, tab, block_index, rule, BS_F_RULE_SCOPE, &out->trust);
}

/* Load every rule and check a block states. */
BS_API bs_status bs_world_load_logic(bs_world *w, bs_symtab *syms,
                                     const bs_symbols *from, const bs_token *t,
                                     const bs_tables *tab, bs_span block,
                                     size_t block_index) {
  bs_cursor c;
  bs_pb_field f;
  bs_status st;

  if (w == NULL || syms == NULL) {
    return BS_ERR_ARGUMENT;
  }
  if (block_index >= (size_t)BS_MAX_BLOCKS) {
    return BS_ERR_LIMIT;
  }

  c = bs_cursor_make(block);
  while (!bs_cursor_done(&c)) {
    if (!bs_pb_next(&c, &f)) {
      return BS_ERR_MALFORMED;
    }
    if (f.number != BS_F_BLOCK_RULES || f.wire != BS_PB_BYTES) {
      continue;
    }
    if (w->rule_count >= w->rule_cap) {
      return BS_ERR_NOMEM;
    }
    st = bs_rule_load(w, syms, from, t, tab, block_index, f.bytes,
                      &w->rules[w->rule_count]);
    if (st != BS_OK) {
      return st;
    }
    w->rule_count++;
  }

  c = bs_cursor_make(block);
  while (!bs_cursor_done(&c)) {
    bs_cursor inner;
    bs_pb_field g;
    uint64_t kind = BS_CHECK_KIND_ONE;
    size_t queries = 0;
    uint32_t at;

    if (!bs_pb_next(&c, &f)) {
      return BS_ERR_MALFORMED;
    }
    if (f.number != BS_F_BLOCK_CHECKS || f.wire != BS_PB_BYTES) {
      continue;
    }

    inner = bs_cursor_make(f.bytes);
    while (!bs_cursor_done(&inner)) {
      if (!bs_pb_next(&inner, &g)) {
        return BS_ERR_MALFORMED;
      }
      if (g.number == BS_F_CHECK_KIND && g.wire == BS_PB_VARINT) {
        kind = g.varint;
      }
    }
    if (kind > (uint64_t)BS_CHECK_KIND_REJECT) {
      return BS_ERR_MALFORMED;
    }

    st = bs_repeated(f.bytes, BS_F_CHECK_QUERIES, NULL, 0U, &queries);
    if (st != BS_OK) {
      return st;
    }
    if (queries == 0U) {
      return BS_ERR_MALFORMED; /* a check with no query cannot mean anything */
    }
    {
      size_t end;
      if (!bs_size_add(w->rule_count, queries, &end) || end > w->rule_cap) {
        return BS_ERR_NOMEM;
      }
      at = (uint32_t)w->rule_count;
    }

    inner = bs_cursor_make(f.bytes);
    while (!bs_cursor_done(&inner)) {
      if (!bs_pb_next(&inner, &g)) {
        return BS_ERR_MALFORMED;
      }
      if (g.number != BS_F_CHECK_QUERIES || g.wire != BS_PB_BYTES) {
        continue;
      }
      if (w->rule_count >= w->rule_cap) {
        return BS_ERR_NOMEM;
      }
      st = bs_rule_load(w, syms, from, t, tab, block_index, g.bytes,
                        &w->rules[w->rule_count]);
      if (st != BS_OK) {
        return st;
      }
      w->rule_count++;
    }

    if (w->check_count >= w->check_cap) {
      return BS_ERR_NOMEM;
    }
    w->checks[w->check_count].query_at = at;
    w->checks[w->check_count].query_count = (uint32_t)queries;
    w->checks[w->check_count].kind = (uint8_t)kind;
    w->checks[w->check_count].block = (uint32_t)block_index;
    w->check_count++;
  }
  return BS_OK;
}
