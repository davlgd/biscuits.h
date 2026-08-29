/* ---------------------------------------------------------------------------
 * Rules, checks, and whole blocks
 *
 * This is where the pieces meet: a rule is a head, a body of predicates, a
 * list of expressions and the scopes it trusts, and a check is one or more
 * rules with a kind. The block is those in a fixed order -- facts, then rules,
 * then checks -- which is the order the reference implementation prints and
 * therefore the order the conformance suite expects.
 * ------------------------------------------------------------------------ */

#define BS_F_RULE_HEAD 1U
#define BS_F_RULE_BODY 2U
#define BS_F_RULE_EXPRESSIONS 3U
#define BS_F_RULE_SCOPE 4U

#define BS_F_CHECK_QUERIES 1U
#define BS_F_CHECK_KIND 2U

#define BS_CHECK_ONE 0U
#define BS_CHECK_ALL 1U
#define BS_CHECK_REJECT 2U

/* Render a rule's body: its predicates, then its expressions, comma
 * separated, then the scopes it trusts.
 *
 * A check prints only this part; a rule prints its head and an arrow first.
 * They are the same message, and which half is shown is the only difference
 * between the two forms. */
static bs_status bs_rule_body_print(bs_writer *w, bs_arena *a,
                                    const bs_tables *tab, bs_span rule) {
  bs_cursor c;
  bs_pb_field f;
  int emitted = 0;
  int scopes = 0;
  bs_status st;

  c = bs_cursor_make(rule);
  while (!bs_cursor_done(&c)) {
    if (!bs_pb_next(&c, &f)) {
      return BS_ERR_MALFORMED;
    }
    if (f.number != BS_F_RULE_BODY || f.wire != BS_PB_BYTES) {
      continue;
    }
    if (emitted++ > 0) {
      BS_PUT_LIT(w, ", ");
    }
    st = bs_predicate_print(w, tab, f.bytes);
    if (st != BS_OK) {
      return st;
    }
  }

  c = bs_cursor_make(rule);
  while (!bs_cursor_done(&c)) {
    if (!bs_pb_next(&c, &f)) {
      return BS_ERR_MALFORMED;
    }
    if (f.number != BS_F_RULE_EXPRESSIONS || f.wire != BS_PB_BYTES) {
      continue;
    }
    if (emitted++ > 0) {
      BS_PUT_LIT(w, ", ");
    }
    st = bs_expr_print(w, a, tab, f.bytes);
    if (st != BS_OK) {
      return st;
    }
  }

  c = bs_cursor_make(rule);
  while (!bs_cursor_done(&c)) {
    if (!bs_pb_next(&c, &f)) {
      return BS_ERR_MALFORMED;
    }
    if (f.number != BS_F_RULE_SCOPE || f.wire != BS_PB_BYTES) {
      continue;
    }
    if (scopes++ == 0) {
      BS_PUT_LIT(w, " trusting ");
    } else {
      BS_PUT_LIT(w, ", ");
    }
    st = bs_scope_print(w, tab, f.bytes);
    if (st != BS_OK) {
      return st;
    }
  }
  return BS_OK;
}

/* `head <- body`. */
BS_API bs_status bs_rule_print(bs_writer *w, bs_arena *a, const bs_tables *tab,
                               bs_span rule) {
  bs_cursor c = bs_cursor_make(rule);
  bs_pb_field f;
  bs_span head = bs_span_make(NULL, 0);
  int found = 0;
  bs_status st;

  if (w == NULL || a == NULL || tab == NULL) {
    return BS_ERR_ARGUMENT;
  }

  while (!bs_cursor_done(&c)) {
    if (!bs_pb_next(&c, &f)) {
      return BS_ERR_MALFORMED;
    }
    if (f.number == BS_F_RULE_HEAD && f.wire == BS_PB_BYTES) {
      if (found++) {
        return BS_ERR_MALFORMED;
      }
      head = f.bytes;
    }
  }
  if (found != 1) {
    return BS_ERR_MALFORMED;
  }

  st = bs_predicate_print(w, tab, head);
  if (st != BS_OK) {
    return st;
  }
  BS_PUT_LIT(w, " <- ");
  return bs_rule_body_print(w, a, tab, rule);
}

/* `check if q`, `check all q`, or `reject if q`, with several queries joined
 * by ` or `. The head of each query is a synthetic predicate the writer never
 * printed, so it is not printed here either. */
BS_API bs_status bs_check_print(bs_writer *w, bs_arena *a, const bs_tables *tab,
                                bs_span check) {
  bs_cursor c;
  bs_pb_field f;
  uint64_t kind = BS_CHECK_ONE;
  int emitted = 0;
  bs_status st;

  if (w == NULL || a == NULL || tab == NULL) {
    return BS_ERR_ARGUMENT;
  }

  c = bs_cursor_make(check);
  while (!bs_cursor_done(&c)) {
    if (!bs_pb_next(&c, &f)) {
      return BS_ERR_MALFORMED;
    }
    if (f.number == BS_F_CHECK_KIND && f.wire == BS_PB_VARINT) {
      kind = f.varint;
    }
  }

  switch (kind) {
  case BS_CHECK_ONE:
    BS_PUT_LIT(w, "check if ");
    break;
  case BS_CHECK_ALL:
    BS_PUT_LIT(w, "check all ");
    break;
  case BS_CHECK_REJECT:
    BS_PUT_LIT(w, "reject if ");
    break;
  default:
    return BS_ERR_MALFORMED;
  }

  c = bs_cursor_make(check);
  while (!bs_cursor_done(&c)) {
    if (!bs_pb_next(&c, &f)) {
      return BS_ERR_MALFORMED;
    }
    if (f.number != BS_F_CHECK_QUERIES || f.wire != BS_PB_BYTES) {
      continue;
    }
    if (emitted++ > 0) {
      BS_PUT_LIT(w, " or ");
    }
    st = bs_rule_body_print(w, a, tab, f.bytes);
    if (st != BS_OK) {
      return st;
    }
  }
  if (emitted == 0) {
    return BS_ERR_MALFORMED; /* a check with no query cannot mean anything */
  }
  return BS_OK;
}

/* Render a whole block as Datalog source: facts, then rules, then checks,
 * each terminated by a semicolon and a newline. That order is not arbitrary --
 * it is what the reference implementation emits, and the conformance suite
 * compares text. */
BS_API bs_status bs_block_print(bs_writer *w, bs_arena *a, const bs_tables *tab,
                                bs_span block) {
  static const uint32_t sections[3] = {
      BS_F_BLOCK_FACTS,
      BS_F_BLOCK_RULES,
      BS_F_BLOCK_CHECKS,
  };
  size_t i;

  if (w == NULL || a == NULL || tab == NULL) {
    return BS_ERR_ARGUMENT;
  }

  /* A block-level scope would apply to everything in the block. No sample in
   * the specification's suite carries one, so its printed form cannot be
   * confirmed against anything -- and inventing a syntax that later turns out
   * to differ would be worse than refusing. Refused explicitly rather than
   * ignored: a block whose trust boundary this build cannot render must not
   * be reported as one it rendered. */
  {
    bs_cursor c = bs_cursor_make(block);
    bs_pb_field f;
    while (!bs_cursor_done(&c)) {
      if (!bs_pb_next(&c, &f)) {
        return BS_ERR_MALFORMED;
      }
      if (f.number == BS_F_BLOCK_SCOPE && f.wire == BS_PB_BYTES) {
        return BS_ERR_UNSUPPORTED;
      }
    }
  }

  for (i = 0; i < 3U; i++) {
    bs_cursor c = bs_cursor_make(block);
    bs_pb_field f;
    while (!bs_cursor_done(&c)) {
      bs_status st;
      if (!bs_pb_next(&c, &f)) {
        return BS_ERR_MALFORMED;
      }
      if (f.number != sections[i] || f.wire != BS_PB_BYTES) {
        continue;
      }
      if (sections[i] == BS_F_BLOCK_FACTS) {
        st = bs_fact_print(w, tab, f.bytes);
      } else if (sections[i] == BS_F_BLOCK_RULES) {
        st = bs_rule_print(w, a, tab, f.bytes);
      } else {
        st = bs_check_print(w, a, tab, f.bytes);
      }
      if (st != BS_OK) {
        return st;
      }
      BS_PUT_LIT(w, ";\n");
    }
  }

  return bs_writer_overflow(w) ? BS_ERR_NOMEM : BS_OK;
}
