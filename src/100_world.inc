/* ---------------------------------------------------------------------------
 * The world -- pool allocation
 *
 * The types live in the API section; what is here is the one function that
 * reserves them. See the commentary there for why everything is an index into
 * a flat pool rather than a pointer.
 * ------------------------------------------------------------------------ */

BS_API bs_limits bs_limits_default(void) {
  bs_limits l;
  l.max_terms = 4096U;
  l.max_ops = 4096U;
  l.max_exprs = 512U;
  l.max_preds = 1024U;
  l.max_syms = 512U;
  l.max_facts = 1024U;
  l.max_rules = 256U;
  l.max_checks = 256U;
  l.max_policies = 64U;
  l.max_iterations = 100U;
  l.max_steps = 10000000U;
  return l;
}

/* Spend units of the evaluation's work budget.
 *
 * Saturates at zero rather than wrapping, so a caller that forgets to check
 * fails safe. Every loop whose length an attacker can influence charges here:
 * the Datalog join, the expression machine's opcode dispatch, term equality,
 * and the duplicate scan a derived fact runs against everything known. A
 * budget that covered only one of them would bound the cheapest of the four
 * and leave the rest to run as long as they liked. */
static void bs_spend(bs_world *w, size_t n) {
  w->steps = (w->steps > n) ? (w->steps - n) : 0U;
}

static int bs_exhausted(const bs_world *w) {
  return w->steps == 0U;
}

BS_API bs_status bs_world_set_externs(bs_world *w, const bs_extern *externs,
                                      size_t count) {
  if (w == NULL || (externs == NULL && count > 0U)) {
    return BS_ERR_ARGUMENT;
  }
  w->externs = externs;
  w->extern_count = count;
  return BS_OK;
}

BS_API bs_status bs_world_init(bs_world *w, bs_arena *a, const bs_tables *tab,
                               size_t block_count, const bs_limits *lim) {
  bs_limits l;

  if (w == NULL || a == NULL || tab == NULL) {
    return BS_ERR_ARGUMENT;
  }
  if (block_count > (size_t)BS_MAX_BLOCKS) {
    return BS_ERR_LIMIT;
  }
  l = (lim == NULL) ? bs_limits_default() : *lim;

  memset(w, 0, sizeof *w);
  w->tables = tab;
  w->block_count = block_count;

  w->terms =
      (bs_term *)bs_arena_array(a, l.max_terms, sizeof(bs_term), BS_ALIGN_MAX);
  w->ops = (bs_op *)bs_arena_array(a, l.max_ops, sizeof(bs_op), BS_ALIGN_MAX);
  w->exprs =
      (bs_expr *)bs_arena_array(a, l.max_exprs, sizeof(bs_expr), BS_ALIGN_MAX);
  w->preds = (bs_predicate *)bs_arena_array(a, l.max_preds,
                                            sizeof(bs_predicate), BS_ALIGN_MAX);
  w->syms =
      (uint64_t *)bs_arena_array(a, l.max_syms, sizeof(uint64_t), BS_ALIGN_MAX);
  w->facts =
      (bs_fact *)bs_arena_array(a, l.max_facts, sizeof(bs_fact), BS_ALIGN_MAX);
  w->rules =
      (bs_rule *)bs_arena_array(a, l.max_rules, sizeof(bs_rule), BS_ALIGN_MAX);
  w->checks = (bs_check *)bs_arena_array(a, l.max_checks, sizeof(bs_check),
                                         BS_ALIGN_MAX);
  w->policies = (bs_policy *)bs_arena_array(a, l.max_policies,
                                            sizeof(bs_policy), BS_ALIGN_MAX);

  if (w->terms == NULL || w->ops == NULL || w->exprs == NULL ||
      w->preds == NULL || w->syms == NULL || w->facts == NULL ||
      w->rules == NULL || w->checks == NULL || w->policies == NULL) {
    return BS_ERR_NOMEM;
  }

  w->term_cap = l.max_terms;
  w->op_cap = l.max_ops;
  w->expr_cap = l.max_exprs;
  w->pred_cap = l.max_preds;
  w->sym_cap = l.max_syms;
  w->fact_cap = l.max_facts;
  w->rule_cap = l.max_rules;
  w->check_cap = l.max_checks;
  w->policy_cap = l.max_policies;
  w->steps = (l.max_steps == 0U) ? bs_limits_default().max_steps : l.max_steps;
  return BS_OK;
}

/* Does every variable in the head appear somewhere in the body?
 *
 * The specification calls a rule that fails this invalid, and it is invalid
 * on sight rather than on use: a rule whose body happens to match nothing
 * would otherwise pass silently and become an error only once some later
 * token supplied the missing fact. Checking at load time makes the verdict a
 * property of the rule. */
static bs_status bs_rule_bound(const bs_world *w, const bs_rule *r) {
  uint32_t i;

  for (i = 0; i < r->head.count; i++) {
    bs_term t = w->terms[r->head.at + i];
    uint32_t j;
    int found = 0;

    if (t.kind != (uint8_t)BS_T_VARIABLE) {
      continue;
    }
    for (j = 0; j < r->body_count && !found; j++) {
      const bs_predicate *p = &w->preds[r->body_at + j];
      uint32_t k;
      for (k = 0; k < p->count; k++) {
        bs_term b = w->terms[p->at + k];
        if (b.kind == (uint8_t)BS_T_VARIABLE && b.as.sym == t.as.sym) {
          found = 1;
          break;
        }
      }
    }
    if (!found) {
      return BS_ERR_UNBOUND;
    }
  }
  return BS_OK;
}
