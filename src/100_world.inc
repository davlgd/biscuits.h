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
  return l;
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
  return BS_OK;
}
