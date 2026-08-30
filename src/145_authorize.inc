/* ---------------------------------------------------------------------------
 * Authorization
 *
 * Everything above produces facts; this decides what they mean. Run the world
 * to a fixpoint, ask every check whether it holds, then walk the policies in
 * order until one matches.
 *
 * The part worth stating plainly is that a policy and a check answer
 * different questions. A policy says what the application will allow; a check
 * says what the token's own blocks insisted on. An implementation that
 * consults only the policy authorizes a token whose every check failed --
 * which is to say it ignores attenuation entirely, silently, while appearing
 * to work. So both are evaluated, always, and both are reported.
 * ------------------------------------------------------------------------ */

/* Does this query have at least one answer that satisfies its expressions? */
static bs_status bs_query_any(bs_world *w, bs_symtab *syms, bs_arena *a,
                              const bs_rule *r, bs_solver *sv, int *yes) {
  bs_status st = bs_solver_init(sv, w, r);

  *yes = 0;
  if (st != BS_OK) {
    return st;
  }
  for (;;) {
    int found = 0;
    int keep = 0;

    st = bs_solver_next(w, r, sv, &found);
    if (st != BS_OK) {
      return st;
    }
    if (!found) {
      return BS_OK;
    }
    st = bs_solver_expressions(w, syms, a, r, sv, &keep);
    if (st != BS_OK) {
      return st;
    }
    if (keep) {
      *yes = 1;
      return BS_OK;
    }
  }
}

/* Do *all* of this query's answers satisfy its expressions?
 *
 * And is there at least one. The specification's wording -- "all the sets of
 * facts that match the body also succeed the expression" -- reads as
 * vacuously true when the body matches nothing, but test025's "no matches"
 * case expects a failure, so an empty body is a failure here. The samples
 * settle what the prose leaves open. */
static bs_status bs_query_all(bs_world *w, bs_symtab *syms, bs_arena *a,
                              const bs_rule *r, bs_solver *sv, int *yes) {
  bs_status st = bs_solver_init(sv, w, r);
  int any = 0;

  *yes = 0;
  if (st != BS_OK) {
    return st;
  }
  for (;;) {
    int found = 0;
    int keep = 0;

    st = bs_solver_next(w, r, sv, &found);
    if (st != BS_OK) {
      return st;
    }
    if (!found) {
      *yes = any;
      return BS_OK;
    }
    any = 1;
    st = bs_solver_expressions(w, syms, a, r, sv, &keep);
    if (st != BS_OK) {
      return st;
    }
    if (!keep) {
      *yes = 0;
      return BS_OK;
    }
  }
}

/* Does a check hold?
 *
 * A check carries several queries joined by `or` and succeeds if any of them
 * succeeds -- except `reject if`, which fails if any of them matches. What
 * "succeeds" means for one query is the check's kind. */
static bs_status bs_check_holds(bs_world *w, bs_symtab *syms, bs_arena *a,
                                const bs_check *c, bs_solver *sv, int *holds) {
  uint32_t i;

  *holds = (c->kind == (uint8_t)BS_CHECK_KIND_REJECT) ? 1 : 0;

  for (i = 0; i < c->query_count; i++) {
    const bs_rule *r = &w->rules[c->query_at + i];
    int yes = 0;
    bs_status st;

    if (c->kind == (uint8_t)BS_CHECK_KIND_ALL) {
      st = bs_query_all(w, syms, a, r, sv, &yes);
    } else {
      st = bs_query_any(w, syms, a, r, sv, &yes);
    }
    if (st != BS_OK) {
      return st;
    }
    if (c->kind == (uint8_t)BS_CHECK_KIND_REJECT) {
      if (yes) {
        *holds = 0; /* something matched, and matching is the rejection */
        return BS_OK;
      }
      continue;
    }
    if (yes) {
      *holds = 1;
      return BS_OK;
    }
  }
  return BS_OK;
}

/* Does a policy's condition match? Its queries are joined by `or` too. */
static bs_status bs_policy_matches(bs_world *w, bs_symtab *syms, bs_arena *a,
                                   const bs_policy *pol, bs_solver *sv,
                                   int *yes) {
  uint32_t i;

  *yes = 0;
  for (i = 0; i < pol->query_count; i++) {
    bs_status st =
        bs_query_any(w, syms, a, &w->rules[pol->query_at + i], sv, yes);
    if (st != BS_OK) {
      return st;
    }
    if (*yes) {
      return BS_OK;
    }
  }
  return BS_OK;
}

BS_API bs_status bs_authorize(bs_world *w, bs_symtab *syms, bs_arena *a,
                              size_t max_iterations, bs_verdict *out) {
  bs_failed_check *failed;
  bs_solver *sv;
  size_t nfailed = 0;
  size_t i;
  bs_status st;

  if (w == NULL || syms == NULL || a == NULL || out == NULL) {
    return BS_ERR_ARGUMENT;
  }

  memset(out, 0, sizeof *out);
  out->kind = (uint8_t)BS_VERDICT_NO_POLICY;

  /* One solver for the whole decision: the fixpoint finishes before any
   * check is asked, so nothing here is ever using two at once. */
  sv = bs_solver_new(a);
  if (sv == NULL) {
    return BS_ERR_NOMEM;
  }
  st = bs_world_run_with(w, syms, a, max_iterations, sv);
  if (st != BS_OK) {
    return st;
  }

  failed = (bs_failed_check *)bs_arena_array(
      a, (w->check_count == 0U) ? 1U : w->check_count, sizeof(bs_failed_check),
      BS_ALIGN_MAX);
  if (failed == NULL) {
    return BS_ERR_NOMEM;
  }

  /* Every check is evaluated, not just up to the first failure: an
   * application that logs why a token was refused wants all the reasons, and
   * stopping early would make the report depend on evaluation order. */
  {
    uint32_t per_block = 0;
    uint32_t block = 0xFFFFFFFFU;

    for (i = 0; i < w->check_count; i++) {
      int holds = 0;

      if (w->checks[i].block != block) {
        block = w->checks[i].block;
        per_block = 0;
      }
      st = bs_check_holds(w, syms, a, &w->checks[i], sv, &holds);
      if (st != BS_OK) {
        return st;
      }
      if (!holds) {
        failed[nfailed].block = w->checks[i].block;
        failed[nfailed].index = per_block;
        failed[nfailed].src = w->checks[i].src;
        failed[nfailed].from_text = w->checks[i].from_text;
        nfailed++;
      }
      per_block++;
    }
  }

  for (i = 0; i < w->policy_count; i++) {
    int matched = 0;
    st = bs_policy_matches(w, syms, a, &w->policies[i], sv, &matched);
    if (st != BS_OK) {
      return st;
    }
    if (!matched) {
      continue;
    }
    out->policy = (uint32_t)i;
    out->has_policy = 1;
    /* A deny that matches denies; an allow that matches only allows if
     * nothing the token itself demanded went unmet. */
    out->kind = (w->policies[i].kind == (uint8_t)BS_POLICY_DENY || nfailed > 0U)
                    ? (uint8_t)BS_VERDICT_DENY
                    : (uint8_t)BS_VERDICT_ALLOW;
    break;
  }

  out->failed_count = nfailed;
  out->failed = failed;
  return BS_OK;
}

BS_API bs_status bs_failed_check_print(bs_writer *wr, bs_arena *a,
                                       const bs_tables *tab,
                                       const bs_failed_check *f) {
  if (wr == NULL || f == NULL) {
    return BS_ERR_ARGUMENT;
  }
  if (f->from_text) {
    bs_put_span(wr, f->src);
    return bs_writer_overflow(wr) ? BS_ERR_NOMEM : BS_OK;
  }
  return bs_check_print(wr, a, tab, f->src);
}
