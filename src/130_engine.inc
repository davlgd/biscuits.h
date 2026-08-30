/* ---------------------------------------------------------------------------
 * Datalog evaluation
 *
 * Repeatedly apply every rule to every combination of facts it can match,
 * until a round produces nothing new. That is the whole algorithm; what makes
 * it worth explaining is the two constraints around it.
 *
 * The first is origin. Every fact carries the set of blocks that allowed it to
 * exist, and a derived fact's origin is the union of the rule's own block and
 * the origins of every fact it matched. A rule only sees facts whose origin is
 * a *subset* of what it trusts -- not merely overlapping. A fact derived from
 * blocks {0, 2} is invisible to a rule trusting only {0}, even though part of
 * it came from a block that rule accepts. This is the whole mechanism that
 * stops an appended block from granting itself rights, and getting it wrong
 * does not fail: it silently authorizes.
 *
 * The second is that matching N body predicates is N nested loops, and the
 * depth is a property of the rule rather than of this code -- so it cannot be
 * written as nested loops, and invariant 2 forbids writing it as recursion.
 * It is an explicit backtracking walk instead: one frame per body position,
 * each remembering which fact it is trying and how many bindings it made, so
 * undoing a choice is truncating a list.
 * ------------------------------------------------------------------------ */

/* Predicates in one rule body. Thirty-two rather than sixteen because
 * test022 writes a check naming all twenty-eight default symbols in a single
 * body, and a limit the specification's own samples exceed is a bug rather
 * than a bound. */
#ifndef BS_MAX_BODY
#define BS_MAX_BODY 32
#endif

typedef struct bs_matchframe {
  size_t fact;      /* the candidate being tried at this body position */
  size_t bind_mark; /* how many bindings existed before it bound any */
  bs_origin origin; /* origins accumulated through this position */
} bs_matchframe;

/* Do two facts state the same thing? Origins are compared too: the same
 * sentence derived through different blocks is a different fact, because
 * scoping asks where it came from. */
static int bs_fact_same(bs_world *w, const bs_fact *a, const bs_fact *b) {
  uint32_t i;
  if (a->pred.name != b->pred.name || a->pred.count != b->pred.count ||
      a->origin != b->origin) {
    return 0;
  }
  for (i = 0; i < a->pred.count; i++) {
    if (!bs_term_eq(w, w->terms[a->pred.at + i], w->terms[b->pred.at + i])) {
      return 0;
    }
  }
  return 1;
}

/* Match one predicate against one fact, extending `binds`.
 *
 * A variable already bound must match what it is bound to; an unbound one
 * takes the fact's value. Anything else must be equal outright. On failure
 * the caller truncates the binding list back to its mark, which is why
 * nothing needs undoing here. */
static int bs_unify(bs_world *w, const bs_predicate *p, const bs_fact *f,
                    bs_binding *binds, size_t *count, size_t cap) {
  uint32_t i;

  if (p->name != f->pred.name || p->count != f->pred.count) {
    return 0;
  }
  for (i = 0; i < p->count; i++) {
    bs_term pt = w->terms[p->at + i];
    bs_term ft = w->terms[f->pred.at + i];

    if (pt.kind == (uint8_t)BS_T_VARIABLE) {
      size_t k;
      int bound = 0;
      for (k = 0; k < *count; k++) {
        if (binds[k].sym == pt.as.sym) {
          if (!bs_term_eq(w, binds[k].value, ft)) {
            return 0;
          }
          bound = 1;
          break;
        }
      }
      if (!bound) {
        if (*count >= cap) {
          return 0; /* more distinct variables than this build will bind */
        }
        binds[*count].sym = pt.as.sym;
        binds[*count].value = ft;
        (*count)++;
      }
      continue;
    }
    if (!bs_term_eq(w, pt, ft)) {
      return 0;
    }
  }
  return 1;
}

/* Build the fact a rule's head states, substituting the bindings. */
static bs_status bs_head_instantiate(bs_world *w, const bs_rule *r,
                                     const bs_binding *binds, size_t count,
                                     bs_origin origin, bs_fact *out) {
  uint32_t at;
  uint32_t i;
  bs_status st = bs_pool_reserve_terms(w, r->head.count, &at);

  if (st != BS_OK) {
    return st;
  }
  for (i = 0; i < r->head.count; i++) {
    bs_term t = w->terms[r->head.at + i];
    if (t.kind == (uint8_t)BS_T_VARIABLE) {
      size_t k;
      int bound = 0;
      for (k = 0; k < count; k++) {
        if (binds[k].sym == t.as.sym) {
          t = binds[k].value;
          bound = 1;
          break;
        }
      }
      if (!bound) {
        /* Unreachable in practice: bs_rule_bound rejects such a rule when it
         * is loaded, which is what the specification asks for -- an invalid
         * rule is invalid whether or not its body happens to match. Kept as
         * a guard because a fact with a hole in it is not a fact. */
        return BS_ERR_UNBOUND;
      }
    }
    w->terms[at + i] = t;
  }
  out->pred.name = r->head.name;
  out->pred.at = at;
  out->pred.count = r->head.count;
  out->origin = origin;
  return BS_OK;
}

/* The origin bit a rule's own block stands for. The authorizer has a bit
 * reserved rather than a position, so its index is never shifted. */
static bs_origin bs_rule_origin(const bs_rule *r) {
  return ((size_t)r->block >= (size_t)BS_MAX_BLOCKS) ? BS_ORIGIN_AUTHORIZER
                                                     : BS_ORIGIN_ONE(r->block);
}

/* The backtracking walk, as a resumable iterator.
 *
 * A rule and a query ask the same question -- which combinations of facts
 * match this body -- and differ only in what they do with each answer. One
 * machine yields the answers; the callers decide. Written as a callback it
 * would be an indirect call, which the stack measurement cannot follow, so it
 * is resumable state instead: `bs_solver_next` picks up exactly where the
 * previous answer left off. */
typedef struct bs_solver {
  bs_matchframe frames[BS_MAX_BODY];
  bs_binding binds[BS_MAX_BINDINGS];
  size_t bind_count;
  size_t level;
  size_t base_facts; /* facts that existed when the walk started */
  int started;
  int done;
} bs_solver;

static bs_status bs_solver_init(bs_solver *s, const bs_world *w,
                                const bs_rule *r) {
  if (r->body_count > (size_t)BS_MAX_BODY) {
    return BS_ERR_LIMIT;
  }
  s->bind_count = 0;
  s->level = 0;
  /* Only facts that existed when this walk started are candidates: a rule
   * must not consume what it produced in the same pass, or a recursive rule
   * would run away inside one round instead of converging over several. */
  s->base_facts = w->fact_count;
  s->started = 0;
  s->done = 0;
  s->frames[0].fact = 0;
  s->frames[0].bind_mark = 0;
  s->frames[0].origin = bs_rule_origin(r);
  return BS_OK;
}

/* Advance to the next combination matching the body. `*found` is 0 when
 * there are none left; the bindings are then meaningless.
 *
 * Every candidate examined spends one step from the world's budget. Without
 * that, the only bound on this walk is base_facts raised to the number of
 * body predicates, and both are the token's to choose. */
static bs_status bs_solver_next(bs_world *w, const bs_rule *r, bs_solver *s,
                                int *found) {
  *found = 0;
  if (s->done) {
    return BS_OK;
  }
  if (s->started) {
    /* Resume by undoing the last answer's final choice. */
    if (s->level == 0U) {
      s->done = 1;
      return BS_OK;
    }
    s->level--;
    s->bind_count = s->frames[s->level].bind_mark;
    s->frames[s->level].fact++;
  }
  s->started = 1;

  for (;;) {
    const bs_predicate *p;
    bs_origin prev;
    int matched = 0;

    if (s->level == r->body_count) {
      *found = 1;
      return BS_OK;
    }

    p = &w->preds[r->body_at + s->level];
    prev =
        (s->level == 0U) ? bs_rule_origin(r) : s->frames[s->level - 1U].origin;

    while (s->frames[s->level].fact < s->base_facts) {
      const bs_fact *f = &w->facts[s->frames[s->level].fact];
      size_t mark = s->bind_count;

      if (w->steps == 0U) {
        s->done = 1;
        return BS_ERR_LIMIT;
      }
      w->steps--;

      /* "Only facts whose origin is a subset of these trusted origins are
       * matched." A subset, not an overlap. */
      if ((f->origin & ~r->trust) != BS_ORIGIN_NONE) {
        s->frames[s->level].fact++;
        continue;
      }
      if (!bs_unify(w, p, f, s->binds, &s->bind_count,
                    (size_t)BS_MAX_BINDINGS)) {
        s->bind_count = mark;
        s->frames[s->level].fact++;
        continue;
      }
      s->frames[s->level].bind_mark = mark;
      s->frames[s->level].origin = prev | f->origin;
      matched = 1;
      break;
    }

    if (!matched) {
      if (s->level == 0U) {
        s->done = 1;
        return BS_OK;
      }
      s->level--;
      s->bind_count = s->frames[s->level].bind_mark;
      s->frames[s->level].fact++;
      continue;
    }

    s->level++;
    if (s->level < r->body_count) {
      s->frames[s->level].fact = 0;
      s->frames[s->level].bind_mark = s->bind_count;
    }
  }
}

/* The origin of the answer the solver is currently sitting on. */
static bs_origin bs_solver_origin(const bs_solver *s, const bs_rule *r) {
  return (r->body_count == 0U) ? bs_rule_origin(r)
                               : s->frames[r->body_count - 1U].origin;
}

/* Do this answer's expressions all hold? */
static bs_status bs_solver_expressions(bs_world *w, bs_symtab *syms,
                                       bs_arena *a, const bs_rule *r,
                                       const bs_solver *s, int *keep) {
  uint32_t k;

  *keep = 1;
  for (k = 0; k < r->expr_count && *keep; k++) {
    int v = 0;
    /* An expression that errors is not a failed match: the specification
     * reports overflow, type errors and shadowing as execution failures of
     * the whole evaluation. */
    bs_status st = bs_expr_evaluate(w, syms, a, w->exprs[r->expr_at + k],
                                    s->binds, s->bind_count, &v);
    if (st != BS_OK) {
      return st;
    }
    *keep = v;
  }
  return BS_OK;
}

/* Apply one rule to everything currently known, appending what it derives.
 *
 * `produced` counts the facts that were not already present, which is what
 * tells the fixpoint loop whether anything changed. */
static bs_status bs_rule_apply(bs_world *w, bs_symtab *syms, bs_arena *a,
                               const bs_rule *r, bs_solver *sv,
                               size_t *produced) {
  bs_status st = bs_solver_init(sv, w, r);

  if (st != BS_OK) {
    return st;
  }
  for (;;) {
    int found = 0;
    int keep = 0;
    bs_fact candidate;
    size_t term_mark;
    size_t i;
    int seen = 0;

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
    if (!keep) {
      continue;
    }

    term_mark = w->term_count;
    st = bs_head_instantiate(w, r, sv->binds, sv->bind_count,
                             bs_solver_origin(sv, r), &candidate);
    if (st != BS_OK) {
      return st;
    }
    /* Every derived fact is compared against everything already known, so
     * this scan is O(fact_count) per accepted answer -- work that scales with
     * the token and has to be charged like any other. */
    for (i = 0; i < w->fact_count; i++) {
      bs_spend(w, 1U);
      if (bs_fact_same(w, &w->facts[i], &candidate)) {
        seen = 1;
        break;
      }
    }
    if (bs_exhausted(w)) {
      return BS_ERR_LIMIT;
    }
    if (seen) {
      /* Already known. Give back the terms the instantiation reserved, or a
       * rule that fires a thousand times costs a thousand copies of the same
       * fact. */
      w->term_count = term_mark;
      continue;
    }
    if (w->fact_count >= w->fact_cap) {
      return BS_ERR_NOMEM;
    }
    w->facts[w->fact_count] = candidate;
    w->fact_count++;
    (*produced)++;
  }
}

/* Run every rule to a fixpoint, with a solver the caller owns.
 *
 * The solver holds one frame per body position and one slot per binding --
 * something over a kilobyte -- so it lives in the arena and is passed down
 * rather than declared at each level. Two of them on one call path was most
 * of a stack budget for no reason: they are never live at the same time.
 *
 * Bounded by iterations rather than by time, which is what the specification's
 * own run limits do: a token cannot buy itself an unbounded evaluation, and
 * hitting the bound is a clean error rather than a hang. */
static bs_status bs_world_run_with(bs_world *w, bs_symtab *syms, bs_arena *a,
                                   size_t max_iterations, bs_solver *sv) {
  size_t round;

  if (max_iterations == 0U) {
    max_iterations = bs_limits_default().max_iterations;
  }

  for (round = 0; round < max_iterations; round++) {
    size_t produced = 0;
    size_t i;

    for (i = 0; i < w->rule_count; i++) {
      bs_status st;
      if (w->rules[i].is_query) {
        continue; /* a check's query is asked later, not derived from */
      }
      st = bs_rule_apply(w, syms, a, &w->rules[i], sv, &produced);
      if (st != BS_OK) {
        return st;
      }
    }
    if (produced == 0U) {
      return BS_OK; /* nothing changed: the fixpoint */
    }
  }
  return BS_ERR_LIMIT;
}

static bs_solver *bs_solver_new(bs_arena *a) {
  return (bs_solver *)bs_arena_alloc(a, sizeof(bs_solver), BS_ALIGN_MAX);
}

BS_API bs_status bs_world_run(bs_world *w, bs_symtab *syms, bs_arena *a,
                              size_t max_iterations) {
  bs_solver *sv;

  if (w == NULL || syms == NULL || a == NULL) {
    return BS_ERR_ARGUMENT;
  }
  sv = bs_solver_new(a);
  if (sv == NULL) {
    return BS_ERR_NOMEM;
  }
  return bs_world_run_with(w, syms, a, max_iterations, sv);
}
