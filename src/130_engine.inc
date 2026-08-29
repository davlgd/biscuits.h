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

#ifndef BS_MAX_BODY
#define BS_MAX_BODY 16
#endif

typedef struct bs_matchframe {
  size_t fact;      /* the candidate being tried at this body position */
  size_t bind_mark; /* how many bindings existed before it bound any */
  bs_origin origin; /* origins accumulated through this position */
} bs_matchframe;

/* Do two facts state the same thing? Origins are compared too: the same
 * sentence derived through different blocks is a different fact, because
 * scoping asks where it came from. */
static int bs_fact_same(const bs_world *w, const bs_fact *a, const bs_fact *b) {
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
static int bs_unify(const bs_world *w, const bs_predicate *p, const bs_fact *f,
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
        /* A head variable that no body predicate bound. The specification
         * calls this an invalid rule; a fact with a hole in it is not a
         * fact. */
        return BS_ERR_MALFORMED;
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

/* Apply one rule to everything currently known, appending what it derives.
 *
 * `produced` counts the facts that were not already present, which is what
 * tells the fixpoint loop whether anything changed. */
static bs_status bs_rule_apply(bs_world *w, bs_symtab *syms, bs_arena *a,
                               const bs_rule *r, size_t *produced) {
  bs_matchframe frames[BS_MAX_BODY];
  bs_binding binds[BS_MAX_BINDINGS];
  size_t bind_count = 0;
  size_t level = 0;
  size_t base_facts = w->fact_count;
  bs_status st;

  if (r->body_count > (size_t)BS_MAX_BODY) {
    return BS_ERR_LIMIT;
  }

  frames[0].fact = 0;
  frames[0].bind_mark = 0;
  frames[0].origin = BS_ORIGIN_ONE(r->block);

  for (;;) {
    if (level == r->body_count) {
      /* Every predicate matched. The expressions decide whether this
       * combination actually counts. */
      bs_origin origin = (r->body_count == 0U)
                             ? BS_ORIGIN_ONE(r->block)
                             : frames[r->body_count - 1U].origin;
      int keep = 1;
      uint32_t k;

      for (k = 0; k < r->expr_count && keep; k++) {
        int v = 0;
        st = bs_expr_evaluate(w, syms, a, w->exprs[r->expr_at + k], binds,
                              bind_count, &v);
        if (st != BS_OK) {
          /* An expression that errors is not a failed match: the
           * specification reports overflow, type errors and shadowing as
           * execution failures of the whole evaluation. */
          return st;
        }
        keep = v;
      }

      if (keep) {
        bs_fact candidate;
        size_t term_mark = w->term_count;
        st = bs_head_instantiate(w, r, binds, bind_count, origin, &candidate);
        if (st != BS_OK) {
          return st;
        }
        {
          size_t i;
          int seen = 0;
          for (i = 0; i < w->fact_count; i++) {
            if (bs_fact_same(w, &w->facts[i], &candidate)) {
              seen = 1;
              break;
            }
          }
          if (seen) {
            /* Already known. Give back the terms the instantiation reserved,
             * or a rule that fires a thousand times costs a thousand copies
             * of the same fact. */
            w->term_count = term_mark;
          } else {
            if (w->fact_count >= w->fact_cap) {
              return BS_ERR_NOMEM;
            }
            w->facts[w->fact_count] = candidate;
            w->fact_count++;
            (*produced)++;
          }
        }
      }

      /* Backtrack into the last position and try its next candidate. */
      if (level == 0U) {
        return BS_OK;
      }
      level--;
      bind_count = frames[level].bind_mark;
      frames[level].fact++;
      continue;
    }

    {
      const bs_predicate *p = &w->preds[r->body_at + level];
      bs_origin prev =
          (level == 0U) ? BS_ORIGIN_ONE(r->block) : frames[level - 1U].origin;
      int matched = 0;

      /* Only facts that existed when this rule started are candidates: a rule
       * must not consume what it produced in the same pass, or a recursive
       * rule would run away inside one round instead of converging over
       * several. */
      while (frames[level].fact < base_facts) {
        const bs_fact *f = &w->facts[frames[level].fact];
        size_t mark = bind_count;

        /* "Only facts whose origin is a subset of these trusted origins are
         * matched." A subset, not an overlap. */
        if ((f->origin & ~r->trust) != BS_ORIGIN_NONE) {
          frames[level].fact++;
          continue;
        }
        if (!bs_unify(w, p, f, binds, &bind_count, (size_t)BS_MAX_BINDINGS)) {
          bind_count = mark;
          frames[level].fact++;
          continue;
        }
        frames[level].bind_mark = mark;
        frames[level].origin = prev | f->origin;
        matched = 1;
        break;
      }

      if (!matched) {
        if (level == 0U) {
          return BS_OK; /* no combination left to try */
        }
        level--;
        bind_count = frames[level].bind_mark;
        frames[level].fact++;
        continue;
      }

      level++;
      if (level < r->body_count) {
        frames[level].fact = 0;
        frames[level].bind_mark = bind_count;
      }
    }
  }
}

/* Run every rule to a fixpoint.
 *
 * Bounded by iterations rather than by time, which is what the specification's
 * own run limits do: a token cannot buy itself an unbounded evaluation, and
 * hitting the bound is a clean error rather than a hang. */
BS_API bs_status bs_world_run(bs_world *w, bs_symtab *syms, bs_arena *a,
                              size_t max_iterations) {
  size_t round;

  if (w == NULL || syms == NULL || a == NULL) {
    return BS_ERR_ARGUMENT;
  }
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
      st = bs_rule_apply(w, syms, a, &w->rules[i], &produced);
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
