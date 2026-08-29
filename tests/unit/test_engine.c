/* Unit tests for Datalog evaluation.
 *
 * The origin rules are the reason this file exists. A fact carries the set of
 * blocks that allowed it to exist, and a rule may only match facts whose
 * origin is a *subset* of what it trusts. That is the whole mechanism
 * stopping an appended block from granting itself rights, and it fails
 * silently when it is wrong: the token authorizes something it should not,
 * and nothing errors.
 *
 * Worlds are built directly in the pools, so a failure points at the engine
 * rather than at the loader or the wire format.
 */

#include <assert.h>
#include <string.h>

#define BS_ASSERT(cond) assert(cond)

#define BISCUITS_IMPLEMENTATION
#include "biscuits.h"

#include "bs_test.h"

static uint8_t arena_buf[256 * 1024];
static bs_arena A;
static bs_world W;
static bs_symtab SYMS;
static bs_tables TAB;

/* Symbol indices used throughout: predicate names and variables. */
#define S_A 1024U
#define S_B 1025U
#define S_C 1026U
#define V_X 1027U
#define V_Y 1028U

static bs_span ENTRIES[5];

static int reset_world(void) {
  bs_limits lim = bs_limits_default();
  lim.max_terms = 512U;
  lim.max_ops = 128U;
  lim.max_exprs = 16U;
  lim.max_preds = 64U;
  lim.max_syms = 16U;
  lim.max_facts = 128U;
  lim.max_rules = 16U;
  lim.max_checks = 8U;
  lim.max_policies = 4U;

  ENTRIES[0] = bs_span_make("a", 1U);
  ENTRIES[1] = bs_span_make("b", 1U);
  ENTRIES[2] = bs_span_make("c", 1U);
  ENTRIES[3] = bs_span_make("x", 1U);
  ENTRIES[4] = bs_span_make("y", 1U);
  TAB.symbols.entries = ENTRIES;
  TAB.symbols.count = 5U;
  TAB.public_keys = NULL;
  TAB.public_key_count = 0U;

  if (bs_arena_init(&A, arena_buf, sizeof arena_buf) != BS_OK) {
    return 0;
  }
  if (bs_symtab_init(&SYMS, &A, &TAB.symbols, 16U) != BS_OK) {
    return 0;
  }
  return bs_world_init(&W, &A, &TAB, 4U, &lim) == BS_OK;
}

static bs_term t_int(int64_t v) {
  bs_term t;
  t.kind = (uint8_t)BS_T_INTEGER;
  t.as.integer = v;
  return t;
}

static bs_term t_var(uint64_t sym) {
  bs_term t;
  t.kind = (uint8_t)BS_T_VARIABLE;
  t.as.sym = sym;
  return t;
}

/* `name(t0, t1)` placed in the term pool; pass count 1 for a single term. */
static bs_predicate pred(uint64_t name, bs_term t0, bs_term t1,
                         uint32_t count) {
  bs_predicate p;
  p.name = name;
  p.at = (uint32_t)W.term_count;
  p.count = count;
  if (count >= 1U) {
    W.terms[W.term_count] = t0;
    W.term_count++;
  }
  if (count >= 2U) {
    W.terms[W.term_count] = t1;
    W.term_count++;
  }
  return p;
}

static void add_fact(uint64_t name, bs_term t0, uint32_t count,
                     bs_origin origin) {
  W.facts[W.fact_count].pred = pred(name, t0, t0, count);
  W.facts[W.fact_count].origin = origin;
  W.fact_count++;
}

/* `head <- body`, with one body predicate. */
static uint32_t add_rule(bs_predicate head, bs_predicate body, uint32_t block,
                         bs_origin trust) {
  uint32_t at = (uint32_t)W.rule_count;
  W.preds[W.pred_count] = body;
  W.rules[at].head = head;
  W.rules[at].is_query = 0;
  W.rules[at].body_at = (uint32_t)W.pred_count;
  W.rules[at].body_count = 1U;
  W.rules[at].expr_at = 0;
  W.rules[at].expr_count = 0;
  W.rules[at].trust = trust;
  W.rules[at].block = block;
  W.pred_count++;
  W.rule_count++;
  return at;
}

static int has_fact(uint64_t name, int64_t value, bs_origin origin) {
  size_t i;
  for (i = 0; i < W.fact_count; i++) {
    const bs_fact *f = &W.facts[i];
    if (f->pred.name != name || f->pred.count != 1U || f->origin != origin) {
      continue;
    }
    if (W.terms[f->pred.at].kind == (uint8_t)BS_T_INTEGER &&
        W.terms[f->pred.at].as.integer == value) {
      return 1;
    }
  }
  return 0;
}

/* --------------------------------------------------------------------------
 * Derivation
 * ----------------------------------------------------------------------- */

static void test_simple_derivation(void) {
  REQUIRE(reset_world());
  add_fact(S_A, t_int(1), 1U, BS_ORIGIN_ONE(0U));
  (void)add_rule(pred(S_B, t_var(V_X), t_var(V_X), 1U),
                 pred(S_A, t_var(V_X), t_var(V_X), 1U), 1U,
                 BS_ORIGIN_ONE(0U) | BS_ORIGIN_ONE(1U));

  REQUIRE(bs_world_run(&W, &SYMS, &A, 0U) == BS_OK);

  /* `b(1)` exists, and its origin is the union of the rule's block and the
   * origin of the fact it matched -- not the rule's block alone. That union
   * is what a later rule's trust set will be tested against. */
  CHECK(has_fact(S_B, 1, BS_ORIGIN_ONE(0U) | BS_ORIGIN_ONE(1U)));
  CHECK(W.fact_count == 2U);

  /* Running again derives nothing: the fixpoint is a fixpoint. */
  REQUIRE(bs_world_run(&W, &SYMS, &A, 0U) == BS_OK);
  CHECK(W.fact_count == 2U);
}

static void test_origin_must_be_a_subset(void) {
  REQUIRE(reset_world());
  /* A fact that came from blocks 0 and 2 together. */
  add_fact(S_A, t_int(1), 1U, BS_ORIGIN_ONE(0U) | BS_ORIGIN_ONE(2U));

  /* A rule in block 1 trusting blocks 0 and 1. It overlaps the fact's origin
   * at block 0 -- and must not match, because the specification says subset,
   * not overlap. Reading this as an intersection is how an appended block
   * gets to launder a fact it was never entitled to see. */
  (void)add_rule(pred(S_B, t_var(V_X), t_var(V_X), 1U),
                 pred(S_A, t_var(V_X), t_var(V_X), 1U), 1U,
                 BS_ORIGIN_ONE(0U) | BS_ORIGIN_ONE(1U));

  REQUIRE(bs_world_run(&W, &SYMS, &A, 0U) == BS_OK);
  CHECK(W.fact_count == 1U); /* nothing derived */

  /* Widen the trust to include block 2 and the same rule now matches. */
  W.rules[0].trust |= BS_ORIGIN_ONE(2U);
  REQUIRE(bs_world_run(&W, &SYMS, &A, 0U) == BS_OK);
  CHECK(W.fact_count == 2U);
  CHECK(has_fact(S_B, 1,
                 BS_ORIGIN_ONE(0U) | BS_ORIGIN_ONE(1U) | BS_ORIGIN_ONE(2U)));
}

static void test_join_on_a_shared_variable(void) {
  bs_predicate head;
  bs_predicate b0;
  bs_predicate b1;
  bs_origin trust = BS_ORIGIN_ONE(0U) | BS_ORIGIN_ONE(1U);

  REQUIRE(reset_world());
  add_fact(S_A, t_int(1), 1U, BS_ORIGIN_ONE(0U));
  add_fact(S_A, t_int(2), 1U, BS_ORIGIN_ONE(0U));
  add_fact(S_B, t_int(2), 1U, BS_ORIGIN_ONE(0U));
  add_fact(S_B, t_int(3), 1U, BS_ORIGIN_ONE(0U));

  /* `c($x) <- a($x), b($x)`: only the value both agree on survives, which is
   * the join the shared variable expresses. */
  head = pred(S_C, t_var(V_X), t_var(V_X), 1U);
  b0 = pred(S_A, t_var(V_X), t_var(V_X), 1U);
  b1 = pred(S_B, t_var(V_X), t_var(V_X), 1U);
  W.preds[W.pred_count] = b0;
  W.preds[W.pred_count + 1U] = b1;
  W.rules[0].head = head;
  W.rules[0].is_query = 0;
  W.rules[0].body_at = (uint32_t)W.pred_count;
  W.rules[0].body_count = 2U;
  W.rules[0].expr_at = 0;
  W.rules[0].expr_count = 0;
  W.rules[0].trust = trust;
  W.rules[0].block = 1U;
  W.pred_count += 2U;
  W.rule_count = 1U;

  REQUIRE(bs_world_run(&W, &SYMS, &A, 0U) == BS_OK);
  CHECK(has_fact(S_C, 2, trust));
  CHECK(!has_fact(S_C, 1, trust));
  CHECK(!has_fact(S_C, 3, trust));
  CHECK(W.fact_count == 5U);
}

static void test_transitive_closure_reaches_a_fixpoint(void) {
  bs_origin trust = BS_ORIGIN_ONE(0U) | BS_ORIGIN_ONE(1U);

  REQUIRE(reset_world());
  add_fact(S_A, t_int(1), 1U, BS_ORIGIN_ONE(0U));

  /* `a($x) <- a($x)` is a rule that can only ever restate what it matched, so
   * the second round produces nothing and the loop stops. A fixpoint that did
   * not notice would run to the iteration limit. */
  (void)add_rule(pred(S_A, t_var(V_X), t_var(V_X), 1U),
                 pred(S_A, t_var(V_X), t_var(V_X), 1U), 1U, trust);

  REQUIRE(bs_world_run(&W, &SYMS, &A, 0U) == BS_OK);
  /* Two facts: the original with origin {0}, and the restatement with the
   * union {0,1}. They differ by origin, which is part of a fact's identity. */
  CHECK(W.fact_count == 2U);
  CHECK(has_fact(S_A, 1, BS_ORIGIN_ONE(0U)));
  CHECK(has_fact(S_A, 1, trust));
}

static void test_head_variable_must_be_bound(void) {
  REQUIRE(reset_world());
  add_fact(S_A, t_int(1), 1U, BS_ORIGIN_ONE(0U));
  /* `b($y) <- a($x)`: nothing binds $y, so the head cannot be instantiated.
   * A fact with a hole in it is not a fact. */
  (void)add_rule(pred(S_B, t_var(V_Y), t_var(V_Y), 1U),
                 pred(S_A, t_var(V_X), t_var(V_X), 1U), 1U,
                 BS_ORIGIN_ONE(0U) | BS_ORIGIN_ONE(1U));
  CHECK(bs_world_run(&W, &SYMS, &A, 0U) == BS_ERR_MALFORMED);
}

static void test_queries_do_not_derive(void) {
  REQUIRE(reset_world());
  add_fact(S_A, t_int(1), 1U, BS_ORIGIN_ONE(0U));
  (void)add_rule(pred(S_B, t_var(V_X), t_var(V_X), 1U),
                 pred(S_A, t_var(V_X), t_var(V_X), 1U), 1U,
                 BS_ORIGIN_ONE(0U) | BS_ORIGIN_ONE(1U));
  /* A check's query lives in the same pool and must stay out of the
   * fixpoint: it is asked once when the check is evaluated, and adding its
   * head to the world would let a check invent facts. */
  W.rules[0].is_query = 1;
  REQUIRE(bs_world_run(&W, &SYMS, &A, 0U) == BS_OK);
  CHECK(W.fact_count == 1U);
}

static void test_iteration_limit(void) {
  bs_origin trust = BS_ORIGIN_ONE(0U) | BS_ORIGIN_ONE(1U);
  size_t i;

  REQUIRE(reset_world());
  /* A chain that keeps producing: each round adds one more fact, so a low
   * limit is reached rather than the fixpoint. Hitting the bound is a clean
   * BS_ERR_LIMIT, which is what stops a token from buying an unbounded
   * evaluation. */
  for (i = 0; i < 40U; i++) {
    add_fact(S_A, t_int((int64_t)i), 1U, BS_ORIGIN_ONE(0U));
  }
  (void)add_rule(pred(S_B, t_var(V_X), t_var(V_X), 1U),
                 pred(S_A, t_var(V_X), t_var(V_X), 1U), 1U, trust);
  (void)add_rule(pred(S_C, t_var(V_X), t_var(V_X), 1U),
                 pred(S_B, t_var(V_X), t_var(V_X), 1U), 1U, trust);

  /* One round cannot reach the fixpoint here: the second rule can only see
   * what the first produced in the round before. */
  CHECK(bs_world_run(&W, &SYMS, &A, 1U) == BS_ERR_LIMIT);
}

static void test_pool_exhaustion_is_reported(void) {
  bs_limits lim = bs_limits_default();
  size_t i;

  lim.max_terms = 512U;
  lim.max_ops = 16U;
  lim.max_exprs = 4U;
  lim.max_preds = 8U;
  lim.max_syms = 8U;
  lim.max_facts = 4U; /* room for the seeds and almost nothing derived */
  lim.max_rules = 4U;
  lim.max_checks = 2U;
  lim.max_policies = 2U;

  ENTRIES[0] = bs_span_make("a", 1U);
  TAB.symbols.entries = ENTRIES;
  TAB.symbols.count = 5U;
  TAB.public_keys = NULL;
  TAB.public_key_count = 0U;
  REQUIRE(bs_arena_init(&A, arena_buf, sizeof arena_buf) == BS_OK);
  REQUIRE(bs_symtab_init(&SYMS, &A, &TAB.symbols, 8U) == BS_OK);
  REQUIRE(bs_world_init(&W, &A, &TAB, 2U, &lim) == BS_OK);

  for (i = 0; i < 4U; i++) {
    add_fact(S_A, t_int((int64_t)i), 1U, BS_ORIGIN_ONE(0U));
  }
  (void)add_rule(pred(S_B, t_var(V_X), t_var(V_X), 1U),
                 pred(S_A, t_var(V_X), t_var(V_X), 1U), 1U,
                 BS_ORIGIN_ONE(0U) | BS_ORIGIN_ONE(1U));
  CHECK(bs_world_run(&W, &SYMS, &A, 0U) == BS_ERR_NOMEM);

  CHECK(bs_world_run(NULL, &SYMS, &A, 0U) == BS_ERR_ARGUMENT);
  CHECK(bs_world_run(&W, NULL, &A, 0U) == BS_ERR_ARGUMENT);
  CHECK(bs_world_run(&W, &SYMS, NULL, 0U) == BS_ERR_ARGUMENT);
}

int main(void) {
  test_simple_derivation();
  test_origin_must_be_a_subset();
  test_join_on_a_shared_variable();
  test_transitive_closure_reaches_a_fixpoint();
  test_head_variable_must_be_bound();
  test_queries_do_not_derive();
  test_iteration_limit();
  test_pool_exhaustion_is_reported();
  return bs_test_finish();
}
