/* Unit tests for authorization.
 *
 * A verdict has two independent halves: what the application's policies allow,
 * and what the token's own blocks insisted on. Getting either wrong produces a
 * plausible answer, so both are checked here separately and together --
 * including the case that matters most, a token whose every check failed and
 * whose policy said allow.
 *
 * Worlds are built from Datalog source rather than in the pools, because that
 * is how an authorizer is actually written and it exercises the parser at the
 * same time.
 */

#include <assert.h>
#include <string.h>

#define BS_ASSERT(cond) assert(cond)

#define BISCUITS_IMPLEMENTATION
#include "biscuits.h"

#include "bs_test.h"

static uint8_t arena_buf[512 * 1024];
static bs_arena A;
static bs_world W;
static bs_symtab SYMS;
static bs_tables TAB;
static bs_verdict V;

static int reset_world(void) {
  bs_limits lim = bs_limits_default();
  lim.max_terms = 2048U;
  lim.max_ops = 512U;
  lim.max_exprs = 64U;
  lim.max_preds = 128U;
  lim.max_syms = 64U;
  lim.max_facts = 256U;
  lim.max_rules = 64U;
  lim.max_checks = 32U;
  lim.max_policies = 16U;

  TAB.symbols.entries = NULL;
  TAB.symbols.count = 0U;
  TAB.public_keys = NULL;
  TAB.public_key_count = 0U;

  if (bs_arena_init(&A, arena_buf, sizeof arena_buf) != BS_OK) {
    return 0;
  }
  if (bs_symtab_init(&SYMS, &A, &TAB.symbols, 64U) != BS_OK) {
    return 0;
  }
  return bs_world_init(&W, &A, &TAB, 4U, &lim) == BS_OK;
}

/* Parse `authority` as block 0 and `code` as the authorizer, then decide. */
static bs_status decide(const char *authority, const char *code) {
  bs_status st;

  if (!reset_world()) {
    return BS_ERR_NOMEM;
  }
  if (authority != NULL) {
    st = bs_world_parse(&W, &SYMS, &A,
                        bs_span_make(authority, strlen(authority)), 0U, NULL,
                        NULL);
    if (st != BS_OK) {
      return st;
    }
  }
  st = bs_world_parse(&W, &SYMS, &A, bs_span_make(code, strlen(code)),
                      (size_t)BS_MAX_BLOCKS, NULL, NULL);
  if (st != BS_OK) {
    return st;
  }
  return bs_authorize(&W, &SYMS, &A, 0U, &V);
}

static void test_a_matching_allow_authorizes(void) {
  REQUIRE(decide("right(\"file1\");", "allow if right(\"file1\");") == BS_OK);
  CHECK(V.kind == (uint8_t)BS_VERDICT_ALLOW);
  CHECK(V.has_policy == 1U);
  CHECK(V.policy == 0U);
  CHECK(V.failed_count == 0U);
}

/* Policies are tried in order and the first match decides, so a deny after a
 * matching allow never runs. */
static void test_the_first_matching_policy_decides(void) {
  REQUIRE(decide(NULL, "allow if true;\ndeny if true;") == BS_OK);
  CHECK(V.kind == (uint8_t)BS_VERDICT_ALLOW);
  CHECK(V.policy == 0U);

  REQUIRE(decide(NULL, "deny if true;\nallow if true;") == BS_OK);
  CHECK(V.kind == (uint8_t)BS_VERDICT_DENY);
  CHECK(V.policy == 0U);

  REQUIRE(decide("a(1);", "allow if a(2);\nallow if a(1);") == BS_OK);
  CHECK(V.kind == (uint8_t)BS_VERDICT_ALLOW);
  CHECK(V.policy == 1U);
}

static void test_no_policy_matches(void) {
  REQUIRE(decide("a(1);", "allow if a(2);") == BS_OK);
  CHECK(V.kind == (uint8_t)BS_VERDICT_NO_POLICY);
  CHECK(V.has_policy == 0U);

  REQUIRE(decide(NULL, "") == BS_OK);
  CHECK(V.kind == (uint8_t)BS_VERDICT_NO_POLICY);
}

/* The case an implementation that only reads the policy gets wrong: the
 * application said allow and the token said no. */
static void test_a_failed_check_denies_a_matching_allow(void) {
  REQUIRE(decide("check if operation(\"read\");", "allow if true;") == BS_OK);
  CHECK(V.kind == (uint8_t)BS_VERDICT_DENY);
  CHECK(V.has_policy == 1U);
  CHECK(V.policy == 0U);
  CHECK(V.failed_count == 1U);
}

/* Every check is evaluated, not just up to the first failure: an application
 * reporting why a token was refused wants all the reasons. */
static void test_all_failures_are_reported(void) {
  REQUIRE(decide("check if a(1);\ncheck if b(1);\ncheck if c(1);",
                 "allow if true;") == BS_OK);
  CHECK(V.failed_count == 3U);
  CHECK(V.failed[0].block == 0U);
  CHECK(V.failed[0].index == 0U);
  CHECK(V.failed[2].index == 2U);
}

/* A failing authorizer check is reported in the words its author wrote,
 * without the trailing semicolon or the whitespace after it. */
static void test_a_failed_check_reports_its_own_text(void) {
  char buf[128];
  bs_writer w;

  REQUIRE(decide(NULL, "check if missing($x);\n\nallow if true;\n") == BS_OK);
  REQUIRE(V.failed_count == 1U);
  CHECK(V.failed[0].block == (uint32_t)BS_MAX_BLOCKS);
  CHECK(V.failed[0].from_text == 1U);
  REQUIRE(bs_writer_init(&w, buf, sizeof buf) == BS_OK);
  REQUIRE(bs_failed_check_print(&w, &A, &TAB, &V.failed[0]) == BS_OK);
  CHECK(bs_writer_len(&w) == sizeof "check if missing($x)" - 1U);
  CHECK(memcmp(buf, "check if missing($x)", bs_writer_len(&w)) == 0);
}

static void test_check_kinds(void) {
  /* `check if` wants one match. */
  REQUIRE(decide("a(1);\ncheck if a($x);", "allow if true;") == BS_OK);
  CHECK(V.kind == (uint8_t)BS_VERDICT_ALLOW);

  /* `reject if` wants none. */
  REQUIRE(decide("a(1);\nreject if a($x);", "allow if true;") == BS_OK);
  CHECK(V.kind == (uint8_t)BS_VERDICT_DENY);
  REQUIRE(decide("a(1);\nreject if b($x);", "allow if true;") == BS_OK);
  CHECK(V.kind == (uint8_t)BS_VERDICT_ALLOW);

  /* `check all` wants every match to satisfy the expressions. */
  REQUIRE(decide("a(1);\na(2);\ncheck all a($x), $x > 0;", "allow if true;") ==
          BS_OK);
  CHECK(V.kind == (uint8_t)BS_VERDICT_ALLOW);
  REQUIRE(decide("a(1);\na(2);\ncheck all a($x), $x > 1;", "allow if true;") ==
          BS_OK);
  CHECK(V.kind == (uint8_t)BS_VERDICT_DENY);

  /* And at least one. The specification's wording reads as vacuously true,
   * but the conformance sample's "no matches" case expects a failure. */
  REQUIRE(decide("check all a($x), $x > 0;", "allow if true;") == BS_OK);
  CHECK(V.kind == (uint8_t)BS_VERDICT_DENY);
}

/* Queries joined by `or`: any one succeeding carries the check, except for
 * `reject if`, where any one matching sinks it. */
static void test_alternatives_in_a_check(void) {
  REQUIRE(decide("a(1);\ncheck if b($x) or a($x);", "allow if true;") == BS_OK);
  CHECK(V.kind == (uint8_t)BS_VERDICT_ALLOW);

  REQUIRE(decide("a(1);\nreject if b($x) or a($x);", "allow if true;") ==
          BS_OK);
  CHECK(V.kind == (uint8_t)BS_VERDICT_DENY);
}

/* Rules run to a fixpoint before anything is checked. */
static void test_derived_facts_are_visible_to_policies(void) {
  REQUIRE(decide("a(1);\nb($x) <- a($x);", "allow if b(1);") == BS_OK);
  CHECK(V.kind == (uint8_t)BS_VERDICT_ALLOW);

  REQUIRE(decide("a(1);\nb($x) <- a($x);\nc($x) <- b($x);", "allow if c(1);") ==
          BS_OK);
  CHECK(V.kind == (uint8_t)BS_VERDICT_ALLOW);
}

/* The authorizer's own facts are not the authority's, and a block that does
 * not trust the authorizer cannot see them. */
static void test_authorizer_facts_have_their_own_origin(void) {
  REQUIRE(decide(NULL, "resource(\"file1\");\nallow if resource(\"file1\");") ==
          BS_OK);
  CHECK(V.kind == (uint8_t)BS_VERDICT_ALLOW);
  CHECK(W.facts[0].origin == BS_ORIGIN_AUTHORIZER);
}

/* Bit 63 is the authorizer's and no block may hold it. A token long enough to
 * reach that bit would otherwise have its last block trusted as though the
 * application had stated its facts itself. */
static void test_no_block_can_hold_the_authorizer_bit(void) {
  size_t i;

  CHECK(BS_ORIGIN_AUTHORIZER == BS_ORIGIN_ONE(63U));
  for (i = 0; i < (size_t)BS_MAX_BLOCKS; i++) {
    if (BS_ORIGIN_ONE(i) == BS_ORIGIN_AUTHORIZER) {
      CHECK(0);
      return;
    }
  }
  CHECK(1);
  /* And a world cannot be asked for more blocks than that. */
  {
    bs_limits lim = bs_limits_default();
    REQUIRE(bs_arena_init(&A, arena_buf, sizeof arena_buf) == BS_OK);
    CHECK(bs_world_init(&W, &A, &TAB, (size_t)BS_MAX_BLOCKS + 1U, &lim) ==
          BS_ERR_LIMIT);
  }
}

int main(void) {
  test_a_matching_allow_authorizes();
  test_the_first_matching_policy_decides();
  test_no_policy_matches();
  test_a_failed_check_denies_a_matching_allow();
  test_all_failures_are_reported();
  test_a_failed_check_reports_its_own_text();
  test_check_kinds();
  test_alternatives_in_a_check();
  test_derived_facts_are_visible_to_policies();
  test_authorizer_facts_have_their_own_origin();
  test_no_block_can_hold_the_authorizer_bit();
  return bs_test_finish();
}
