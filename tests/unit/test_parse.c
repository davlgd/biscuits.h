/* Unit tests for the Datalog text parser.
 *
 * Most of these evaluate what they parse rather than inspecting the opcodes,
 * because a precedence mistake is invisible in a structural check and obvious
 * in an answer: `1 + 2 * 3 === 7` is true only if `*` bound tighter, and the
 * assertion reads in the same notation the author would have written.
 *
 * The rest check the shapes an expression cannot be evaluated into -- the
 * containers, the statement forms -- and the inputs that must be refused.
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

static int reset_world(void) {
  bs_limits lim = bs_limits_default();
  lim.max_terms = 4096U;
  lim.max_ops = 1024U;
  lim.max_exprs = 64U;
  lim.max_preds = 64U;
  lim.max_syms = 64U;
  lim.max_facts = 128U;
  lim.max_rules = 32U;
  lim.max_checks = 16U;
  lim.max_policies = 8U;

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

/* Parse into a fresh world, as the authorizer would. */
static bs_status parse(const char *src) {
  if (!reset_world()) {
    return BS_ERR_NOMEM;
  }
  return bs_world_parse(&W, &SYMS, &A, bs_span_make(src, strlen(src)),
                        (size_t)BS_MAX_BLOCKS, NULL, NULL);
}

/* Parse one expression, as a check's only condition, and evaluate it. */
static int truth(const char *expr) {
  char buf[512];
  int value = 0;
  const bs_rule *q;

  buf[0] = '\0';
  strncat(buf, "check if ", sizeof buf - 1U);
  strncat(buf, expr, sizeof buf - strlen(buf) - 1U);
  if (parse(buf) != BS_OK) {
    return -2;
  }
  if (W.check_count != 1U || W.rule_count != 1U) {
    return -3;
  }
  q = &W.rules[W.checks[0].query_at];
  if (q->expr_count != 1U) {
    return -4;
  }
  if (bs_expr_evaluate(&W, &SYMS, &A, W.exprs[q->expr_at], NULL, 0U, &value) !=
      BS_OK) {
    return -5;
  }
  return value;
}

static int refuses(const char *src) {
  return parse(src) != BS_OK;
}

#define TRUE_EXPR(e) CHECK(truth(e) == 1)
#define FALSE_EXPR(e) CHECK(truth(e) == 0)

/* Precedence, checked by arithmetic: a table read wrong gives a wrong
 * answer rather than a differently-shaped tree nobody inspects. */
static void test_precedence(void) {
  TRUE_EXPR("1 + 2 * 3 === 7");
  TRUE_EXPR("2 * 3 + 1 === 7");
  TRUE_EXPR("(1 + 2) * 3 === 9");
  TRUE_EXPR("10 - 2 - 3 === 5");
  /* The grammar makes the space optional, so a `-` with a digit against it is
   * subtraction where an operand has just been read, and the sign of a
   * literal where one has not. Nothing about the character says which. */
  TRUE_EXPR("3-2 === 1");
  TRUE_EXPR("3-2-1 === 0");
  TRUE_EXPR("(3)-2 === 1");
  TRUE_EXPR("[9].get(0)-2 === 7");
  TRUE_EXPR("-3 + 2 === -1");
  TRUE_EXPR("[-1, -2].get(1) === -2");
  TRUE_EXPR("{-1: \"a\"}.get(-1) === \"a\"");
  TRUE_EXPR("100 / 10 / 2 === 5");

  /* Not C's order: `&` binds tighter than `|`, which binds tighter than `^`.
   * Read in C's order these three would all come out differently. */
  TRUE_EXPR("1 ^ 2 | 4 & 4 === 7");
  TRUE_EXPR("6 & 3 | 8 === 10");
  TRUE_EXPR("1 | 2 ^ 3 === 0");

  TRUE_EXPR("1 + 1 === 2");
  TRUE_EXPR("1 < 2 && 3 < 4");
  TRUE_EXPR("false || 1 < 2");
}

/* Prefix `!` binds looser than a method call and tighter than any binary. */
static void test_negation(void) {
  TRUE_EXPR("!false");
  TRUE_EXPR("!false && true");
  TRUE_EXPR("!{1, 2}.contains(3)");
  FALSE_EXPR("!true || false");
}

static void test_methods(void) {
  TRUE_EXPR("\"hello\".starts_with(\"he\")");
  TRUE_EXPR("\"hello\".ends_with(\"lo\")");
  TRUE_EXPR("\"hello\".length() === 5");
  TRUE_EXPR("\"hello\".contains(\"ell\")");
  TRUE_EXPR("1.type() === \"integer\"");
  TRUE_EXPR("{1, 2, 3}.contains(2)");
  TRUE_EXPR("{1, 2}.union({3}).length() === 3");
  TRUE_EXPR("{1, 2, 3}.intersection({2, 3, 4}) === {2, 3}");
  TRUE_EXPR("[1, 2, 3].get(1) === 2");
  TRUE_EXPR("{\"a\": 1}.get(\"a\") === 1");
  /* Chained calls apply left to right. */
  TRUE_EXPR("\"abc\".length().type() === \"integer\"");
}

/* A closure's body has to reach the pool as a contiguous run of its own,
 * which is the one thing about this parser that could be subtly wrong and
 * still produce plausible output. Nested closures are the case that would
 * expose it. */
static void test_closures(void) {
  TRUE_EXPR("[1, 2, 3].all($p -> $p > 0)");
  FALSE_EXPR("[1, 2, 3].all($p -> $p > 1)");
  TRUE_EXPR("[1, 2, 3].any($p -> $p > 2)");
  TRUE_EXPR("[1, 2].all($p -> [3, 4].any($q -> $q > $p))");
  TRUE_EXPR("[\"ab\", \"ac\"].all($p -> $p.starts_with(\"a\"))");
  TRUE_EXPR("[1, 2].all($p -> $p > 0 && $p < 3)");
}

static void test_literals(void) {
  TRUE_EXPR("\"file.txt\".matches(\"^file[.]txt$\")");
  TRUE_EXPR("2020-12-21T09:23:12Z < 2021-01-01T00:00:00Z");
  /* A date that does not exist is refused rather than normalised into a
   * different instant: the 31st of February would otherwise be the 2nd of
   * March, which is a second spelling nobody wrote on purpose. */
  CHECK(refuses("check if 2020-02-31T00:00:00Z === 2020-02-31T00:00:00Z"));
  CHECK(refuses("check if 2021-02-29T00:00:00Z === 2021-02-29T00:00:00Z"));
  CHECK(refuses("check if 2020-04-31T00:00:00Z === 2020-04-31T00:00:00Z"));
  CHECK(refuses("check if 2020-00-01T00:00:00Z === 2020-00-01T00:00:00Z"));
  TRUE_EXPR("2020-02-29T00:00:00Z < 2020-03-01T00:00:00Z"); /* a leap year */
  TRUE_EXPR(
      "2000-02-29T00:00:00Z < 2000-03-01T00:00:00Z"); /* and a leap century */
  TRUE_EXPR("hex:0102 === hex:0102");
  TRUE_EXPR("hex:01 !== hex:02");
  TRUE_EXPR("null == null");
  /* The bounds of an integer literal, and one digit past them. */
  TRUE_EXPR("9223372036854775807 === 9223372036854775807");
  TRUE_EXPR("-9223372036854775808 < 0");
  CHECK(refuses("check if 9223372036854775808 === 0"));
  CHECK(refuses("check if 99999999999999999999999999999999 === 0"));
  TRUE_EXPR("1 != \"1\"");
}

/* The empty spellings are the interesting ones: `{}` is a map and `{,}` is a
 * set, and only the comma tells them apart. */
static void test_containers(void) {
  TRUE_EXPR("{,}.length() === 0");
  TRUE_EXPR("{}.length() === 0");
  TRUE_EXPR("{,}.type() === \"set\"");
  TRUE_EXPR("{}.type() === \"map\"");
  TRUE_EXPR("[].length() === 0");
  TRUE_EXPR("[1, 2, 3,].length() === 3");
  TRUE_EXPR("[1, [2, 3]].length() === 2");
  TRUE_EXPR("[1, [2, 3]].get(1).length() === 2");
  TRUE_EXPR("{\"a\": [1, 2]}.get(\"a\").get(0) === 1");
}

/* A negative number in an argument list is a literal, not a subtraction of
 * something that is not there. */
static void test_negative_literals_in_arguments(void) {
  REQUIRE(parse("f(-1, 2);\ng(-1);") == BS_OK);
  CHECK(W.fact_count == 2U);
  CHECK(W.terms[W.facts[0].pred.at].kind == (uint8_t)BS_T_INTEGER);
  CHECK(W.terms[W.facts[0].pred.at].as.integer == -1);
}

static void test_statements(void) {
  REQUIRE(parse("right(\"file1\", \"read\");\n"
                "right(\"file2\", \"write\");\n"
                "owner($u, $f) <- user($u), file($f);\n"
                "check if right(\"file1\", \"read\");\n"
                "check all right($f, $op), $op != \"admin\";\n"
                "reject if bad($x);\n"
                "allow if true;\n"
                "deny if false;") == BS_OK);
  CHECK(W.fact_count == 2U);
  CHECK(W.check_count == 3U);
  CHECK(W.policy_count == 2U);
  CHECK(W.checks[0].kind == (uint8_t)BS_CHECK_KIND_ONE);
  CHECK(W.checks[1].kind == (uint8_t)BS_CHECK_KIND_ALL);
  CHECK(W.checks[2].kind == (uint8_t)BS_CHECK_KIND_REJECT);
  CHECK(W.policies[0].kind == (uint8_t)BS_POLICY_ALLOW);
  CHECK(W.policies[1].kind == (uint8_t)BS_POLICY_DENY);
}

/* Queries joined by `or` are separate rules under one check. */
static void test_alternatives(void) {
  REQUIRE(parse("check if a($x) or b($x) or c($x)") == BS_OK);
  CHECK(W.checks[0].query_count == 3U);
  CHECK(W.rule_count == 3U);
  CHECK(W.rules[0].is_query == 1U);
}

static void test_rule_body(void) {
  REQUIRE(parse("h($x) <- p($x), q($x, $y), $x > 0, $y < 10") == BS_OK);
  CHECK(W.rules[0].body_count == 2U);
  CHECK(W.rules[0].expr_count == 2U);
  CHECK(W.rules[0].is_query == 0U);
  CHECK(W.rules[0].head.count == 1U);
}

/* `true` opens a term, not a predicate: only a name followed by `(` is one. */
static void test_body_may_open_with_an_expression(void) {
  REQUIRE(parse("check if true") == BS_OK);
  CHECK(W.rules[0].body_count == 0U);
  CHECK(W.rules[0].expr_count == 1U);
}

static void test_trust_annotations(void) {
  REQUIRE(parse("check if a($x) trusting authority") == BS_OK);
  CHECK(W.rules[0].trust == (BS_ORIGIN_AUTHORIZER | BS_ORIGIN_ONE(0U)));

  /* With no annotation at all the authority is trusted, which is what makes
   * the annotated case above a real difference rather than a spelling. */
  REQUIRE(parse("check if a($x)") == BS_OK);
  CHECK((W.rules[0].trust & BS_ORIGIN_ONE(0U)) != BS_ORIGIN_NONE);

  /* `previous` is ignored in the authorizer -- and the annotation still
   * replaces the default, so it leaves the authorizer trusting only itself.
   * Reading it as "every block there is" instead would invert it: an
   * annotation that narrows to nothing would widen to every block an
   * attacker appended. */
  REQUIRE(parse("check if a($x) trusting previous") == BS_OK);
  CHECK(W.rules[0].trust == BS_ORIGIN_AUTHORIZER);

  /* In a block it does mean every block up to and including that one. */
  REQUIRE(reset_world());
  REQUIRE(bs_world_parse(&W, &SYMS, &A,
                         bs_span_make("check if a($x) trusting previous", 32U),
                         2U, NULL, NULL) == BS_OK);
  CHECK(W.rules[0].trust == (BS_ORIGIN_AUTHORIZER | BS_ORIGIN_ONE(0U) |
                             BS_ORIGIN_ONE(1U) | BS_ORIGIN_ONE(2U)));
  CHECK((W.rules[0].trust & BS_ORIGIN_ONE(3U)) == BS_ORIGIN_NONE);

  /* A key nobody signed with adds nothing, which is the honest reading of
   * "the blocks this key signed" when there are none -- not an error. */
  REQUIRE(parse("check if a($x) trusting "
                "ed25519/0000000000000000000000000000000000000000"
                "000000000000000000000000") == BS_OK);
  /* And not the authority either: an annotation replaces the default rather
   * than adding to it, so naming a key that signed nothing trusts nothing
   * beyond the authorizer itself. Keeping the authority here is the
   * difference between a policy that denies and one that grants. */
  CHECK(W.rules[0].trust == BS_ORIGIN_AUTHORIZER);
}

/* A block may open with a trust annotation covering everything in it, and a
 * statement of its own still overrides it. Ignoring the clause would hand
 * those statements the default set instead -- wider, and containing exactly
 * what the block asked to exclude. */
static void test_block_level_trust(void) {
  REQUIRE(reset_world());
  REQUIRE(bs_world_parse(&W, &SYMS, &A,
                         bs_span_make("trusting previous;\n"
                                      "check if a($x);\n"
                                      "check if b($x) trusting authority;",
                                      69U),
                         2U, NULL, NULL) == BS_OK);
  /* Inherited: the authorizer, this block, and every block before it. */
  CHECK(W.rules[W.checks[0].query_at].trust ==
        (BS_ORIGIN_AUTHORIZER | BS_ORIGIN_ONE(0U) | BS_ORIGIN_ONE(1U) |
         BS_ORIGIN_ONE(2U)));
  /* Overridden: the authorizer, this block, and the authority only. */
  CHECK(W.rules[W.checks[1].query_at].trust ==
        (BS_ORIGIN_AUTHORIZER | BS_ORIGIN_ONE(0U) | BS_ORIGIN_ONE(2U)));

  /* Without the clause, the default still includes the authority. */
  REQUIRE(reset_world());
  REQUIRE(bs_world_parse(&W, &SYMS, &A, bs_span_make("check if a($x);", 15U),
                         2U, NULL, NULL) == BS_OK);
  CHECK(W.rules[0].trust ==
        (BS_ORIGIN_AUTHORIZER | BS_ORIGIN_ONE(0U) | BS_ORIGIN_ONE(2U)));

  /* The authorizer is not a block and has no such clause. */
  CHECK(refuses("trusting authority;\ncheck if a($x);"));

  /* The language has no reserved words: `trusting(1)` is a fact, wherever it
   * appears. Matching the clause on the bare identifier would have made a
   * block whose first statement happens to be named `trusting` a syntax
   * error -- and block content is the token's to choose. */
  REQUIRE(reset_world());
  REQUIRE(bs_world_parse(&W, &SYMS, &A, bs_span_make("trusting(1);", 12U), 1U,
                         NULL, NULL) == BS_OK);
  CHECK(W.fact_count == 1U);
  REQUIRE(parse("trusting(1);\nallow if trusting(1);") == BS_OK);
  CHECK(W.fact_count == 1U);
  CHECK(W.policy_count == 1U);
}

static void test_refusals(void) {
  CHECK(refuses("1 < 2 < 3"));             /* comparisons do not chain */
  CHECK(refuses("check if (1 + 2"));       /* an unclosed parenthesis */
  CHECK(refuses("check if 1 + 2)"));       /* a parenthesis closing nothing */
  CHECK(refuses("f($x)"));                 /* a fact may not hold a variable */
  CHECK(refuses("check if \"a\".nope()")); /* an unknown method */
  CHECK(refuses("check if 1.extern::()")); /* an external call with no name */
  CHECK(refuses("check"));                 /* a keyword with nothing after */
  CHECK(refuses("check all"));             /* likewise */
  CHECK(refuses("allow"));                 /* a policy with no condition */
  CHECK(refuses("allow unless true"));     /* the wrong keyword */
  CHECK(refuses("f(1) f(2)"));             /* two statements, no separator */
  CHECK(refuses("check if {1: 2, 3}"));    /* a map key with no value */
  CHECK(refuses("check if 1 +"));          /* an operator with no operand */
  CHECK(refuses("check if .length()"));    /* a call with no receiver */
  CHECK(refuses("f("));                    /* an unterminated predicate */
  CHECK(refuses("check if [1, 2"));        /* an unterminated array */
  CHECK(refuses("check if \"a\".contains()")); /* a call with no argument */
}

/* A bound that only holds for well-behaved input is not a bound. */
static void test_depth_is_bounded(void) {
  char deep[160];
  size_t i;

  for (i = 0; i < 64U; i++) {
    deep[i] = '[';
    deep[64U + i] = ']';
  }
  deep[128] = '\0';
  CHECK(refuses(deep));
}

int main(void) {
  test_precedence();
  test_negation();
  test_methods();
  test_closures();
  test_literals();
  test_containers();
  test_negative_literals_in_arguments();
  test_statements();
  test_alternatives();
  test_rule_body();
  test_body_may_open_with_an_expression();
  test_trust_annotations();
  test_block_level_trust();
  test_refusals();
  test_depth_is_bounded();
  return bs_test_finish();
}
