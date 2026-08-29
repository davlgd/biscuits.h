/* Unit tests for expression evaluation.
 *
 * The specification's own samples exercise the operators that appear in real
 * tokens; what they do not exercise is the edges, and the edges are where an
 * authorization decision goes wrong quietly. Overflow that wraps instead of
 * failing, strict equality that returns false instead of erroring, a
 * comparison between a string and a date that answers rather than refusing --
 * each of those turns a check that should have failed into one that passes.
 *
 * Expressions are built directly in the world's pools here rather than
 * encoded and decoded, so a failure points at the evaluator and not at the
 * loader.
 */

#include <assert.h>
#include <string.h>

#define BS_ASSERT(cond) assert(cond)

#define BISCUITS_IMPLEMENTATION
#include "biscuits.h"

#include "bs_test.h"

static uint8_t arena_buf[128 * 1024];
static bs_arena A;
static bs_world W;
static bs_symtab SYMS;
static bs_tables TAB;
static bs_span TAB_ENTRIES[4];

static bs_limits small_limits(void) {
  bs_limits l = bs_limits_default();
  l.max_terms = 256U;
  l.max_ops = 256U;
  l.max_exprs = 32U;
  l.max_preds = 32U;
  l.max_syms = 32U;
  l.max_facts = 32U;
  l.max_rules = 16U;
  l.max_checks = 16U;
  l.max_policies = 8U;
  return l;
}

/* Start a fresh world for one expression. */
static int reset_world(void) {
  bs_limits lim = small_limits();
  TAB_ENTRIES[0] = bs_span_make("alpha", 5U);
  TAB_ENTRIES[1] = bs_span_make("beta", 4U);
  TAB_ENTRIES[2] = bs_span_make("alphabet", 8U);
  TAB.symbols.entries = TAB_ENTRIES;
  TAB.symbols.count = 3U;
  TAB.public_keys = NULL;
  TAB.public_key_count = 0U;
  if (bs_arena_init(&A, arena_buf, sizeof arena_buf) != BS_OK) {
    return 0;
  }
  if (bs_symtab_init(&SYMS, &A, &TAB.symbols, 32U) != BS_OK) {
    return 0;
  }
  return bs_world_init(&W, &A, &TAB, 1U, &lim) == BS_OK;
}

/* --------------------------------------------------------------------------
 * Building expressions straight into the pools
 * ----------------------------------------------------------------------- */

static uint32_t term(bs_term t) {
  uint32_t at = (uint32_t)W.term_count;
  W.terms[W.term_count] = t;
  W.term_count++;
  return at;
}

static bs_term t_int(int64_t v) {
  bs_term t;
  t.kind = (uint8_t)BS_T_INTEGER;
  t.as.integer = v;
  return t;
}

static bs_term t_bool(int v) {
  bs_term t;
  t.kind = (uint8_t)BS_T_BOOL;
  t.as.boolean = v;
  return t;
}

static bs_term t_date(uint64_t v) {
  bs_term t;
  t.kind = (uint8_t)BS_T_DATE;
  t.as.date = v;
  return t;
}

static bs_term t_str(uint64_t sym) {
  bs_term t;
  t.kind = (uint8_t)BS_T_STRING;
  t.as.sym = sym;
  return t;
}

static bs_term t_null(void) {
  bs_term t;
  t.kind = (uint8_t)BS_T_NULL;
  return t;
}

static bs_term t_var(uint64_t sym) {
  bs_term t;
  t.kind = (uint8_t)BS_T_VARIABLE;
  t.as.sym = sym;
  return t;
}

/* A container whose elements are appended first, then wrapped. */
static bs_term t_list(uint8_t kind, const bs_term *items, size_t n) {
  bs_term t;
  uint32_t at = (uint32_t)W.term_count;
  size_t i;
  for (i = 0; i < n; i++) {
    (void)term(items[i]);
  }
  t.kind = kind;
  t.as.list.at = at;
  t.as.list.count = (uint32_t)n;
  return t;
}

static bs_expr EXPR;

static void expr_begin(void) {
  EXPR.at = (uint32_t)W.op_count;
  EXPR.count = 0;
}

static void op_value(bs_term t) {
  W.ops[W.op_count].tag = (uint8_t)BS_OP_VALUE;
  W.ops[W.op_count].kind = 0;
  W.ops[W.op_count].as.term = term(t);
  W.op_count++;
  EXPR.count++;
}

static void op_binary(uint32_t kind) {
  W.ops[W.op_count].tag = (uint8_t)BS_OP_BINARY;
  W.ops[W.op_count].kind = kind;
  W.ops[W.op_count].as.ffi = 0;
  W.op_count++;
  EXPR.count++;
}

static void op_unary(uint32_t kind) {
  W.ops[W.op_count].tag = (uint8_t)BS_OP_UNARY;
  W.ops[W.op_count].kind = kind;
  W.ops[W.op_count].as.ffi = 0;
  W.op_count++;
  EXPR.count++;
}

static bs_status run(int *out) {
  return bs_expr_evaluate(&W, &SYMS, EXPR, NULL, 0U, out);
}

/* `a OP b`, the shape almost every case below takes. */
static bs_status binop(bs_term a, bs_term b, uint32_t kind, int *out) {
  if (!reset_world()) {
    return BS_ERR_NOMEM;
  }
  expr_begin();
  op_value(a);
  op_value(b);
  op_binary(kind);
  return run(out);
}

static int yields(bs_term a, bs_term b, uint32_t kind, int expect) {
  int got = -1;
  return binop(a, b, kind, &got) == BS_OK && got == expect;
}

static int fails(bs_term a, bs_term b, uint32_t kind, bs_status expect) {
  int got = -1;
  return binop(a, b, kind, &got) == expect;
}

/* --------------------------------------------------------------------------
 * Comparison
 * ----------------------------------------------------------------------- */

static void test_comparison(void) {
  CHECK(yields(t_int(1), t_int(2), 0U, 1)); /* 1 < 2 */
  CHECK(yields(t_int(2), t_int(1), 0U, 0));
  CHECK(yields(t_int(2), t_int(1), 1U, 1)); /* 2 > 1 */
  CHECK(yields(t_int(1), t_int(1), 2U, 1)); /* 1 <= 1 */
  CHECK(yields(t_int(1), t_int(1), 3U, 1)); /* 1 >= 1 */
  CHECK(yields(t_int(1), t_int(2), 3U, 0));

  CHECK(yields(t_date(100U), t_date(200U), 0U, 1));
  CHECK(yields(t_date(200U), t_date(100U), 1U, 1));

  /* Comparison is defined on integers and dates, and on nothing else. A
   * string against a date has no answer, and answering `false` would hide a
   * mistake in the token rather than report it. */
  CHECK(fails(t_str(1024U), t_str(1025U), 0U, BS_ERR_TYPE));
  CHECK(fails(t_bool(1), t_bool(0), 0U, BS_ERR_TYPE));
  CHECK(fails(t_int(1), t_date(1U), 0U, BS_ERR_TYPE));
  CHECK(fails(t_null(), t_null(), 0U, BS_ERR_TYPE));
}

/* --------------------------------------------------------------------------
 * Equality
 * ----------------------------------------------------------------------- */

static void test_equality(void) {
  /* Strict: same type, compared. */
  CHECK(yields(t_int(3), t_int(3), 4U, 1));
  CHECK(yields(t_int(3), t_int(4), 4U, 0));
  CHECK(yields(t_int(3), t_int(4), 20U, 1)); /* !== */
  CHECK(yields(t_str(1024U), t_str(1024U), 4U, 1));
  CHECK(yields(t_null(), t_null(), 4U, 1)); /* null equals itself */

  /* Strict across types is an error, not false. Getting this wrong turns a
   * check that should have failed loudly into one that quietly returns
   * false. */
  CHECK(fails(t_int(1), t_str(1024U), 4U, BS_ERR_TYPE));
  CHECK(fails(t_int(1), t_bool(1), 4U, BS_ERR_TYPE));
  CHECK(fails(t_int(1), t_null(), 20U, BS_ERR_TYPE));

  /* Lenient across types is simply false, and never an error. */
  CHECK(yields(t_int(1), t_str(1024U), 21U, 0));
  CHECK(yields(t_int(1), t_str(1024U), 22U, 1));
  CHECK(yields(t_int(1), t_null(), 21U, 0));
  CHECK(yields(t_int(3), t_int(3), 21U, 1));
  CHECK(yields(t_null(), t_null(), 21U, 1));
}

/* --------------------------------------------------------------------------
 * Arithmetic
 * ----------------------------------------------------------------------- */

static void test_arithmetic(void) {
  int got = 0;

  CHECK(reset_world());
  expr_begin();
  op_value(t_int(2));
  op_value(t_int(3));
  op_binary(9U); /* + */
  op_value(t_int(5));
  op_binary(4U); /* === */
  CHECK(run(&got) == BS_OK && got == 1);

  CHECK(reset_world());
  expr_begin();
  op_value(t_int(7));
  op_value(t_int(2));
  op_binary(12U); /* / truncates toward zero */
  op_value(t_int(3));
  op_binary(4U);
  CHECK(run(&got) == BS_OK && got == 1);

  /* "Integer operations must have overflow checks. If it overflows, the
   * expression fails." Not wraps -- fails. A token that could compute its way
   * past INT64_MAX and back down would satisfy bounds it must not. */
  CHECK(fails(t_int(INT64_MAX), t_int(1), 9U, BS_ERR_OVERFLOW));
  CHECK(fails(t_int(INT64_MIN), t_int(1), 10U, BS_ERR_OVERFLOW));
  CHECK(fails(t_int(INT64_MAX), t_int(2), 11U, BS_ERR_OVERFLOW));
  CHECK(fails(t_int(INT64_MIN), t_int(-1), 11U, BS_ERR_OVERFLOW));

  /* Division by zero, and the one division whose result has no
   * representation. */
  CHECK(fails(t_int(1), t_int(0), 12U, BS_ERR_OVERFLOW));
  CHECK(fails(t_int(INT64_MIN), t_int(-1), 12U, BS_ERR_OVERFLOW));

  /* Arithmetic on anything but integers. */
  CHECK(fails(t_bool(1), t_int(1), 10U, BS_ERR_TYPE));
  CHECK(fails(t_date(1U), t_date(1U), 11U, BS_ERR_TYPE));
}

static void test_bitwise_and_boolean(void) {
  int got = 0;

  CHECK(reset_world());
  expr_begin();
  op_value(t_int(6));
  op_value(t_int(3));
  op_binary(17U); /* & */
  op_value(t_int(2));
  op_binary(4U);
  CHECK(run(&got) == BS_OK && got == 1);

  CHECK(reset_world());
  expr_begin();
  op_value(t_int(6));
  op_value(t_int(3));
  op_binary(19U); /* ^ */
  op_value(t_int(5));
  op_binary(4U);
  CHECK(run(&got) == BS_OK && got == 1);

  CHECK(yields(t_bool(1), t_bool(0), 13U, 0)); /* eager && */
  CHECK(yields(t_bool(1), t_bool(1), 13U, 1));
  CHECK(yields(t_bool(1), t_bool(0), 14U, 1)); /* eager || */
  CHECK(yields(t_bool(0), t_bool(0), 14U, 0));
  CHECK(fails(t_int(1), t_bool(1), 13U, BS_ERR_TYPE));
  CHECK(fails(t_bool(1), t_int(1), 17U, BS_ERR_TYPE));
}

/* --------------------------------------------------------------------------
 * Unary
 * ----------------------------------------------------------------------- */

static void test_unary(void) {
  int got = 0;

  CHECK(reset_world());
  expr_begin();
  op_value(t_bool(0));
  op_unary(BS_U_NEGATE);
  CHECK(run(&got) == BS_OK && got == 1);

  CHECK(reset_world());
  expr_begin();
  op_value(t_int(1));
  op_unary(BS_U_NEGATE);
  CHECK(run(&got) == BS_ERR_TYPE);

  /* Parens exist so the printer can reproduce the source; they change
   * nothing at run time. */
  CHECK(reset_world());
  expr_begin();
  op_value(t_bool(1));
  op_unary(BS_U_PARENS);
  CHECK(run(&got) == BS_OK && got == 1);

  /* Length counts UTF-8 bytes for a string, not characters -- the
   * specification chose bytes because grapheme clusters would give different
   * answers in different languages. */
  CHECK(reset_world());
  expr_begin();
  op_value(t_str(1024U)); /* "alpha" */
  op_unary(BS_U_LENGTH);
  op_value(t_int(5));
  op_binary(4U);
  CHECK(run(&got) == BS_OK && got == 1);

  CHECK(reset_world());
  expr_begin();
  {
    bs_term items[3];
    items[0] = t_int(1);
    items[1] = t_int(2);
    items[2] = t_int(3);
    op_value(t_list((uint8_t)BS_T_ARRAY, items, 3U));
  }
  op_unary(BS_U_LENGTH);
  op_value(t_int(3));
  op_binary(4U);
  CHECK(run(&got) == BS_OK && got == 1);

  CHECK(reset_world());
  expr_begin();
  op_value(t_int(1));
  op_unary(BS_U_LENGTH);
  CHECK(run(&got) == BS_ERR_TYPE);
}

static void test_typeof(void) {
  int got = 0;

  /* `1.type() == "integer"` */
  CHECK(reset_world());
  expr_begin();
  op_value(t_int(1));
  op_unary(BS_U_TYPEOF);
  {
    uint64_t sym = 0;
    CHECK(bs_symtab_intern(&SYMS, bs_span_make("integer", 7U), &sym) == BS_OK);
    op_value(t_str(sym));
  }
  op_binary(21U); /* == */
  CHECK(run(&got) == BS_OK && got == 1);

  /* `null.type() == "null"` */
  CHECK(reset_world());
  expr_begin();
  op_value(t_null());
  op_unary(BS_U_TYPEOF);
  {
    uint64_t sym = 0;
    CHECK(bs_symtab_intern(&SYMS, bs_span_make("null", 4U), &sym) == BS_OK);
    op_value(t_str(sym));
  }
  op_binary(21U);
  CHECK(run(&got) == BS_OK && got == 1);
}

/* --------------------------------------------------------------------------
 * Containers
 * ----------------------------------------------------------------------- */

static void test_contains_and_get(void) {
  int got = 0;
  bs_term items[3];

  /* A set contains one of its elements. */
  CHECK(reset_world());
  expr_begin();
  items[0] = t_int(1);
  items[1] = t_int(2);
  op_value(t_list((uint8_t)BS_T_SET, items, 2U));
  op_value(t_int(2));
  op_binary(5U);
  CHECK(run(&got) == BS_OK && got == 1);

  CHECK(reset_world());
  expr_begin();
  items[0] = t_int(1);
  items[1] = t_int(2);
  op_value(t_list((uint8_t)BS_T_SET, items, 2U));
  op_value(t_int(9));
  op_binary(5U);
  CHECK(run(&got) == BS_OK && got == 0);

  /* Between two sets, whether the first is a superset of the second. */
  CHECK(reset_world());
  expr_begin();
  items[0] = t_int(1);
  items[1] = t_int(2);
  items[2] = t_int(3);
  op_value(t_list((uint8_t)BS_T_SET, items, 3U));
  items[0] = t_int(3);
  items[1] = t_int(1);
  op_value(t_list((uint8_t)BS_T_SET, items, 2U));
  op_binary(5U);
  CHECK(run(&got) == BS_OK && got == 1);

  /* A substring test between two strings. */
  CHECK(reset_world());
  expr_begin();
  op_value(t_str(1026U)); /* "alphabet" */
  op_value(t_str(1024U)); /* "alpha" */
  op_binary(5U);
  CHECK(run(&got) == BS_OK && got == 1);

  CHECK(reset_world());
  expr_begin();
  op_value(t_str(1024U)); /* "alpha" does not contain "alphabet" */
  op_value(t_str(1026U));
  op_binary(5U);
  CHECK(run(&got) == BS_OK && got == 0);

  /* `.get()` out of range is null rather than an error, which is what makes
   * it usable without a length check in front of it. */
  CHECK(reset_world());
  expr_begin();
  items[0] = t_int(7);
  items[1] = t_int(8);
  op_value(t_list((uint8_t)BS_T_ARRAY, items, 2U));
  op_value(t_int(5));
  op_binary(27U);
  op_value(t_null());
  op_binary(21U);
  CHECK(run(&got) == BS_OK && got == 1);

  CHECK(reset_world());
  expr_begin();
  items[0] = t_int(7);
  items[1] = t_int(8);
  op_value(t_list((uint8_t)BS_T_ARRAY, items, 2U));
  op_value(t_int(1));
  op_binary(27U);
  op_value(t_int(8));
  op_binary(4U);
  CHECK(run(&got) == BS_OK && got == 1);
}

/* --------------------------------------------------------------------------
 * Bindings and stack discipline
 * ----------------------------------------------------------------------- */

static void test_bindings(void) {
  bs_binding bind[1];
  int got = 0;

  CHECK(reset_world());
  expr_begin();
  op_value(t_var(1024U));
  op_value(t_int(41));
  op_binary(9U);
  op_value(t_int(42));
  op_binary(4U);

  bind[0].sym = 1024U;
  bind[0].value = t_int(1);
  CHECK(bs_expr_evaluate(&W, &SYMS, EXPR, bind, 1U, &got) == BS_OK && got == 1);

  /* An unbound variable. The specification requires every variable in an
   * expression to appear in a predicate of the same rule, so reaching this
   * means the rule should have been rejected earlier. */
  CHECK(bs_expr_evaluate(&W, &SYMS, EXPR, NULL, 0U, &got) == BS_ERR_TYPE);
}

static void test_stack_discipline(void) {
  int got = 0;

  /* An operator with nothing to consume. */
  CHECK(reset_world());
  expr_begin();
  op_binary(9U);
  CHECK(run(&got) == BS_ERR_MALFORMED);

  CHECK(reset_world());
  expr_begin();
  op_value(t_int(1));
  op_binary(9U);
  CHECK(run(&got) == BS_ERR_MALFORMED);

  /* Two values and no operator: more than one result. */
  CHECK(reset_world());
  expr_begin();
  op_value(t_int(1));
  op_value(t_int(2));
  CHECK(run(&got) == BS_ERR_MALFORMED);

  /* An empty expression. */
  CHECK(reset_world());
  expr_begin();
  CHECK(run(&got) == BS_ERR_MALFORMED);

  /* "After executing, the stack must contain only one value, of the boolean
   * type." An expression that leaves an integer is not false; it is wrong. */
  CHECK(reset_world());
  expr_begin();
  op_value(t_int(1));
  CHECK(run(&got) == BS_ERR_TYPE);

  /* A single boolean is a complete expression. */
  CHECK(reset_world());
  expr_begin();
  op_value(t_bool(1));
  CHECK(run(&got) == BS_OK && got == 1);

  CHECK(bs_expr_evaluate(NULL, &SYMS, EXPR, NULL, 0U, &got) == BS_ERR_ARGUMENT);
  CHECK(bs_expr_evaluate(&W, &SYMS, EXPR, NULL, 0U, NULL) == BS_ERR_ARGUMENT);
}

/* --------------------------------------------------------------------------
 * Closures
 * ----------------------------------------------------------------------- */

/* A closure op whose body is the ops appended since `body_at`. */
static void op_closure(uint32_t body_at, uint32_t body_count, uint64_t param,
                       int has_param) {
  uint32_t sym_at = (uint32_t)W.sym_count;
  if (has_param) {
    W.syms[W.sym_count] = param;
    W.sym_count++;
  }
  W.ops[W.op_count].tag = (uint8_t)BS_OP_CLOSURE;
  W.ops[W.op_count].kind = 0;
  W.ops[W.op_count].as.closure.at = sym_at;
  W.ops[W.op_count].as.closure.count = has_param ? 1U : 0U;
  W.ops[W.op_count].as.closure.body.at = body_at;
  W.ops[W.op_count].as.closure.body.count = body_count;
  W.ops[W.op_count].as.closure.src = bs_span_make(NULL, 0U);
  W.op_count++;
  EXPR.count++;
}

/* Build a closure body out of line, then return where it sits. */
static uint32_t body_begin(void) {
  return (uint32_t)W.op_count;
}

static void body_value(bs_term t) {
  W.ops[W.op_count].tag = (uint8_t)BS_OP_VALUE;
  W.ops[W.op_count].kind = 0;
  W.ops[W.op_count].as.term = term(t);
  W.op_count++;
}

static void body_binary(uint32_t kind) {
  W.ops[W.op_count].tag = (uint8_t)BS_OP_BINARY;
  W.ops[W.op_count].kind = kind;
  W.ops[W.op_count].as.ffi = 0;
  W.op_count++;
}

static void test_short_circuit(void) {
  int got = 0;
  uint32_t at;

  /* `false && <closure>`: the closure must not run. Its body is an expression
   * that would fail loudly if it did -- a strict comparison across types --
   * so a passing result proves the skip rather than merely suggesting it. */
  CHECK(reset_world());
  at = body_begin();
  body_value(t_int(1));
  body_value(t_bool(1));
  body_binary(4U); /* === across types: a type error if evaluated */
  expr_begin();
  op_value(t_bool(0));
  op_closure(at, 3U, 0U, 0);
  op_binary(23U); /* && */
  CHECK(run(&got) == BS_OK && got == 0);

  /* `true || <closure>`: likewise skipped. */
  CHECK(reset_world());
  at = body_begin();
  body_value(t_int(1));
  body_value(t_bool(1));
  body_binary(4U);
  expr_begin();
  op_value(t_bool(1));
  op_closure(at, 3U, 0U, 0);
  op_binary(24U); /* || */
  CHECK(run(&got) == BS_OK && got == 1);

  /* `true && <closure>`: the closure does run, and its value is the answer. */
  CHECK(reset_world());
  at = body_begin();
  body_value(t_bool(0));
  expr_begin();
  op_value(t_bool(1));
  op_closure(at, 1U, 0U, 0);
  op_binary(23U);
  CHECK(run(&got) == BS_OK && got == 0);

  /* And when it does run, its errors are the expression's errors. */
  CHECK(reset_world());
  at = body_begin();
  body_value(t_int(1));
  body_value(t_bool(1));
  body_binary(4U);
  expr_begin();
  op_value(t_bool(1));
  op_closure(at, 3U, 0U, 0);
  op_binary(23U);
  CHECK(run(&got) == BS_ERR_TYPE);
}

static void test_all_and_any(void) {
  int got = 0;
  uint32_t at;
  bs_term items[3];

  /* `[1, 2, 3].all($p -> $p > 0)` */
  CHECK(reset_world());
  at = body_begin();
  body_value(t_var(2000U));
  body_value(t_int(0));
  body_binary(1U); /* > */
  expr_begin();
  items[0] = t_int(1);
  items[1] = t_int(2);
  items[2] = t_int(3);
  op_value(t_list((uint8_t)BS_T_ARRAY, items, 3U));
  op_closure(at, 3U, 2000U, 1);
  op_binary(25U);
  CHECK(run(&got) == BS_OK && got == 1);

  /* `.all()` is false as soon as one element fails, and must stop there. */
  CHECK(reset_world());
  at = body_begin();
  body_value(t_var(2000U));
  body_value(t_int(2));
  body_binary(4U); /* === 2 */
  expr_begin();
  items[0] = t_int(1);
  items[1] = t_int(2);
  items[2] = t_int(3);
  op_value(t_list((uint8_t)BS_T_ARRAY, items, 3U));
  op_closure(at, 3U, 2000U, 1);
  op_binary(25U);
  CHECK(run(&got) == BS_OK && got == 0);

  /* `.any()` is true as soon as one element passes. */
  CHECK(reset_world());
  at = body_begin();
  body_value(t_var(2000U));
  body_value(t_int(2));
  body_binary(1U); /* > 2 */
  expr_begin();
  items[0] = t_int(1);
  items[1] = t_int(2);
  items[2] = t_int(3);
  op_value(t_list((uint8_t)BS_T_ARRAY, items, 3U));
  op_closure(at, 3U, 2000U, 1);
  op_binary(26U);
  CHECK(run(&got) == BS_OK && got == 1);

  /* An empty container: vacuously true for all, vacuously false for any. */
  CHECK(reset_world());
  at = body_begin();
  body_value(t_bool(0));
  expr_begin();
  op_value(t_list((uint8_t)BS_T_ARRAY, items, 0U));
  op_closure(at, 1U, 2000U, 1);
  op_binary(25U);
  CHECK(run(&got) == BS_OK && got == 1);

  CHECK(reset_world());
  at = body_begin();
  body_value(t_bool(1));
  expr_begin();
  op_value(t_list((uint8_t)BS_T_ARRAY, items, 0U));
  op_closure(at, 1U, 2000U, 1);
  op_binary(26U);
  CHECK(run(&got) == BS_OK && got == 0);
}

static void test_shadowing_is_rejected(void) {
  bs_binding bind[1];
  int got = 0;
  uint32_t at;
  bs_term items[1];

  /* "Shadowing (defining a parameter with the same name as a variable already
   * in scope) is not allowed and should be rejected." */
  CHECK(reset_world());
  at = body_begin();
  body_value(t_bool(1));
  expr_begin();
  items[0] = t_int(1);
  op_value(t_list((uint8_t)BS_T_ARRAY, items, 1U));
  op_closure(at, 1U, 3000U, 1);
  op_binary(25U);

  bind[0].sym = 3000U; /* the same name the closure parameter uses */
  bind[0].value = t_int(9);
  CHECK(bs_expr_evaluate(&W, &SYMS, EXPR, bind, 1U, &got) == BS_ERR_SHADOWED);
}

static void test_try_or(void) {
  int got = 0;
  uint32_t at;

  /* `(true === 12).try_or(true)`: the closure fails with a type error, and
   * try_or turns that failure into the fallback rather than propagating it.
   * This is the one place in the language where an error becomes a value. */
  CHECK(reset_world());
  at = body_begin();
  body_value(t_bool(1));
  body_value(t_int(12));
  body_binary(4U); /* === across types */
  expr_begin();
  op_closure(at, 3U, 0U, 0);
  op_value(t_bool(1));
  op_binary(29U);
  CHECK(run(&got) == BS_OK && got == 1);

  /* When the closure succeeds, its own value wins and the fallback is
   * ignored -- `true == 12` is lenient, so it is false rather than an error,
   * and false is the answer. */
  CHECK(reset_world());
  at = body_begin();
  body_value(t_bool(1));
  body_value(t_int(12));
  body_binary(21U); /* == across types: false, not an error */
  expr_begin();
  op_closure(at, 3U, 0U, 0);
  op_value(t_bool(1));
  op_binary(29U);
  CHECK(run(&got) == BS_OK && got == 0);

  /* An overflow inside the closure is caught the same way. */
  CHECK(reset_world());
  at = body_begin();
  body_value(t_int(INT64_MAX));
  body_value(t_int(1));
  body_binary(9U); /* + overflows */
  body_value(t_int(0));
  body_binary(4U);
  expr_begin();
  op_closure(at, 5U, 0U, 0);
  op_value(t_bool(1));
  op_binary(29U);
  CHECK(run(&got) == BS_OK && got == 1);
}

int main(void) {
  test_comparison();
  test_equality();
  test_arithmetic();
  test_bitwise_and_boolean();
  test_unary();
  test_typeof();
  test_contains_and_get();
  test_bindings();
  test_stack_discipline();
  test_short_circuit();
  test_all_and_any();
  test_shadowing_is_rejected();
  test_try_or();
  return bs_test_finish();
}
