/* Unit tests for the output writer and the term printer.
 *
 * The conformance suite will exercise these against real tokens once whole
 * blocks can be rendered. Until then -- and afterwards, because the suite
 * contains no hostile terms -- this is where the edge cases live: INT64_MIN,
 * leap days, nesting at the depth limit, and terms that encode two readings
 * of themselves.
 */

#include <assert.h>
#include <stdio.h>
#include <string.h>

#define BS_ASSERT(cond) assert(cond)

#define BISCUITS_IMPLEMENTATION
#include "biscuits.h"

#include "bs_test.h"

#include "pb_build.h"

/* --------------------------------------------------------------------------
 * Helpers
 * ----------------------------------------------------------------------- */

static char render_buf[4096];
static bs_writer W;

static void reset(void) {
  memset(render_buf, 0, sizeof render_buf);
  (void)bs_writer_init(&W, render_buf, sizeof render_buf);
}

/* Compare the writer's contents with an expected string. */
static int rendered(const char *expect) {
  size_t n = strlen(expect);
  return !bs_writer_overflow(&W) && bs_writer_len(&W) == n &&
         memcmp(render_buf, expect, n) == 0;
}

/* --------------------------------------------------------------------------
 * Writer
 * ----------------------------------------------------------------------- */

static void test_writer_overflow_is_sticky(void) {
  char small[4];
  bs_writer w;

  CHECK(bs_writer_init(&w, small, sizeof small) == BS_OK);
  BS_PUT_LIT(&w, "abcd");
  CHECK(!bs_writer_overflow(&w) && bs_writer_len(&w) == 4U); /* exact fit */

  BS_PUT_LIT(&w, "e");
  CHECK(bs_writer_overflow(&w));
  CHECK(bs_writer_len(&w) == 4U); /* nothing was written past the end */

  /* Once full, it stays full: a later append that would fit is still a
   * no-op, so a caller checking only at the end cannot be handed a buffer
   * with a hole in the middle. */
  bs_put_byte(&w, (uint8_t)'x');
  CHECK(bs_writer_len(&w) == 4U);

  /* A zero-capacity writer measures demand without writing anything. */
  CHECK(bs_writer_init(&w, NULL, 0U) == BS_OK);
  BS_PUT_LIT(&w, "anything");
  CHECK(bs_writer_overflow(&w) && bs_writer_len(&w) == 0U);

  CHECK(bs_writer_init(&w, NULL, 4U) == BS_ERR_ARGUMENT);
  CHECK(bs_writer_init(NULL, small, sizeof small) == BS_ERR_ARGUMENT);
  CHECK(bs_writer_overflow(NULL));
  CHECK(bs_writer_len(NULL) == 0U);
}

static void test_writer_integers(void) {
  reset();
  bs_put_i64(&W, 0);
  CHECK(rendered("0"));

  reset();
  bs_put_i64(&W, 42);
  CHECK(rendered("42"));

  reset();
  bs_put_i64(&W, -42);
  CHECK(rendered("-42"));

  reset();
  bs_put_i64(&W, INT64_MAX);
  CHECK(rendered("9223372036854775807"));

  /* INT64_MIN has no positive counterpart, so a printer that negates first
   * has undefined behaviour here. The digits are accumulated on the negative
   * side of zero precisely to make this case ordinary. */
  reset();
  bs_put_i64(&W, INT64_MIN);
  CHECK(rendered("-9223372036854775808"));
}

static void test_writer_dates(void) {
  reset();
  bs_put_date(&W, 0U);
  CHECK(rendered("1970-01-01T00:00:00Z"));

  /* Taken from the specification's own expression sample. */
  reset();
  bs_put_date(&W, 1575452801U);
  CHECK(rendered("2019-12-04T09:46:41Z"));

  /* A leap day in a century year divisible by 400. */
  reset();
  bs_put_date(&W, 951782400U);
  CHECK(rendered("2000-02-29T00:00:00Z"));

  /* An ordinary leap day, at the last second. */
  reset();
  bs_put_date(&W, 1709251199U);
  CHECK(rendered("2024-02-29T23:59:59Z"));

  /* Well past 2038, because a 32-bit time_t is not involved anywhere here. */
  reset();
  bs_put_date(&W, 4133894400U);
  CHECK(rendered("2100-12-31T00:00:00Z"));
}

static void test_writer_strings_and_hex(void) {
  static const uint8_t bytes[3] = {0x00U, 0xABU, 0xFFU};

  reset();
  bs_put_string(&W, bs_span_make("hi", 2U));
  CHECK(rendered("\"hi\""));

  /* Verbatim, with no escaping: the reference implementation does the same,
   * and test021_parsing of the official suite carries a literal tab inside a
   * string and expects that byte back. Escaping would fail the round trip. */
  reset();
  bs_put_string(&W, bs_span_make("a\tb", 3U));
  CHECK(rendered("\"a\tb\""));

  /* And the hazard that comes with it, recorded rather than hidden: a string
   * containing a quote renders as source that cannot be parsed back. That is
   * a property of the specification's text format, not of this printer. */
  reset();
  bs_put_string(&W, bs_span_make("a\"b", 3U));
  CHECK(rendered("\"a\"b\""));

  /* UTF-8 passes through byte for byte: the samples print multi-byte
   * characters verbatim and re-encoding them would break the round trip. */
  reset();
  bs_put_string(&W, bs_span_make("\xc3\xa9", 2U));
  CHECK(rendered("\"\xc3\xa9\""));

  reset();
  bs_put_hex(&W, bs_span_make(bytes, sizeof bytes));
  CHECK(rendered("00abff"));

  reset();
  bs_put_hex(&W, bs_span_make(NULL, 0U));
  CHECK(rendered(""));
}

/* --------------------------------------------------------------------------
 * Symbols
 * ----------------------------------------------------------------------- */

static void test_symbols(void) {
  bs_span entries[2];
  bs_symbols sym;
  bs_span got;

  entries[0] = bs_span_make("file1", 5U);
  entries[1] = bs_span_make("file2", 5U);
  sym.entries = entries;
  sym.count = 2U;

  /* The well-known half. */
  CHECK(bs_symbol_get(&sym, 0U, &got) &&
        bs_span_eq(got, bs_span_make("read", 4U)));
  CHECK(bs_symbol_get(&sym, 27U, &got) &&
        bs_span_eq(got, bs_span_make("query", 5U)));
  CHECK(bs_symbol_default_count() == 28U);

  /* Reserved but not defined by this build: refused rather than guessed, so a
   * token cannot read differently here than elsewhere. */
  CHECK(!bs_symbol_get(&sym, 28U, &got));
  CHECK(!bs_symbol_get(&sym, 1023U, &got));

  /* The token-provided half starts at the offset. */
  CHECK(bs_symbol_get(&sym, 1024U, &got) &&
        bs_span_eq(got, bs_span_make("file1", 5U)));
  CHECK(bs_symbol_get(&sym, 1025U, &got) &&
        bs_span_eq(got, bs_span_make("file2", 5U)));
  CHECK(!bs_symbol_get(&sym, 1026U, &got));
  CHECK(!bs_symbol_get(&sym, 0xFFFFFFFFFFFFFFFFU, &got));

  CHECK(!bs_symbol_get(NULL, 1024U, &got));
  CHECK(!bs_symbol_get(&sym, 0U, NULL));
}

/* --------------------------------------------------------------------------
 * Terms
 * ----------------------------------------------------------------------- */

static bs_span sym_entries[3];
static bs_symbols SYM;

static void symbols_for_tests(void) {
  sym_entries[0] = bs_span_make("alpha", 5U);
  sym_entries[1] = bs_span_make("beta", 4U);
  sym_entries[2] = bs_span_make("p", 1U);
  SYM.entries = sym_entries;
  SYM.count = 3U;
}

static void term_varint(buf *w, uint32_t field, uint64_t v) {
  put_tag(w, field, BS_PB_VARINT);
  put_varint(w, v);
}

static int print_term(const buf *w, const char *expect) {
  reset();
  if (bs_term_print(&W, &SYM, span_of(w)) != BS_OK) {
    return 0;
  }
  return rendered(expect);
}

static void test_term_scalars(void) {
  buf t;

  t.n = 0;
  term_varint(&t, BS_F_TERM_VARIABLE, 1026U);
  CHECK(print_term(&t, "$p"));

  t.n = 0;
  term_varint(&t, BS_F_TERM_INTEGER, (uint64_t)(-7));
  CHECK(print_term(&t, "-7"));

  t.n = 0;
  term_varint(&t, BS_F_TERM_STRING, 1024U);
  CHECK(print_term(&t, "\"alpha\""));

  t.n = 0;
  term_varint(&t, BS_F_TERM_DATE, 1575452801U);
  CHECK(print_term(&t, "2019-12-04T09:46:41Z"));

  t.n = 0;
  term_varint(&t, BS_F_TERM_BOOL, 1U);
  CHECK(print_term(&t, "true"));

  t.n = 0;
  term_varint(&t, BS_F_TERM_BOOL, 0U);
  CHECK(print_term(&t, "false"));

  t.n = 0;
  put_bytes(&t, BS_F_TERM_NULL, NULL, 0U);
  CHECK(print_term(&t, "null"));

  {
    static const uint8_t raw[2] = {0x12U, 0xABU};
    t.n = 0;
    put_bytes(&t, BS_F_TERM_BYTES, raw, sizeof raw);
    CHECK(print_term(&t, "hex:12ab"));
  }
}

static void test_term_rejects_ambiguity(void) {
  buf t;

  /* A Term is a oneof. Two readings of the same value would let a token mean
   * one thing here and another elsewhere. */
  t.n = 0;
  term_varint(&t, BS_F_TERM_INTEGER, 1U);
  term_varint(&t, BS_F_TERM_BOOL, 1U);
  reset();
  CHECK(bs_term_print(&W, &SYM, span_of(&t)) == BS_ERR_MALFORMED);

  /* No recognised field at all. */
  t.n = 0;
  term_varint(&t, 900U, 1U);
  reset();
  CHECK(bs_term_print(&W, &SYM, span_of(&t)) == BS_ERR_MALFORMED);

  /* A bool that is neither true nor false. */
  t.n = 0;
  term_varint(&t, BS_F_TERM_BOOL, 2U);
  reset();
  CHECK(bs_term_print(&W, &SYM, span_of(&t)) == BS_ERR_MALFORMED);

  /* A symbol index nothing defines. */
  t.n = 0;
  term_varint(&t, BS_F_TERM_STRING, 9999U);
  reset();
  CHECK(bs_term_print(&W, &SYM, span_of(&t)) == BS_ERR_MALFORMED);

  /* Right field number, wrong wire type. */
  t.n = 0;
  put_bytes(&t, BS_F_TERM_INTEGER, NULL, 0U);
  reset();
  CHECK(bs_term_print(&W, &SYM, span_of(&t)) == BS_ERR_MALFORMED);
}

/* Wrap the encoded term `inner` in a container of the given field number. */
static void wrap(buf *out_buf, uint32_t container_field, const buf *items) {
  buf list;
  size_t i;
  list.n = 0;
  for (i = 0; i < items->n; i++) {
    put(&list, items->b[i]);
  }
  out_buf->n = 0;
  put_bytes(out_buf, container_field, list.b, list.n);
}

/* Append one encoded term as repeated field 1 of a container body. */
static void add_item(buf *list, const buf *term) {
  put_bytes(list, 1U, term->b, term->n);
}

static void test_term_containers(void) {
  buf item;
  buf list;
  buf t;

  /* A set: braces, no colons. */
  list.n = 0;
  item.n = 0;
  term_varint(&item, BS_F_TERM_STRING, 1024U);
  add_item(&list, &item);
  item.n = 0;
  term_varint(&item, BS_F_TERM_STRING, 1025U);
  add_item(&list, &item);
  wrap(&t, BS_F_TERM_SET, &list);
  CHECK(print_term(&t, "{\"alpha\", \"beta\"}"));

  /* An array: brackets. */
  wrap(&t, BS_F_TERM_ARRAY, &list);
  CHECK(print_term(&t, "[\"alpha\", \"beta\"]"));

  /* Empty containers. A set prints as `{,}` rather than `{}`: the brace is
   * shared with maps and the colon is what separates them, so an empty set
   * and an empty map would otherwise be the same text. The specification's
   * own sample checks `{,}.length() === 0`. */
  list.n = 0;
  wrap(&t, BS_F_TERM_ARRAY, &list);
  CHECK(print_term(&t, "[]"));

  wrap(&t, BS_F_TERM_SET, &list);
  CHECK(print_term(&t, "{,}"));

  wrap(&t, BS_F_TERM_MAP, &list);
  CHECK(print_term(&t, "{}"));
}

static void test_term_maps(void) {
  buf key;
  buf value;
  buf entry;
  buf list;
  buf t;

  list.n = 0;

  /* {"alpha": 1, 2: "beta"} -- both key kinds in one map. */
  key.n = 0;
  term_varint(&key, BS_F_MAPKEY_STRING, 1024U);
  value.n = 0;
  term_varint(&value, BS_F_TERM_INTEGER, 1U);
  entry.n = 0;
  put_bytes(&entry, BS_F_MAPENTRY_KEY, key.b, key.n);
  put_bytes(&entry, BS_F_MAPENTRY_VALUE, value.b, value.n);
  add_item(&list, &entry);

  key.n = 0;
  term_varint(&key, BS_F_MAPKEY_INTEGER, 2U);
  value.n = 0;
  term_varint(&value, BS_F_TERM_STRING, 1025U);
  entry.n = 0;
  put_bytes(&entry, BS_F_MAPENTRY_KEY, key.b, key.n);
  put_bytes(&entry, BS_F_MAPENTRY_VALUE, value.b, value.n);
  add_item(&list, &entry);

  wrap(&t, BS_F_TERM_MAP, &list);
  CHECK(print_term(&t, "{\"alpha\": 1, 2: \"beta\"}"));

  /* An entry missing its value is malformed: both fields are required. */
  list.n = 0;
  entry.n = 0;
  key.n = 0;
  term_varint(&key, BS_F_MAPKEY_INTEGER, 1U);
  put_bytes(&entry, BS_F_MAPENTRY_KEY, key.b, key.n);
  add_item(&list, &entry);
  wrap(&t, BS_F_TERM_MAP, &list);
  reset();
  CHECK(bs_term_print(&W, &SYM, span_of(&t)) == BS_ERR_MALFORMED);
}

static void test_term_nesting_is_bounded(void) {
  buf inner;
  buf list;
  buf outer;
  int i;

  /* [[[...]]] built up one level at a time. At BS_MAX_DEPTH containers the
   * printer must report BS_ERR_DEPTH -- an ordinary error return, not a
   * smashed stack. That is the whole point of not recursing. */
  inner.n = 0;
  list.n = 0;
  wrap(&inner, BS_F_TERM_ARRAY, &list);

  for (i = 1; i < BS_MAX_DEPTH; i++) {
    list.n = 0;
    add_item(&list, &inner);
    wrap(&outer, BS_F_TERM_ARRAY, &list);
    inner = outer;
    reset();
    CHECK(bs_term_print(&W, &SYM, span_of(&inner)) == BS_OK);
  }

  /* One level too far. */
  list.n = 0;
  add_item(&list, &inner);
  wrap(&outer, BS_F_TERM_ARRAY, &list);
  reset();
  CHECK(bs_term_print(&W, &SYM, span_of(&outer)) == BS_ERR_DEPTH);
}

static void test_term_output_can_overflow(void) {
  char tiny[2];
  bs_writer w;
  buf t;

  t.n = 0;
  term_varint(&t, BS_F_TERM_STRING, 1024U);
  CHECK(bs_writer_init(&w, tiny, sizeof tiny) == BS_OK);
  /* The rendering does not fit. The writer reports it; nothing is written
   * past the end of the buffer. */
  (void)bs_term_print(&w, &SYM, span_of(&t));
  CHECK(bs_writer_overflow(&w));
  CHECK(bs_writer_len(&w) <= sizeof tiny);
}

/* --------------------------------------------------------------------------
 * Expressions
 * ----------------------------------------------------------------------- */

static uint8_t expr_arena_buf[16384];
static bs_arena EXPR_A;
static bs_tables EXPR_TAB;

static void put_op_value_int(buf *w, int64_t v) {
  buf term;
  buf op;
  term.n = 0;
  put_tag(&term, BS_F_TERM_INTEGER, BS_PB_VARINT);
  put_varint(&term, (uint64_t)v);
  op.n = 0;
  put_bytes(&op, BS_F_OP_VALUE, term.b, term.n);
  put_bytes(w, BS_F_EXPR_OPS, op.b, op.n);
}

static void put_op_kind(buf *w, uint32_t branch, uint32_t kind, uint64_t ffi,
                        int has_ffi) {
  buf inner;
  buf op;
  inner.n = 0;
  put_tag(&inner, BS_F_OPKIND, BS_PB_VARINT);
  put_varint(&inner, kind);
  if (has_ffi) {
    put_tag(&inner, BS_F_OPFFI, BS_PB_VARINT);
    put_varint(&inner, ffi);
  }
  op.n = 0;
  put_bytes(&op, branch, inner.b, inner.n);
  put_bytes(w, BS_F_EXPR_OPS, op.b, op.n);
}

static int expr_renders(const buf *e, const char *expect) {
  reset();
  if (bs_arena_init(&EXPR_A, expr_arena_buf, sizeof expr_arena_buf) != BS_OK) {
    return 0;
  }
  if (bs_expr_print(&W, &EXPR_A, &EXPR_TAB, span_of(e)) != BS_OK) {
    return 0;
  }
  return rendered(expect);
}

/* Every binary opcode the specification defines, with its rendered form.
 *
 * The conformance samples exercise about half of these; the eager `And` and
 * `Or` appear in none of the 38, and printing them the same way as their
 * short-circuiting counterparts was a real divergence the suite could not
 * catch. Pinning all thirty here is what closes that gap. */
static void test_every_binary_opcode(void) {
  static const struct {
    uint32_t kind;
    const char *expect;
  } CASES[] = {
      {0U, "1 < 2"},
      {1U, "1 > 2"},
      {2U, "1 <= 2"},
      {3U, "1 >= 2"},
      {4U, "1 === 2"},
      {5U, "1.contains(2)"},
      {6U, "1.starts_with(2)"},
      {7U, "1.ends_with(2)"},
      {8U, "1.matches(2)"},
      {9U, "1 + 2"},
      {10U, "1 - 2"},
      {11U, "1 * 2"},
      {12U, "1 / 2"},
      {13U, "1 &&! 2"}, /* eager */
      {14U, "1 ||! 2"}, /* eager */
      {15U, "1.intersection(2)"},
      {16U, "1.union(2)"},
      {17U, "1 & 2"},
      {18U, "1 | 2"},
      {19U, "1 ^ 2"},
      {20U, "1 !== 2"},
      {21U, "1 == 2"},
      {22U, "1 != 2"},
      {23U, "1 && 2"}, /* short-circuiting */
      {24U, "1 || 2"}, /* short-circuiting */
      {25U, "1.all(2)"},
      {26U, "1.any(2)"},
      {27U, "1.get(2)"},
      {29U, "1.try_or(2)"},
  };
  size_t i;

  for (i = 0; i < sizeof CASES / sizeof CASES[0]; i++) {
    buf e;
    e.n = 0;
    put_op_value_int(&e, 1);
    put_op_value_int(&e, 2);
    put_op_kind(&e, BS_F_OP_BINARY, CASES[i].kind, 0U, 0);
    if (!expr_renders(&e, CASES[i].expect)) {
      (void)printf("# binary opcode %u rendered as %.*s, wanted %s\n",
                   (unsigned int)CASES[i].kind, (int)bs_writer_len(&W),
                   render_buf, CASES[i].expect);
    }
    CHECK(expr_renders(&e, CASES[i].expect));
  }

  /* The external call carries its name in the symbol table. */
  {
    buf e;
    e.n = 0;
    put_op_value_int(&e, 1);
    put_op_value_int(&e, 2);
    put_op_kind(&e, BS_F_OP_BINARY, 28U, 1024U, 1);
    CHECK(expr_renders(&e, "1.extern::alpha(2)"));
  }

  /* An opcode nobody has defined is malformed, not blank. */
  {
    buf e;
    e.n = 0;
    put_op_value_int(&e, 1);
    put_op_value_int(&e, 2);
    put_op_kind(&e, BS_F_OP_BINARY, 99U, 0U, 0);
    CHECK(!expr_renders(&e, ""));
  }
}

static void test_every_unary_opcode(void) {
  static const struct {
    uint32_t kind;
    const char *expect;
  } CASES[] = {
      {0U, "!1"},
      {1U, "(1)"},
      {2U, "1.length()"},
      {3U, "1.type()"},
  };
  size_t i;

  for (i = 0; i < sizeof CASES / sizeof CASES[0]; i++) {
    buf e;
    e.n = 0;
    put_op_value_int(&e, 1);
    put_op_kind(&e, BS_F_OP_UNARY, CASES[i].kind, 0U, 0);
    CHECK(expr_renders(&e, CASES[i].expect));
  }

  {
    buf e;
    e.n = 0;
    put_op_value_int(&e, 1);
    put_op_kind(&e, BS_F_OP_UNARY, 4U, 1024U, 1);
    CHECK(expr_renders(&e, "1.extern::alpha()"));
  }
}

static void test_expression_stack_discipline(void) {
  buf e;

  /* A binary operator with only one operand underflows the stack. */
  e.n = 0;
  put_op_value_int(&e, 1);
  put_op_kind(&e, BS_F_OP_BINARY, 0U, 0U, 0);
  CHECK(!expr_renders(&e, ""));

  /* Two values and no operator leaves two results where one is required. */
  e.n = 0;
  put_op_value_int(&e, 1);
  put_op_value_int(&e, 2);
  CHECK(!expr_renders(&e, ""));

  /* An empty expression produces nothing to print. */
  e.n = 0;
  CHECK(!expr_renders(&e, ""));

  /* A single value is a complete expression. */
  e.n = 0;
  put_op_value_int(&e, 42);
  CHECK(expr_renders(&e, "42"));
}

int main(void) {
  symbols_for_tests();
  EXPR_TAB.symbols = SYM;
  EXPR_TAB.public_keys = NULL;
  EXPR_TAB.public_key_count = 0U;
  test_writer_overflow_is_sticky();
  test_writer_integers();
  test_writer_dates();
  test_writer_strings_and_hex();
  test_symbols();
  test_term_scalars();
  test_term_rejects_ambiguity();
  test_term_containers();
  test_term_maps();
  test_term_nesting_is_bounded();
  test_term_output_can_overflow();
  test_every_binary_opcode();
  test_every_unary_opcode();
  test_expression_stack_discipline();
  return bs_test_finish();
}
