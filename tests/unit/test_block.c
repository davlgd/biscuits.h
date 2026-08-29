/* Unit tests for the token-wide tables and the block-level printers.
 *
 * The interesting property here is not that a well-formed block prints -- the
 * conformance suite will prove that against real tokens. It is that the symbol
 * indices are token-wide: block 1's first symbol continues block 0's numbering
 * rather than restarting. Getting that wrong renames every predicate in the
 * token silently, which is the kind of bug that ships.
 */

#include <assert.h>
#include <string.h>

#define BS_ASSERT(cond) assert(cond)

#define BISCUITS_IMPLEMENTATION
#include "biscuits.h"

#include "bs_test.h"

#include "pb_build.h"

static char render_buf[2048];
static bs_writer W;
static uint8_t arena_buf[8192];
static bs_arena A;

static void reset(void) {
  memset(render_buf, 0, sizeof render_buf);
  (void)bs_writer_init(&W, render_buf, sizeof render_buf);
}

static int rendered(const char *expect) {
  size_t n = strlen(expect);
  return !bs_writer_overflow(&W) && bs_writer_len(&W) == n &&
         memcmp(render_buf, expect, n) == 0;
}

/* --------------------------------------------------------------------------
 * Builders
 * ----------------------------------------------------------------------- */

static void put_string_field(buf *w, uint32_t field, const char *s) {
  size_t n = 0;
  while (s[n] != '\0') {
    n++;
  }
  put_bytes(w, field, (const uint8_t *)s, n);
}

static void put_term_string(buf *w, uint32_t field, uint64_t symbol) {
  buf t;
  t.n = 0;
  put_tag(&t, BS_F_TERM_STRING, BS_PB_VARINT);
  put_varint(&t, symbol);
  put_bytes(w, field, t.b, t.n);
}

/* A SignedBlock whose payload is the given Block bytes. */
static void put_block(buf *w, uint32_t field, const buf *payload) {
  buf inner;
  size_t i;
  inner.n = 0;
  put_bytes(&inner, BS_F_SIGNED_BLOCK, payload->b, payload->n);
  put_tag(&inner, BS_F_SIGNED_NEXT_KEY, BS_PB_BYTES);
  {
    buf key;
    key.n = 0;
    put_tag(&key, BS_F_PUBKEY_ALGORITHM, BS_PB_VARINT);
    put_varint(&key, 0U);
    put_tag(&key, BS_F_PUBKEY_KEY, BS_PB_BYTES);
    put_varint(&key, 32U);
    for (i = 0; i < 32U; i++) {
      put(&key, (uint8_t)(0x40U + (i & 0x0FU)));
    }
    put_varint(&inner, key.n);
    for (i = 0; i < key.n; i++) {
      put(&inner, key.b[i]);
    }
  }
  put_tag(&inner, BS_F_SIGNED_SIGNATURE, BS_PB_BYTES);
  put_varint(&inner, 64U);
  for (i = 0; i < 64U; i++) {
    put(&inner, (uint8_t)i);
  }
  put_bytes(w, field, inner.b, inner.n);
}

static void put_proof(buf *w) {
  buf inner;
  size_t i;
  inner.n = 0;
  put_tag(&inner, BS_F_PROOF_NEXT_SECRET, BS_PB_BYTES);
  put_varint(&inner, 32U);
  for (i = 0; i < 32U; i++) {
    put(&inner, 0U);
  }
  put_bytes(w, BS_F_BISCUIT_PROOF, inner.b, inner.n);
}

/* --------------------------------------------------------------------------
 * Tables
 * ----------------------------------------------------------------------- */

static void test_symbol_indices_span_the_whole_token(void) {
  buf b0;
  buf b1;
  buf tok;
  bs_token t;
  bs_tables tab;
  bs_span got;

  /* Block 0 contributes two symbols, block 1 contributes two more. The second
   * block's first symbol must be index 1026, not 1024: the numbering is
   * token-wide and continues across blocks. */
  b0.n = 0;
  put_string_field(&b0, BS_F_BLOCK_SYMBOLS, "alpha");
  put_string_field(&b0, BS_F_BLOCK_SYMBOLS, "beta");
  b1.n = 0;
  put_string_field(&b1, BS_F_BLOCK_SYMBOLS, "gamma");
  put_string_field(&b1, BS_F_BLOCK_SYMBOLS, "delta");

  tok.n = 0;
  put_block(&tok, BS_F_BISCUIT_AUTHORITY, &b0);
  put_block(&tok, BS_F_BISCUIT_BLOCKS, &b1);
  put_proof(&tok);

  REQUIRE(bs_arena_init(&A, arena_buf, sizeof arena_buf) == BS_OK);
  REQUIRE(bs_token_parse(&A, span_of(&tok), &t) == BS_OK);
  REQUIRE(bs_tables_build(&A, &t, &tab) == BS_OK);
  CHECK(tab.symbols.count == 4U);

  CHECK(bs_symbol_get(&tab.symbols, 1024U, &got) &&
        bs_span_eq(got, bs_span_make("alpha", 5U)));
  CHECK(bs_symbol_get(&tab.symbols, 1025U, &got) &&
        bs_span_eq(got, bs_span_make("beta", 4U)));
  CHECK(bs_symbol_get(&tab.symbols, 1026U, &got) &&
        bs_span_eq(got, bs_span_make("gamma", 5U)));
  CHECK(bs_symbol_get(&tab.symbols, 1027U, &got) &&
        bs_span_eq(got, bs_span_make("delta", 5U)));
  CHECK(!bs_symbol_get(&tab.symbols, 1028U, &got));

  /* The well-known half is unaffected by anything the token carries. */
  CHECK(bs_symbol_get(&tab.symbols, 0U, &got) &&
        bs_span_eq(got, bs_span_make("read", 4U)));
}

static void test_tables_reject_bad_arguments(void) {
  bs_token t;
  bs_tables tab;

  t.blocks = NULL;
  t.block_count = 0;
  CHECK(bs_arena_init(&A, arena_buf, sizeof arena_buf) == BS_OK);
  CHECK(bs_tables_build(&A, &t, &tab) == BS_ERR_ARGUMENT);
  CHECK(bs_tables_build(NULL, &t, &tab) == BS_ERR_ARGUMENT);
  CHECK(bs_tables_build(&A, NULL, &tab) == BS_ERR_ARGUMENT);
}

/* --------------------------------------------------------------------------
 * Predicates and facts
 * ----------------------------------------------------------------------- */

static bs_tables TAB;
static bs_span TAB_ENTRIES[2];

static void tables_for_tests(void) {
  TAB_ENTRIES[0] = bs_span_make("file1", 5U);
  TAB_ENTRIES[1] = bs_span_make("owner", 5U);
  TAB.symbols.entries = TAB_ENTRIES;
  TAB.symbols.count = 2U;
  TAB.public_keys = NULL;
  TAB.public_key_count = 0U;
}

static void test_predicate_printing(void) {
  /* A well-known predicate name, one token-carried term and one well-known
   * term: the two halves of the symbol table in a single predicate. */
  {
    buf inner;
    inner.n = 0;
    put_tag(&inner, BS_F_PREDICATE_NAME, BS_PB_VARINT);
    put_varint(&inner, 4U);
    put_term_string(&inner, BS_F_PREDICATE_TERMS, 1024U);
    put_term_string(&inner, BS_F_PREDICATE_TERMS, 0U);
    reset();
    CHECK(bs_predicate_print(&W, &TAB, span_of(&inner)) == BS_OK);
    CHECK(rendered("right(\"file1\", \"read\")"));
  }

  /* A predicate with no terms is legal and prints with empty parentheses. */
  {
    buf inner;
    inner.n = 0;
    put_tag(&inner, BS_F_PREDICATE_NAME, BS_PB_VARINT);
    put_varint(&inner, 1025U);
    reset();
    CHECK(bs_predicate_print(&W, &TAB, span_of(&inner)) == BS_OK);
    CHECK(rendered("owner()"));
  }

  /* A name the symbol table cannot resolve is malformed, not blank. */
  {
    buf inner;
    inner.n = 0;
    put_tag(&inner, BS_F_PREDICATE_NAME, BS_PB_VARINT);
    put_varint(&inner, 9999U);
    reset();
    CHECK(bs_predicate_print(&W, &TAB, span_of(&inner)) == BS_ERR_MALFORMED);
  }

  /* A predicate with no name at all. */
  {
    buf inner;
    inner.n = 0;
    put_term_string(&inner, BS_F_PREDICATE_TERMS, 1024U);
    reset();
    CHECK(bs_predicate_print(&W, &TAB, span_of(&inner)) == BS_ERR_MALFORMED);
  }
}

static void test_fact_printing(void) {
  buf pred;
  buf fact;

  pred.n = 0;
  put_tag(&pred, BS_F_PREDICATE_NAME, BS_PB_VARINT);
  put_varint(&pred, 4U);
  put_term_string(&pred, BS_F_PREDICATE_TERMS, 1024U);

  fact.n = 0;
  put_bytes(&fact, BS_F_FACT_PREDICATE, pred.b, pred.n);
  reset();
  CHECK(bs_fact_print(&W, &TAB, span_of(&fact)) == BS_OK);
  CHECK(rendered("right(\"file1\")"));

  /* A Fact wraps exactly one Predicate: none, or two, is malformed. */
  fact.n = 0;
  reset();
  CHECK(bs_fact_print(&W, &TAB, span_of(&fact)) == BS_ERR_MALFORMED);

  fact.n = 0;
  put_bytes(&fact, BS_F_FACT_PREDICATE, pred.b, pred.n);
  put_bytes(&fact, BS_F_FACT_PREDICATE, pred.b, pred.n);
  reset();
  CHECK(bs_fact_print(&W, &TAB, span_of(&fact)) == BS_ERR_MALFORMED);
}

/* --------------------------------------------------------------------------
 * Scopes
 * ----------------------------------------------------------------------- */

static void test_scope_printing(void) {
  bs_public_key keys[1];
  bs_tables tab;
  buf s;
  static const uint8_t raw[4] = {0xACU, 0xDDU, 0x6DU, 0x5BU};

  keys[0].alg = BS_ALG_ED25519;
  keys[0].key = bs_span_make(raw, sizeof raw);
  tab.symbols.entries = NULL;
  tab.symbols.count = 0U;
  tab.public_keys = keys;
  tab.public_key_count = 1U;

  s.n = 0;
  put_tag(&s, BS_F_SCOPE_TYPE, BS_PB_VARINT);
  put_varint(&s, BS_SCOPE_AUTHORITY);
  reset();
  CHECK(bs_scope_print(&W, &tab, span_of(&s)) == BS_OK);
  CHECK(rendered("authority"));

  s.n = 0;
  put_tag(&s, BS_F_SCOPE_TYPE, BS_PB_VARINT);
  put_varint(&s, BS_SCOPE_PREVIOUS);
  reset();
  CHECK(bs_scope_print(&W, &tab, span_of(&s)) == BS_OK);
  CHECK(rendered("previous"));

  s.n = 0;
  put_tag(&s, BS_F_SCOPE_PUBLIC_KEY, BS_PB_VARINT);
  put_varint(&s, 0U);
  reset();
  CHECK(bs_scope_print(&W, &tab, span_of(&s)) == BS_OK);
  CHECK(rendered("ed25519/acdd6d5b"));

  /* A key index past the table. */
  s.n = 0;
  put_tag(&s, BS_F_SCOPE_PUBLIC_KEY, BS_PB_VARINT);
  put_varint(&s, 1U);
  reset();
  CHECK(bs_scope_print(&W, &tab, span_of(&s)) == BS_ERR_MALFORMED);

  /* A negative index, which the wire can express and nothing should accept. */
  s.n = 0;
  put_tag(&s, BS_F_SCOPE_PUBLIC_KEY, BS_PB_VARINT);
  put_varint(&s, (uint64_t)(-1));
  reset();
  CHECK(bs_scope_print(&W, &tab, span_of(&s)) == BS_ERR_MALFORMED);

  /* A scope kind nobody has defined. */
  s.n = 0;
  put_tag(&s, BS_F_SCOPE_TYPE, BS_PB_VARINT);
  put_varint(&s, 7U);
  reset();
  CHECK(bs_scope_print(&W, &tab, span_of(&s)) == BS_ERR_MALFORMED);

  /* Both branches of the oneof, and neither: a scope names a kind or a key. */
  s.n = 0;
  put_tag(&s, BS_F_SCOPE_TYPE, BS_PB_VARINT);
  put_varint(&s, BS_SCOPE_AUTHORITY);
  put_tag(&s, BS_F_SCOPE_PUBLIC_KEY, BS_PB_VARINT);
  put_varint(&s, 0U);
  reset();
  CHECK(bs_scope_print(&W, &tab, span_of(&s)) == BS_ERR_MALFORMED);

  s.n = 0;
  reset();
  CHECK(bs_scope_print(&W, &tab, span_of(&s)) == BS_ERR_MALFORMED);
}

int main(void) {
  tables_for_tests();
  test_symbol_indices_span_the_whole_token();
  test_tables_reject_bad_arguments();
  test_predicate_printing();
  test_fact_printing();
  test_scope_printing();
  return bs_test_finish();
}
