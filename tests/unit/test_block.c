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

/* A printer that runs out of room says so.
 *
 * Reporting BS_OK with truncated output hands the caller a shorter string
 * that still reads as Datalog: `right("fil` is not an error, it is a
 * different fact. The writer's overflow flag is sticky, so every public
 * printer checks it before returning. */
static void test_truncation_is_reported(void) {
  static const size_t SIZES[] = {0U, 1U, 5U, 9U, 13U};
  buf pred;
  buf fact;
  size_t i;

  pred.n = 0;
  put_tag(&pred, BS_F_PREDICATE_NAME, BS_PB_VARINT);
  put_varint(&pred, 4U);
  put_term_string(&pred, BS_F_PREDICATE_TERMS, 1024U);
  fact.n = 0;
  put_bytes(&fact, BS_F_FACT_PREDICATE, pred.b, pred.n);

  for (i = 0; i < sizeof SIZES / sizeof SIZES[0]; i++) {
    bs_writer w;
    char small[16];
    REQUIRE(bs_writer_init(&w, small, SIZES[i]) == BS_OK);
    CHECK(bs_fact_print(&w, &TAB, span_of(&fact)) == BS_ERR_NOMEM);
    REQUIRE(bs_writer_init(&w, small, SIZES[i]) == BS_OK);
    CHECK(bs_predicate_print(&w, &TAB, span_of(&pred)) == BS_ERR_NOMEM);
  }

  /* `right("file1")` is fourteen bytes; a buffer of exactly that fits. */
  {
    bs_writer w;
    char exact[14];
    REQUIRE(bs_writer_init(&w, exact, sizeof exact) == BS_OK);
    CHECK(bs_fact_print(&w, &TAB, span_of(&fact)) == BS_OK);
    CHECK(bs_writer_len(&w) == sizeof exact);
  }
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

/* --------------------------------------------------------------------------
 * The world
 * ----------------------------------------------------------------------- */

static void test_world_reserves_everything_up_front(void) {
  static uint8_t big[512 * 1024];
  bs_arena a;
  bs_world w;
  bs_limits lim = bs_limits_default();

  /* The point of reserving every pool at init is that an arena which survives
   * this call cannot run out later: there is no growth step anywhere in the
   * evaluator to fail at an awkward moment. */
  REQUIRE(bs_arena_init(&a, big, sizeof big) == BS_OK);
  REQUIRE(bs_world_init(&w, &a, &TAB, 2U, &lim) == BS_OK);
  CHECK(w.term_cap == lim.max_terms);
  CHECK(w.fact_cap == lim.max_facts);
  CHECK(w.term_count == 0U && w.fact_count == 0U && w.rule_count == 0U);
  CHECK(w.tables == &TAB);
  CHECK(w.block_count == 2U);

  /* An arena too small reports exhaustion here, where the caller can still do
   * something about it, rather than midway through evaluating a token. */
  {
    uint8_t small[1024];
    bs_arena tiny;
    REQUIRE(bs_arena_init(&tiny, small, sizeof small) == BS_OK);
    CHECK(bs_world_init(&w, &tiny, &TAB, 1U, &lim) == BS_ERR_NOMEM);
  }

  /* Smaller limits fit in a smaller arena: the caller decides what to spend. */
  {
    uint8_t modest[16 * 1024];
    bs_arena m;
    bs_limits small = bs_limits_default();
    small.max_terms = 64U;
    small.max_ops = 64U;
    small.max_exprs = 16U;
    small.max_preds = 32U;
    small.max_syms = 16U;
    small.max_facts = 32U;
    small.max_rules = 8U;
    small.max_checks = 8U;
    small.max_policies = 4U;
    REQUIRE(bs_arena_init(&m, modest, sizeof modest) == BS_OK);
    CHECK(bs_world_init(&w, &m, &TAB, 1U, &small) == BS_OK);
    CHECK(w.term_cap == 64U);
  }

  /* More blocks than a bs_origin bitset can name. */
  REQUIRE(bs_arena_init(&a, big, sizeof big) == BS_OK);
  CHECK(bs_world_init(&w, &a, &TAB, (size_t)BS_MAX_BLOCKS + 1U, &lim) ==
        BS_ERR_LIMIT);

  CHECK(bs_world_init(NULL, &a, &TAB, 1U, &lim) == BS_ERR_ARGUMENT);
  CHECK(bs_world_init(&w, NULL, &TAB, 1U, &lim) == BS_ERR_ARGUMENT);
  CHECK(bs_world_init(&w, &a, NULL, 1U, &lim) == BS_ERR_ARGUMENT);
}

static void test_origin_bitset(void) {
  /* The origin of a fact is the set of blocks that allowed it to exist, and
   * `trusting` filters on it. A bitset because the block ceiling is 64, which
   * makes the union a single OR -- the operation the fixpoint loop performs
   * more than any other. */
  CHECK(BS_ORIGIN_ONE(0U) == 1U);
  CHECK(BS_ORIGIN_ONE(1U) == 2U);
  CHECK((BS_ORIGIN_ONE(0U) | BS_ORIGIN_ONE(3U)) == 9U);
  CHECK(BS_ORIGIN_NONE == 0U);
  /* The authorizer is not a block, and gets the top bit so that it stays
   * expressible in a trust mask like any other source. */
  CHECK(BS_ORIGIN_AUTHORIZER == BS_ORIGIN_ONE(63U));
  CHECK((BS_ORIGIN_AUTHORIZER & BS_ORIGIN_ONE(0U)) == 0U);
}

/* --------------------------------------------------------------------------
 * Interning
 * ----------------------------------------------------------------------- */

/* One scratch buffer for the interning tests: they run in sequence and each
 * re-initialises the arena, so three separate ones bought nothing. */
static uint8_t symtab_buf[8192];

static void test_symtab_preserves_token_indices(void) {
  bs_arena a;
  bs_symtab t;
  bs_span got;
  uint64_t idx = 0;

  /* Seeded from the token's own table, so an index that arrived on the wire
   * still names the same text afterwards. Renumbering here would silently
   * rename every predicate in the token. */
  REQUIRE(bs_arena_init(&a, symtab_buf, sizeof symtab_buf) == BS_OK);
  REQUIRE(bs_symtab_init(&t, &a, &TAB.symbols, 8U) == BS_OK);
  CHECK(t.count == 2U);
  CHECK(bs_symtab_get(&t, 1024U, &got) &&
        bs_span_eq(got, bs_span_make("file1", 5U)));
  CHECK(bs_symtab_get(&t, 1025U, &got) &&
        bs_span_eq(got, bs_span_make("owner", 5U)));

  /* A symbol already present keeps its index. */
  CHECK(bs_symtab_intern(&t, bs_span_make("file1", 5U), &idx) == BS_OK);
  CHECK(idx == 1024U);
  CHECK(t.count == 2U);

  /* A well-known symbol resolves to its shared index, never to a fresh one --
   * otherwise a token that spells out "read" would state a different fact
   * from one that used the well-known index. */
  CHECK(bs_symtab_intern(&t, bs_span_make("read", 4U), &idx) == BS_OK);
  CHECK(idx == 0U);
  CHECK(t.count == 2U);

  /* A token symbol that happens to duplicate a well-known one resolves to the
   * shared index, not to the token's copy. TAB carries "owner" at 1025 and
   * "owner" is also well-known symbol 7; interning it gives 7. That is the
   * point of interning -- two blocks writing owner("alice") state one fact,
   * whichever spelling each used. */
  CHECK(bs_symtab_intern(&t, bs_span_make("owner", 5U), &idx) == BS_OK);
  CHECK(idx == 7U);

  /* A genuinely new symbol is appended past everything the token carried. */
  CHECK(bs_symtab_intern(&t, bs_span_make("gamma", 5U), &idx) == BS_OK);
  CHECK(idx == 1026U);
  CHECK(t.count == 3U);
  CHECK(bs_symtab_intern(&t, bs_span_make("gamma", 5U), &idx) == BS_OK);
  CHECK(idx == 1026U && t.count == 3U);
}

static void test_symtab_translates_block_local_indices(void) {
  bs_span third_party[2];
  bs_symbols theirs;
  bs_arena a;
  bs_symtab t;
  uint64_t idx = 0;

  /* A third-party block numbers from its own array: its index 1024 is its
   * first symbol, which has nothing to do with the token's 1024. */
  third_party[0] = bs_span_make("gamma", 5U);
  third_party[1] = bs_span_make("file1", 5U);
  theirs.entries = third_party;
  theirs.count = 2U;

  REQUIRE(bs_arena_init(&a, symtab_buf, sizeof symtab_buf) == BS_OK);
  REQUIRE(bs_symtab_init(&t, &a, &TAB.symbols, 8U) == BS_OK);

  /* Their 1024 is "gamma", which the token did not carry: a new index. */
  CHECK(bs_symtab_translate(&t, &theirs, 1024U, &idx) == BS_OK);
  CHECK(idx == 1026U);

  /* Their 1025 is "file1", which the token did carry at 1024. Translation
   * must land on that one, or the same fact stated by two blocks would count
   * as two different facts. */
  CHECK(bs_symtab_translate(&t, &theirs, 1025U, &idx) == BS_OK);
  CHECK(idx == 1024U);

  /* Translating through the token's own table leaves an ordinary symbol
   * alone. */
  CHECK(bs_symtab_translate(&t, &TAB.symbols, 1024U, &idx) == BS_OK);
  CHECK(idx == 1024U);
  CHECK(bs_symtab_translate(&t, &TAB.symbols, 3U, &idx) == BS_OK);
  CHECK(idx == 3U);

  /* It does *not* leave alone a token symbol that duplicates a well-known
   * one: TAB's 1025 is "owner", and interning that lands on well-known 7.
   * Translation is therefore not the identity in general, which is why it is
   * applied to every index rather than only to third-party ones. */
  CHECK(bs_symtab_translate(&t, &TAB.symbols, 1025U, &idx) == BS_OK);
  CHECK(idx == 7U);

  /* An index the source cannot name is refused, not passed through. */
  CHECK(bs_symtab_translate(&t, &theirs, 1026U, &idx) == BS_ERR_MALFORMED);
  CHECK(bs_symtab_translate(&t, &theirs, 900U, &idx) == BS_ERR_MALFORMED);
}

static void test_symtab_exhaustion(void) {
  bs_arena a;
  bs_symtab t;
  uint64_t idx = 0;

  /* Room for the seed and one more. The second new symbol has nowhere to go,
   * and says so rather than overwriting. */
  REQUIRE(bs_arena_init(&a, symtab_buf, sizeof symtab_buf) == BS_OK);
  REQUIRE(bs_symtab_init(&t, &a, &TAB.symbols, 1U) == BS_OK);
  CHECK(bs_symtab_intern(&t, bs_span_make("one", 3U), &idx) == BS_OK);
  CHECK(bs_symtab_intern(&t, bs_span_make("two", 3U), &idx) == BS_ERR_NOMEM);
  /* Interning something already present still works when full. */
  CHECK(bs_symtab_intern(&t, bs_span_make("one", 3U), &idx) == BS_OK);

  CHECK(bs_symtab_init(NULL, &a, &TAB.symbols, 1U) == BS_ERR_ARGUMENT);
  CHECK(bs_symtab_init(&t, NULL, &TAB.symbols, 1U) == BS_ERR_ARGUMENT);
  CHECK(!bs_symtab_get(NULL, 0U, NULL));
}

/* --------------------------------------------------------------------------
 * Loading facts
 * ----------------------------------------------------------------------- */

static uint8_t load_buf[64 * 1024];

/* A Block message carrying one fact `name(term...)`. */
static void put_fact_block(buf *w, uint64_t name, const buf *terms) {
  buf pred;
  buf fact;
  size_t i;
  pred.n = 0;
  put_tag(&pred, BS_F_PREDICATE_NAME, BS_PB_VARINT);
  put_varint(&pred, name);
  for (i = 0; i < terms->n; i++) {
    put(&pred, terms->b[i]);
  }
  fact.n = 0;
  put_bytes(&fact, BS_F_FACT_PREDICATE, pred.b, pred.n);
  w->n = 0;
  put_bytes(w, BS_F_BLOCK_FACTS, fact.b, fact.n);
}

/* An encoded container nested `depth` levels deep, as a Term. */
static void put_nested_array(buf *out, unsigned int depth) {
  buf inner;
  buf outer;
  unsigned int d;
  inner.n = 0;
  put_bytes(&inner, BS_F_TERM_ARRAY, NULL, 0U);
  for (d = 1; d < depth; d++) {
    buf list;
    list.n = 0;
    put_bytes(&list, 1U, inner.b, inner.n);
    outer.n = 0;
    put_bytes(&outer, BS_F_TERM_ARRAY, list.b, list.n);
    inner = outer;
  }
  *out = inner;
}

/* Modest pools: these tests exercise the loader, not the default sizing, and
 * the defaults reserve enough opcode slots to want a third of a megabyte. */
static bs_limits modest_limits(void) {
  bs_limits l = bs_limits_default();
  l.max_terms = 256U;
  l.max_ops = 256U;
  l.max_exprs = 32U;
  l.max_preds = 64U;
  l.max_syms = 32U;
  l.max_facts = 64U;
  l.max_rules = 16U;
  l.max_checks = 16U;
  l.max_policies = 8U;
  return l;
}

static bs_status load_one(const buf *block, bs_world *w, bs_symtab *syms) {
  static bs_arena a;
  bs_limits lim = modest_limits();
  bs_status st;
  st = bs_arena_init(&a, load_buf, sizeof load_buf);
  if (st != BS_OK) {
    return st;
  }
  st = bs_symtab_init(syms, &a, &TAB.symbols, 64U);
  if (st != BS_OK) {
    return st;
  }
  st = bs_world_init(w, &a, &TAB, 1U, &lim);
  if (st != BS_OK) {
    return st;
  }
  return bs_world_load_facts(w, syms, &TAB.symbols, span_of(block), 0U);
}

static void test_load_facts_and_origins(void) {
  bs_world w;
  bs_symtab syms;
  buf terms;
  buf block;

  /* right("file1") -- name 4 is well-known, 1024 is the token's "file1". */
  terms.n = 0;
  put_term_string(&terms, BS_F_PREDICATE_TERMS, 1024U);
  put_fact_block(&block, 4U, &terms);

  REQUIRE(load_one(&block, &w, &syms) == BS_OK);
  REQUIRE(w.fact_count == 1U);
  CHECK(w.facts[0].pred.name == 4U);
  CHECK(w.facts[0].pred.count == 1U);
  CHECK(w.terms[w.facts[0].pred.at].kind == BS_T_STRING);
  CHECK(w.terms[w.facts[0].pred.at].as.sym == 1024U);
  /* A fact stated in block 0 has origin {0}, which is what `trusting`
   * filters on and what a rule will union into whatever it derives. */
  CHECK(w.facts[0].origin == BS_ORIGIN_ONE(0U));
}

static void test_load_rejects_deep_nesting(void) {
  bs_world w;
  bs_symtab syms;
  buf terms;
  buf block;
  buf nested;

  /* At the limit: accepted. */
  put_nested_array(&nested, (unsigned int)BS_MAX_DEPTH);
  terms.n = 0;
  put_bytes(&terms, BS_F_PREDICATE_TERMS, nested.b, nested.n);
  put_fact_block(&block, 4U, &terms);
  CHECK(load_one(&block, &w, &syms) == BS_OK);

  /* One level further: a clean BS_ERR_DEPTH. The whole point of expanding
   * breadth-first in the pool rather than recursing is that this is an
   * ordinary error return and not a smashed stack. */
  put_nested_array(&nested, (unsigned int)BS_MAX_DEPTH + 1U);
  terms.n = 0;
  put_bytes(&terms, BS_F_PREDICATE_TERMS, nested.b, nested.n);
  put_fact_block(&block, 4U, &terms);
  CHECK(load_one(&block, &w, &syms) == BS_ERR_DEPTH);
}

static void test_load_rejects_malformed_facts(void) {
  bs_world w;
  bs_symtab syms;
  buf block;
  buf fact;
  buf pred;

  /* A fact with no predicate. */
  fact.n = 0;
  block.n = 0;
  put_bytes(&block, BS_F_BLOCK_FACTS, fact.b, fact.n);
  CHECK(load_one(&block, &w, &syms) == BS_ERR_MALFORMED);

  /* A predicate with no name. */
  pred.n = 0;
  put_term_string(&pred, BS_F_PREDICATE_TERMS, 1024U);
  fact.n = 0;
  put_bytes(&fact, BS_F_FACT_PREDICATE, pred.b, pred.n);
  block.n = 0;
  put_bytes(&block, BS_F_BLOCK_FACTS, fact.b, fact.n);
  CHECK(load_one(&block, &w, &syms) == BS_ERR_MALFORMED);

  /* A name the symbol table cannot resolve. */
  pred.n = 0;
  put_tag(&pred, BS_F_PREDICATE_NAME, BS_PB_VARINT);
  put_varint(&pred, 9999U);
  fact.n = 0;
  put_bytes(&fact, BS_F_FACT_PREDICATE, pred.b, pred.n);
  block.n = 0;
  put_bytes(&block, BS_F_BLOCK_FACTS, fact.b, fact.n);
  CHECK(load_one(&block, &w, &syms) == BS_ERR_MALFORMED);
}

static void test_load_reports_pool_exhaustion(void) {
  static bs_arena a;
  bs_world w;
  bs_symtab syms;
  bs_limits lim = modest_limits();
  buf terms;
  buf block;

  terms.n = 0;
  put_term_string(&terms, BS_F_PREDICATE_TERMS, 1024U);
  put_fact_block(&block, 4U, &terms);

  /* No room for a single fact: reported, not overwritten. */
  lim.max_facts = 0U;
  REQUIRE(bs_arena_init(&a, load_buf, sizeof load_buf) == BS_OK);
  REQUIRE(bs_symtab_init(&syms, &a, &TAB.symbols, 8U) == BS_OK);
  REQUIRE(bs_world_init(&w, &a, &TAB, 1U, &lim) == BS_OK);
  CHECK(bs_world_load_facts(&w, &syms, &TAB.symbols, span_of(&block), 0U) ==
        BS_ERR_NOMEM);

  /* Room for the fact but not for its terms. */
  lim = modest_limits();
  lim.max_terms = 0U;
  REQUIRE(bs_arena_init(&a, load_buf, sizeof load_buf) == BS_OK);
  REQUIRE(bs_symtab_init(&syms, &a, &TAB.symbols, 8U) == BS_OK);
  REQUIRE(bs_world_init(&w, &a, &TAB, 1U, &lim) == BS_OK);
  CHECK(bs_world_load_facts(&w, &syms, &TAB.symbols, span_of(&block), 0U) ==
        BS_ERR_NOMEM);

  CHECK(bs_world_load_facts(NULL, &syms, &TAB.symbols, span_of(&block), 0U) ==
        BS_ERR_ARGUMENT);
  CHECK(bs_world_load_facts(&w, &syms, &TAB.symbols, span_of(&block),
                            (size_t)BS_MAX_BLOCKS) == BS_ERR_LIMIT);
}

/* --------------------------------------------------------------------------
 * Scopes
 * ----------------------------------------------------------------------- */

/* A Block message carrying one rule with the given scope annotations. */
static void put_rule_block(buf *w, const buf *scopes) {
  buf head;
  buf rule;
  size_t i;
  head.n = 0;
  put_tag(&head, BS_F_PREDICATE_NAME, BS_PB_VARINT);
  put_varint(&head, 27U); /* the well-known "query" */
  rule.n = 0;
  put_bytes(&rule, BS_F_RULE_HEAD, head.b, head.n);
  for (i = 0; i < scopes->n; i++) {
    put(&rule, scopes->b[i]);
  }
  w->n = 0;
  put_bytes(w, BS_F_BLOCK_RULES, rule.b, rule.n);
}

static void put_scope_kind(buf *w, uint64_t kind) {
  buf s;
  s.n = 0;
  put_tag(&s, BS_F_SCOPE_TYPE, BS_PB_VARINT);
  put_varint(&s, kind);
  put_bytes(w, BS_F_RULE_SCOPE, s.b, s.n);
}

static bs_status trust_of(const buf *block, size_t block_index,
                          const bs_token *tok, const bs_tables *tab,
                          bs_origin *out) {
  /* All locals: a static bs_world would outlive the caller's tables and hold
   * a dangling pointer to them. Only the arena's storage is static, and that
   * is a plain byte buffer with no references into anything. */
  bs_arena a;
  bs_world w;
  bs_symtab syms;
  bs_limits lim = modest_limits();
  bs_status st;

  st = bs_arena_init(&a, load_buf, sizeof load_buf);
  if (st != BS_OK) {
    return st;
  }
  st = bs_symtab_init(&syms, &a, &tab->symbols, 32U);
  if (st != BS_OK) {
    return st;
  }
  st = bs_world_init(&w, &a, tab, tok->block_count, &lim);
  if (st != BS_OK) {
    return st;
  }
  st = bs_world_load_logic(&w, &syms, &tab->symbols, tok, tab, span_of(block),
                           block_index);
  if (st != BS_OK) {
    return st;
  }
  if (w.rule_count != 1U) {
    return BS_ERR_MALFORMED;
  }
  *out = w.rules[0].trust;
  return BS_OK;
}

static void test_scope_resolution(void) {
  bs_token tok;
  bs_signed_block blocks[4];
  bs_tables tab;
  buf scopes;
  buf block;
  bs_origin trust = 0;

  /* Four blocks, two of which carry the same external key. */
  memset(blocks, 0, sizeof blocks);
  blocks[2].has_external = 1;
  blocks[2].external_key.alg = BS_ALG_ED25519;
  blocks[2].external_key.key = bs_span_make("KEYA", 4U);
  blocks[3].has_external = 1;
  blocks[3].external_key.alg = BS_ALG_ED25519;
  blocks[3].external_key.key = bs_span_make("KEYA", 4U);
  tok.blocks = blocks;
  tok.block_count = 4U;

  {
    static bs_public_key keys[2];
    keys[0].alg = BS_ALG_ED25519;
    keys[0].key = bs_span_make("KEYA", 4U);
    keys[1].alg = BS_ALG_ED25519;
    keys[1].key = bs_span_make("KEYB", 4U);
    tab.symbols = TAB.symbols;
    tab.public_keys = keys;
    tab.public_key_count = 2U;
  }

  /* No annotation: the authorizer, the current block and the authority. */
  scopes.n = 0;
  put_rule_block(&block, &scopes);
  REQUIRE(trust_of(&block, 1U, &tok, &tab, &trust) == BS_OK);
  CHECK(trust ==
        (BS_ORIGIN_AUTHORIZER | BS_ORIGIN_ONE(0U) | BS_ORIGIN_ONE(1U)));

  /* `authority` says the same thing explicitly. */
  scopes.n = 0;
  put_scope_kind(&scopes, BS_SCOPE_AUTHORITY);
  put_rule_block(&block, &scopes);
  REQUIRE(trust_of(&block, 1U, &tok, &tab, &trust) == BS_OK);
  CHECK(trust ==
        (BS_ORIGIN_AUTHORIZER | BS_ORIGIN_ONE(0U) | BS_ORIGIN_ONE(1U)));

  /* `previous` adds every block up to and including this one. */
  scopes.n = 0;
  put_scope_kind(&scopes, BS_SCOPE_PREVIOUS);
  put_rule_block(&block, &scopes);
  REQUIRE(trust_of(&block, 2U, &tok, &tab, &trust) == BS_OK);
  CHECK(trust == (BS_ORIGIN_AUTHORIZER | BS_ORIGIN_ONE(0U) | BS_ORIGIN_ONE(1U) |
                  BS_ORIGIN_ONE(2U)));

  /* A public key names every block carrying an external signature by it --
   * here blocks 2 and 3 -- plus the always-trusted pair. Note the authority
   * is *not* included: an explicit annotation replaces the default. */
  scopes.n = 0;
  {
    buf s;
    s.n = 0;
    put_tag(&s, BS_F_SCOPE_PUBLIC_KEY, BS_PB_VARINT);
    put_varint(&s, 0U);
    put_bytes(&scopes, BS_F_RULE_SCOPE, s.b, s.n);
  }
  put_rule_block(&block, &scopes);
  REQUIRE(trust_of(&block, 1U, &tok, &tab, &trust) == BS_OK);
  CHECK(trust == (BS_ORIGIN_AUTHORIZER | BS_ORIGIN_ONE(1U) | BS_ORIGIN_ONE(2U) |
                  BS_ORIGIN_ONE(3U)));

  /* A key nobody signed with trusts nothing extra, which is the honest
   * reading of "the blocks verified by this key" when there are none. */
  scopes.n = 0;
  {
    buf s;
    s.n = 0;
    put_tag(&s, BS_F_SCOPE_PUBLIC_KEY, BS_PB_VARINT);
    put_varint(&s, 1U);
    put_bytes(&scopes, BS_F_RULE_SCOPE, s.b, s.n);
  }
  put_rule_block(&block, &scopes);
  REQUIRE(trust_of(&block, 1U, &tok, &tab, &trust) == BS_OK);
  CHECK(trust == (BS_ORIGIN_AUTHORIZER | BS_ORIGIN_ONE(1U)));

  /* Several annotations are added, not intersected. */
  scopes.n = 0;
  put_scope_kind(&scopes, BS_SCOPE_AUTHORITY);
  {
    buf s;
    s.n = 0;
    put_tag(&s, BS_F_SCOPE_PUBLIC_KEY, BS_PB_VARINT);
    put_varint(&s, 0U);
    put_bytes(&scopes, BS_F_RULE_SCOPE, s.b, s.n);
  }
  put_rule_block(&block, &scopes);
  REQUIRE(trust_of(&block, 1U, &tok, &tab, &trust) == BS_OK);
  CHECK(trust == (BS_ORIGIN_AUTHORIZER | BS_ORIGIN_ONE(0U) | BS_ORIGIN_ONE(1U) |
                  BS_ORIGIN_ONE(2U) | BS_ORIGIN_ONE(3U)));

  /* A scope kind nobody has defined, and a key index past the table. */
  scopes.n = 0;
  put_scope_kind(&scopes, 7U);
  put_rule_block(&block, &scopes);
  CHECK(trust_of(&block, 1U, &tok, &tab, &trust) == BS_ERR_MALFORMED);

  scopes.n = 0;
  {
    buf s;
    s.n = 0;
    put_tag(&s, BS_F_SCOPE_PUBLIC_KEY, BS_PB_VARINT);
    put_varint(&s, 9U);
    put_bytes(&scopes, BS_F_RULE_SCOPE, s.b, s.n);
  }
  put_rule_block(&block, &scopes);
  CHECK(trust_of(&block, 1U, &tok, &tab, &trust) == BS_ERR_MALFORMED);
}

int main(void) {
  tables_for_tests();
  test_symbol_indices_span_the_whole_token();
  test_tables_reject_bad_arguments();
  test_predicate_printing();
  test_fact_printing();
  test_truncation_is_reported();
  test_scope_printing();
  test_world_reserves_everything_up_front();
  test_origin_bitset();
  test_symtab_preserves_token_indices();
  test_symtab_translates_block_local_indices();
  test_symtab_exhaustion();
  test_load_facts_and_origins();
  test_load_rejects_deep_nesting();
  test_load_rejects_malformed_facts();
  test_load_reports_pool_exhaustion();
  test_scope_resolution();
  return bs_test_finish();
}
