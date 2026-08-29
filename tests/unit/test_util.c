/* Unit tests for the foundation layer: spans, cursors and the arena.
 *
 * These are the primitives every later decoder is built on, so the tests below
 * are deliberately adversarial: they poke at the overflow and aliasing cases
 * that a decoder fed hostile bytes will eventually reach.
 */

#include <assert.h>

/* Turn documented invariants into hard failures for the whole test build.
 * This is the point of BS_ASSERT: silent in production, an oracle under test
 * and under the fuzzer. */
#define BS_ASSERT(cond) assert(cond)

#define BISCUITS_IMPLEMENTATION
#include "biscuits.h"

#include "bs_test.h"

static void test_status_strings(void) {
  int i;
  CHECK(bs_strstatus(BS_OK) != NULL);
  /* Every declared status has a distinct, non-empty description. */
  for (i = 0; i < BS_STATUS_COUNT; i++) {
    const char *s = bs_strstatus((bs_status)i);
    CHECK(s != NULL && s[0] != '\0');
  }
  /* Out-of-range values must not index past the table. */
  CHECK(bs_strstatus((bs_status)BS_STATUS_COUNT) != NULL);
  CHECK(bs_strstatus((bs_status)-1) != NULL);
  CHECK(bs_strstatus((bs_status)9999) != NULL);
}

static void test_span_basics(void) {
  static const uint8_t data[4] = {0xDE, 0xAD, 0xBE, 0xEF};
  bs_span s = bs_span_make(data, sizeof data);
  bs_span sub;
  uint8_t b = 0;

  CHECK(s.n == 4U);
  CHECK(bs_span_at(s, 0U, &b) && b == 0xDEU);
  CHECK(bs_span_at(s, 3U, &b) && b == 0xEFU);
  CHECK(!bs_span_at(s, 4U, &b));
  CHECK(b == 0xEFU); /* failed read left the output untouched */
  CHECK(!bs_span_at(s, 0U, NULL));

  /* A null pointer never yields a nonzero length, whatever the caller says. */
  CHECK(bs_span_make(NULL, 99U).n == 0U);

  CHECK(bs_span_slice(s, 1U, 2U, &sub) && sub.n == 2U && sub.p[0] == 0xADU);
  CHECK(bs_span_slice(s, 4U, 0U, &sub) &&
        sub.n == 0U);                     /* empty tail is legal */
  CHECK(!bs_span_slice(s, 3U, 2U, &sub)); /* runs off the end */
  CHECK(!bs_span_slice(s, 0U, 5U, &sub));
  /* The classic: an offset and a length that sum to something small. */
  CHECK(!bs_span_slice(s, SIZE_MAX, 2U, &sub));
  CHECK(!bs_span_slice(s, 2U, SIZE_MAX, &sub));
}

static void test_span_equality(void) {
  static const uint8_t a[3] = {1, 2, 3};
  static const uint8_t b[3] = {1, 2, 3};
  static const uint8_t c[3] = {1, 2, 4};

  CHECK(bs_span_eq(bs_span_make(a, 3U), bs_span_make(b, 3U)));
  CHECK(!bs_span_eq(bs_span_make(a, 3U), bs_span_make(c, 3U)));
  CHECK(!bs_span_eq(bs_span_make(a, 3U), bs_span_make(a, 2U)));
  /* Two empty spans are equal even with unrelated (or null) pointers. */
  CHECK(bs_span_eq(bs_span_make(a, 0U), bs_span_make(NULL, 0U)));
}

static void test_cursor(void) {
  static const uint8_t data[4] = {1, 2, 3, 4};
  bs_cursor c = bs_cursor_make(bs_span_make(data, sizeof data));
  bs_span chunk;
  uint8_t b = 0;

  CHECK(bs_cursor_left(&c) == 4U);
  CHECK(!bs_cursor_done(&c));
  CHECK(bs_take_u8(&c, &b) && b == 1U);
  CHECK(bs_cursor_left(&c) == 3U);

  /* An over-long take must not consume anything. */
  CHECK(!bs_take_bytes(&c, 4U, &chunk));
  CHECK(bs_cursor_left(&c) == 3U);
  CHECK(!bs_take_bytes(&c, SIZE_MAX, &chunk));
  CHECK(bs_cursor_left(&c) == 3U);

  CHECK(bs_take_bytes(&c, 3U, &chunk) && chunk.n == 3U && chunk.p[0] == 2U);
  CHECK(bs_cursor_done(&c));
  CHECK(!bs_take_u8(&c, &b));
  CHECK(b == 1U);
}

static void test_arena_basics(void) {
  uint8_t buf[64];
  bs_arena a;
  const void *p;
  const void *q;

  CHECK(bs_arena_init(&a, buf, sizeof buf) == BS_OK);
  CHECK(bs_arena_used(&a) == 0U);
  CHECK(!bs_arena_failed(&a));

  p = bs_arena_alloc(&a, 8U, 8U);
  CHECK(p != NULL);
  CHECK(((uintptr_t)p % 8U) == 0U);
  CHECK(bs_arena_used(&a) >= 8U);

  q = bs_arena_alloc(&a, 1U, 8U);
  CHECK(q != NULL && q != p);
  CHECK(((uintptr_t)q % 8U) == 0U);

  /* Zero-size requests still get their own address. */
  CHECK(bs_arena_alloc(&a, 0U, 1U) != bs_arena_alloc(&a, 0U, 1U));

  CHECK(bs_arena_peak(&a) == bs_arena_used(&a));
  bs_arena_reset(&a);
  CHECK(bs_arena_used(&a) == 0U);
  CHECK(bs_arena_peak(&a) > 0U); /* the high-water mark survives a reset */
}

static void test_arena_exhaustion_is_sticky(void) {
  uint8_t buf[16];
  bs_arena a;

  CHECK(bs_arena_init(&a, buf, sizeof buf) == BS_OK);
  CHECK(bs_arena_alloc(&a, 32U, 1U) == NULL);
  CHECK(bs_arena_failed(&a));
  /* Once failed, an allocation that would otherwise fit still fails: a caller
   * that only checks at the end of a chain cannot be handed a live pointer
   * from the middle of a failed sequence. */
  CHECK(bs_arena_alloc(&a, 1U, 1U) == NULL);
  bs_arena_reset(&a);
  CHECK(!bs_arena_failed(&a));
  CHECK(bs_arena_alloc(&a, 1U, 1U) != NULL);
}

static void test_arena_hostile_arguments(void) {
  uint8_t buf[64];
  bs_arena a;

  CHECK(bs_arena_init(NULL, buf, sizeof buf) == BS_ERR_ARGUMENT);
  CHECK(bs_arena_init(&a, NULL, 16U) == BS_ERR_ARGUMENT);
  /* A null buffer with zero capacity is legal: it measures demand. */
  CHECK(bs_arena_init(&a, NULL, 0U) == BS_OK);
  CHECK(bs_arena_alloc(&a, 1U, 1U) == NULL);

  CHECK(bs_arena_init(&a, buf, sizeof buf) == BS_OK);
  CHECK(bs_arena_alloc(&a, 1U, 0U) == NULL); /* alignment must be nonzero */
  CHECK(bs_arena_failed(&a));

  CHECK(bs_arena_init(&a, buf, sizeof buf) == BS_OK);
  CHECK(bs_arena_alloc(&a, 1U, 3U) == NULL); /* and a power of two */

  CHECK(bs_arena_init(&a, buf, sizeof buf) == BS_OK);
  CHECK(bs_arena_alloc(&a, 1U, BS_ALIGN_MAX * 2U) == NULL); /* and bounded */

  /* Size arithmetic must not wrap into a small, satisfiable request. */
  CHECK(bs_arena_init(&a, buf, sizeof buf) == BS_OK);
  CHECK(bs_arena_alloc(&a, SIZE_MAX, 8U) == NULL);
  CHECK(bs_arena_init(&a, buf, sizeof buf) == BS_OK);
  CHECK(bs_arena_alloc(&a, SIZE_MAX - 3U, 8U) == NULL);

  CHECK(bs_arena_failed(NULL));
  CHECK(bs_arena_used(NULL) == 0U);
  CHECK(bs_arena_alloc(NULL, 1U, 1U) == NULL);
}

static void test_arena_array_guards_multiplication(void) {
  uint8_t buf[128];
  bs_arena a;
  const uint8_t *p;
  size_t i;

  CHECK(bs_arena_init(&a, buf, sizeof buf) == BS_OK);
  p = (const uint8_t *)bs_arena_array(&a, 8U, 4U, 4U);
  CHECK(p != NULL);
  for (i = 0U; i < 32U; i++) {
    CHECK(p[i] == 0U); /* arrays come back zeroed */
  }

  /* n * size must not wrap. Two factors whose product is 0 modulo SIZE_MAX+1
   * is the shape that turns a huge request into a tiny allocation. */
  CHECK(bs_arena_init(&a, buf, sizeof buf) == BS_OK);
  CHECK(bs_arena_array(&a, SIZE_MAX / 2U + 1U, 4U, 4U) == NULL);
  CHECK(bs_arena_failed(&a));

  CHECK(bs_arena_init(&a, buf, sizeof buf) == BS_OK);
  CHECK(bs_arena_array(&a, SIZE_MAX, SIZE_MAX, 8U) == NULL);
}

static void test_arena_realigns_a_misaligned_base(void) {
  /* An arena carved out of a larger buffer -- bs_arena_init(&a, buf + used,
   * n) -- is the ordinary case, and nothing makes `used` a multiple of the
   * alignment. bs_arena_alloc aligns the offset, so without normalising the
   * base here every pointer it returns would inherit the misalignment. */
  static uint8_t backing[256];
  size_t skew;

  for (skew = 0U; skew < 2U * BS_ALIGN_MAX; skew++) {
    bs_arena a;
    const void *p;
    CHECK(bs_arena_init(&a, backing + skew, sizeof backing - skew) == BS_OK);
    p = bs_arena_alloc(&a, sizeof(bs_max_align), BS_ALIGN_MAX);
    CHECK(p != NULL);
    CHECK(((uintptr_t)p % BS_ALIGN_MAX) == 0U);
  }

  /* A buffer too small to survive its own padding yields an arena that fails
   * every allocation, rather than a short one that looks usable. */
  {
    bs_arena a;
    CHECK(bs_arena_init(&a, backing + 1U, 2U) == BS_OK);
    CHECK(bs_arena_alloc(&a, 1U, BS_ALIGN_MAX) == NULL);
  }
}

static void test_slice_of_an_empty_span_forms_no_null_arithmetic(void) {
  /* NULL + 0 is undefined in C99, however harmless it looks, and this library
   * claims C99. UBSan's pointer-overflow check catches it. */
  bs_span empty = bs_span_make(NULL, 0U);
  bs_span sub;
  bs_cursor c = bs_cursor_make(empty);
  bs_span taken;

  CHECK(bs_span_slice(empty, 0U, 0U, &sub));
  CHECK(sub.n == 0U && sub.p == NULL);
  CHECK(bs_take_bytes(&c, 0U, &taken));
  CHECK(taken.n == 0U && taken.p == NULL);
}

int main(void) {
  test_status_strings();
  test_span_basics();
  test_span_equality();
  test_cursor();
  test_arena_basics();
  test_arena_exhaustion_is_sticky();
  test_arena_hostile_arguments();
  test_arena_array_guards_multiplication();
  test_arena_realigns_a_misaligned_base();
  test_slice_of_an_empty_span_forms_no_null_arithmetic();
  return bs_test_finish();
}
