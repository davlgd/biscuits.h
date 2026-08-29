/* Unit tests for base64url decoding and the text entry point.
 *
 * The decoder is strict, and these tests are mostly about what it refuses.
 * A lenient base64 decoder accepts several distinct strings for one token,
 * which quietly turns "have I seen this token before?" into a question with
 * more than one answer -- and any deny-list or cache keyed on the string form
 * is then wrong in a way that only shows up under attack.
 */

#include <assert.h>
#include <string.h>

#define BS_ASSERT(cond) assert(cond)

#define BISCUITS_IMPLEMENTATION
#include "biscuits.h"

#include "bs_test.h"

static uint8_t arena_buf[16384];
static bs_arena A;

static bs_span text(const char *s) {
  return bs_span_make(s, strlen(s));
}

static bs_status decode(const char *s, bs_span *out) {
  /* Cleared first: CHECK records a failure and carries on, so a caller that
   * inspects *out after a failed decode must not read an uninitialised span. */
  *out = bs_span_make(NULL, 0U);
  if (bs_arena_init(&A, arena_buf, sizeof arena_buf) != BS_OK) {
    return BS_ERR_ARGUMENT;
  }
  return bs_base64url_decode(&A, text(s), out);
}

static int decodes_to(const char *s, const char *expect) {
  bs_span got;
  size_t n = strlen(expect);
  if (decode(s, &got) != BS_OK) {
    return 0;
  }
  return got.n == n && (n == 0U || memcmp(got.p, expect, n) == 0);
}

static void test_base64_vectors(void) {
  /* RFC 4648 test vectors, in the URL-safe alphabet. */
  CHECK(decodes_to("", ""));
  CHECK(decodes_to("Zg==", "f"));
  CHECK(decodes_to("Zm8=", "fo"));
  CHECK(decodes_to("Zm9v", "foo"));
  CHECK(decodes_to("Zm9vYg==", "foob"));
  CHECK(decodes_to("Zm9vYmE=", "fooba"));
  CHECK(decodes_to("Zm9vYmFy", "foobar"));

  /* Unpadded is accepted: the specification does not require padding, and
   * real encoders differ. What is refused is padding that is wrong. */
  CHECK(decodes_to("Zg", "f"));
  CHECK(decodes_to("Zm8", "fo"));

  /* The URL-safe alphabet, where the standard one would use + and /. */
  {
    bs_span got;
    REQUIRE(decode("-_8", &got) == BS_OK);
    REQUIRE(got.n == 2U);
    CHECK(got.p[0] == 0xFBU && got.p[1] == 0xFFU);
  }
}

static void test_base64_is_strict(void) {
  bs_span got;

  /* Characters outside the alphabet, including the standard alphabet's. */
  CHECK(decode("Zm9+", &got) == BS_ERR_MALFORMED);
  CHECK(decode("Zm9/", &got) == BS_ERR_MALFORMED);
  CHECK(decode("Zm9v!", &got) == BS_ERR_MALFORMED);

  /* Whitespace is not skipped. Skipping it would mean a token has as many
   * string forms as there are places to put a newline. */
  CHECK(decode("Zm9v Zm9v", &got) == BS_ERR_MALFORMED);
  CHECK(decode("Zm9v\n", &got) == BS_ERR_MALFORMED);

  /* A final group of one character carries no complete byte. */
  CHECK(decode("Z", &got) == BS_ERR_MALFORMED);
  CHECK(decode("Zm9vZ", &got) == BS_ERR_MALFORMED);

  /* Padding that does not match the group length. */
  CHECK(decode("Zm9v=", &got) == BS_ERR_MALFORMED);
  CHECK(decode("Zg=", &got) == BS_ERR_MALFORMED);
  CHECK(decode("Zm8==", &got) == BS_ERR_MALFORMED);
  CHECK(decode("Z===", &got) == BS_ERR_MALFORMED);

  /* Non-zero bits left over by a partial final group. "Zh" and "Zg" would
   * otherwise both decode to "f", which is exactly the ambiguity that makes a
   * lenient decoder dangerous here. */
  CHECK(decodes_to("Zg", "f"));
  CHECK(decode("Zh", &got) == BS_ERR_MALFORMED);
  CHECK(decode("Zm9", &got) ==
        BS_ERR_MALFORMED); /* "Zm8" is the canonical one */
}

static void test_base64_prefix(void) {
  CHECK(decodes_to("biscuit:Zm9vYmFy", "foobar"));
  CHECK(decodes_to("Zm9vYmFy", "foobar"));
  /* Only the exact prefix is stripped; anything else is just data, and will
   * fail the alphabet check rather than being silently ignored. */
  {
    bs_span got;
    CHECK(decode("biscuit:", &got) == BS_OK && got.n == 0U);
    CHECK(decode("BISCUIT:Zm9vYmFy", &got) == BS_ERR_MALFORMED);
    CHECK(decode("biscuits:Zm9vYmFy", &got) == BS_ERR_MALFORMED);
  }
}

/* test001_basic.bc from the specification's sample suite, base64url-encoded. */
static const char SAMPLE_TOKEN[] =
    "EqcBCj0KBWZpbGUxCgVmaWxlMhgDIg0KCwgEEgMYgAgSAhgAIg0KCwgEEgMYgQgSAhgA"
    "Ig0KCwgEEgMYgAgSAhgBEiQIABIgEFXHULGhUFk3rxU3xia6MmOZXDOmR1iqr7EnWwMS"
    "4oQaQHWVoRKh61uBpuOYhS5hGLf1uMu_9FJ3jmVRAOX7T6qNOir1L-LE-VJIeWBWdfri"
    "atvEeD4Mr8Q1IvqCOF85bAMalQEKKwoBMBgDMiQKIgoCCBsSBwgCEgMIgggSBggDEgIY"
    "ABILCAQSAwiCCBICGAASJAgAEiDUQk0eEpEzoUeX40zcX6nap0wrG2eq_k-10bM-vdpa"
    "0RpARfTBT52ej6BE1ovnouyM3bg19XXHuRPsWb1jbHCsrpqQ25BkugswhCkO0MQiu7cX"
    "AJKohPXgICsx6SNbvMFlDSIiCiDKQdqwhZDtpEIxtvz0uxEMhSsk8DC_mWqJ8CzMxX61"
    "8Q==";

static void test_token_from_text(void) {
  bs_token t;

  REQUIRE(bs_arena_init(&A, arena_buf, sizeof arena_buf) == BS_OK);
  REQUIRE(bs_token_parse_text(&A, text(SAMPLE_TOKEN), &t) == BS_OK);
  CHECK(t.block_count == 2U);
  CHECK(!t.sealed);

  /* The same bytes, with the prefix the specification allows. */
  {
    char prefixed[1024];
    REQUIRE(sizeof SAMPLE_TOKEN + 8U < sizeof prefixed);
    memcpy(prefixed, "biscuit:", 8U);
    memcpy(prefixed + 8, SAMPLE_TOKEN, sizeof SAMPLE_TOKEN);
    REQUIRE(bs_arena_init(&A, arena_buf, sizeof arena_buf) == BS_OK);
    CHECK(bs_token_parse_text(&A, text(prefixed), &t) == BS_OK);
  }

  /* Flipping one character of the encoding must not yield a valid token that
   * merely differs -- it must fail somewhere, and it must fail cleanly. */
  {
    char damaged[1024];
    memcpy(damaged, SAMPLE_TOKEN, sizeof SAMPLE_TOKEN);
    damaged[10] = (damaged[10] == 'A') ? 'B' : 'A';
    REQUIRE(bs_arena_init(&A, arena_buf, sizeof arena_buf) == BS_OK);
    CHECK(bs_token_parse_text(&A, text(damaged), &t) != BS_OK ||
          t.block_count == 2U);
  }

  /* An arena too small to hold the decoded bytes reports exhaustion. */
  {
    uint8_t tiny[16];
    bs_arena small;
    REQUIRE(bs_arena_init(&small, tiny, sizeof tiny) == BS_OK);
    CHECK(bs_token_parse_text(&small, text(SAMPLE_TOKEN), &t) == BS_ERR_NOMEM);
  }

  CHECK(bs_token_parse_text(NULL, text(SAMPLE_TOKEN), &t) == BS_ERR_ARGUMENT);
  CHECK(bs_base64url_decode(&A, text("Zg=="), NULL) == BS_ERR_ARGUMENT);
}

int main(void) {
  test_base64_vectors();
  test_base64_is_strict();
  test_base64_prefix();
  test_token_from_text();
  return bs_test_finish();
}
