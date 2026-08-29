/* Unit tests for the protobuf wire decoder and the token container.
 *
 * The conformance suite proves this code reads tokens a correct implementation
 * produced. These tests prove it *rejects* the ones an attacker would produce,
 * which the sample suite barely covers -- it has five malformed tokens and
 * they are all malformed in the same way.
 */

#include <assert.h>

#define BS_ASSERT(cond) assert(cond)

#define BISCUITS_IMPLEMENTATION
#include "biscuits.h"

#include "bs_test.h"

#include "pb_build.h"

/* --------------------------------------------------------------------------
 * Varints
 * ----------------------------------------------------------------------- */

static void test_varint_roundtrip(void) {
  static const uint64_t values[] = {
      0U,
      1U,
      127U,
      128U,
      16383U,
      16384U,
      0xFFFFFFFFU,
      0x7FFFFFFFFFFFFFFFU,
      0xFFFFFFFFFFFFFFFFU,
  };
  size_t i;
  for (i = 0; i < sizeof values / sizeof values[0]; i++) {
    buf w;
    bs_cursor c;
    uint64_t got = 0;
    w.n = 0;
    put_varint(&w, values[i]);
    c = bs_cursor_make(span_of(&w));
    CHECK(bs_pb_varint(&c, &got) && got == values[i]);
    CHECK(bs_cursor_done(&c));
  }
}

static void test_varint_rejects_malformed(void) {
  /* Ten continuation bytes then an eleventh: no valid varint is this long. */
  static const uint8_t too_long[11] = {
      0x80U, 0x80U, 0x80U, 0x80U, 0x80U, 0x80U,
      0x80U, 0x80U, 0x80U, 0x80U, 0x01U,
  };
  /* Ten bytes whose last carries more than the single remaining bit. */
  static const uint8_t too_wide[10] = {
      0x80U, 0x80U, 0x80U, 0x80U, 0x80U, 0x80U, 0x80U, 0x80U, 0x80U, 0x02U,
  };
  /* A continuation byte with nothing after it. */
  static const uint8_t truncated[2] = {0x80U, 0x80U};

  bs_cursor c;
  uint64_t v = 0;

  c = bs_cursor_make(bs_span_make(too_long, sizeof too_long));
  CHECK(!bs_pb_varint(&c, &v));
  CHECK(c.off == 0U); /* cursor restored, so a caller can back out cleanly */

  c = bs_cursor_make(bs_span_make(too_wide, sizeof too_wide));
  CHECK(!bs_pb_varint(&c, &v));
  CHECK(c.off == 0U);

  c = bs_cursor_make(bs_span_make(truncated, sizeof truncated));
  CHECK(!bs_pb_varint(&c, &v));
  CHECK(c.off == 0U);
}

static void test_varint_accepts_non_minimal(void) {
  /* 0x81 0x00 is a padded encoding of 1. Real writers emit these; rejecting
   * them would fail on valid tokens. What must be rejected is an encoding of
   * a value that cannot be represented, not an inefficient one. */
  static const uint8_t padded[2] = {0x81U, 0x00U};
  bs_cursor c = bs_cursor_make(bs_span_make(padded, sizeof padded));
  uint64_t v = 0;
  CHECK(bs_pb_varint(&c, &v) && v == 1U);
}

/* --------------------------------------------------------------------------
 * Fields
 * ----------------------------------------------------------------------- */

static void test_field_rejects_groups_and_zero(void) {
  bs_pb_field f;
  buf w;
  bs_cursor c;

  /* Field number 0 does not exist in the wire format. */
  w.n = 0;
  put_tag(&w, 0U, BS_PB_VARINT);
  put_varint(&w, 1U);
  c = bs_cursor_make(span_of(&w));
  CHECK(!bs_pb_next(&c, &f));

  /* Groups were removed from proto2; accepting them would add a nesting
   * construct with its own termination rules. */
  w.n = 0;
  put_tag(&w, 1U, BS_PB_SGROUP);
  c = bs_cursor_make(span_of(&w));
  CHECK(!bs_pb_next(&c, &f));

  w.n = 0;
  put_tag(&w, 1U, BS_PB_EGROUP);
  c = bs_cursor_make(span_of(&w));
  CHECK(!bs_pb_next(&c, &f));
}

static void test_field_length_cannot_overrun(void) {
  bs_pb_field f;
  buf w;
  bs_cursor c;

  /* A declared length longer than what remains. */
  w.n = 0;
  put_tag(&w, 1U, BS_PB_BYTES);
  put_varint(&w, 64U);
  put(&w, 0xAAU);
  c = bs_cursor_make(span_of(&w));
  CHECK(!bs_pb_next(&c, &f));
  CHECK(c.off == 0U);

  /* A length that does not fit in size_t on a 32-bit target. Compared as a
   * 64-bit value before any narrowing, so the result is the same everywhere. */
  w.n = 0;
  put_tag(&w, 1U, BS_PB_BYTES);
  put_varint(&w, 0xFFFFFFFFFFFFFFFFU);
  c = bs_cursor_make(span_of(&w));
  CHECK(!bs_pb_next(&c, &f));

  /* A zero-length field is legal and yields an empty span. */
  w.n = 0;
  put_bytes(&w, 1U, NULL, 0U);
  c = bs_cursor_make(span_of(&w));
  CHECK(bs_pb_next(&c, &f) && f.number == 1U && f.bytes.n == 0U);
  CHECK(bs_cursor_done(&c));
}

static void test_field_fixed_widths_are_little_endian(void) {
  static const uint8_t i64[8] = {
      0x01U, 0x02U, 0x03U, 0x04U, 0x05U, 0x06U, 0x07U, 0x08U,
  };
  bs_pb_field f;
  buf w;
  bs_cursor c;
  size_t i;

  w.n = 0;
  put_tag(&w, 7U, BS_PB_I64);
  for (i = 0; i < sizeof i64; i++) {
    put(&w, i64[i]);
  }
  c = bs_cursor_make(span_of(&w));
  CHECK(bs_pb_next(&c, &f));
  CHECK(f.varint == 0x0807060504030201U);

  /* Truncated fixed-width field. */
  w.n = 0;
  put_tag(&w, 7U, BS_PB_I32);
  put(&w, 0x01U);
  c = bs_cursor_make(span_of(&w));
  CHECK(!bs_pb_next(&c, &f));
}

/* --------------------------------------------------------------------------
 * Tokens
 * ----------------------------------------------------------------------- */

/* A public key message. secp256r1 keys are compressed SEC1 points, so their
 * leading byte must be 0x02 or 0x03; anything else is malformed regardless of
 * whether this build supports the curve. */
static void put_pubkey_prefixed(buf *w, uint32_t field, uint64_t alg,
                                size_t key_len, uint8_t first) {
  buf inner;
  size_t i;
  inner.n = 0;
  put_tag(&inner, BS_F_PUBKEY_ALGORITHM, BS_PB_VARINT);
  put_varint(&inner, alg);
  put_tag(&inner, BS_F_PUBKEY_KEY, BS_PB_BYTES);
  put_varint(&inner, key_len);
  for (i = 0; i < key_len; i++) {
    put(&inner, (i == 0U) ? first : (uint8_t)(0x40U + (i & 0x0FU)));
  }
  put_bytes(w, field, inner.b, inner.n);
}

static void put_signed_block_prefixed(buf *w, uint32_t field, size_t sig_len,
                                      uint64_t key_alg, size_t key_len,
                                      uint8_t first) {
  buf inner;
  size_t i;
  inner.n = 0;
  put_bytes(&inner, BS_F_SIGNED_BLOCK, NULL, 0U);
  put_pubkey_prefixed(&inner, BS_F_SIGNED_NEXT_KEY, key_alg, key_len, first);
  put_tag(&inner, BS_F_SIGNED_SIGNATURE, BS_PB_BYTES);
  put_varint(&inner, sig_len);
  for (i = 0; i < sig_len; i++) {
    put(&inner, (uint8_t)i);
  }
  put_bytes(w, field, inner.b, inner.n);
}

static void put_signed_block(buf *w, uint32_t field, size_t sig_len,
                             uint64_t key_alg, size_t key_len) {
  put_signed_block_prefixed(w, field, sig_len, key_alg, key_len,
                            (key_alg == 1U) ? 0x02U : 0x40U);
}

static void put_proof(buf *w, uint32_t which) {
  buf inner;
  static const uint8_t secret[32] = {0};
  inner.n = 0;
  if (which != 0U) {
    put_bytes(&inner, which, secret, sizeof secret);
  }
  put_bytes(w, BS_F_BISCUIT_PROOF, inner.b, inner.n);
}

static bs_status parse(const buf *w) {
  static uint8_t scratch[16384];
  bs_arena a;
  bs_token t;
  if (bs_arena_init(&a, scratch, sizeof scratch) != BS_OK) {
    return BS_ERR_ARGUMENT;
  }
  return bs_token_parse(&a, span_of(w), &t);
}

static void test_token_requires_authority_and_proof(void) {
  buf w;

  /* Nothing at all. */
  w.n = 0;
  CHECK(parse(&w) == BS_ERR_MALFORMED);

  /* Authority without proof. */
  w.n = 0;
  put_signed_block(&w, BS_F_BISCUIT_AUTHORITY, 64U, 0U, 32U);
  CHECK(parse(&w) == BS_ERR_MALFORMED);

  /* Proof without authority. */
  w.n = 0;
  put_proof(&w, BS_F_PROOF_NEXT_SECRET);
  CHECK(parse(&w) == BS_ERR_MALFORMED);

  /* Both: accepted. */
  w.n = 0;
  put_signed_block(&w, BS_F_BISCUIT_AUTHORITY, 64U, 0U, 32U);
  put_proof(&w, BS_F_PROOF_NEXT_SECRET);
  CHECK(parse(&w) == BS_OK);
}

static void test_token_proof_is_exclusive(void) {
  buf w;
  buf inner;
  static const uint8_t blob[32] = {0};

  /* Neither branch of the oneof. */
  w.n = 0;
  put_signed_block(&w, BS_F_BISCUIT_AUTHORITY, 64U, 0U, 32U);
  put_proof(&w, 0U);
  CHECK(parse(&w) == BS_ERR_MALFORMED);

  /* Both branches: a verifier could otherwise pick whichever suits it, so a
   * token offering the choice must be refused outright. */
  w.n = 0;
  put_signed_block(&w, BS_F_BISCUIT_AUTHORITY, 64U, 0U, 32U);
  inner.n = 0;
  put_bytes(&inner, BS_F_PROOF_NEXT_SECRET, blob, sizeof blob);
  put_bytes(&inner, BS_F_PROOF_FINAL_SIGNATURE, blob, sizeof blob);
  put_bytes(&w, BS_F_BISCUIT_PROOF, inner.b, inner.n);
  CHECK(parse(&w) == BS_ERR_MALFORMED);
}

static void test_token_validates_key_and_signature_sizes(void) {
  buf w;

  /* An Ed25519 key that is not 32 bytes. */
  w.n = 0;
  put_signed_block(&w, BS_F_BISCUIT_AUTHORITY, 64U, 0U, 31U);
  put_proof(&w, BS_F_PROOF_NEXT_SECRET);
  CHECK(parse(&w) == BS_ERR_MALFORMED);

  /* A truncated signature: this is what test003 of the official suite is. */
  w.n = 0;
  put_signed_block(&w, BS_F_BISCUIT_AUTHORITY, 16U, 0U, 32U);
  put_proof(&w, BS_F_PROOF_NEXT_SECRET);
  CHECK(parse(&w) == BS_ERR_MALFORMED);

  /* An over-long signature is equally wrong. */
  w.n = 0;
  put_signed_block(&w, BS_F_BISCUIT_AUTHORITY, 65U, 0U, 32U);
  put_proof(&w, BS_F_PROOF_NEXT_SECRET);
  CHECK(parse(&w) == BS_ERR_MALFORMED);
}

static void test_token_rejects_unknown_algorithms(void) {
  buf w;

  /* secp256r1 is recognised and refused, never ignored: a token this build
   * cannot check must not be reported as one it checked. */
  w.n = 0;
  put_signed_block(&w, BS_F_BISCUIT_AUTHORITY, 64U, 1U, 33U);
  put_proof(&w, BS_F_PROOF_NEXT_SECRET);
  CHECK(parse(&w) == BS_ERR_UNSUPPORTED);

  /* A secp256r1 key whose SEC1 prefix is neither 0x02 nor 0x03 is malformed,
   * and that verdict must win over "unsupported": the token is wrong, not
   * merely beyond this build. */
  w.n = 0;
  put_signed_block_prefixed(&w, BS_F_BISCUIT_AUTHORITY, 64U, 1U, 33U, 0x04U);
  put_proof(&w, BS_F_PROOF_NEXT_SECRET);
  CHECK(parse(&w) == BS_ERR_MALFORMED);

  /* A secp256r1 key of the wrong length, likewise. */
  w.n = 0;
  put_signed_block_prefixed(&w, BS_F_BISCUIT_AUTHORITY, 64U, 1U, 32U, 0x02U);
  put_proof(&w, BS_F_PROOF_NEXT_SECRET);
  CHECK(parse(&w) == BS_ERR_MALFORMED);

  /* An algorithm nobody has defined is malformed, not unsupported. */
  w.n = 0;
  put_signed_block(&w, BS_F_BISCUIT_AUTHORITY, 64U, 99U, 32U);
  put_proof(&w, BS_F_PROOF_NEXT_SECRET);
  CHECK(parse(&w) == BS_ERR_MALFORMED);
}

static void test_token_block_ceiling(void) {
  buf w;
  int i;

  w.n = 0;
  put_signed_block(&w, BS_F_BISCUIT_AUTHORITY, 64U, 0U, 32U);
  /* Each block costs a signature verification, so the ceiling bounds work as
   * well as memory. The writer's buffer caps how many we can build here; the
   * point is that the limit is enforced, not where it sits. */
  for (i = 0; i < BS_MAX_BLOCKS; i++) {
    put_tag(&w, BS_F_BISCUIT_BLOCKS, BS_PB_BYTES);
    put_varint(&w, 0U);
  }
  put_proof(&w, BS_F_PROOF_NEXT_SECRET);
  CHECK(parse(&w) == BS_ERR_LIMIT);
}

static void test_token_ignores_unknown_fields(void) {
  buf w;
  static const uint8_t junk[4] = {0xDEU, 0xADU, 0xBEU, 0xEFU};

  w.n = 0;
  put_bytes(&w, 900U, junk, sizeof junk);
  put_signed_block(&w, BS_F_BISCUIT_AUTHORITY, 64U, 0U, 32U);
  put_tag(&w, 901U, BS_PB_VARINT);
  put_varint(&w, 12345U);
  put_proof(&w, BS_F_PROOF_NEXT_SECRET);
  /* Unknown fields are ignored, as proto2 requires -- but they are still
   * parsed, so trailing garbage is rejected rather than skipped over. */
  CHECK(parse(&w) == BS_OK);

  w.n = 0;
  put_signed_block(&w, BS_F_BISCUIT_AUTHORITY, 64U, 0U, 32U);
  put_proof(&w, BS_F_PROOF_NEXT_SECRET);
  put(&w, 0xFFU); /* not a valid tag */
  CHECK(parse(&w) == BS_ERR_MALFORMED);
}

static void test_token_arena_exhaustion_is_reported(void) {
  buf w;
  uint8_t tiny[8];
  bs_arena a;
  bs_token t;

  w.n = 0;
  put_signed_block(&w, BS_F_BISCUIT_AUTHORITY, 64U, 0U, 32U);
  put_proof(&w, BS_F_PROOF_NEXT_SECRET);

  CHECK(bs_arena_init(&a, tiny, sizeof tiny) == BS_OK);
  CHECK(bs_token_parse(&a, span_of(&w), &t) == BS_ERR_NOMEM);

  /* A null arena or output is a caller error, distinct from exhaustion. */
  CHECK(bs_token_parse(NULL, span_of(&w), &t) == BS_ERR_ARGUMENT);
  CHECK(bs_token_parse(&a, span_of(&w), NULL) == BS_ERR_ARGUMENT);
}

static void test_revocation_id_is_the_signature(void) {
  static uint8_t scratch[16384];
  buf w;
  bs_arena a;
  bs_token t;
  bs_span id;

  w.n = 0;
  put_signed_block(&w, BS_F_BISCUIT_AUTHORITY, 64U, 0U, 32U);
  put_proof(&w, BS_F_PROOF_NEXT_SECRET);

  CHECK(bs_arena_init(&a, scratch, sizeof scratch) == BS_OK);
  CHECK(bs_token_parse(&a, span_of(&w), &t) == BS_OK);
  CHECK(t.block_count == 1U);
  CHECK(!t.sealed);

  id = bs_token_revocation_id(&t, 0U);
  CHECK(id.n == 64U && id.p[0] == 0U && id.p[63] == 63U);

  /* Out of range yields an empty span, never a wild pointer. */
  CHECK(bs_token_revocation_id(&t, 1U).n == 0U);
  CHECK(bs_token_revocation_id(&t, (size_t)-1).n == 0U);
  CHECK(bs_token_revocation_id(NULL, 0U).n == 0U);
}

int main(void) {
  test_varint_roundtrip();
  test_varint_rejects_malformed();
  test_varint_accepts_non_minimal();
  test_field_rejects_groups_and_zero();
  test_field_length_cannot_overrun();
  test_field_fixed_widths_are_little_endian();
  test_token_requires_authority_and_proof();
  test_token_proof_is_exclusive();
  test_token_validates_key_and_signature_sizes();
  test_token_rejects_unknown_algorithms();
  test_token_block_ceiling();
  test_token_ignores_unknown_fields();
  test_token_arena_exhaustion_is_reported();
  test_revocation_id_is_the_signature();
  return bs_test_finish();
}
