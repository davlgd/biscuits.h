/* Unit tests for the vendored Ed25519 arithmetic and the code around it.
 *
 * These exist because 45_ed25519.inc was mechanically transformed on its way
 * in -- every symbol renamed, two functions dropped, the hash restructured to
 * stream and the verification equation reassembled to avoid copying the
 * message. Each of those is a chance to have broken the arithmetic silently.
 * The RFC 8032 vectors are what makes the claim "unchanged arithmetic"
 * checkable rather than merely asserted, and the rejection cases matter more
 * than the acceptances: a verifier that accepts everything passes every
 * positive test.
 */

#include <assert.h>
#include <stdio.h>
#include <string.h>

#define BS_ASSERT(cond) assert(cond)

#define BISCUITS_IMPLEMENTATION
#include "biscuits.h"

#include "bs_test.h"

static uint8_t scratch_a[512];
static uint8_t scratch_b[512];

static size_t unhex(const char *h, uint8_t *out, size_t cap) {
  size_t n = 0;
  while (h[0] != '\0' && h[1] != '\0' && n < cap) {
    unsigned int hi = (unsigned int)h[0];
    unsigned int lo = (unsigned int)h[1];
    unsigned int v = 0;
    size_t k;
    for (k = 0; k < 2U; k++) {
      unsigned int c = (k == 0U) ? hi : lo;
      unsigned int d;
      if (c >= (unsigned int)'0' && c <= (unsigned int)'9') {
        d = c - (unsigned int)'0';
      } else {
        d = (c | 0x20U) - (unsigned int)'a' + 10U;
      }
      v = (v << 4U) | d;
    }
    out[n++] = (uint8_t)v;
    h += 2;
  }
  return n;
}

/* --------------------------------------------------------------------------
 * SHA-512
 * ----------------------------------------------------------------------- */

typedef struct sha_case {
  const char *name;
  size_t len;
  const char *input;
  const char *digest;
} sha_case;

/* Chosen around the padding boundaries: 111 and 112 bytes straddle the point
 * where the length no longer fits in the final block, and 127/128/129 straddle
 * the block itself. Those are where a transcribed padding routine goes wrong.
 */
static const sha_case SHA_CASES[] = {
    {
        "empty",
        0U,
        "",
        "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d1"
        "3c5"
        "d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
    },
    {
        "abc",
        3U,
        "616263",
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a219299"
        "2a2"
        "74fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
    },
    {
        "111 bytes",
        111U,
        "6161616161616161616161616161616161616161616161616161616161616161616161"
        "616"
        "1616161616161616161616161616161616161616161616161616161616161616161616"
        "161"
        "6161616161616161616161616161616161616161616161616161616161616161616161"
        "616"
        "161",
        "fa9121c7b32b9e01733d034cfc78cbf67f926c7ed83e82200ef86818196921760b4bef"
        "f48"
        "404df811b953828274461673c68d04e297b0eb7b2b4d60fc6b566a2",
    },
    {
        "112 bytes",
        112U,
        "6161616161616161616161616161616161616161616161616161616161616161616161"
        "616"
        "1616161616161616161616161616161616161616161616161616161616161616161616"
        "161"
        "6161616161616161616161616161616161616161616161616161616161616161616161"
        "616"
        "16161",
        "c01d080efd492776a1c43bd23dd99d0a2e626d481e16782e75d54c2503b5dc32bd05f0"
        "f1b"
        "a33e568b88fd2d970929b719ecbb152f58f130a407c8830604b70ca",
    },
    {
        "127 bytes",
        127U,
        "6161616161616161616161616161616161616161616161616161616161616161616161"
        "616"
        "1616161616161616161616161616161616161616161616161616161616161616161616"
        "161"
        "6161616161616161616161616161616161616161616161616161616161616161616161"
        "616"
        "16161616161616161616161616161616161",
        "828613968b501dc00a97e08c73b118aa8876c26b8aac93df128502ab360f91bab50a51"
        "e08"
        "8769a5c1eff4782ace147dce3642554199876374291f5d921629502",
    },
    {
        "128 bytes",
        128U,
        "6161616161616161616161616161616161616161616161616161616161616161616161"
        "616"
        "1616161616161616161616161616161616161616161616161616161616161616161616"
        "161"
        "6161616161616161616161616161616161616161616161616161616161616161616161"
        "616"
        "1616161616161616161616161616161616161",
        "b73d1929aa615934e61a871596b3f3b33359f42b8175602e89f7e06e5f658a24366780"
        "7ed"
        "300314b95cacdd579f3e33abdfbe351909519a846d465c59582f321",
    },
    {
        "129 bytes",
        129U,
        "6161616161616161616161616161616161616161616161616161616161616161616161"
        "616"
        "1616161616161616161616161616161616161616161616161616161616161616161616"
        "161"
        "6161616161616161616161616161616161616161616161616161616161616161616161"
        "616"
        "161616161616161616161616161616161616161",
        "4f681e0bd53cda4b5a2041cc8a06f2eabde44fb16c951fbd5b87702f07aeab611565b1"
        "9c4"
        "7fde30587177ebb852e3971bbd8d3fd30da18d71037dfbd98420429",
    },
    {
        "200 bytes",
        200U,
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122"
        "232"
        "425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464"
        "748"
        "494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b"
        "6c6"
        "d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f9"
        "091"
        "92939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4"
        "b5b"
        "6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7",
        "986058e9895e2c2ab8f9e8cbdf801db12a44842a56a91d5a4e87b1fc98b293722c4664"
        "142"
        "e42c3c551ff898646268cd92b84ed230b8c94bed7798d4f27cd7465",
    },
};

static void test_sha512_vectors(void) {
  size_t i;
  for (i = 0; i < sizeof SHA_CASES / sizeof SHA_CASES[0]; i++) {
    const sha_case *c = &SHA_CASES[i];
    uint8_t want[64];
    uint8_t got[64];
    bs_sha512 h;
    size_t n = unhex(c->input, scratch_a, sizeof scratch_a);
    (void)unhex(c->digest, want, sizeof want);
    CHECK(n == c->len);
    bs_sha512_init(&h);
    bs_sha512_update(&h, bs_span_make(scratch_a, n));
    bs_sha512_final(&h, got);
    if (memcmp(got, want, 64U) != 0) {
      (void)printf("# SHA-512 case %s\n", c->name);
    }
    CHECK(memcmp(got, want, 64U) == 0);
  }
}

static void test_sha512_streaming_matches_one_shot(void) {
  /* The streaming path exists only to avoid copying the message. If it
   * disagrees with the one-shot path at any split point, it is not an
   * optimisation, it is a second implementation with its own bugs. */
  static const size_t splits[] = {
      0U, 1U, 63U, 64U, 111U, 112U, 127U, 128U, 129U, 200U,
  };
  size_t total;
  size_t i;

  for (i = 0; i < 300U; i++) {
    scratch_a[i] = (uint8_t)((i * 7U) + 3U);
  }
  total = 300U;

  {
    uint8_t whole[64];
    bs_sha512 h;
    bs_sha512_init(&h);
    bs_sha512_update(&h, bs_span_make(scratch_a, total));
    bs_sha512_final(&h, whole);

    for (i = 0; i < sizeof splits / sizeof splits[0]; i++) {
      uint8_t split[64];
      bs_sha512 s;
      size_t at = splits[i];
      if (at > total) {
        continue;
      }
      bs_sha512_init(&s);
      bs_sha512_update(&s, bs_span_make(scratch_a, at));
      bs_sha512_update(&s, bs_span_make(scratch_a + at, total - at));
      bs_sha512_final(&s, split);
      CHECK(memcmp(whole, split, 64U) == 0);
    }

    /* And byte at a time, which exercises every partial-block path. */
    {
      uint8_t drip[64];
      bs_sha512 s;
      bs_sha512_init(&s);
      for (i = 0; i < total; i++) {
        bs_sha512_update(&s, bs_span_make(scratch_a + i, 1U));
      }
      bs_sha512_final(&s, drip);
      CHECK(memcmp(whole, drip, 64U) == 0);
    }
  }
}

/* --------------------------------------------------------------------------
 * Ed25519, RFC 8032 section 7.1
 * ----------------------------------------------------------------------- */

typedef struct sig_case {
  const char *pubkey;
  const char *message;
  const char *signature;
  int valid;
} sig_case;

static const sig_case SIG_CASES[] = {
    /* TEST 1: empty message. */
    {
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        "",
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb882"
        "1"
        "590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
        1,
    },
    /* TEST 2: one byte. */
    {
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        "72",
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1"
        "e"
        "43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
        1,
    },
    /* TEST 3: two bytes. */
    {
        "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
        "af82",
        "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b"
        "5"
        "38d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
        1,
    },
    /* The same signature with its last bit flipped. */
    {
        "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
        "af82",
        "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b"
        "5"
        "38d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40b",
        0,
    },
    /* A valid signature checked against the wrong key. */
    {
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        "af82",
        "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b"
        "5"
        "38d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
        0,
    },
    /* A valid signature over a different message. */
    {
        "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
        "af83",
        "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b"
        "5"
        "38d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
        0,
    },
};

static void test_ed25519_vectors(void) {
  size_t i;
  for (i = 0; i < sizeof SIG_CASES / sizeof SIG_CASES[0]; i++) {
    const sig_case *c = &SIG_CASES[i];
    uint8_t pk[32];
    uint8_t sig[64];
    size_t mlen = unhex(c->message, scratch_b, sizeof scratch_b);
    bs_status st;
    CHECK(unhex(c->pubkey, pk, sizeof pk) == 32U);
    CHECK(unhex(c->signature, sig, sizeof sig) == 64U);
    {
      bs_span msg = bs_span_make(scratch_b, mlen);
      st = bs_ed25519_verify_parts(bs_span_make(pk, 32U),
                                   bs_span_make(sig, 64U), &msg, 1U);
    }
    CHECK((st == BS_OK) == (c->valid != 0));
  }
}

static bs_status verify_one(bs_span pk, bs_span sig, bs_span msg) {
  return bs_ed25519_verify_parts(pk, sig, &msg, 1U);
}

static void test_ed25519_rejects_bad_shapes(void) {
  uint8_t pk[32];
  uint8_t sig[64];
  (void)unhex(
      "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", pk,
      sizeof pk);
  memset(sig, 0, sizeof sig);

  /* Wrong widths are a verification failure, never a crash and never a pass. */
  CHECK(verify_one(bs_span_make(pk, 31U), bs_span_make(sig, 64U),
                   bs_span_make(NULL, 0U)) == BS_ERR_SIGNATURE);
  CHECK(verify_one(bs_span_make(pk, 32U), bs_span_make(sig, 63U),
                   bs_span_make(NULL, 0U)) == BS_ERR_SIGNATURE);
  CHECK(verify_one(bs_span_make(NULL, 0U), bs_span_make(sig, 64U),
                   bs_span_make(NULL, 0U)) == BS_ERR_SIGNATURE);

  /* An all-zero signature must not verify against a real key. */
  CHECK(verify_one(bs_span_make(pk, 32U), bs_span_make(sig, 64U),
                   bs_span_make(NULL, 0U)) == BS_ERR_SIGNATURE);

  /* A public key that is not a point on the curve. */
  memset(pk, 0xFF, sizeof pk);
  CHECK(verify_one(bs_span_make(pk, 32U), bs_span_make(sig, 64U),
                   bs_span_make(NULL, 0U)) == BS_ERR_SIGNATURE);
}

/* L, the order of the Ed25519 base point, little-endian. Adding it to a
 * signature's S half produces a different byte string that satisfies the same
 * verification equation -- which is precisely what must be refused. */
static const uint8_t ED25519_L[32] = {
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7,
    0xa2, 0xde, 0xf9, 0xde, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
};

/* out = in + k*L, little-endian, modulo 2^256. */
static void add_l(const uint8_t in[32], unsigned int k, uint8_t out[32]) {
  unsigned int i;
  unsigned int j;
  for (i = 0; i < 32U; i++) {
    out[i] = in[i];
  }
  for (j = 0; j < k; j++) {
    unsigned int carry = 0;
    for (i = 0; i < 32U; i++) {
      unsigned int sum =
          (unsigned int)out[i] + (unsigned int)ED25519_L[i] + carry;
      out[i] = (uint8_t)(sum & 0xFFU);
      carry = sum >> 8U;
    }
  }
}

static void test_ed25519_rejects_malleable_signatures(void) {
  /* This is a regression test for a defect that shipped.
   *
   * L*B is the identity, so S and S + k*L give the same point and both
   * satisfy the verification equation. The vendored NaCl code predates the
   * requirement to reject that, and nothing here added the check -- so for a
   * while any holder of a token could produce a different byte string that
   * still verified.
   *
   * That is not cosmetic: the specification defines a block's revocation
   * identifier as its signature, so a malleable signature is a revocation
   * identifier the holder can rewrite, and a deny-list naming a token could
   * be stepped around by whoever holds it. */
  uint8_t pk[32];
  uint8_t sig[64];
  uint8_t mutated[64];
  unsigned int k;

  (void)unhex(
      "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", pk,
      sizeof pk);
  (void)unhex(
      "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
      "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
      sig, sizeof sig);

  /* The canonical signature verifies. */
  CHECK(verify_one(bs_span_make(pk, 32U), bs_span_make(sig, 64U),
                   bs_span_make(NULL, 0U)) == BS_OK);

  /* Every non-canonical variant of it must not. */
  for (k = 1U; k <= 4U; k++) {
    memcpy(mutated, sig, 64U);
    add_l(&sig[32], k, &mutated[32]);
    CHECK(memcmp(mutated, sig, 64U) != 0);
    CHECK(verify_one(bs_span_make(pk, 32U), bs_span_make(mutated, 64U),
                     bs_span_make(NULL, 0U)) == BS_ERR_SIGNATURE);
  }

  /* S exactly equal to L is also non-canonical: the bound is strict. */
  memcpy(mutated, sig, 64U);
  memcpy(&mutated[32], ED25519_L, 32U);
  CHECK(verify_one(bs_span_make(pk, 32U), bs_span_make(mutated, 64U),
                   bs_span_make(NULL, 0U)) == BS_ERR_SIGNATURE);
}

static void test_ed25519_rejects_small_order_keys(void) {
  /* A small-order public key makes one signature verify every message, which
   * empties "signed by that key" of content. The reference rejects these
   * through verify_strict; so does this. */
  static const uint8_t small_order[][32] = {
      /* the identity */
      {
          0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      },
      /* the point of order two */
      {
          0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
          0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
          0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
      },
      /* one of the points of order eight */
      {
          0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0, 0x45, 0xc3, 0xf4,
          0x89, 0xf2, 0xef, 0x98, 0xf0, 0xd5, 0xdf, 0xac, 0x05, 0xd3, 0xc6,
          0x33, 0x39, 0xb1, 0x38, 0x02, 0x88, 0x6d, 0x53, 0xfc, 0x05,
      },
  };
  uint8_t sig[64];
  size_t i;

  memset(sig, 0, sizeof sig);
  sig[32] = 1U; /* a canonical S, so the scalar check is not what rejects it */

  for (i = 0; i < sizeof small_order / sizeof small_order[0]; i++) {
    CHECK(verify_one(bs_span_make(small_order[i], 32U), bs_span_make(sig, 64U),
                     bs_span_make(NULL, 0U)) == BS_ERR_SIGNATURE);
  }
}

int main(void) {
  test_sha512_vectors();
  test_sha512_streaming_matches_one_shot();
  test_ed25519_vectors();
  test_ed25519_rejects_bad_shapes();
  test_ed25519_rejects_malleable_signatures();
  test_ed25519_rejects_small_order_keys();
  return bs_test_finish();
}
