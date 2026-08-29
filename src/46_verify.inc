#ifdef BS_BUNDLED_CRYPTO

/* ---------------------------------------------------------------------------
 * SHA-512, streaming, and detached Ed25519 verification
 *
 * Upstream's one-shot hash and its crypto_sign_open both want the whole input
 * in one contiguous buffer -- for verification that means signature followed
 * by message, and the message copied out again afterwards. Two buffers the
 * size of the input, in a library whose first invariant is that it never
 * allocates.
 *
 * So the hash is streamed and the verification equation is assembled here
 * instead. Every arithmetic operation below is the vendored one, called in
 * the same order upstream calls it; what changes is only where the bytes
 * live. tests/unit/test_crypto.c checks the result against the RFC 8032
 * vectors, rejection cases included, which is what makes that claim testable
 * rather than merely stated.
 * ------------------------------------------------------------------------ */

#define BS_SHA512_BLOCK 128U
#define BS_SHA512_DIGEST 64U

typedef struct bs_sha512 {
  uint8_t state[BS_SHA512_DIGEST];
  uint8_t buf[BS_SHA512_BLOCK];
  size_t buflen;
  uint64_t total; /* message length in bytes */
} bs_sha512;

static void bs_sha512_init(bs_sha512 *h) {
  size_t i;
  for (i = 0; i < BS_SHA512_DIGEST; i++) {
    h->state[i] = bs_na_iv[i];
  }
  h->buflen = 0U;
  h->total = 0U;
}

static void bs_sha512_update(bs_sha512 *h, bs_span in) {
  size_t off = 0;
  bs_span chunk;

  h->total += (uint64_t)in.n;

  /* Top up a partial block first, so the fast path below can hand whole
   * blocks straight to the compression function without copying. */
  if (h->buflen != 0U) {
    size_t want = BS_SHA512_BLOCK - h->buflen;
    size_t take = (in.n < want) ? in.n : want;
    if (!bs_span_slice(in, 0U, take, &chunk)) {
      return;
    }
    if (take != 0U) {
      memcpy(&h->buf[h->buflen], chunk.p, take);
    }
    h->buflen += take;
    off = take;
    if (h->buflen < BS_SHA512_BLOCK) {
      return;
    }
    (void)bs_na_crypto_hashblocks(h->state, h->buf, BS_SHA512_BLOCK);
    h->buflen = 0U;
  }

  {
    size_t rest = in.n - off;
    size_t whole = rest & ~(size_t)(BS_SHA512_BLOCK - 1U);
    if (whole != 0U) {
      if (!bs_span_slice(in, off, whole, &chunk)) {
        return;
      }
      (void)bs_na_crypto_hashblocks(h->state, chunk.p, whole);
      off += whole;
      rest -= whole;
    }
    if (rest != 0U) {
      if (!bs_span_slice(in, off, rest, &chunk)) {
        return;
      }
      memcpy(h->buf, chunk.p, rest);
      h->buflen = rest;
    }
  }
}

/* The padding is upstream's, transcribed: the tail, a 0x80 byte, zeroes, and
 * the bit length in the last sixteen bytes -- one extra block when the tail
 * leaves no room for the length. */
static void bs_sha512_final(bs_sha512 *h, uint8_t out[BS_SHA512_DIGEST]) {
  uint8_t x[2U * BS_SHA512_BLOCK];
  uint64_t bits = h->total;
  size_t n = h->buflen;
  size_t i;

  memset(x, 0, sizeof x);
  memcpy(x, h->buf, n);
  x[n] = 0x80U;
  n = (n < 112U) ? BS_SHA512_BLOCK : (2U * BS_SHA512_BLOCK);
  x[n - 9U] = (uint8_t)(bits >> 61U);
  bs_na_ts64(&x[n - 8U], bits << 3U);
  (void)bs_na_crypto_hashblocks(h->state, x, n);

  for (i = 0; i < BS_SHA512_DIGEST; i++) {
    out[i] = h->state[i];
  }
}

/* Is the signature's S half a canonically reduced scalar, that is S < L?
 *
 * It has to be checked, and this cost the project a real defect. L*B is the
 * identity, so S and S + k*L give the same point and both satisfy the
 * verification equation: without this check a signature is malleable, and
 * anyone holding a token can produce a different byte string that still
 * verifies.
 *
 * That is not merely untidy here. The specification defines a block's
 * revocation identifier as its signature, "as it uniquely identifies the
 * block" -- so a malleable signature is a malleable revocation identifier,
 * and a deny-list keyed on it can be stepped around by the holder of the very
 * token it names. The reference implementation checks this (ed25519-dalek's
 * verify_strict); the vendored NaCl code predates the requirement and does
 * not.
 *
 * Constant-time, in the shape libsodium uses: walking down from the most
 * significant byte, `n` stays set while every byte so far has matched, and
 * `c` latches as soon as a byte of S falls below the corresponding byte of L.
 */
static int bs_scalar_is_canonical(bs_span s) {
  unsigned int c = 0;
  unsigned int n = 1;
  size_t i = 32U;

  if (s.n != 32U) {
    return 0;
  }
  do {
    unsigned int a;
    unsigned int b;
    i--;
    a = (unsigned int)s.p[i];
    b = (unsigned int)bs_na_L[i];
    c |= ((a - b) >> 8U) & n & 1U;
    n &= (((a ^ b) - 1U) >> 8U) & 1U;
  } while (i != 0U);

  return c != 0U;
}

/* Does this point have order dividing 8?
 *
 * A small-order public key makes one signature verify every message, which
 * turns "this block was signed by that third party" into a statement with no
 * content. The reference rejects these too, via verify_strict.
 *
 * Checked by tripling the point rather than by comparing against a table of
 * known small-order encodings: three doublings cost almost nothing next to
 * the scalar multiplication already happening, and a table is a transcription
 * that can be got wrong silently. */
static int bs_point_is_small_order(const bs_na_gf *q) {
  bs_na_gf p[4];
  uint8_t enc[32];
  size_t i;
  size_t j;
  unsigned int diff;

  for (i = 0; i < 4U; i++) {
    for (j = 0; j < 16U; j++) {
      p[i][j] = q[i][j];
    }
  }
  bs_na_add(p, p); /* 2Q */
  bs_na_add(p, p); /* 4Q */
  bs_na_add(p, p); /* 8Q */
  bs_na_pack(enc, p);

  /* The identity encodes as 1. */
  diff = (unsigned int)enc[0] ^ 1U;
  for (i = 1U; i < 32U; i++) {
    diff |= (unsigned int)enc[i];
  }
  return diff == 0U;
}

/* Verify a detached Ed25519 signature.
 *
 * The equation is the one in RFC 8032 section 5.1.7: with A the public key,
 * R the first half of the signature and S the second,
 *
 *     S*B - SHA512(R || A || message) * A  ==  R
 *
 * A malformed key or a signature of the wrong width is a verification
 * failure, not a separate error: from the caller's side there is nothing to
 * distinguish "this token was not signed by you" from "this token's signature
 * could not even be parsed", and giving them different names invites a caller
 * to treat one as recoverable. */
static bs_status bs_ed25519_verify_parts(bs_span pubkey, bs_span sig,
                                         const bs_span *parts,
                                         size_t part_count) {
  bs_na_gf p[4];
  bs_na_gf q[4];
  uint8_t h[BS_SHA512_DIGEST];
  uint8_t t[32];
  bs_sha512 sha;
  bs_span r;
  bs_span s;

  if (pubkey.n != 32U || sig.n != 64U) {
    return BS_ERR_SIGNATURE;
  }
  /* The two halves, taken through the span accessors rather than by pointer
   * arithmetic, so invariant 4 holds here as everywhere else. */
  if (!bs_span_slice(sig, 0U, 32U, &r) || !bs_span_slice(sig, 32U, 32U, &s)) {
    return BS_ERR_SIGNATURE;
  }
  /* Both guards match the reference's verify_strict. Neither is optional:
   * see the notes on each. */
  if (!bs_scalar_is_canonical(s)) {
    return BS_ERR_SIGNATURE;
  }
  /* unpackneg yields -A, which is why the equation above is written with a
   * subtraction and computed here with an addition. */
  if (bs_na_unpackneg(q, pubkey.p) != 0) {
    return BS_ERR_SIGNATURE;
  }
  if (bs_point_is_small_order(q)) {
    return BS_ERR_SIGNATURE;
  }

  bs_sha512_init(&sha);
  bs_sha512_update(&sha, r);
  bs_sha512_update(&sha, pubkey);
  {
    size_t i;
    for (i = 0; i < part_count; i++) {
      bs_sha512_update(&sha, parts[i]);
    }
  }
  bs_sha512_final(&sha, h);
  bs_na_reduce(h);

  bs_na_scalarmult(p, q, h);
  bs_na_scalarbase(q, s.p);
  bs_na_add(p, q);
  bs_na_pack(t, p);

  /* Constant-time comparison, from upstream. Signatures are public data, so
   * this is belt rather than braces -- but a timing-variable memcmp here is
   * the kind of detail a reviewer should not have to wonder about. */
  if (bs_na_crypto_verify_32(r.p, t) != 0) {
    return BS_ERR_SIGNATURE;
  }
  return BS_OK;
}

/* Derive a public key from a 32-byte seed, to check that the proof at the end
 * of an unsealed token really belongs to the last block's next key. */
static bs_status bs_ed25519_public_from_secret(bs_span seed, uint8_t out[32]) {
  uint8_t h[BS_SHA512_DIGEST];
  bs_na_gf p[4];
  bs_sha512 s;

  if (seed.n != 32U) {
    return BS_ERR_SIGNATURE;
  }
  bs_sha512_init(&s);
  bs_sha512_update(&s, seed);
  bs_sha512_final(&s, h);
  /* RFC 8032 section 5.1.5 clamping. */
  h[0] &= 248U;
  h[31] &= 127U;
  h[31] |= 64U;
  bs_na_scalarbase(p, h);
  bs_na_pack(out, p);
  return BS_OK;
}

#endif /* BS_BUNDLED_CRYPTO */
