/* ---------------------------------------------------------------------------
 * Signature chain
 *
 * A Biscuit is a chain: the root key signs the authority block together with
 * the key that will sign the next one, and so on. Verification walks that
 * chain from the root outwards, and finishes by proving that whoever holds
 * the token also holds the last private key -- or, for a sealed token, that
 * nobody can extend it any further.
 *
 * The payloads below are byte-exact reproductions of what the reference
 * implementation signs. They are built as a list of spans and hashed in
 * order, never concatenated: the block data is the largest thing in a token,
 * and copying it to hash it would put a buffer the size of the input into a
 * library that does not allocate.
 *
 * One divergence is worth recording. For payload version 0 the specification
 * text lists the order as data, next key, algorithm; the reference
 * implementation writes data, algorithm, next key. The code is what tokens in
 * the wild are signed with, so the code is what is reproduced here. The
 * specification's own conformance samples agree with the code.
 * ------------------------------------------------------------------------ */

/* Payload markers, spelled out rather than assembled, so they can be compared
 * against the specification by eye. The leading and trailing NUL bytes are
 * part of each marker: they are what stops a crafted block from containing
 * text that impersonates a field boundary. */
#define BS_MARK_BLOCK "\0BLOCK\0\0VERSION\0"
#define BS_MARK_PAYLOAD "\0PAYLOAD\0"
#define BS_MARK_ALGORITHM "\0ALGORITHM\0"
#define BS_MARK_NEXTKEY "\0NEXTKEY\0"
#define BS_MARK_PREVSIG "\0PREVSIG\0"
#define BS_MARK_EXTERNALSIG "\0EXTERNALSIG\0"
#define BS_MARK_EXTERNAL "\0EXTERNAL\0\0VERSION\0"

/* A marker span. sizeof - 1 drops the terminator the compiler adds, not the
 * NUL that belongs to the marker itself. */
#define BS_MARK(lit) bs_span_make("" lit, sizeof(lit) - 1U)

static void bs_le32(uint8_t out[4], uint32_t v) {
  out[0] = (uint8_t)(v & 0xFFU);
  out[1] = (uint8_t)((v >> 8U) & 0xFFU);
  out[2] = (uint8_t)((v >> 16U) & 0xFFU);
  out[3] = (uint8_t)((v >> 24U) & 0xFFU);
}

/* Build the payload a block's signature covers.
 *
 * `prev_sig` is empty for the authority block, which has no predecessor. In
 * payload version 1 that is load-bearing: the authority's payload has no
 * PREVSIG section, so an authority signature cannot be replayed in any other
 * position or any other token.
 *
 * Version 0 gives no such guarantee. There, the authority and appended
 * payloads are identical by construction -- data, algorithm, next key, with
 * nothing naming the position -- which is exactly the weakness version 1
 * exists to close. Reproduced here because tokens signed that way exist, not
 * because it is sound. */
static bs_status bs_block_payload(const bs_signed_block *b, bs_span prev_sig,
                                  int is_authority, uint8_t ver_le[4],
                                  uint8_t alg_le[4], bs_span *parts,
                                  size_t *count) {
  size_t n = 0;

  bs_le32(ver_le, b->version);
  bs_le32(alg_le, (uint32_t)b->next_key.alg);

  if (b->version == 0U) {
    /* Deprecated, and reproduced only because tokens signed this way exist.
     * Note the order: data, algorithm, next key -- see the file header. */
    parts[n++] = b->block;
    if (b->has_external) {
      parts[n++] = b->external_signature;
    }
    parts[n++] = bs_span_make(alg_le, 4U);
    parts[n++] = b->next_key.key;
    *count = n;
    return BS_OK;
  }

  if (b->version != 1U) {
    /* A version this build does not know how to hash. Refused rather than
     * guessed: a signature checked against the wrong payload is not a
     * signature check at all. */
    return BS_ERR_UNSUPPORTED;
  }

  parts[n++] = BS_MARK(BS_MARK_BLOCK);
  parts[n++] = bs_span_make(ver_le, 4U);
  parts[n++] = BS_MARK(BS_MARK_PAYLOAD);
  parts[n++] = b->block;
  parts[n++] = BS_MARK(BS_MARK_ALGORITHM);
  parts[n++] = bs_span_make(alg_le, 4U);
  parts[n++] = BS_MARK(BS_MARK_NEXTKEY);
  parts[n++] = b->next_key.key;

  if (!is_authority) {
    parts[n++] = BS_MARK(BS_MARK_PREVSIG);
    parts[n++] = prev_sig;
    if (b->has_external) {
      parts[n++] = BS_MARK(BS_MARK_EXTERNALSIG);
      parts[n++] = b->external_signature;
    }
  }

  BS_ASSERT(n <= BS_MAX_SIG_PARTS);
  *count = n;
  return BS_OK;
}

/* The payload a third-party signature covers.
 *
 * It deliberately does not name the next key: a third party signs its own
 * block and the chain position it was handed, so its signature says "I
 * authored this block, here" and nothing about what comes after. */
static bs_status bs_external_payload(const bs_signed_block *b, bs_span prev_sig,
                                     uint8_t ver_le[4], bs_span *parts,
                                     size_t *count) {
  size_t n = 0;

  if (b->version != 1U) {
    /* External signature payload v0 is withdrawn by the specification, and
     * the container decoder already refuses a third-party block that is not
     * version 1. */
    return BS_ERR_UNSUPPORTED;
  }

  bs_le32(ver_le, b->version);
  parts[n++] = BS_MARK(BS_MARK_EXTERNAL);
  parts[n++] = bs_span_make(ver_le, 4U);
  parts[n++] = BS_MARK(BS_MARK_PAYLOAD);
  parts[n++] = b->block;
  parts[n++] = BS_MARK(BS_MARK_PREVSIG);
  parts[n++] = prev_sig;

  BS_ASSERT(n <= BS_MAX_SIG_PARTS);
  *count = n;
  return BS_OK;
}

/* Verify a token's signature chain against a root public key.
 *
 * Returns BS_OK only when every block verifies, every external signature
 * verifies, and the proof at the end matches. Any other status means the
 * token is not authentic; none of them means "probably fine".
 *
 * This says nothing about whether the token authorizes anything. That is the
 * authorizer's question, and keeping the two apart is what stops a caller
 * from treating a well-formed token as an authorized one. */
BS_API bs_status bs_token_verify(const bs_token *t, bs_span root_key) {
  bs_span parts[BS_MAX_SIG_PARTS];
  uint8_t ver_le[4];
  uint8_t alg_le[4];
  bs_span current = root_key;
  bs_span prev_sig = bs_span_make(NULL, 0);
  size_t i;

  if (t == NULL || t->blocks == NULL || t->block_count == 0U) {
    return BS_ERR_ARGUMENT;
  }
  if (root_key.n != BS_ED25519_PUBKEY_LEN) {
    return BS_ERR_UNSUPPORTED;
  }

  for (i = 0; i < t->block_count; i++) {
    const bs_signed_block *b = &t->blocks[i];
    size_t count = 0;
    bs_status st;

    st =
        bs_block_payload(b, prev_sig, (i == 0U), ver_le, alg_le, parts, &count);
    if (st != BS_OK) {
      return st;
    }
    st = bs_ed25519_verify_parts(current, b->signature, parts, count);
    if (st != BS_OK) {
      return st;
    }

    if (b->has_external) {
      st = bs_external_payload(b, prev_sig, ver_le, parts, &count);
      if (st != BS_OK) {
        return st;
      }
      st = bs_ed25519_verify_parts(b->external_key.key, b->external_signature,
                                   parts, count);
      if (st != BS_OK) {
        return st;
      }
    }

    current = b->next_key.key;
    prev_sig = b->signature;
  }

  if (t->sealed) {
    /* A sealed token proves that no further block can be appended: the last
     * private key was used once more, over the last block, and then discarded.
     * The payload is the seal payload, which has no version marker. */
    const bs_signed_block *last = &t->blocks[t->block_count - 1U];
    size_t n = 0;
    bs_le32(alg_le, (uint32_t)last->next_key.alg);
    parts[n++] = last->block;
    parts[n++] = bs_span_make(alg_le, 4U);
    parts[n++] = last->next_key.key;
    parts[n++] = last->signature;
    return bs_ed25519_verify_parts(current, t->proof, parts, n);
  }

  /* An open token carries the next private key, so that the holder can
   * attenuate it. Checking that it matches the last public key is what proves
   * the token was not truncated: lopping off the final block would leave a
   * proof that belongs to a key no longer in the chain. */
  {
    uint8_t derived[BS_ED25519_PUBKEY_LEN];
    bs_status st = bs_ed25519_public_from_secret(t->proof, derived);
    if (st != BS_OK) {
      return st;
    }
    if (!bs_span_eq(bs_span_make(derived, sizeof derived), current)) {
      return BS_ERR_SIGNATURE;
    }
  }
  return BS_OK;
}
