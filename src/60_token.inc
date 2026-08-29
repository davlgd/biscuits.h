/* ---------------------------------------------------------------------------
 * Token container
 *
 * Decodes the outer `Biscuit` message: the authority block, the appended
 * blocks, and the proof. The Datalog inside each block is left as bytes here
 * and decoded separately, because signature verification happens first and
 * operates on exactly these undecoded bytes.
 *
 * Nothing in this file verifies anything. A token that parses is a token that
 * is *shaped* correctly; whether it is authentic is a later question, and
 * keeping the two apart is what stops a decode error from ever being mistaken
 * for a successful verification.
 * ------------------------------------------------------------------------ */

/* Field numbers, from schema.proto. Named rather than inlined because a
 * transposed digit here is a silent misparse, not a compile error. */
#define BS_F_BISCUIT_ROOT_KEY_ID 1U
#define BS_F_BISCUIT_AUTHORITY 2U
#define BS_F_BISCUIT_BLOCKS 3U
#define BS_F_BISCUIT_PROOF 4U

#define BS_F_SIGNED_BLOCK 1U
#define BS_F_SIGNED_NEXT_KEY 2U
#define BS_F_SIGNED_SIGNATURE 3U
#define BS_F_SIGNED_EXTERNAL_SIG 4U
#define BS_F_SIGNED_VERSION 5U

#define BS_F_EXTSIG_SIGNATURE 1U
#define BS_F_EXTSIG_PUBLIC_KEY 2U

#define BS_F_PUBKEY_ALGORITHM 1U
#define BS_F_PUBKEY_KEY 2U

#define BS_F_PROOF_NEXT_SECRET 1U
#define BS_F_PROOF_FINAL_SIGNATURE 2U

/* Key widths. Ed25519 is a compressed Edwards point; secp256r1 is a
 * compressed SEC1 point whose leading byte must be 0x02 or 0x03. */
#define BS_ED25519_PUBKEY_LEN 32U
#define BS_ED25519_SIG_LEN 64U
#define BS_SECP256R1_PUBKEY_LEN 33U

static bs_status bs_pb_pubkey(bs_span in, bs_public_key *out) {
  bs_cursor c = bs_cursor_make(in);
  bs_pb_field f;
  int have_alg = 0;
  int have_key = 0;
  uint64_t alg = 0;
  bs_span key = bs_span_make(NULL, 0);

  while (!bs_cursor_done(&c)) {
    if (!bs_pb_next(&c, &f)) {
      return BS_ERR_MALFORMED;
    }
    if (f.number == BS_F_PUBKEY_ALGORITHM && f.wire == BS_PB_VARINT) {
      alg = f.varint;
      have_alg = 1;
    } else if (f.number == BS_F_PUBKEY_KEY && f.wire == BS_PB_BYTES) {
      key = f.bytes;
      have_key = 1;
    }
  }
  if (!have_alg || !have_key) {
    return BS_ERR_MALFORMED; /* both are `required` in the schema */
  }

  switch (alg) {
  case (uint64_t)BS_ALG_ED25519:
    if (key.n != BS_ED25519_PUBKEY_LEN) {
      return BS_ERR_MALFORMED;
    }
    break;
  case (uint64_t)BS_ALG_SECP256R1:
    if (key.n != BS_SECP256R1_PUBKEY_LEN ||
        (key.p[0] != 0x02U && key.p[0] != 0x03U)) {
      return BS_ERR_MALFORMED;
    }
    /* Recognised, and refused rather than ignored: a token this build cannot
     * check must never be reported as one it checked. See SECURITY.md. */
    return BS_ERR_UNSUPPORTED;
  default:
    return BS_ERR_MALFORMED;
  }

  out->alg = (bs_alg)alg;
  out->key = key;
  return BS_OK;
}

static bs_status bs_pb_external_sig(bs_span in, bs_signed_block *out) {
  bs_cursor c = bs_cursor_make(in);
  bs_pb_field f;
  int have_sig = 0;
  int have_key = 0;

  while (!bs_cursor_done(&c)) {
    if (!bs_pb_next(&c, &f)) {
      return BS_ERR_MALFORMED;
    }
    if (f.number == BS_F_EXTSIG_SIGNATURE && f.wire == BS_PB_BYTES) {
      out->external_signature = f.bytes;
      have_sig = 1;
    } else if (f.number == BS_F_EXTSIG_PUBLIC_KEY && f.wire == BS_PB_BYTES) {
      bs_status st = bs_pb_pubkey(f.bytes, &out->external_key);
      if (st != BS_OK) {
        return st;
      }
      have_key = 1;
    }
  }
  if (!have_sig || !have_key) {
    return BS_ERR_MALFORMED;
  }
  out->has_external = 1;
  return BS_OK;
}

static bs_status bs_pb_signed_block(bs_span in, bs_signed_block *out) {
  bs_cursor c = bs_cursor_make(in);
  bs_pb_field f;
  int have_block = 0;
  int have_next = 0;
  int have_sig = 0;

  out->block = bs_span_make(NULL, 0);
  out->signature = bs_span_make(NULL, 0);
  out->external_signature = bs_span_make(NULL, 0);
  out->has_external = 0;
  out->version = 0; /* absent means version 0, per the specification */

  while (!bs_cursor_done(&c)) {
    bs_status st;
    if (!bs_pb_next(&c, &f)) {
      return BS_ERR_MALFORMED;
    }
    switch (f.number) {
    case BS_F_SIGNED_BLOCK:
      if (f.wire != BS_PB_BYTES) {
        return BS_ERR_MALFORMED;
      }
      out->block = f.bytes;
      have_block = 1;
      break;
    case BS_F_SIGNED_NEXT_KEY:
      if (f.wire != BS_PB_BYTES) {
        return BS_ERR_MALFORMED;
      }
      st = bs_pb_pubkey(f.bytes, &out->next_key);
      if (st != BS_OK) {
        return st;
      }
      have_next = 1;
      break;
    case BS_F_SIGNED_SIGNATURE:
      if (f.wire != BS_PB_BYTES) {
        return BS_ERR_MALFORMED;
      }
      out->signature = f.bytes;
      have_sig = 1;
      break;
    case BS_F_SIGNED_EXTERNAL_SIG:
      if (f.wire != BS_PB_BYTES) {
        return BS_ERR_MALFORMED;
      }
      st = bs_pb_external_sig(f.bytes, out);
      if (st != BS_OK) {
        return st;
      }
      break;
    case BS_F_SIGNED_VERSION:
      if (f.wire != BS_PB_VARINT || f.varint > 0xFFFFFFFFU) {
        return BS_ERR_MALFORMED;
      }
      out->version = (uint32_t)f.varint;
      break;
    default:
      break; /* unknown field: well-formed, and ignored */
    }
  }

  if (!have_block || !have_next || !have_sig) {
    return BS_ERR_MALFORMED;
  }
  /* A signature is verified with the *previous* block's key, whose algorithm
   * this function cannot see. That does not matter while Ed25519 is the only
   * algorithm this build accepts -- every other one has already been refused
   * by bs_pb_pubkey -- so every signature must be 64 bytes.
   *
   * When secp256r1 lands in 1.1 this check moves to the verifier, which knows
   * the signing key. Until then, catching a truncated signature here is what
   * stops a malformed token from reaching the crypto at all. */
  if (out->signature.n != BS_ED25519_SIG_LEN) {
    return BS_ERR_MALFORMED;
  }
  if (out->has_external && out->external_signature.n != BS_ED25519_SIG_LEN) {
    return BS_ERR_MALFORMED;
  }
  return BS_OK;
}

static bs_status bs_pb_proof(bs_span in, bs_token *out) {
  bs_cursor c = bs_cursor_make(in);
  bs_pb_field f;
  int seen = 0;

  while (!bs_cursor_done(&c)) {
    if (!bs_pb_next(&c, &f)) {
      return BS_ERR_MALFORMED;
    }
    if (f.wire != BS_PB_BYTES) {
      continue;
    }
    if (f.number == BS_F_PROOF_NEXT_SECRET) {
      out->sealed = 0;
      out->proof = f.bytes;
      seen++;
    } else if (f.number == BS_F_PROOF_FINAL_SIGNATURE) {
      out->sealed = 1;
      out->proof = f.bytes;
      seen++;
    }
  }
  /* The schema makes these a oneof: exactly one, never both, never neither.
   * A token carrying both would let a verifier pick the branch it prefers. */
  if (seen != 1) {
    return BS_ERR_MALFORMED;
  }
  return BS_OK;
}

BS_API bs_status bs_token_parse(bs_arena *a, bs_span input, bs_token *out) {
  bs_cursor c;
  bs_pb_field f;
  size_t appended = 0;
  size_t index;
  bs_span authority = bs_span_make(NULL, 0);
  bs_span proof = bs_span_make(NULL, 0);
  int have_authority = 0;
  int have_proof = 0;
  bs_token tok;

  if (a == NULL || out == NULL) {
    return BS_ERR_ARGUMENT;
  }

  tok.has_root_key_id = 0;
  tok.root_key_id = 0;
  tok.blocks = NULL;
  tok.block_count = 0;
  tok.sealed = 0;
  tok.proof = bs_span_make(NULL, 0);

  /* First pass: locate the top-level fields and count the appended blocks.
   * Counting before allocating is what keeps the arena free of any growth
   * strategy -- there is no realloc here because there is never a second
   * guess about how many blocks there are. */
  c = bs_cursor_make(input);
  while (!bs_cursor_done(&c)) {
    if (!bs_pb_next(&c, &f)) {
      return BS_ERR_MALFORMED;
    }
    switch (f.number) {
    case BS_F_BISCUIT_ROOT_KEY_ID:
      if (f.wire != BS_PB_VARINT || f.varint > 0xFFFFFFFFU) {
        return BS_ERR_MALFORMED;
      }
      tok.root_key_id = (uint32_t)f.varint;
      tok.has_root_key_id = 1;
      break;
    case BS_F_BISCUIT_AUTHORITY:
      if (f.wire != BS_PB_BYTES) {
        return BS_ERR_MALFORMED;
      }
      authority = f.bytes;
      have_authority = 1;
      break;
    case BS_F_BISCUIT_BLOCKS:
      if (f.wire != BS_PB_BYTES) {
        return BS_ERR_MALFORMED;
      }
      appended++;
      break;
    case BS_F_BISCUIT_PROOF:
      if (f.wire != BS_PB_BYTES) {
        return BS_ERR_MALFORMED;
      }
      proof = f.bytes;
      have_proof = 1;
      break;
    default:
      break;
    }
  }

  if (!have_authority || !have_proof) {
    return BS_ERR_MALFORMED;
  }
  /* Every block costs a signature verification, so the ceiling is a denial-of
   * -service bound as much as a memory one. */
  if (appended + 1U > (size_t)BS_MAX_BLOCKS) {
    return BS_ERR_LIMIT;
  }

  tok.block_count = appended + 1U;
  tok.blocks = (bs_signed_block *)bs_arena_array(
      a, tok.block_count, sizeof(bs_signed_block), BS_ALIGN_MAX);
  if (tok.blocks == NULL) {
    return BS_ERR_NOMEM;
  }

  /* Second pass: decode each block in wire order. Order is load-bearing --
   * the signature chain is verified block by block from the authority
   * outwards, and a reordered token must not verify. */
  {
    bs_status st = bs_pb_signed_block(authority, &tok.blocks[0]);
    if (st != BS_OK) {
      return st;
    }
  }

  index = 1U;
  c = bs_cursor_make(input);
  while (!bs_cursor_done(&c)) {
    if (!bs_pb_next(&c, &f)) {
      return BS_ERR_MALFORMED; /* unreachable: the first pass validated it */
    }
    if (f.number == BS_F_BISCUIT_BLOCKS && f.wire == BS_PB_BYTES) {
      bs_status st;
      if (index >= tok.block_count) {
        return BS_ERR_MALFORMED;
      }
      st = bs_pb_signed_block(f.bytes, &tok.blocks[index]);
      if (st != BS_OK) {
        return st;
      }
      index++;
    }
  }
  if (index != tok.block_count) {
    return BS_ERR_MALFORMED;
  }

  {
    bs_status st = bs_pb_proof(proof, &tok);
    if (st != BS_OK) {
      return st;
    }
  }

  *out = tok;
  return BS_OK;
}

BS_API bs_span bs_token_revocation_id(const bs_token *t, size_t index) {
  if (t == NULL || t->blocks == NULL || index >= t->block_count) {
    return bs_span_make(NULL, 0);
  }
  /* The revocation identifier for a block is its signature, verbatim. */
  return t->blocks[index].signature;
}
