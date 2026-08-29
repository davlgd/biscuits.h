/* The container decoder, fed arbitrary bytes.
 *
 * This is the shallowest target and the most important one: every other path
 * in the library is downstream of a token that parsed. It is also the only
 * code that sees bytes before any length has been validated.
 */

#include "fuzz_common.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  bs_token t;
  bs_status st = bs_token_parse(fuzz_arena(), bs_span_make(data, size), &t);

  if (st != BS_OK) {
    return 0;
  }

  /* On success the token must be internally consistent. These are the
   * invariants the decoder promises; if any is false the parse should have
   * failed, and finding that input is the point. */
  assert(t.blocks != NULL);
  assert(t.block_count >= 1U);
  assert(t.block_count <= (size_t)BS_MAX_BLOCKS);
  {
    size_t i;
    for (i = 0; i < t.block_count; i++) {
      assert(t.blocks[i].signature.n == BS_ED25519_SIG_LEN);
      assert(t.blocks[i].next_key.key.n == BS_ED25519_PUBKEY_LEN);
      /* The authority block can never carry an external signature. */
      assert(i != 0U || !t.blocks[i].has_external);
      /* Every revocation identifier is the block's signature, verbatim. */
      assert(bs_span_eq(bs_token_revocation_id(&t, i), t.blocks[i].signature));
    }
    assert(bs_token_revocation_id(&t, t.block_count).n == 0U);
  }
  return 0;
}
