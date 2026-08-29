/* Decode and verify against the sample suite's root key.
 *
 * The seed corpus is signed with that key, so the corpus exercises the whole
 * chain rather than stopping at the first signature. What this target hunts
 * is an input that verifies when it should not -- a mutated token that still
 * returns BS_OK is the finding that matters most in the whole project.
 */

#include "fuzz_common.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  bs_arena *a = fuzz_arena();
  bs_token t;

  if (bs_token_parse(a, bs_span_make(data, size), &t) != BS_OK) {
    return 0;
  }

  if (bs_token_verify(&t, fuzz_root_key()) == BS_OK) {
    /* A verified token must still satisfy every structural invariant: nothing
     * about holding a valid signature makes a malformed container safe. */
    assert(t.block_count >= 1U);
    assert(t.blocks[t.block_count - 1U].next_key.key.n ==
           BS_ED25519_PUBKEY_LEN);
    assert(t.proof.n ==
           (t.sealed ? BS_ED25519_SIG_LEN : BS_ED25519_SECRET_LEN));
  }

  /* Verification must be deterministic: the same bytes twice give the same
   * answer. A difference would mean state leaking between calls. */
  {
    bs_arena *b = fuzz_arena();
    bs_token u;
    if (bs_token_parse(b, bs_span_make(data, size), &u) == BS_OK) {
      assert(bs_token_verify(&u, fuzz_root_key()) ==
             bs_token_verify(&u, fuzz_root_key()));
    }
  }
  return 0;
}
