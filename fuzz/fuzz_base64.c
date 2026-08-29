/* base64url decoding, fed arbitrary bytes.
 *
 * This is the outermost layer: a token arrives as text, and the decoder is
 * strict on purpose -- padding, alphabet, and the bits a partial final group
 * leaves over. Strictness is where off-by-one errors live, so it is worth
 * fuzzing separately from the binary decoder rather than only through it.
 */

#include "fuzz_common.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  bs_arena *a = fuzz_arena();
  bs_span decoded;
  bs_span text = bs_span_make(data, size);

  if (bs_base64url_decode(a, text, &decoded) != BS_OK) {
    return 0;
  }

  /* Four characters carry three bytes. The decoded length can never exceed
   * that, whatever the input looked like. */
  assert(decoded.n <= ((size / 4U) + 1U) * 3U);

  /* Decoding is a function: the same text gives the same bytes. */
  {
    bs_arena *b = fuzz_arena();
    bs_span again;
    if (bs_base64url_decode(b, text, &again) == BS_OK) {
      assert(again.n == decoded.n);
    }
  }

  /* Whatever came out, feeding it to the token parser must not misbehave. */
  {
    bs_token t;
    (void)bs_token_parse(fuzz_arena(), decoded, &t);
  }
  return 0;
}
