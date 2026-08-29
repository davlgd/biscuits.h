/* Decode a token and render every block back to Datalog source.
 *
 * This reaches the deepest code in the library: the symbol table, the term
 * decoder with its nesting bound, the expression opcode machine and the
 * rule and check printers. A crash here is a crash on a token someone could
 * simply hand to a gateway.
 */

#include "fuzz_common.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  bs_arena *a = fuzz_arena();
  bs_token t;
  bs_tables tab;
  size_t i;

  if (bs_token_parse(a, bs_span_make(data, size), &t) != BS_OK) {
    return 0;
  }
  if (bs_tables_build(a, &t, &tab) != BS_OK) {
    return 0;
  }

  for (i = 0; i < t.block_count; i++) {
    bs_writer *w = fuzz_writer();
    const bs_tables *use = &tab;
    bs_tables own;

    /* A third-party block numbers only its own symbols and keys. */
    if (t.blocks[i].has_external &&
        bs_tables_build_block(a, t.blocks[i].block, &own) == BS_OK) {
      use = &own;
    }
    if (bs_block_print(w, a, use, t.blocks[i].block) == BS_OK) {
      /* A successful render never reports overflow, and never claims to have
       * written more than the buffer holds. */
      assert(!bs_writer_overflow(w));
      assert(bs_writer_len(w) <= FUZZ_RENDER_BYTES);
    }
  }
  return 0;
}
