/* Shared setup for the fuzz targets.
 *
 * Two decisions here matter more than the targets themselves.
 *
 * Assertions are ON. BS_ASSERT compiles to nothing in a release build, which
 * is right -- it states facts the code has already established, and a released
 * library should not pay for restating them. Under the fuzzer that is exactly
 * backwards: every one of those documented beliefs becomes an oracle, and the
 * fuzzer is looking for the input that falsifies one. A fuzzer that only finds
 * segfaults is finding a fraction of what is there.
 *
 * The helpers are `static inline` rather than plain `static`: not every target
 * uses every one, and an unused `static` in a header is a warning that would
 * push these builds out of the project's -Werror discipline for no reason.
 *
 * The arena is a fixed static buffer, reset per input rather than reallocated.
 * That keeps each iteration cheap, and it means an input that exhausts the
 * arena exercises the exhaustion path instead of quietly getting more memory --
 * which is the path a real deployment with a fixed scratch buffer will hit.
 */

#ifndef FUZZ_COMMON_H_INCLUDED
#define FUZZ_COMMON_H_INCLUDED

#include <assert.h>
#include <stddef.h>
#include <stdint.h>

#define BS_ASSERT(cond) assert(cond)

#define BISCUITS_IMPLEMENTATION
#include "biscuits.h"

/* Deliberately modest. A verifier embedded in a proxy is given a scratch
 * buffer, not a heap, and 64 KB is a realistic one; sizing this generously
 * would hide the exhaustion paths rather than test them. */
#define FUZZ_ARENA_BYTES ((size_t)64U * 1024U)
#define FUZZ_RENDER_BYTES ((size_t)64U * 1024U)

static uint8_t fuzz_arena_buf[FUZZ_ARENA_BYTES];
static char fuzz_render_buf[FUZZ_RENDER_BYTES];

static inline bs_arena *fuzz_arena(void) {
  static bs_arena a;
  (void)bs_arena_init(&a, fuzz_arena_buf, sizeof fuzz_arena_buf);
  return &a;
}

static inline bs_writer *fuzz_writer(void) {
  static bs_writer w;
  (void)bs_writer_init(&w, fuzz_render_buf, sizeof fuzz_render_buf);
  return &w;
}

/* The root key from the specification's own sample suite, so that the seed
 * corpus verifies rather than failing at the first signature and leaving the
 * rest of the code unexercised. */
static inline bs_span fuzz_root_key(void) {
  static const uint8_t key[32] = {
      0x10, 0x55, 0xc7, 0x50, 0xb1, 0xa1, 0x50, 0x59, 0x37, 0xaf, 0x15,
      0x37, 0xc6, 0x26, 0xba, 0x32, 0x63, 0x99, 0x5c, 0x33, 0xa6, 0x47,
      0x58, 0xaa, 0xaf, 0xb1, 0x27, 0x5b, 0x03, 0x12, 0xe2, 0x84,
  };
  return bs_span_make(key, sizeof key);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

#endif /* FUZZ_COMMON_H_INCLUDED */
