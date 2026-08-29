/* A tiny protobuf writer for tests, so a test case reads as the message it
 * describes rather than as a hex dump.
 *
 * Deliberately not part of the library: it is the inverse of the code under
 * test, and building it from the same primitives would let one bug hide
 * another.
 */

#ifndef PB_BUILD_H_INCLUDED
#define PB_BUILD_H_INCLUDED

/* Include after biscuits.h: this header uses bs_span and the BS_PB_* wire
 * constants. The standard headers below are pulled in so an editor can make
 * sense of the file on its own. */
#include <stddef.h>
#include <stdint.h>

typedef struct buf {
  uint8_t b[1024];
  size_t n;
} buf;

/* Silently drops on overflow. A test that overruns this is a test that needs
 * a smaller fixture, and the assertion it makes will fail loudly anyway. */
static void put(buf *w, uint8_t byte) {
  if (w->n < sizeof w->b) {
    w->b[w->n++] = byte;
  }
}

static void put_varint(buf *w, uint64_t v) {
  do {
    uint8_t byte = (uint8_t)(v & 0x7FU);
    v >>= 7U;
    if (v != 0U) {
      byte |= 0x80U;
    }
    put(w, byte);
  } while (v != 0U);
}

static void put_tag(buf *w, uint32_t field, uint32_t wire) {
  put_varint(w, ((uint64_t)field << 3U) | wire);
}

static void put_bytes(buf *w, uint32_t field, const uint8_t *p, size_t n) {
  size_t i;
  put_tag(w, field, BS_PB_BYTES);
  put_varint(w, n);
  for (i = 0; i < n; i++) {
    put(w, p[i]);
  }
}

static bs_span span_of(const buf *w) {
  return bs_span_make(w->b, w->n);
}

#endif /* PB_BUILD_H_INCLUDED */
