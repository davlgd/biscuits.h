/* ---------------------------------------------------------------------------
 * Protocol Buffers wire format
 *
 * Just enough of proto2 to read the Biscuit schema, and deliberately no more.
 * There is no descriptor, no reflection and no generated code: the schema is
 * small, fixed, and read by hand in the decoders above. A generic protobuf
 * library would be larger than the whole of this one.
 *
 * This is the only code in the library that sees bytes an attacker chose. It
 * is written to be read: no state machine, no jump table, one function per
 * wire concept, and every length checked before it is trusted.
 * ------------------------------------------------------------------------ */

/* Wire types. Groups (3 and 4) were removed from proto2 long before this
 * schema existed; accepting them would mean a nesting construct with its own
 * termination rules, which is exactly the kind of surface this decoder exists
 * to not have. They are rejected. */
#define BS_PB_VARINT 0U
#define BS_PB_I64 1U
#define BS_PB_BYTES 2U
#define BS_PB_SGROUP 3U
#define BS_PB_EGROUP 4U
#define BS_PB_I32 5U

/* Field numbers are 29 bits in the wire format, and zero is not a valid one. */
#define BS_PB_MAX_FIELD 0x1FFFFFFFU

typedef struct bs_pb_field {
  uint32_t number;
  uint32_t wire;
  uint64_t varint; /* wire == VARINT, I64 or I32 */
  bs_span bytes;   /* wire == BYTES */
} bs_pb_field;

/* A base-128 varint, at most ten bytes.
 *
 * The tenth byte carries the 64th bit and nothing else, so any value above 1
 * in it would encode a number that does not fit. Protobuf writers in the wild
 * do emit non-minimal encodings (a value padded with 0x80 continuation
 * bytes), so those are accepted; what is rejected is an encoding that cannot
 * be represented at all.
 *
 * On failure the cursor is left exactly where it started. Every take_* in
 * this file keeps that property, which is what lets a decoder try a parse and
 * back out without tracking how far it got. */
static int bs_pb_varint(bs_cursor *c, uint64_t *out) {
  size_t save;
  uint64_t v = 0;
  unsigned shift = 0;
  size_t i;

  if (c == NULL || out == NULL) {
    return 0;
  }
  save = c->off;

  for (i = 0; i < 10U; i++) {
    uint8_t b;
    if (!bs_take_u8(c, &b)) {
      c->off = save;
      return 0; /* truncated mid-varint */
    }
    if (i == 9U && (b & 0x7FU) > 1U) {
      c->off = save;
      return 0; /* does not fit in 64 bits */
    }
    v |= (uint64_t)(b & 0x7FU) << shift;
    if ((b & 0x80U) == 0U) {
      *out = v;
      return 1;
    }
    shift += 7U;
  }

  c->off = save;
  return 0; /* eleventh byte: no valid varint is this long */
}

/* Read one field. Returns 1 on success, 0 at clean end of input or on a
 * malformed field; use bs_cursor_done() to tell the two apart. */
static int bs_pb_next(bs_cursor *c, bs_pb_field *f) {
  size_t save;
  uint64_t tag;
  uint64_t len;

  if (c == NULL || f == NULL || bs_cursor_done(c)) {
    return 0;
  }
  save = c->off;

  if (!bs_pb_varint(c, &tag)) {
    return 0;
  }

  f->wire = (uint32_t)(tag & 7U);
  tag >>= 3U;
  if (tag == 0U || tag > (uint64_t)BS_PB_MAX_FIELD) {
    c->off = save;
    return 0;
  }
  f->number = (uint32_t)tag;
  f->varint = 0;
  f->bytes = bs_span_make(NULL, 0);

  switch (f->wire) {
  case BS_PB_VARINT:
    if (!bs_pb_varint(c, &f->varint)) {
      c->off = save;
      return 0;
    }
    return 1;

  case BS_PB_BYTES:
    if (!bs_pb_varint(c, &len)) {
      c->off = save;
      return 0;
    }
    /* A length wider than the address space cannot be satisfied, and casting
     * it to size_t first is how a 64-bit length becomes a small one on a
     * 32-bit target. Compare before narrowing. */
    if (len > (uint64_t)bs_cursor_left(c)) {
      c->off = save;
      return 0;
    }
    if (!bs_take_bytes(c, (size_t)len, &f->bytes)) {
      c->off = save;
      return 0;
    }
    return 1;

  case BS_PB_I64:
  case BS_PB_I32: {
    size_t width = (f->wire == BS_PB_I64) ? 8U : 4U;
    bs_span raw;
    size_t i;
    if (!bs_take_bytes(c, width, &raw)) {
      c->off = save;
      return 0;
    }
    /* Little-endian, per the wire format. Assembled byte by byte rather than
     * cast, because the source is not guaranteed to be aligned and the host
     * is not guaranteed to be little-endian. */
    for (i = 0; i < width; i++) {
      f->varint |= (uint64_t)raw.p[i] << (8U * i);
    }
    return 1;
  }

  case BS_PB_SGROUP:
  case BS_PB_EGROUP:
  default:
    c->off = save;
    return 0;
  }
}
