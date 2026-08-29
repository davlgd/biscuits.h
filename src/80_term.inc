/* ---------------------------------------------------------------------------
 * Terms
 *
 * Terms are printed straight from the wire. There is no intermediate tree:
 * building one would cost an allocation per node and buy nothing, since every
 * consumer of a term either prints it or compares it, and both can be done in
 * one pass over the encoded bytes.
 *
 * Nesting is handled with an explicit frame stack (invariant 2). A frame is
 * pushed only for a container, so the depth limit counts exactly what a reader
 * would call nesting: `{"a": [1, {"b": 2}]}` is three deep. A scalar never
 * costs a frame, which is why the common case -- a flat list of strings --
 * runs at constant stack.
 * ------------------------------------------------------------------------ */

#define BS_F_TERM_VARIABLE 1U
#define BS_F_TERM_INTEGER 2U
#define BS_F_TERM_STRING 3U
#define BS_F_TERM_DATE 4U
#define BS_F_TERM_BYTES 5U
#define BS_F_TERM_BOOL 6U
#define BS_F_TERM_SET 7U
#define BS_F_TERM_NULL 8U
#define BS_F_TERM_ARRAY 9U
#define BS_F_TERM_MAP 10U

#define BS_F_MAPENTRY_KEY 1U
#define BS_F_MAPENTRY_VALUE 2U
#define BS_F_MAPKEY_INTEGER 1U
#define BS_F_MAPKEY_STRING 2U

/* Container kinds, and how each one brackets its items. Sets and maps share
 * the brace; what tells them apart when reading is the colon, which is why an
 * empty set and an empty map print identically. That ambiguity is in the
 * specification's text format, not introduced here. */
#define BS_CTR_SET 0U
#define BS_CTR_ARRAY 1U
#define BS_CTR_MAP 2U

typedef struct bs_pframe {
  bs_cursor c;   /* the container's remaining items */
  uint32_t kind; /* BS_CTR_* */
  int emitted;   /* items already written, for separator placement */
} bs_pframe;

static void bs_put_symbol(bs_writer *w, const bs_symbols *sym, uint64_t index,
                          int quoted, int *ok) {
  bs_span text;
  if (!bs_symbol_get(sym, index, &text)) {
    *ok = 0;
    return;
  }
  if (quoted) {
    bs_put_string(w, text);
  } else {
    bs_put_span(w, text);
  }
}

/* Print a term if it is a scalar, or report the container to descend into.
 *
 * Returns 0 on malformed input, 1 when the term was printed in full, and 2
 * when the caller must push a frame -- *kind and *inner then describe it.
 *
 * A Term is a protobuf oneof, so exactly one recognised field must be
 * present. Accepting several would let a token carry two readings of the same
 * value and leave it to the verifier to pick one. */
static int bs_term_step(bs_writer *w, const bs_symbols *sym, bs_span term,
                        uint32_t *kind, bs_span *inner) {
  bs_cursor c = bs_cursor_make(term);
  bs_pb_field f;
  int found = 0;
  int result = 0;
  int ok = 1;

  while (!bs_cursor_done(&c)) {
    if (!bs_pb_next(&c, &f)) {
      return 0;
    }
    switch (f.number) {
    case BS_F_TERM_VARIABLE:
      if (f.wire != BS_PB_VARINT || found++) {
        return 0;
      }
      bs_put_byte(w, (uint8_t)'$');
      bs_put_symbol(w, sym, f.varint, 0, &ok);
      result = 1;
      break;
    case BS_F_TERM_INTEGER:
      if (f.wire != BS_PB_VARINT || found++) {
        return 0;
      }
      /* proto2 int64 is two's complement in a varint, not zigzag, so a
       * negative value arrives as a ten-byte encoding and this cast is the
       * decoding. */
      bs_put_i64(w, (int64_t)f.varint);
      result = 1;
      break;
    case BS_F_TERM_STRING:
      if (f.wire != BS_PB_VARINT || found++) {
        return 0;
      }
      bs_put_symbol(w, sym, f.varint, 1, &ok);
      result = 1;
      break;
    case BS_F_TERM_DATE:
      if (f.wire != BS_PB_VARINT || found++) {
        return 0;
      }
      bs_put_date(w, f.varint);
      result = 1;
      break;
    case BS_F_TERM_BYTES:
      if (f.wire != BS_PB_BYTES || found++) {
        return 0;
      }
      BS_PUT_LIT(w, "hex:");
      bs_put_hex(w, f.bytes);
      result = 1;
      break;
    case BS_F_TERM_BOOL:
      if (f.wire != BS_PB_VARINT || found++) {
        return 0;
      }
      /* Anything other than 0 or 1 is not a bool. A token that encodes 2 here
       * would read as true in one implementation and be rejected by another. */
      if (f.varint > 1U) {
        return 0;
      }
      if (f.varint != 0U) {
        BS_PUT_LIT(w, "true");
      } else {
        BS_PUT_LIT(w, "false");
      }
      result = 1;
      break;
    case BS_F_TERM_NULL:
      if (f.wire != BS_PB_BYTES || found++) {
        return 0;
      }
      BS_PUT_LIT(w, "null");
      result = 1;
      break;
    case BS_F_TERM_SET:
    case BS_F_TERM_ARRAY:
    case BS_F_TERM_MAP:
      if (f.wire != BS_PB_BYTES || found++) {
        return 0;
      }
      *kind = (f.number == BS_F_TERM_SET)     ? BS_CTR_SET
              : (f.number == BS_F_TERM_ARRAY) ? BS_CTR_ARRAY
                                              : BS_CTR_MAP;
      *inner = f.bytes;
      result = 2;
      break;
    default:
      break; /* unknown field: parsed, then ignored */
    }
  }

  if (!found || !ok) {
    return 0;
  }
  return result;
}

/* A map key is always a scalar, so it never needs a frame. */
static int bs_mapkey_print(bs_writer *w, const bs_symbols *sym, bs_span key) {
  bs_cursor c = bs_cursor_make(key);
  bs_pb_field f;
  int found = 0;
  int ok = 1;

  while (!bs_cursor_done(&c)) {
    if (!bs_pb_next(&c, &f)) {
      return 0;
    }
    if (f.number == BS_F_MAPKEY_INTEGER && f.wire == BS_PB_VARINT) {
      if (found++) {
        return 0;
      }
      bs_put_i64(w, (int64_t)f.varint);
    } else if (f.number == BS_F_MAPKEY_STRING && f.wire == BS_PB_VARINT) {
      if (found++) {
        return 0;
      }
      bs_put_symbol(w, sym, f.varint, 1, &ok);
    }
  }
  return (found == 1 && ok) ? 1 : 0;
}

/* Split a MapEntry into its key and value. Both are required. */
static int bs_mapentry_split(bs_span entry, bs_span *key, bs_span *value) {
  bs_cursor c = bs_cursor_make(entry);
  bs_pb_field f;
  int have_key = 0;
  int have_value = 0;

  while (!bs_cursor_done(&c)) {
    if (!bs_pb_next(&c, &f)) {
      return 0;
    }
    if (f.number == BS_F_MAPENTRY_KEY && f.wire == BS_PB_BYTES) {
      *key = f.bytes;
      have_key = 1;
    } else if (f.number == BS_F_MAPENTRY_VALUE && f.wire == BS_PB_BYTES) {
      *value = f.bytes;
      have_value = 1;
    }
  }
  return (have_key && have_value) ? 1 : 0;
}

static void bs_put_open(bs_writer *w, uint32_t kind) {
  bs_put_byte(w, (uint8_t)((kind == BS_CTR_ARRAY) ? '[' : '{'));
}

/* An empty set prints as `{,}`, not `{}`.
 *
 * Sets and maps share the brace, and the colon is what tells them apart --
 * which leaves nothing to distinguish an empty one from the other. The text
 * format resolves it with a lone comma in the set. The specification's own
 * sample checks `{,}.length() === 0`, so this is required, not cosmetic. */
static void bs_put_close(bs_writer *w, uint32_t kind, int emitted) {
  if (kind == BS_CTR_SET && emitted == 0) {
    bs_put_byte(w, (uint8_t)',');
  }
  bs_put_byte(w, (uint8_t)((kind == BS_CTR_ARRAY) ? ']' : '}'));
}

/* Render one encoded Term as Datalog source. */
BS_API bs_status bs_term_print(bs_writer *w, const bs_symbols *sym,
                               bs_span term) {
  bs_pframe stack[BS_MAX_DEPTH];
  size_t depth = 0;
  uint32_t kind = 0;
  bs_span inner = bs_span_make(NULL, 0);

  switch (bs_term_step(w, sym, term, &kind, &inner)) {
  case 0:
    return BS_ERR_MALFORMED;
  case 1:
    return BS_OK; /* a scalar: no stack needed at all */
  default:
    break;
  }

  bs_put_open(w, kind);
  stack[0].c = bs_cursor_make(inner);
  stack[0].kind = kind;
  stack[0].emitted = 0;
  depth = 1;

  while (depth > 0U) {
    bs_pframe *f = &stack[depth - 1U];
    bs_pb_field item;
    bs_span value;
    int step;

    if (bs_cursor_done(&f->c)) {
      bs_put_close(w, f->kind, f->emitted);
      depth--;
      continue;
    }

    if (!bs_pb_next(&f->c, &item)) {
      return BS_ERR_MALFORMED;
    }
    /* Every container holds its items in repeated field 1. */
    if (item.number != 1U || item.wire != BS_PB_BYTES) {
      continue; /* unknown field inside a container: parsed, then ignored */
    }

    if (f->emitted++ > 0) {
      BS_PUT_LIT(w, ", ");
    }

    value = item.bytes;
    if (f->kind == BS_CTR_MAP) {
      bs_span key;
      if (!bs_mapentry_split(item.bytes, &key, &value)) {
        return BS_ERR_MALFORMED;
      }
      if (!bs_mapkey_print(w, sym, key)) {
        return BS_ERR_MALFORMED;
      }
      BS_PUT_LIT(w, ": ");
    }

    step = bs_term_step(w, sym, value, &kind, &inner);
    if (step == 0) {
      return BS_ERR_MALFORMED;
    }
    if (step == 2) {
      if (depth >= (size_t)BS_MAX_DEPTH) {
        /* Deeper than this build will walk. A clean error, never a smashed
         * stack -- which is the whole point of not recursing. */
        return BS_ERR_DEPTH;
      }
      BS_ASSERT(depth < (size_t)BS_MAX_DEPTH);
      bs_put_open(w, kind);
      stack[depth].c = bs_cursor_make(inner);
      stack[depth].kind = kind;
      stack[depth].emitted = 0;
      depth++;
    }
  }

  return bs_writer_overflow(w) ? BS_ERR_NOMEM : BS_OK;
}
