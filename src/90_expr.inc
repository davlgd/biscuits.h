/* ---------------------------------------------------------------------------
 * Expressions
 *
 * Expressions travel as a postfix opcode sequence for a stack machine. Turning
 * that back into source is the one place in this library where a naive design
 * is quadratic: rendering each operator by concatenating the text of its
 * operands copies the accumulated string once per operator, so `1+1+1+...`
 * costs O(n^2) bytes.
 *
 * So it is done in two passes instead. The first replays the stack machine but
 * pushes *node indices* rather than text, which reconstructs the tree in O(n).
 * The second walks that tree and writes straight to the output, with an
 * explicit stack and no intermediate buffers at all.
 *
 * Precedence needs no handling: the encoder emits an explicit `Parens` opcode
 * wherever the source had one, which is exactly why that opcode exists. The
 * printer therefore never adds a parenthesis and never removes one -- it
 * reproduces what the writer chose.
 * ------------------------------------------------------------------------ */

#define BS_F_EXPR_OPS 1U

#define BS_F_OP_VALUE 1U
#define BS_F_OP_UNARY 2U
#define BS_F_OP_BINARY 3U
#define BS_F_OP_CLOSURE 4U

#define BS_F_OPKIND 1U
#define BS_F_OPFFI 2U

#define BS_F_CLOSURE_PARAMS 1U
#define BS_F_CLOSURE_OPS 2U

#define BS_U_NEGATE 0U
#define BS_U_PARENS 1U
#define BS_U_LENGTH 2U
#define BS_U_TYPEOF 3U
#define BS_U_FFI 4U

#define BS_B_FFI 28U

/* How a binary operator is written. The specification defines the opcodes;
 * this table defines their surface syntax, and every entry is taken from the
 * conformance samples rather than guessed. */
#define BS_OP_INFIX 0U
#define BS_OP_METHOD 1U

typedef struct bs_binop {
  uint8_t style;
  const char *text;
  size_t len;
} bs_binop;

#define BS_OP(style, lit) {style, lit, sizeof(lit) - 1U}

static const bs_binop BS_BINOPS[] = {
    BS_OP(BS_OP_INFIX, "<"),             /*  0 LessThan */
    BS_OP(BS_OP_INFIX, ">"),             /*  1 GreaterThan */
    BS_OP(BS_OP_INFIX, "<="),            /*  2 LessOrEqual */
    BS_OP(BS_OP_INFIX, ">="),            /*  3 GreaterOrEqual */
    BS_OP(BS_OP_INFIX, "==="),           /*  4 Equal */
    BS_OP(BS_OP_METHOD, "contains"),     /*  5 Contains */
    BS_OP(BS_OP_METHOD, "starts_with"),  /*  6 Prefix */
    BS_OP(BS_OP_METHOD, "ends_with"),    /*  7 Suffix */
    BS_OP(BS_OP_METHOD, "matches"),      /*  8 Regex */
    BS_OP(BS_OP_INFIX, "+"),             /*  9 Add */
    BS_OP(BS_OP_INFIX, "-"),             /* 10 Sub */
    BS_OP(BS_OP_INFIX, "*"),             /* 11 Mul */
    BS_OP(BS_OP_INFIX, "/"),             /* 12 Div */
    BS_OP(BS_OP_INFIX, "&&"),            /* 13 And */
    BS_OP(BS_OP_INFIX, "||"),            /* 14 Or */
    BS_OP(BS_OP_METHOD, "intersection"), /* 15 Intersection */
    BS_OP(BS_OP_METHOD, "union"),        /* 16 Union */
    BS_OP(BS_OP_INFIX, "&"),             /* 17 BitwiseAnd */
    BS_OP(BS_OP_INFIX, "|"),             /* 18 BitwiseOr */
    BS_OP(BS_OP_INFIX, "^"),             /* 19 BitwiseXor */
    BS_OP(BS_OP_INFIX, "!=="),           /* 20 NotEqual */
    BS_OP(BS_OP_INFIX, "=="),            /* 21 HeterogeneousEqual */
    BS_OP(BS_OP_INFIX, "!="),            /* 22 HeterogeneousNotEqual */
    BS_OP(BS_OP_INFIX, "&&"),            /* 23 LazyAnd */
    BS_OP(BS_OP_INFIX, "||"),            /* 24 LazyOr */
    BS_OP(BS_OP_METHOD, "all"),          /* 25 All */
    BS_OP(BS_OP_METHOD, "any"),          /* 26 Any */
    BS_OP(BS_OP_METHOD, "get"),          /* 27 Get */
    BS_OP(BS_OP_METHOD, "extern"),       /* 28 Ffi, name supplied separately */
    BS_OP(BS_OP_METHOD, "try_or"),       /* 29 TryOr */
};

#define BS_BINOP_COUNT (sizeof BS_BINOPS / sizeof BS_BINOPS[0])

#define BS_E_VALUE 0U
#define BS_E_UNARY 1U
#define BS_E_BINARY 2U
#define BS_E_CLOSURE 3U

#define BS_E_NONE 0xFFFFFFFFU

typedef struct bs_enode {
  bs_span payload; /* value: the Term bytes; closure: the Closure message */
  uint64_t ffi;    /* symbol index of an external call's name */
  uint32_t kind;   /* the unary or binary opcode */
  uint32_t a;      /* first operand, or BS_E_NONE */
  uint32_t b;      /* second operand, or BS_E_NONE */
  uint8_t tag;     /* BS_E_* */
  uint8_t has_ffi;
} bs_enode;

/* One frame of the reconstruction: an opcode list being replayed, and the
 * height of the value stack when it started. */
typedef struct bs_eframe {
  bs_cursor ops;
  bs_span closure; /* the Closure message, for its parameters */
  size_t base;
  uint32_t field; /* ops are field 1 of an Expression, field 2 of a Closure */
  int is_closure;
} bs_eframe;

/* Read an OpUnary or OpBinary: a kind, and optionally an external name. */
static bs_status bs_op_kind(bs_span msg, uint32_t *kind, uint64_t *ffi,
                            uint8_t *has_ffi) {
  bs_cursor c = bs_cursor_make(msg);
  bs_pb_field f;
  int found = 0;

  *has_ffi = 0;
  while (!bs_cursor_done(&c)) {
    if (!bs_pb_next(&c, &f)) {
      return BS_ERR_MALFORMED;
    }
    if (f.wire != BS_PB_VARINT) {
      continue;
    }
    if (f.number == BS_F_OPKIND) {
      if (found++ || f.varint > 0xFFFFFFFFU) {
        return BS_ERR_MALFORMED;
      }
      *kind = (uint32_t)f.varint;
    } else if (f.number == BS_F_OPFFI) {
      *ffi = f.varint;
      *has_ffi = 1;
    }
  }
  return (found == 1) ? BS_OK : BS_ERR_MALFORMED;
}

/* Classify one Op. Returns the oneof branch that was present, or an error if
 * the count is anything but one -- an Op that claims to be two things at once
 * would let a token mean different things to different readers. */
static bs_status bs_op_branch(bs_span op, uint32_t *branch, bs_span *body) {
  bs_cursor c = bs_cursor_make(op);
  bs_pb_field f;
  int found = 0;

  while (!bs_cursor_done(&c)) {
    if (!bs_pb_next(&c, &f)) {
      return BS_ERR_MALFORMED;
    }
    if (f.wire != BS_PB_BYTES) {
      continue;
    }
    if (f.number == BS_F_OP_VALUE || f.number == BS_F_OP_UNARY ||
        f.number == BS_F_OP_BINARY || f.number == BS_F_OP_CLOSURE) {
      if (found++) {
        return BS_ERR_MALFORMED;
      }
      *branch = f.number;
      *body = f.bytes;
    }
  }
  return (found == 1) ? BS_OK : BS_ERR_MALFORMED;
}

/* Replay the opcode stream, pushing node indices instead of values. */
static bs_status bs_expr_build(bs_arena *a, bs_span expr, bs_enode **nodes_out,
                               uint32_t **stack_out, uint32_t *root,
                               size_t *node_count) {
  bs_eframe frames[BS_MAX_DEPTH];
  bs_enode *nodes;
  uint32_t *stack;
  size_t cap;
  size_t used = 0;
  size_t sp = 0;
  size_t depth = 1;

  /* Every Op is a length-delimited field, so it costs at least two bytes in
   * its parent message. That bounds the node count by half the expression's
   * length -- an upper bound derived from the input rather than a constant,
   * which is what keeps a hostile expression's cost proportional to what the
   * attacker actually sent. */
  cap = (expr.n / 2U) + 1U;
  nodes = (bs_enode *)bs_arena_array(a, cap, sizeof(bs_enode), BS_ALIGN_MAX);
  stack = (uint32_t *)bs_arena_array(a, cap, sizeof(uint32_t), BS_ALIGN_MAX);
  if (nodes == NULL || stack == NULL) {
    return BS_ERR_NOMEM;
  }

  frames[0].ops = bs_cursor_make(expr);
  frames[0].closure = bs_span_make(NULL, 0);
  frames[0].base = 0;
  frames[0].field = BS_F_EXPR_OPS;
  frames[0].is_closure = 0;

  while (depth > 0U) {
    bs_eframe *fr = &frames[depth - 1U];
    bs_pb_field f;
    bs_span body;
    uint32_t branch = 0;
    bs_status st;

    if (bs_cursor_done(&fr->ops)) {
      if (!fr->is_closure) {
        depth--;
        continue;
      }
      /* A closure body must leave exactly one value behind, like any
       * expression. */
      if (sp != fr->base + 1U) {
        return BS_ERR_MALFORMED;
      }
      if (used >= cap) {
        return BS_ERR_LIMIT;
      }
      nodes[used].tag = (uint8_t)BS_E_CLOSURE;
      nodes[used].payload = fr->closure;
      nodes[used].a = stack[fr->base];
      nodes[used].b = BS_E_NONE;
      nodes[used].kind = 0;
      nodes[used].ffi = 0;
      nodes[used].has_ffi = 0;
      sp = fr->base;
      stack[sp++] = (uint32_t)used;
      used++;
      depth--;
      continue;
    }

    if (!bs_pb_next(&fr->ops, &f)) {
      return BS_ERR_MALFORMED;
    }
    if (f.number != fr->field || f.wire != BS_PB_BYTES) {
      continue;
    }

    st = bs_op_branch(f.bytes, &branch, &body);
    if (st != BS_OK) {
      return st;
    }
    if (used >= cap || sp >= cap) {
      return BS_ERR_LIMIT;
    }

    if (branch == BS_F_OP_CLOSURE) {
      if (depth >= (size_t)BS_MAX_DEPTH) {
        return BS_ERR_DEPTH;
      }
      frames[depth].ops = bs_cursor_make(body);
      frames[depth].closure = body;
      frames[depth].base = sp;
      frames[depth].field = BS_F_CLOSURE_OPS;
      frames[depth].is_closure = 1;
      depth++;
      continue;
    }

    nodes[used].payload = bs_span_make(NULL, 0);
    nodes[used].ffi = 0;
    nodes[used].has_ffi = 0;
    nodes[used].kind = 0;
    nodes[used].a = BS_E_NONE;
    nodes[used].b = BS_E_NONE;

    if (branch == BS_F_OP_VALUE) {
      nodes[used].tag = (uint8_t)BS_E_VALUE;
      nodes[used].payload = body;
    } else if (branch == BS_F_OP_UNARY) {
      if (sp < fr->base + 1U) {
        return BS_ERR_MALFORMED; /* not enough operands */
      }
      st = bs_op_kind(body, &nodes[used].kind, &nodes[used].ffi,
                      &nodes[used].has_ffi);
      if (st != BS_OK) {
        return st;
      }
      nodes[used].tag = (uint8_t)BS_E_UNARY;
      nodes[used].a = stack[--sp];
    } else {
      if (sp < fr->base + 2U) {
        return BS_ERR_MALFORMED;
      }
      st = bs_op_kind(body, &nodes[used].kind, &nodes[used].ffi,
                      &nodes[used].has_ffi);
      if (st != BS_OK) {
        return st;
      }
      nodes[used].tag = (uint8_t)BS_E_BINARY;
      /* The stack machine pushes the left operand first, so the top of the
       * stack is the right-hand side. */
      nodes[used].b = stack[--sp];
      nodes[used].a = stack[--sp];
    }

    stack[sp++] = (uint32_t)used;
    used++;
  }

  /* After the whole stream, exactly one value must remain. */
  if (sp != 1U) {
    return BS_ERR_MALFORMED;
  }
  *nodes_out = nodes;
  *stack_out = stack;
  *root = stack[0];
  *node_count = used;
  return BS_OK;
}

static void bs_put_extern(bs_writer *w, const bs_symbols *sym, uint64_t name,
                          int *ok) {
  BS_PUT_LIT(w, ".extern::");
  bs_put_symbol(w, sym, name, 0, ok);
  bs_put_byte(w, (uint8_t)'(');
}

/* Walk the tree and write the source. Two stages per node at most, so the
 * traversal is a flat loop over an explicit stack. */
static bs_status bs_expr_emit(bs_writer *w, const bs_tables *tab,
                              const bs_enode *nodes, size_t node_count,
                              uint32_t root, uint32_t *stack, size_t cap) {
  size_t sp = 0;
  int ok = 1;

  /* The traversal reuses the reconstruction stack, which is no longer needed
   * and is already sized to the node count. Each entry packs a node index
   * with a two-bit stage, so the index must fit in the remaining thirty bits.
   * An expression large enough to break that would have to be a gigabyte of
   * opcodes; the check costs one comparison and removes the assumption. */
  if (cap == 0U || node_count > 0x3FFFFFFFU) {
    return BS_ERR_LIMIT;
  }

  stack[sp++] = root << 2U;

  while (sp > 0U) {
    uint32_t packed = stack[sp - 1U];
    uint32_t index = packed >> 2U;
    uint32_t st = packed & 3U;
    const bs_enode *n;

    if (index >= (uint32_t)node_count) {
      return BS_ERR_MALFORMED;
    }
    n = &nodes[index];

    if (n->tag == BS_E_VALUE) {
      bs_status s = bs_term_print(w, &tab->symbols, n->payload);
      if (s != BS_OK) {
        return s;
      }
      sp--;
      continue;
    }

    if (n->tag == BS_E_UNARY) {
      if (st == 0U) {
        if (n->kind == BS_U_NEGATE) {
          bs_put_byte(w, (uint8_t)'!');
        } else if (n->kind == BS_U_PARENS) {
          bs_put_byte(w, (uint8_t)'(');
        }
        stack[sp - 1U] = (index << 2U) | 1U;
        if (sp >= cap) {
          return BS_ERR_LIMIT;
        }
        stack[sp++] = n->a << 2U;
        continue;
      }
      switch (n->kind) {
      case BS_U_NEGATE:
        break;
      case BS_U_PARENS:
        bs_put_byte(w, (uint8_t)')');
        break;
      case BS_U_LENGTH:
        BS_PUT_LIT(w, ".length()");
        break;
      case BS_U_TYPEOF:
        BS_PUT_LIT(w, ".type()");
        break;
      case BS_U_FFI:
        if (!n->has_ffi) {
          return BS_ERR_MALFORMED;
        }
        bs_put_extern(w, &tab->symbols, n->ffi, &ok);
        bs_put_byte(w, (uint8_t)')');
        break;
      default:
        return BS_ERR_MALFORMED;
      }
      sp--;
      continue;
    }

    if (n->tag == BS_E_CLOSURE) {
      if (st == 0U) {
        /* Parameters, when there are any. A zero-parameter closure is how the
         * short-circuiting operators carry their right-hand side, and it is
         * invisible in the source: `a && b`, not `a && (() -> b)`. */
        bs_cursor c = bs_cursor_make(n->payload);
        bs_pb_field f;
        int emitted = 0;
        while (!bs_cursor_done(&c)) {
          if (!bs_pb_next(&c, &f)) {
            return BS_ERR_MALFORMED;
          }
          if (f.number != BS_F_CLOSURE_PARAMS || f.wire != BS_PB_VARINT) {
            continue;
          }
          if (emitted++ > 0) {
            BS_PUT_LIT(w, ", ");
          }
          bs_put_byte(w, (uint8_t)'$');
          bs_put_symbol(w, &tab->symbols, f.varint, 0, &ok);
        }
        if (emitted > 0) {
          BS_PUT_LIT(w, " -> ");
        }
        stack[sp - 1U] = (index << 2U) | 1U;
        if (sp >= cap) {
          return BS_ERR_LIMIT;
        }
        stack[sp++] = n->a << 2U;
        continue;
      }
      sp--;
      continue;
    }

    /* Binary. */
    if (n->kind >= (uint32_t)BS_BINOP_COUNT) {
      return BS_ERR_MALFORMED;
    }
    if (st == 0U) {
      stack[sp - 1U] = (index << 2U) | 1U;
      if (sp >= cap) {
        return BS_ERR_LIMIT;
      }
      stack[sp++] = n->a << 2U;
      continue;
    }
    if (st == 1U) {
      const bs_binop *op = &BS_BINOPS[n->kind];
      if (n->kind == BS_B_FFI) {
        if (!n->has_ffi) {
          return BS_ERR_MALFORMED;
        }
        bs_put_extern(w, &tab->symbols, n->ffi, &ok);
      } else if (op->style == BS_OP_INFIX) {
        bs_put_byte(w, (uint8_t)' ');
        bs_put_span(w, bs_span_make(op->text, op->len));
        bs_put_byte(w, (uint8_t)' ');
      } else {
        bs_put_byte(w, (uint8_t)'.');
        bs_put_span(w, bs_span_make(op->text, op->len));
        bs_put_byte(w, (uint8_t)'(');
      }
      stack[sp - 1U] = (index << 2U) | 2U;
      if (sp >= cap) {
        return BS_ERR_LIMIT;
      }
      stack[sp++] = n->b << 2U;
      continue;
    }

    if (n->kind == BS_B_FFI || BS_BINOPS[n->kind].style == BS_OP_METHOD) {
      bs_put_byte(w, (uint8_t)')');
    }
    sp--;
  }

  if (!ok) {
    return BS_ERR_MALFORMED;
  }
  return bs_writer_overflow(w) ? BS_ERR_NOMEM : BS_OK;
}

/* Render one encoded Expression as Datalog source. */
BS_API bs_status bs_expr_print(bs_writer *w, bs_arena *a, const bs_tables *tab,
                               bs_span expr) {
  bs_enode *nodes = NULL;
  uint32_t *stack = NULL;
  uint32_t root = 0;
  size_t count = 0;
  bs_status st;

  if (w == NULL || a == NULL || tab == NULL) {
    return BS_ERR_ARGUMENT;
  }
  st = bs_expr_build(a, expr, &nodes, &stack, &root, &count);
  if (st != BS_OK) {
    return st;
  }
  return bs_expr_emit(w, tab, nodes, count, root, stack, (expr.n / 2U) + 1U);
}
