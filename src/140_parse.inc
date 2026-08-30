/* ---------------------------------------------------------------------------
 * Parsing Datalog source
 *
 * Facts, rules, checks and policies, from text into the same pools the wire
 * format loads into. One representation, two front ends: the evaluator never
 * learns where anything came from.
 *
 * This is written without recursion, and the first draft was not. A parser is
 * the place where recursive descent is so natural that it takes an effort of
 * will to write anything else -- which is exactly why the invariant is worth
 * having, and why an exception "just for the parser" would have been the
 * beginning of the end of it. Nesting here comes from the source text, and
 * while that text is the application's rather than the token's, a stack bound
 * that holds for one input and not another is not a bound.
 *
 * Two explicit stacks do the work:
 *
 *   - Terms: a stack of container frames. A `[` or `{` opens one; the closing
 *     bracket pops it, assembles the run in the term pool, and hands the
 *     finished container back as the value the enclosing frame was waiting
 *     for.
 *
 *   - Expressions: shunting-yard, with `(`, method calls and closures pushed
 *     onto the operator stack as markers rather than becoming calls. Output
 *     is postfix, which is the order the opcode pool already wants.
 *
 * A closure's body has to be a contiguous run of its own. At the `)` that
 * closes it, its opcodes are exactly the suffix of the output buffer since the
 * marker, so they move to the pool in one copy and the buffer truncates back.
 * Nested closures work out because the inner one closes first.
 *
 * The precedence table is the reference implementation's, read rather than
 * guessed, and it is not C's: `&` binds tighter than `|`, which binds tighter
 * than `^`, and comparisons do not chain.
 * ------------------------------------------------------------------------ */

#ifndef BS_PARSE_SCRATCH
#define BS_PARSE_SCRATCH 128
#endif

typedef struct bs_parser {
  bs_lexer lex;
  bs_token_t tok; /* one token of lookahead */
  bs_world *w;
  bs_symtab *syms;
  const bs_token *token; /* for a scope naming a public key */
  const bs_tables *tables;
  bs_arena *arena; /* for byte literals */
  bs_op *scratch;  /* the expression under construction */
  /* Two term buffers, because a predicate's argument list and a container
   * literal inside it fill at the same moment. They live in the arena rather
   * than on the stack: at a hundred-odd terms each they would otherwise be
   * most of this build's stack budget. */
  bs_term *tscratch; /* bs_p_term */
  bs_term *pscratch; /* bs_p_predicate */
  size_t scratch_cap;
  size_t block;            /* which block these statements belong to */
  bs_origin default_trust; /* what a statement with no annotation trusts */
} bs_parser;

static bs_status bs_p_advance(bs_parser *p) {
  return bs_lex_next(&p->lex, &p->tok);
}

static int bs_p_is_punct(const bs_parser *p, uint8_t punct) {
  return p->tok.kind == (uint8_t)BS_TK_PUNCT && p->tok.punct == punct;
}

static int bs_p_is_word(const bs_parser *p, const char *word, size_t n) {
  return p->tok.kind == (uint8_t)BS_TK_IDENT &&
         bs_span_eq(p->tok.text, bs_span_make(word, n));
}

#define BS_WORD(p, lit) bs_p_is_word((p), "" lit, sizeof(lit) - 1U)

static bs_status bs_p_expect(bs_parser *p, uint8_t punct) {
  if (!bs_p_is_punct(p, punct)) {
    return BS_ERR_MALFORMED;
  }
  return bs_p_advance(p);
}

/* --------------------------------------------------------------------------
 * Terms
 * ----------------------------------------------------------------------- */

/* Hex digit pairs into bytes. The lexer has already checked that every
 * character is a digit and that there is an even number of them, so this
 * only has to pack them. */
static int bs_p_unhex(bs_span text, uint8_t *out, size_t cap) {
  size_t n = text.n / 2U;
  size_t i;
  if (n > cap) {
    return 0;
  }
  for (i = 0; i < n; i++) {
    uint8_t hi = 0;
    uint8_t lo = 0;
    (void)bs_hex_digit(text.p[2U * i], &hi);
    (void)bs_hex_digit(text.p[(2U * i) + 1U], &lo);
    out[i] = (uint8_t)(((unsigned int)hi << 4U) | (unsigned int)lo);
  }
  return 1;
}

/* A scalar: everything that is not a container. */
static bs_status bs_p_scalar(bs_parser *p, bs_term *out) {
  bs_status st;

  switch (p->tok.kind) {
  case BS_TK_STRING:
    out->kind = (uint8_t)BS_T_STRING;
    st = bs_symtab_intern(p->syms, p->tok.text, &out->as.sym);
    return (st == BS_OK) ? bs_p_advance(p) : st;
  case BS_TK_VARIABLE:
    out->kind = (uint8_t)BS_T_VARIABLE;
    st = bs_symtab_intern(p->syms, p->tok.text, &out->as.sym);
    return (st == BS_OK) ? bs_p_advance(p) : st;
  case BS_TK_INTEGER:
    out->kind = (uint8_t)BS_T_INTEGER;
    out->as.integer = p->tok.integer;
    return bs_p_advance(p);
  case BS_TK_DATE:
    out->kind = (uint8_t)BS_T_DATE;
    out->as.date = p->tok.date;
    return bs_p_advance(p);
  case BS_TK_BYTES: {
    size_t n = p->tok.text.n / 2U;
    uint8_t *buf = (uint8_t *)bs_arena_alloc(p->arena, (n == 0U) ? 1U : n, 1U);
    if (buf == NULL) {
      return BS_ERR_NOMEM;
    }
    if (!bs_p_unhex(p->tok.text, buf, n)) {
      return BS_ERR_MALFORMED;
    }
    out->kind = (uint8_t)BS_T_BYTES;
    out->as.bytes = bs_span_make(buf, n);
    return bs_p_advance(p);
  }
  case BS_TK_IDENT:
    if (BS_WORD(p, "true")) {
      out->kind = (uint8_t)BS_T_BOOL;
      out->as.boolean = 1;
      return bs_p_advance(p);
    }
    if (BS_WORD(p, "false")) {
      out->kind = (uint8_t)BS_T_BOOL;
      out->as.boolean = 0;
      return bs_p_advance(p);
    }
    if (BS_WORD(p, "null")) {
      out->kind = (uint8_t)BS_T_NULL;
      return bs_p_advance(p);
    }
    return BS_ERR_MALFORMED;
  default:
    return BS_ERR_MALFORMED;
  }
}

/* A container kind that is not yet known: `{` opens either a set or a map,
 * and only the colon after the first element tells them apart. */
#define BS_T_UNKNOWN 0xFEU

typedef struct bs_termframe {
  uint8_t kind;  /* BS_T_ARRAY, BS_T_SET, BS_T_MAP, or BS_T_UNKNOWN */
  uint8_t close; /* the punctuation that ends it */
  size_t base;   /* where this frame's elements start in the shared buffer */
} bs_termframe;

/* One term, containers and all. */
static bs_status bs_p_term(bs_parser *p, bs_term *out) {
  bs_termframe frames[BS_MAX_DEPTH];
  bs_term *items = p->tscratch;
  size_t nitems = 0;
  size_t depth = 0;
  bs_term value;
  bs_status st;

  for (;;) {
    /* Open as many containers as the source opens, then read one scalar. */
    for (;;) {
      uint8_t close;
      uint8_t kind;
      if (bs_p_is_punct(p, (uint8_t)BS_P_LBRACKET)) {
        close = (uint8_t)BS_P_RBRACKET;
        kind = (uint8_t)BS_T_ARRAY;
      } else if (bs_p_is_punct(p, (uint8_t)BS_P_LBRACE)) {
        close = (uint8_t)BS_P_RBRACE;
        kind = (uint8_t)BS_T_UNKNOWN;
      } else {
        break;
      }
      if (depth >= (size_t)BS_MAX_DEPTH) {
        return BS_ERR_DEPTH;
      }
      st = bs_p_advance(p);
      if (st != BS_OK) {
        return st;
      }
      frames[depth].kind = kind;
      frames[depth].close = close;
      frames[depth].base = nitems;
      depth++;

      /* The empty spellings. `{}` is a map and `{,}` is a set: with no
       * element to disambiguate them, the comma is the whole difference. */
      if (kind == (uint8_t)BS_T_UNKNOWN &&
          bs_p_is_punct(p, (uint8_t)BS_P_COMMA)) {
        st = bs_p_advance(p);
        if (st != BS_OK) {
          return st;
        }
        if (!bs_p_is_punct(p, close)) {
          return BS_ERR_MALFORMED;
        }
        kind = (uint8_t)BS_T_SET;
      } else if (kind == (uint8_t)BS_T_UNKNOWN && bs_p_is_punct(p, close)) {
        kind = (uint8_t)BS_T_MAP;
      } else if (!bs_p_is_punct(p, close)) {
        continue;
      }
      value.kind = kind;
      value.as.list.at = (uint32_t)p->w->term_count;
      value.as.list.count = 0;
      st = bs_p_advance(p);
      if (st != BS_OK) {
        return st;
      }
      depth--;
      goto have_value;
    }

    st = bs_p_scalar(p, &value);
    if (st != BS_OK) {
      return st;
    }

  have_value:
    if (depth == 0U) {
      *out = value;
      return BS_OK;
    }

    if (nitems >= (size_t)BS_PARSE_SCRATCH) {
      return BS_ERR_LIMIT;
    }
    items[nitems] = value;
    nitems++;

    {
      bs_termframe *f = &frames[depth - 1U];
      size_t placed = nitems - f->base;

      if (f->kind == (uint8_t)BS_T_UNKNOWN) {
        /* Decided by what follows the first element. */
        f->kind = bs_p_is_punct(p, (uint8_t)BS_P_COLON) ? (uint8_t)BS_T_MAP
                                                        : (uint8_t)BS_T_SET;
      }

      if (f->kind == (uint8_t)BS_T_MAP && (placed % 2U) == 1U) {
        /* A key was just placed; its value follows the colon, and keys and
         * values sit adjacently in the run. */
        st = bs_p_expect(p, (uint8_t)BS_P_COLON);
        if (st != BS_OK) {
          return st;
        }
        continue;
      }

      if (bs_p_is_punct(p, (uint8_t)BS_P_COMMA)) {
        st = bs_p_advance(p);
        if (st != BS_OK) {
          return st;
        }
        if (!bs_p_is_punct(p, f->close)) {
          continue;
        }
        /* A trailing comma. `{,}` is how an empty set is written, and it has
         * already placed no elements, so the frame closes as a set. */
        if (placed == 0U) {
          f->kind = (uint8_t)BS_T_SET;
        }
      }
    }

    /* Close the innermost frame and hand its container to the frame outside,
     * or to the caller. */
    {
      const bs_termframe *f = &frames[depth - 1U];
      size_t n = nitems - f->base;
      uint32_t at;
      size_t i;

      st = bs_p_expect(p, f->close);
      if (st != BS_OK) {
        return st;
      }
      if (f->kind == (uint8_t)BS_T_MAP && (n % 2U) != 0U) {
        return BS_ERR_MALFORMED; /* a key with no value */
      }
      st = bs_pool_reserve_terms(p->w, n, &at);
      if (st != BS_OK) {
        return st;
      }
      for (i = 0; i < n; i++) {
        p->w->terms[at + i] = items[f->base + i];
      }
      value.kind = f->kind;
      value.as.list.at = at;
      value.as.list.count = (uint32_t)n;
      nitems = f->base;
      depth--;
      goto have_value;
    }
  }
}

/* --------------------------------------------------------------------------
 * Expressions
 * ----------------------------------------------------------------------- */

/* Lowest binds loosest; 0 means "not a binary operator". Prefix `!` sits
 * above every binary so that `!a && b` negates `a` and not the conjunction,
 * while method calls, which bind tighter still, are applied inline. */
#define BS_PREC_UNARY 9U

static unsigned int bs_p_prec(uint8_t punct) {
  switch (punct) {
  case BS_P_OR2:
  case BS_P_OR2E:
    return 1U;
  case BS_P_AND2:
  case BS_P_AND2E:
    return 2U;
  case BS_P_LT:
  case BS_P_GT:
  case BS_P_LE:
  case BS_P_GE:
  case BS_P_EQ3:
  case BS_P_NEQ3:
  case BS_P_EQ2:
  case BS_P_NEQ2:
    return 3U;
  case BS_P_CARET:
    return 4U;
  case BS_P_PIPE:
    return 5U;
  case BS_P_AMP:
    return 6U;
  case BS_P_PLUS:
  case BS_P_MINUS:
    return 7U;
  case BS_P_STAR:
  case BS_P_SLASH:
    return 8U;
  default:
    return 0U;
  }
}

static uint32_t bs_p_binop(uint8_t punct) {
  switch (punct) {
  case BS_P_LT:
    return 0U;
  case BS_P_GT:
    return 1U;
  case BS_P_LE:
    return 2U;
  case BS_P_GE:
    return 3U;
  case BS_P_EQ3:
    return 4U;
  case BS_P_PLUS:
    return 9U;
  case BS_P_MINUS:
    return 10U;
  case BS_P_STAR:
    return 11U;
  case BS_P_SLASH:
    return 12U;
  case BS_P_AND2E:
    return 13U;
  case BS_P_OR2E:
    return 14U;
  case BS_P_AMP:
    return 17U;
  case BS_P_PIPE:
    return 18U;
  case BS_P_CARET:
    return 19U;
  case BS_P_NEQ3:
    return 20U;
  case BS_P_EQ2:
    return 21U;
  case BS_P_NEQ2:
    return 22U;
  case BS_P_AND2:
    return 23U;
  default:
    return 24U; /* BS_P_OR2 */
  }
}

/* The methods this build knows, and which of them take no argument. */
static int bs_p_method(bs_span name, uint32_t *kind, int *nullary) {
  static const struct {
    const char *text;
    size_t len;
    uint32_t kind;
    int nullary;
  } METHODS[] = {
      {"contains", 8U, 5U, 0},
      {"starts_with", 11U, 6U, 0},
      {"ends_with", 9U, 7U, 0},
      {"matches", 7U, 8U, 0},
      {"intersection", 12U, 15U, 0},
      {"union", 5U, 16U, 0},
      {"all", 3U, 25U, 0},
      {"any", 3U, 26U, 0},
      {"get", 3U, 27U, 0},
      {"try_or", 6U, 29U, 0},
      {"length", 6U, BS_U_LENGTH, 1},
      {"type", 4U, BS_U_TYPEOF, 1},
  };
  size_t i;
  for (i = 0; i < sizeof METHODS / sizeof METHODS[0]; i++) {
    if (bs_span_eq(name, bs_span_make(METHODS[i].text, METHODS[i].len))) {
      *kind = METHODS[i].kind;
      *nullary = METHODS[i].nullary;
      return 1;
    }
  }
  return 0;
}

/* What sits on the operator stack. Three of the five are not operators at
 * all but the open brackets of a construct, kept here so that closing one is
 * a pop rather than a return. */
#define BS_S_BINARY 0U
#define BS_S_UNARY 1U
#define BS_S_PAREN 2U
#define BS_S_METHOD 3U
#define BS_S_CLOSURE 4U

typedef struct bs_opstack {
  uint8_t what;
  uint8_t punct; /* BS_S_BINARY */
  uint32_t kind; /* BS_S_METHOD */
  /* Where in the output this entry's operand begins. Three constructs need
   * it: a lazy connective, whose right-hand side becomes a closure so that it
   * can go unevaluated; `try_or`, whose receiver becomes one for the same
   * reason; and a closure written as such. */
  size_t out;
  uint64_t param; /* BS_S_CLOSURE: the bound variable, BS_S_METHOD: the
                   * external call's name */
} bs_opstack;

/* Is this connective one that must not evaluate its right-hand side unless
 * the left fails to decide? */
static int bs_p_is_lazy(uint8_t punct) {
  return punct == (uint8_t)BS_P_AND2 || punct == (uint8_t)BS_P_OR2;
}

/* Move ops[from..*n) into the pool as a closure body, and put a closure in
 * their place. `param` is the bound variable, or `count` 0 for the anonymous
 * closures the lazy connectives and `try_or` are built from. */
static bs_status bs_p_close_over(bs_parser *p, bs_op *out, size_t *n,
                                 size_t cap, size_t from, uint32_t count,
                                 uint64_t param);

static bs_status bs_p_emit(bs_op *out, size_t *n, size_t cap, bs_op op) {
  if (*n >= cap) {
    return BS_ERR_LIMIT;
  }
  out[*n] = op;
  (*n)++;
  return BS_OK;
}

static bs_status bs_p_emit_op(bs_op *out, size_t *n, size_t cap, uint8_t tag,
                              uint32_t kind) {
  bs_op op;
  op.tag = tag;
  op.kind = kind;
  op.as.ffi = 0;
  return bs_p_emit(out, n, cap, op);
}

/* An external call carries the name it reaches, which an ordinary operator
 * does not have. */
static bs_status bs_p_emit_ffi(bs_op *out, size_t *n, size_t cap, uint8_t tag,
                               uint32_t kind, uint64_t name) {
  bs_op op;
  op.tag = tag;
  op.kind = kind;
  op.as.ffi = name;
  return bs_p_emit(out, n, cap, op);
}

static bs_status bs_p_close_over(bs_parser *p, bs_op *out, size_t *n,
                                 size_t cap, size_t from, uint32_t count,
                                 uint64_t param) {
  size_t body_n = *n - from;
  uint32_t at;
  size_t i;
  bs_op op;
  bs_status st;

  st = bs_pool_reserve_ops(p->w, body_n, &at);
  if (st != BS_OK) {
    return st;
  }
  for (i = 0; i < body_n; i++) {
    p->w->ops[at + i] = out[from + i];
  }
  *n = from;
  op.tag = (uint8_t)BS_OP_CLOSURE;
  op.kind = 0;
  op.as.closure.count = count;
  op.as.closure.body.at = at;
  op.as.closure.body.count = (uint32_t)body_n;
  op.as.closure.src = bs_span_make(NULL, 0);
  op.as.closure.at = (uint32_t)p->w->sym_count;
  if (count > 0U) {
    if (p->w->sym_count >= p->w->sym_cap) {
      return BS_ERR_NOMEM;
    }
    p->w->syms[p->w->sym_count] = param;
    p->w->sym_count++;
  }
  return bs_p_emit(out, n, cap, op);
}

/* Apply one stack entry, turning it into the opcode it stands for. */
static bs_status bs_p_apply(bs_parser *p, const bs_opstack *e, bs_op *out,
                            size_t *n, size_t cap) {
  if (e->what == (uint8_t)BS_S_UNARY) {
    return bs_p_emit_op(out, n, cap, (uint8_t)BS_OP_UNARY, BS_U_NEGATE);
  }
  if (bs_p_is_lazy(e->punct)) {
    /* `a && b` is stored as `a` and a closure over `b`, which is what lets
     * the evaluator skip `b` when `a` already decides the answer. */
    bs_status st = bs_p_close_over(p, out, n, cap, e->out, 0U, 0U);
    if (st != BS_OK) {
      return st;
    }
  }
  return bs_p_emit_op(out, n, cap, (uint8_t)BS_OP_BINARY, bs_p_binop(e->punct));
}

/* One expression, from the current token up to whatever does not continue it.
 *
 * `out` is the caller's buffer; the finished run is copied into the op pool
 * at the end, so that closure bodies -- which reach the pool first, as they
 * complete -- stay contiguous runs of their own. */
static bs_status bs_p_expression(bs_parser *p, bs_op *out, size_t cap,
                                 bs_expr *result) {
  bs_opstack stack[BS_MAX_DEPTH];
  size_t depth = 0;
  size_t n = 0;
  /* Where the operand a method call would attach to begins. `try_or` needs
   * it, because the receiver rather than the argument is what must not be
   * evaluated eagerly. */
  size_t operand_at = 0;
  unsigned int last_prec = 0;
  int want_operand = 1;
  bs_status st;

  for (;;) {
    if (want_operand) {
      if (bs_p_is_punct(p, (uint8_t)BS_P_BANG)) {
        if (depth >= (size_t)BS_MAX_DEPTH) {
          return BS_ERR_DEPTH;
        }
        stack[depth].what = (uint8_t)BS_S_UNARY;
        depth++;
        st = bs_p_advance(p);
        if (st != BS_OK) {
          return st;
        }
        continue;
      }
      if (bs_p_is_punct(p, (uint8_t)BS_P_LPAREN)) {
        if (depth >= (size_t)BS_MAX_DEPTH) {
          return BS_ERR_DEPTH;
        }
        stack[depth].what = (uint8_t)BS_S_PAREN;
        stack[depth].out = n;
        depth++;
        last_prec = 0;
        st = bs_p_advance(p);
        if (st != BS_OK) {
          return st;
        }
        continue;
      }
      /* A closure, if the variable is followed by an arrow. Deciding needs
       * one token more than the lexer holds, so the lexer's position is
       * saved and put back when it turns out to be an ordinary variable. */
      if (p->tok.kind == (uint8_t)BS_TK_VARIABLE) {
        bs_lexer save_lex = p->lex;
        bs_token_t save_tok = p->tok;
        bs_span param = p->tok.text;
        st = bs_p_advance(p);
        if (st != BS_OK) {
          return st;
        }
        if (bs_p_is_punct(p, (uint8_t)BS_P_ARROW)) {
          uint64_t sym = 0;
          if (depth >= (size_t)BS_MAX_DEPTH) {
            return BS_ERR_DEPTH;
          }
          st = bs_symtab_intern(p->syms, param, &sym);
          if (st != BS_OK) {
            return st;
          }
          stack[depth].what = (uint8_t)BS_S_CLOSURE;
          stack[depth].out = n;
          stack[depth].param = sym;
          depth++;
          last_prec = 0;
          st = bs_p_advance(p);
          if (st != BS_OK) {
            return st;
          }
          continue;
        }
        p->lex = save_lex;
        p->tok = save_tok;
      }
      {
        bs_term t;
        uint32_t at;
        bs_op op;
        operand_at = n;
        st = bs_p_term(p, &t);
        if (st != BS_OK) {
          return st;
        }
        st = bs_pool_reserve_terms(p->w, 1U, &at);
        if (st != BS_OK) {
          return st;
        }
        p->w->terms[at] = t;
        op.tag = (uint8_t)BS_OP_VALUE;
        op.kind = 0;
        op.as.term = at;
        st = bs_p_emit(out, &n, cap, op);
        if (st != BS_OK) {
          return st;
        }
      }
      want_operand = 0;
      continue;
    }

    /* A method call binds to the operand just produced. */
    if (bs_p_is_punct(p, (uint8_t)BS_P_DOT)) {
      uint32_t kind = 0;
      int nullary = 0;
      int is_extern = 0;
      uint64_t ffi = 0;
      bs_span name;
      bs_span prefix;

      st = bs_p_advance(p);
      if (st != BS_OK) {
        return st;
      }
      if (p->tok.kind != (uint8_t)BS_TK_IDENT) {
        return BS_ERR_MALFORMED;
      }
      name = p->tok.text;
      if (bs_span_slice(name, 0U, 8U, &prefix) &&
          bs_span_eq(prefix, bs_span_make("extern::", 8U))) {
        /* An external call reaches a function the host registered. Its name
         * is interned like any other symbol; whether anything answers to it
         * is settled at evaluation, not here. */
        if (!bs_span_slice(name, 8U, name.n - 8U, &prefix) || prefix.n == 0U) {
          return BS_ERR_MALFORMED;
        }
        st = bs_symtab_intern(p->syms, prefix, &ffi);
        if (st != BS_OK) {
          return st;
        }
        kind = BS_U_FFI; /* replaced by BS_B_FFI if an argument follows */
        nullary = 0;
        is_extern = 1;
      } else if (!bs_p_method(name, &kind, &nullary)) {
        return BS_ERR_MALFORMED;
      }
      st = bs_p_advance(p);
      if (st != BS_OK) {
        return st;
      }
      st = bs_p_expect(p, (uint8_t)BS_P_LPAREN);
      if (st != BS_OK) {
        return st;
      }
      if (is_extern && bs_p_is_punct(p, (uint8_t)BS_P_RPAREN)) {
        st = bs_p_advance(p);
        if (st != BS_OK) {
          return st;
        }
        st = bs_p_emit_ffi(out, &n, cap, (uint8_t)BS_OP_UNARY, BS_U_FFI, ffi);
        if (st != BS_OK) {
          return st;
        }
        continue;
      }
      if (nullary) {
        st = bs_p_expect(p, (uint8_t)BS_P_RPAREN);
        if (st != BS_OK) {
          return st;
        }
        st = bs_p_emit_op(out, &n, cap, (uint8_t)BS_OP_UNARY, kind);
        if (st != BS_OK) {
          return st;
        }
        continue;
      }
      if (depth >= (size_t)BS_MAX_DEPTH) {
        return BS_ERR_DEPTH;
      }
      if (kind == 29U) {
        /* `x.try_or(y)` catches a failure in `x`, so it is `x` that must be
         * held back unevaluated -- the receiver, not the argument. */
        st = bs_p_close_over(p, out, &n, cap, operand_at, 0U, 0U);
        if (st != BS_OK) {
          return st;
        }
      }
      stack[depth].what = (uint8_t)BS_S_METHOD;
      stack[depth].kind = is_extern ? BS_B_FFI : kind;
      stack[depth].param = ffi;
      stack[depth].out = operand_at;
      depth++;
      want_operand = 1;
      last_prec = 0;
      continue;
    }

    if (bs_p_is_punct(p, (uint8_t)BS_P_RPAREN)) {
      /* Close whatever the innermost bracket was. A closure and the method
       * call holding it are closed by the same `)`, which is why this pops
       * more than once. */
      int closed = 0;
      while (!closed) {
        while (depth > 0U && stack[depth - 1U].what <= (uint8_t)BS_S_UNARY) {
          depth--;
          st = bs_p_apply(p, &stack[depth], out, &n, cap);
          if (st != BS_OK) {
            return st;
          }
        }
        if (depth == 0U) {
          return BS_ERR_MALFORMED; /* a `)` that opens nothing */
        }
        depth--;
        operand_at = stack[depth].out;
        if (stack[depth].what == (uint8_t)BS_S_PAREN) {
          st = bs_p_emit_op(out, &n, cap, (uint8_t)BS_OP_UNARY, BS_U_PARENS);
          if (st != BS_OK) {
            return st;
          }
          closed = 1;
        } else if (stack[depth].what == (uint8_t)BS_S_METHOD) {
          st = bs_p_emit_ffi(out, &n, cap, (uint8_t)BS_OP_BINARY,
                             stack[depth].kind, stack[depth].param);
          if (st != BS_OK) {
            return st;
          }
          closed = 1;
        } else {
          /* A closure. Its opcodes are exactly the suffix produced since the
           * marker, so they move to the pool in one copy. Round again after
           * it, to close the method call it was an argument to. */
          st = bs_p_close_over(p, out, &n, cap, stack[depth].out, 1U,
                               stack[depth].param);
          if (st != BS_OK) {
            return st;
          }
        }
      }
      st = bs_p_advance(p);
      if (st != BS_OK) {
        return st;
      }
      last_prec = 0;
      continue;
    }

    {
      unsigned int prec;
      if (p->tok.kind != (uint8_t)BS_TK_PUNCT) {
        break;
      }
      prec = bs_p_prec(p->tok.punct);
      if (prec == 0U) {
        break;
      }
      /* Comparisons do not chain: `a < b < c` is refused rather than read as
       * something its author did not mean. */
      if (prec == 3U && last_prec == 3U) {
        return BS_ERR_MALFORMED;
      }
      while (depth > 0U && stack[depth - 1U].what <= (uint8_t)BS_S_UNARY) {
        unsigned int top = (stack[depth - 1U].what == (uint8_t)BS_S_UNARY)
                               ? BS_PREC_UNARY
                               : bs_p_prec(stack[depth - 1U].punct);
        if (top < prec) {
          break;
        }
        depth--;
        st = bs_p_apply(p, &stack[depth], out, &n, cap);
        if (st != BS_OK) {
          return st;
        }
      }
      if (depth >= (size_t)BS_MAX_DEPTH) {
        return BS_ERR_DEPTH;
      }
      stack[depth].what = (uint8_t)BS_S_BINARY;
      stack[depth].punct = p->tok.punct;
      stack[depth].out = n;
      depth++;
      last_prec = prec;
      want_operand = 1;
      st = bs_p_advance(p);
      if (st != BS_OK) {
        return st;
      }
    }
  }

  while (depth > 0U) {
    depth--;
    if (stack[depth].what > (uint8_t)BS_S_UNARY) {
      return BS_ERR_MALFORMED; /* a bracket nothing closed */
    }
    st = bs_p_apply(p, &stack[depth], out, &n, cap);
    if (st != BS_OK) {
      return st;
    }
  }

  {
    uint32_t at;
    size_t i;
    st = bs_pool_reserve_ops(p->w, n, &at);
    if (st != BS_OK) {
      return st;
    }
    for (i = 0; i < n; i++) {
      p->w->ops[at + i] = out[i];
    }
    result->at = at;
    result->count = (uint32_t)n;
  }
  return BS_OK;
}

/* --------------------------------------------------------------------------
 * Predicates, scopes and statements
 * ----------------------------------------------------------------------- */

static bs_status bs_p_predicate(bs_parser *p, bs_predicate *out) {
  bs_term *items = p->pscratch;
  size_t n = 0;
  uint64_t name = 0;
  uint32_t at;
  size_t i;
  bs_status st;

  if (p->tok.kind != (uint8_t)BS_TK_IDENT) {
    return BS_ERR_MALFORMED;
  }
  st = bs_symtab_intern(p->syms, p->tok.text, &name);
  if (st != BS_OK) {
    return st;
  }
  st = bs_p_advance(p);
  if (st != BS_OK) {
    return st;
  }
  st = bs_p_expect(p, (uint8_t)BS_P_LPAREN);
  if (st != BS_OK) {
    return st;
  }
  if (!bs_p_is_punct(p, (uint8_t)BS_P_RPAREN)) {
    for (;;) {
      if (n >= (size_t)BS_PARSE_SCRATCH) {
        return BS_ERR_LIMIT;
      }
      st = bs_p_term(p, &items[n]);
      if (st != BS_OK) {
        return st;
      }
      n++;
      if (!bs_p_is_punct(p, (uint8_t)BS_P_COMMA)) {
        break;
      }
      st = bs_p_advance(p);
      if (st != BS_OK) {
        return st;
      }
    }
  }
  st = bs_p_expect(p, (uint8_t)BS_P_RPAREN);
  if (st != BS_OK) {
    return st;
  }
  st = bs_pool_reserve_terms(p->w, n, &at);
  if (st != BS_OK) {
    return st;
  }
  for (i = 0; i < n; i++) {
    p->w->terms[at + i] = items[i];
  }
  out->name = name;
  out->at = at;
  out->count = (uint32_t)n;
  return BS_OK;
}

/* The origin bit a statement's own position stands for. The authorizer sits
 * outside the chain and has a bit reserved for it rather than a position, so
 * its index is never shifted. */
static bs_origin bs_p_self(const bs_parser *p) {
  return (p->block >= (size_t)BS_MAX_BLOCKS) ? BS_ORIGIN_AUTHORIZER
                                             : BS_ORIGIN_ONE(p->block);
}

/* One scope annotation: `authority`, `previous`, or a public key. */
static bs_status bs_p_scope(bs_parser *p, bs_origin *add) {
  size_t i;

  *add = BS_ORIGIN_NONE;

  if (BS_WORD(p, "authority")) {
    *add = BS_ORIGIN_ONE(0U);
    return bs_p_advance(p);
  }
  if (BS_WORD(p, "previous")) {
    /* Every block up to and including the one that said this. The authorizer
     * has no position in the chain, so for it the annotation means every
     * block there is. */
    size_t last =
        (p->block >= (size_t)BS_MAX_BLOCKS) ? p->w->block_count : p->block + 1U;
    for (i = 0; i < last && i < (size_t)BS_MAX_BLOCKS; i++) {
      *add |= BS_ORIGIN_ONE(i);
    }
    return bs_p_advance(p);
  }
  if (p->tok.kind == (uint8_t)BS_TK_KEY) {
    uint8_t key[32];
    bs_span hex;

    /* The token spans the algorithm too, so the digits start after the
     * slash. Only Ed25519 keys are resolved here; a secp256r1 scope parses
     * and matches nothing, because no block in this build carries one. */
    if (!bs_span_slice(p->tok.text, 0U, 8U, &hex) ||
        !bs_span_eq(hex, bs_span_make("ed25519/", 8U)) ||
        !bs_span_slice(p->tok.text, 8U, p->tok.text.n - 8U, &hex)) {
      return BS_ERR_UNSUPPORTED;
    }
    if (hex.n != 2U * sizeof key || !bs_p_unhex(hex, key, sizeof key)) {
      return BS_ERR_MALFORMED;
    }
    /* A key names every block carrying an external signature by it. Naming
     * one nobody signed with trusts nothing, which is the honest reading
     * rather than an error. */
    if (p->token != NULL) {
      for (i = 0; i < p->token->block_count; i++) {
        if (p->token->blocks[i].has_external &&
            p->token->blocks[i].external_key.alg == BS_ALG_ED25519 &&
            bs_span_eq(p->token->blocks[i].external_key.key,
                       bs_span_make(key, sizeof key))) {
          *add |= BS_ORIGIN_ONE(i);
        }
      }
    }
    return bs_p_advance(p);
  }
  return BS_ERR_MALFORMED;
}

/* An optional `trusting` clause. Without one, a statement trusts what its
 * position in the chain implies and nothing more. */
static bs_status bs_p_trusting(bs_parser *p, bs_origin *trust) {
  bs_status st;

  *trust = p->default_trust;
  if (!BS_WORD(p, "trusting")) {
    return BS_OK;
  }
  st = bs_p_advance(p);
  if (st != BS_OK) {
    return st;
  }
  /* An annotation replaces the default rather than adding to it, and the
   * authority is part of the default. Only the current block and the
   * authorizer are always trusted -- so `trusting ed25519/...` does *not*
   * keep seeing the authority, which is the difference between denying a
   * policy and granting it. */
  *trust = BS_ORIGIN_AUTHORIZER | bs_p_self(p);
  for (;;) {
    bs_origin add = BS_ORIGIN_NONE;
    st = bs_p_scope(p, &add);
    if (st != BS_OK) {
      return st;
    }
    *trust |= add;
    if (!bs_p_is_punct(p, (uint8_t)BS_P_COMMA)) {
      return BS_OK;
    }
    st = bs_p_advance(p);
    if (st != BS_OK) {
      return st;
    }
  }
}

/* Does an identifier here open a predicate rather than a term? Only a name
 * immediately followed by `(` does, which is one token further than the
 * lexer holds -- so the position is saved and put back. */
static bs_status bs_p_starts_predicate(bs_parser *p, int *yes) {
  bs_lexer save_lex;
  bs_token_t save_tok;
  bs_status st;

  *yes = 0;
  if (p->tok.kind != (uint8_t)BS_TK_IDENT) {
    return BS_OK;
  }
  if (BS_WORD(p, "true") || BS_WORD(p, "false") || BS_WORD(p, "null")) {
    return BS_OK;
  }
  save_lex = p->lex;
  save_tok = p->tok;
  st = bs_p_advance(p);
  if (st != BS_OK) {
    return st;
  }
  *yes = bs_p_is_punct(p, (uint8_t)BS_P_LPAREN);
  p->lex = save_lex;
  p->tok = save_tok;
  return BS_OK;
}

/* A rule body: predicates and expressions, comma-separated, with an optional
 * trust annotation at the end. Used for rules, for a check's queries and for
 * a policy's. */
static bs_status bs_p_body(bs_parser *p, bs_rule *out) {
  bs_predicate preds[BS_MAX_BODY];
  bs_expr exprs[BS_MAX_BODY];
  size_t npred = 0;
  size_t nexpr = 0;
  uint32_t at;
  size_t i;
  bs_status st;

  for (;;) {
    int is_pred = 0;
    st = bs_p_starts_predicate(p, &is_pred);
    if (st != BS_OK) {
      return st;
    }
    if (is_pred) {
      if (npred >= (size_t)BS_MAX_BODY) {
        return BS_ERR_LIMIT;
      }
      st = bs_p_predicate(p, &preds[npred]);
      if (st != BS_OK) {
        return st;
      }
      npred++;
    } else {
      if (nexpr >= (size_t)BS_MAX_BODY) {
        return BS_ERR_LIMIT;
      }
      st = bs_p_expression(p, p->scratch, p->scratch_cap, &exprs[nexpr]);
      if (st != BS_OK) {
        return st;
      }
      nexpr++;
    }
    if (!bs_p_is_punct(p, (uint8_t)BS_P_COMMA)) {
      break;
    }
    st = bs_p_advance(p);
    if (st != BS_OK) {
      return st;
    }
  }

  st = bs_p_trusting(p, &out->trust);
  if (st != BS_OK) {
    return st;
  }
  st = bs_pool_reserve_preds(p->w, npred, &at);
  if (st != BS_OK) {
    return st;
  }
  for (i = 0; i < npred; i++) {
    p->w->preds[at + i] = preds[i];
  }
  out->body_at = at;
  out->body_count = (uint32_t)npred;

  st = bs_pool_reserve_exprs(p->w, nexpr, &at);
  if (st != BS_OK) {
    return st;
  }
  for (i = 0; i < nexpr; i++) {
    p->w->exprs[at + i] = exprs[i];
  }
  out->expr_at = at;
  out->expr_count = (uint32_t)nexpr;
  out->block = (uint32_t)p->block;
  return BS_OK;
}

/* One or more queries joined by `or`, appended to the rule pool as one run.
 * A query is a rule with no head: it is asked, never fired. */
static bs_status bs_p_queries(bs_parser *p, uint32_t *at, uint32_t *count) {
  size_t n = 0;

  *at = (uint32_t)p->w->rule_count;
  for (;;) {
    bs_rule r;
    uint32_t slot;
    bs_status st;

    memset(&r, 0, sizeof r);
    r.is_query = 1;
    r.head.name = 0;
    r.head.at = 0;
    r.head.count = 0;
    st = bs_p_body(p, &r);
    if (st != BS_OK) {
      return st;
    }
    if (p->w->rule_count >= p->w->rule_cap) {
      return BS_ERR_NOMEM;
    }
    slot = (uint32_t)p->w->rule_count;
    p->w->rules[slot] = r;
    p->w->rule_count++;
    n++;

    if (!BS_WORD(p, "or")) {
      break;
    }
    st = bs_p_advance(p);
    if (st != BS_OK) {
      return st;
    }
  }
  *count = (uint32_t)n;
  return BS_OK;
}

/* The source a statement occupies, without the whitespace that followed it.
 * The check printer works from an encoding; the authorizer has none, so a
 * failing check is reported in the words its author wrote. */
static bs_span bs_p_since(const bs_parser *p, size_t start) {
  size_t end = p->tok.at;
  bs_span out = bs_span_make(NULL, 0);

  while (end > start) {
    uint8_t c = 0;
    if (!bs_span_at(p->lex.src, end - 1U, &c) || !bs_is_space(c)) {
      break;
    }
    end--;
  }
  (void)bs_span_slice(p->lex.src, start, end - start, &out);
  return out;
}

static bs_status bs_p_statement(bs_parser *p) {
  size_t start = p->tok.at;
  bs_status st;

  /* check if ... / check all ... / reject if ... */
  if (BS_WORD(p, "check") || BS_WORD(p, "reject")) {
    uint8_t kind = (uint8_t)BS_CHECK_KIND_ONE;
    int is_reject = BS_WORD(p, "reject");

    st = bs_p_advance(p);
    if (st != BS_OK) {
      return st;
    }
    if (is_reject) {
      if (!BS_WORD(p, "if")) {
        return BS_ERR_MALFORMED;
      }
      kind = (uint8_t)BS_CHECK_KIND_REJECT;
    } else if (BS_WORD(p, "if")) {
      kind = (uint8_t)BS_CHECK_KIND_ONE;
    } else if (BS_WORD(p, "all")) {
      kind = (uint8_t)BS_CHECK_KIND_ALL;
    } else {
      return BS_ERR_MALFORMED;
    }
    st = bs_p_advance(p);
    if (st != BS_OK) {
      return st;
    }
    {
      bs_check c;
      st = bs_p_queries(p, &c.query_at, &c.query_count);
      if (st != BS_OK) {
        return st;
      }
      c.kind = kind;
      c.block = (uint32_t)p->block;
      c.src = bs_p_since(p, start);
      c.from_text = 1;
      if (p->w->check_count >= p->w->check_cap) {
        return BS_ERR_NOMEM;
      }
      p->w->checks[p->w->check_count] = c;
      p->w->check_count++;
    }
    return BS_OK;
  }

  /* allow if ... / deny if ... */
  if (BS_WORD(p, "allow") || BS_WORD(p, "deny")) {
    uint8_t kind = BS_WORD(p, "allow") ? (uint8_t)BS_POLICY_ALLOW
                                       : (uint8_t)BS_POLICY_DENY;
    bs_policy pol;

    st = bs_p_advance(p);
    if (st != BS_OK) {
      return st;
    }
    if (!BS_WORD(p, "if")) {
      return BS_ERR_MALFORMED;
    }
    st = bs_p_advance(p);
    if (st != BS_OK) {
      return st;
    }
    st = bs_p_queries(p, &pol.query_at, &pol.query_count);
    if (st != BS_OK) {
      return st;
    }
    pol.kind = kind;
    if (p->w->policy_count >= p->w->policy_cap) {
      return BS_ERR_NOMEM;
    }
    p->w->policies[p->w->policy_count] = pol;
    p->w->policy_count++;
    return BS_OK;
  }

  /* Otherwise a head: a fact on its own, or a rule if an arrow follows. */
  {
    bs_predicate head;
    st = bs_p_predicate(p, &head);
    if (st != BS_OK) {
      return st;
    }
    if (bs_p_is_punct(p, (uint8_t)BS_P_LEFTARROW)) {
      bs_rule r;
      st = bs_p_advance(p);
      if (st != BS_OK) {
        return st;
      }
      memset(&r, 0, sizeof r);
      r.head = head;
      r.is_query = 0;
      st = bs_p_body(p, &r);
      if (st != BS_OK) {
        return st;
      }
      if (p->w->rule_count >= p->w->rule_cap) {
        return BS_ERR_NOMEM;
      }
      p->w->rules[p->w->rule_count] = r;
      st = bs_rule_bound(p->w, &p->w->rules[p->w->rule_count]);
      if (st != BS_OK) {
        return st;
      }
      p->w->rule_count++;
      return BS_OK;
    }
    {
      bs_fact f;
      uint32_t i;
      /* A fact states something outright, so nothing in it may be a
       * variable: there would be nothing to bind it to. */
      for (i = 0; i < head.count; i++) {
        if (p->w->terms[head.at + i].kind == (uint8_t)BS_T_VARIABLE) {
          return BS_ERR_MALFORMED;
        }
      }
      f.pred = head;
      f.origin = bs_p_self(p);
      if (p->w->fact_count >= p->w->fact_cap) {
        return BS_ERR_NOMEM;
      }
      p->w->facts[p->w->fact_count] = f;
      p->w->fact_count++;
      return BS_OK;
    }
  }
}

/* Parse a whole source into the world.
 *
 * `block` is the block these statements belong to, or BS_MAX_BLOCKS for the
 * authorizer, which sits outside the chain and trusts only the authority and
 * itself. */
BS_API bs_status bs_world_parse(bs_world *w, bs_symtab *syms, bs_arena *a,
                                bs_span source, size_t block,
                                const bs_token *token, const bs_tables *tab) {
  bs_parser p;
  bs_status st;

  if (w == NULL || syms == NULL || a == NULL || source.p == NULL) {
    return BS_ERR_ARGUMENT;
  }
  if (block > (size_t)BS_MAX_BLOCKS) {
    return BS_ERR_ARGUMENT;
  }

  memset(&p, 0, sizeof p);
  p.w = w;
  p.syms = syms;
  p.arena = a;
  p.token = token;
  p.tables = tab;
  p.block = block;
  p.default_trust = BS_ORIGIN_AUTHORIZER | BS_ORIGIN_ONE(0U) | bs_p_self(&p);
  p.scratch_cap = (size_t)BS_PARSE_SCRATCH;
  p.scratch =
      (bs_op *)bs_arena_array(a, p.scratch_cap, sizeof(bs_op), BS_ALIGN_MAX);
  p.tscratch = (bs_term *)bs_arena_array(a, p.scratch_cap, sizeof(bs_term),
                                         BS_ALIGN_MAX);
  p.pscratch = (bs_term *)bs_arena_array(a, p.scratch_cap, sizeof(bs_term),
                                         BS_ALIGN_MAX);
  if (p.scratch == NULL || p.tscratch == NULL || p.pscratch == NULL) {
    return BS_ERR_NOMEM;
  }

  p.lex.src = source;
  p.lex.pos = 0;
  st = bs_p_advance(&p);
  if (st != BS_OK) {
    return st;
  }

  while (p.tok.kind != (uint8_t)BS_TK_EOF) {
    st = bs_p_statement(&p);
    if (st != BS_OK) {
      return st;
    }
    /* A semicolon ends a statement. The last one may leave it out. */
    if (bs_p_is_punct(&p, (uint8_t)BS_P_SEMI)) {
      st = bs_p_advance(&p);
      if (st != BS_OK) {
        return st;
      }
      continue;
    }
    if (p.tok.kind != (uint8_t)BS_TK_EOF) {
      return BS_ERR_MALFORMED;
    }
  }
  return BS_OK;
}
