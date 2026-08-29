/* ---------------------------------------------------------------------------
 * Parsing Datalog source
 *
 * Facts, rules, checks and policies, from text into the same pools the wire
 * format loads into. One representation, two front ends: the evaluator never
 * learns where anything came from.
 *
 * Expressions are the interesting part. They are written infix and stored
 * postfix, which is normally a recursive-descent parser per precedence level
 * -- eight of them here -- and invariant 2 forbids that. Shunting-yard does
 * the same job with two explicit stacks, and it produces postfix directly,
 * which is exactly the order the opcode pool wants. The precedence table
 * below is taken from the reference parser rather than guessed, and it is not
 * C's: `&` binds tighter than `|`, which binds tighter than `^`, and
 * comparisons do not chain.
 *
 * A closure's body has to be one contiguous run of opcodes, separate from the
 * expression containing it. So the expression being parsed accumulates in
 * scratch while closure bodies are written straight to the pool as they
 * complete -- innermost first, the enclosing expression last. Everything ends
 * up contiguous without anything being moved twice.
 * ------------------------------------------------------------------------ */

#ifndef BS_PARSE_SCRATCH
#define BS_PARSE_SCRATCH 256
#endif

typedef struct bs_parser {
  bs_lexer lex;
  bs_token_t tok; /* one token of lookahead */
  bs_world *w;
  bs_symtab *syms;
  const bs_token *token; /* for a scope naming a public key */
  const bs_tables *tables;
  bs_arena *arena; /* for bytes literals and parser scratch */
  bs_op *scratch;  /* the expression under construction */
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

static bs_status bs_p_term(bs_parser *p, bs_term *out);

/* A container's elements, appended to the term pool as one run.
 *
 * The elements are parsed into a local array first because a nested container
 * would otherwise write into the middle of this one's run. The bound on that
 * array is what limits how many elements a literal may have. */
static bs_status bs_p_container(bs_parser *p, uint8_t close, uint8_t kind,
                                bs_term *out) {
  bs_term items[BS_PARSE_SCRATCH];
  size_t n = 0;
  uint32_t at;
  size_t i;
  bs_status st;

  if (bs_p_is_punct(p, close)) {
    st = bs_p_advance(p);
    if (st != BS_OK) {
      return st;
    }
    out->kind = kind;
    out->as.list.at = (uint32_t)p->w->term_count;
    out->as.list.count = 0;
    return BS_OK;
  }

  for (;;) {
    if (n >= (size_t)BS_PARSE_SCRATCH) {
      return BS_ERR_LIMIT;
    }
    st = bs_p_term(p, &items[n]);
    if (st != BS_OK) {
      return st;
    }
    n++;
    if (kind == (uint8_t)BS_T_MAP) {
      /* A map's key and value sit adjacently, so the colon separates two
       * elements of the same run rather than introducing a second one. */
      st = bs_p_expect(p, (uint8_t)BS_P_COLON);
      if (st != BS_OK) {
        return st;
      }
      if (n >= (size_t)BS_PARSE_SCRATCH) {
        return BS_ERR_LIMIT;
      }
      st = bs_p_term(p, &items[n]);
      if (st != BS_OK) {
        return st;
      }
      n++;
    }
    if (bs_p_is_punct(p, (uint8_t)BS_P_COMMA)) {
      st = bs_p_advance(p);
      if (st != BS_OK) {
        return st;
      }
      /* A trailing comma before the closer is how an empty set is written:
       * `{,}`, which distinguishes it from an empty map. */
      if (bs_p_is_punct(p, close)) {
        break;
      }
      continue;
    }
    break;
  }

  st = bs_p_expect(p, close);
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
  out->kind = kind;
  out->as.list.at = at;
  out->as.list.count = (uint32_t)n;
  return BS_OK;
}

static bs_status bs_p_term(bs_parser *p, bs_term *out) {
  bs_status st;

  switch (p->tok.kind) {
  case BS_TK_STRING:
    out->kind = (uint8_t)BS_T_STRING;
    st = bs_symtab_intern(p->syms, p->tok.text, &out->as.sym);
    if (st != BS_OK) {
      return st;
    }
    return bs_p_advance(p);
  case BS_TK_VARIABLE:
    out->kind = (uint8_t)BS_T_VARIABLE;
    st = bs_symtab_intern(p->syms, p->tok.text, &out->as.sym);
    if (st != BS_OK) {
      return st;
    }
    return bs_p_advance(p);
  case BS_TK_INTEGER:
    out->kind = (uint8_t)BS_T_INTEGER;
    out->as.integer = p->tok.integer;
    return bs_p_advance(p);
  case BS_TK_DATE:
    out->kind = (uint8_t)BS_T_DATE;
    out->as.date = p->tok.date;
    return bs_p_advance(p);
  case BS_TK_BYTES: {
    /* The hex digits are decoded in place into the pool's own bytes... except
     * a term's bytes are a span into memory that must outlive it, so they go
     * in the arena. */
    size_t n = p->tok.text.n / 2U;
    uint8_t *buf = (uint8_t *)bs_arena_alloc(p->arena, (n == 0U) ? 1U : n, 1U);
    size_t i;
    if (buf == NULL) {
      return BS_ERR_NOMEM;
    }
    for (i = 0; i < n; i++) {
      uint8_t hi = 0;
      uint8_t lo = 0;
      (void)bs_hex_digit(p->tok.text.p[2U * i], &hi);
      (void)bs_hex_digit(p->tok.text.p[2U * i + 1U], &lo);
      buf[i] = (uint8_t)((hi << 4U) | lo);
    }
    out->kind = (uint8_t)BS_T_BYTES;
    out->as.bytes = bs_span_make(buf, n);
    return bs_p_advance(p);
  }
  case BS_TK_IDENT:
    if (BS_WORD(p, "true") || BS_WORD(p, "false")) {
      out->kind = (uint8_t)BS_T_BOOL;
      out->as.boolean = BS_WORD(p, "true");
      return bs_p_advance(p);
    }
    if (BS_WORD(p, "null")) {
      out->kind = (uint8_t)BS_T_NULL;
      return bs_p_advance(p);
    }
    return BS_ERR_MALFORMED;
  case BS_TK_PUNCT:
    if (p->tok.punct == (uint8_t)BS_P_LBRACKET) {
      st = bs_p_advance(p);
      if (st != BS_OK) {
        return st;
      }
      return bs_p_container(p, (uint8_t)BS_P_RBRACKET, (uint8_t)BS_T_ARRAY,
                            out);
    }
    if (p->tok.punct == (uint8_t)BS_P_LBRACE) {
      /* A brace opens either a set or a map, and only the colon after the
       * first element tells them apart. Rather than backtrack, the container
       * parser is told which to expect after a one-token peek. */
      bs_lexer save = p->lex;
      bs_token_t saved_tok = p->tok;
      int is_map = 0;
      st = bs_p_advance(p);
      if (st != BS_OK) {
        return st;
      }
      if (!bs_p_is_punct(p, (uint8_t)BS_P_RBRACE)) {
        bs_term probe;
        bs_lexer inner = p->lex;
        bs_token_t inner_tok = p->tok;
        size_t term_mark = p->w->term_count;
        if (bs_p_term(p, &probe) == BS_OK &&
            bs_p_is_punct(p, (uint8_t)BS_P_COLON)) {
          is_map = 1;
        }
        p->w->term_count = term_mark;
        p->lex = inner;
        p->tok = inner_tok;
      }
      (void)save;
      (void)saved_tok;
      return bs_p_container(p, (uint8_t)BS_P_RBRACE,
                            is_map ? (uint8_t)BS_T_MAP : (uint8_t)BS_T_SET,
                            out);
    }
    return BS_ERR_MALFORMED;
  default:
    return BS_ERR_MALFORMED;
  }
}

/* --------------------------------------------------------------------------
 * Expressions
 *
 * Shunting-yard: operands out, operators onto a stack, and an operator is
 * flushed when one of no-lower precedence arrives. The output is postfix,
 * which is what the opcode pool holds, so nothing is rearranged afterwards.
 *
 * The precedence table is the reference implementation's, and it is worth
 * reading twice because it is not C's: `&` binds tighter than `|`, which
 * binds tighter than `^`, and comparisons are non-associative -- `a < b < c`
 * is a syntax error rather than something surprising.
 * ----------------------------------------------------------------------- */

/* Lowest binds loosest. 0 means "not a binary operator". */
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

/* The opcode a punctuation token stands for. */
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
  case BS_P_NEQ3:
    return 20U;
  case BS_P_EQ2:
    return 21U;
  case BS_P_NEQ2:
    return 22U;
  case BS_P_PLUS:
    return 9U;
  case BS_P_MINUS:
    return 10U;
  case BS_P_STAR:
    return 11U;
  case BS_P_SLASH:
    return 12U;
  case BS_P_AND2:
    return 23U; /* short-circuiting */
  case BS_P_OR2:
    return 24U;
  case BS_P_AND2E:
    return 13U; /* eager */
  case BS_P_OR2E:
    return 14U;
  case BS_P_AMP:
    return 17U;
  case BS_P_PIPE:
    return 18U;
  default:
    return 19U; /* BS_P_CARET */
  }
}

/* The method names that are binary, and the two that are unary. */
static int bs_p_method(bs_span name, uint32_t *kind, int *is_unary) {
  static const struct {
    const char *text;
    size_t len;
    uint32_t kind;
    int unary;
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
      *is_unary = METHODS[i].unary;
      return 1;
    }
  }
  return 0;
}

typedef struct bs_exprbuf {
  bs_op *ops;
  size_t count;
  size_t cap;
} bs_exprbuf;

static bs_status bs_eb_push(bs_exprbuf *b, bs_op op) {
  if (b->count >= b->cap) {
    return BS_ERR_LIMIT;
  }
  b->ops[b->count] = op;
  b->count++;
  return BS_OK;
}

static bs_status bs_eb_value(bs_parser *p, bs_exprbuf *b, bs_term t) {
  bs_op op;
  uint32_t at;
  bs_status st = bs_pool_reserve_terms(p->w, 1U, &at);
  if (st != BS_OK) {
    return st;
  }
  p->w->terms[at] = t;
  op.tag = (uint8_t)BS_OP_VALUE;
  op.kind = 0;
  op.as.term = at;
  return bs_eb_push(b, op);
}

static bs_status bs_eb_op(bs_exprbuf *b, uint8_t tag, uint32_t kind) {
  bs_op op;
  op.tag = tag;
  op.kind = kind;
  op.as.ffi = 0;
  return bs_eb_push(b, op);
}

/* Copy a finished run of opcodes into the pool. */
static bs_status bs_eb_emit(bs_parser *p, const bs_op *ops, size_t n,
                            bs_expr *out) {
  uint32_t at;
  size_t i;
  bs_status st = bs_pool_reserve_ops(p->w, n, &at);
  if (st != BS_OK) {
    return st;
  }
  for (i = 0; i < n; i++) {
    p->w->ops[at + i] = ops[i];
  }
  out->at = at;
  out->count = (uint32_t)n;
  return BS_OK;
}

static bs_status bs_p_expression(bs_parser *p, bs_op *scratch, size_t cap,
                                 bs_expr *out);

/* One operand: a term, a parenthesised expression, a negation, or a closure,
 * followed by any number of method calls. */
static bs_status bs_p_operand(bs_parser *p, bs_exprbuf *b) {
  bs_status st;

  if (bs_p_is_punct(p, (uint8_t)BS_P_BANG)) {
    st = bs_p_advance(p);
    if (st != BS_OK) {
      return st;
    }
    st = bs_p_operand(p, b);
    if (st != BS_OK) {
      return st;
    }
    return bs_eb_op(b, (uint8_t)BS_OP_UNARY, BS_U_NEGATE);
  }

  if (bs_p_is_punct(p, (uint8_t)BS_P_LPAREN)) {
    /* Parentheses are kept, as an opcode, because the printer has to be able
     * to put them back exactly where the author wrote them. */
    st = bs_p_advance(p);
    if (st != BS_OK) {
      return st;
    }
    {
      bs_expr inner;
      size_t i;
      st = bs_p_expression(p, b->ops + b->count, b->cap - b->count, &inner);
      if (st != BS_OK) {
        return st;
      }
      /* The sub-expression went to the pool; copy it back into this buffer so
       * the enclosing run stays one piece. */
      if (b->count + inner.count > b->cap) {
        return BS_ERR_LIMIT;
      }
      for (i = 0; i < inner.count; i++) {
        b->ops[b->count + i] = p->w->ops[inner.at + i];
      }
      b->count += inner.count;
      p->w->op_count -= inner.count;
    }
    st = bs_p_expect(p, (uint8_t)BS_P_RPAREN);
    if (st != BS_OK) {
      return st;
    }
    st = bs_eb_op(b, (uint8_t)BS_OP_UNARY, BS_U_PARENS);
    if (st != BS_OK) {
      return st;
    }
  } else {
    bs_term t;
    st = bs_p_term(p, &t);
    if (st != BS_OK) {
      return st;
    }
    st = bs_eb_value(p, b, t);
    if (st != BS_OK) {
      return st;
    }
  }

  /* Method calls, left to right. */
  while (bs_p_is_punct(p, (uint8_t)BS_P_DOT)) {
    bs_span name;
    uint32_t kind = 0;
    int unary = 0;

    st = bs_p_advance(p);
    if (st != BS_OK) {
      return st;
    }
    if (p->tok.kind != (uint8_t)BS_TK_IDENT) {
      return BS_ERR_MALFORMED;
    }
    name = p->tok.text;
    if (!bs_p_method(name, &kind, &unary)) {
      /* External calls are implementation-defined and this build defines
       * none, so a call to one is refused rather than ignored. */
      return BS_ERR_UNSUPPORTED;
    }
    st = bs_p_advance(p);
    if (st != BS_OK) {
      return st;
    }
    st = bs_p_expect(p, (uint8_t)BS_P_LPAREN);
    if (st != BS_OK) {
      return st;
    }
    if (unary) {
      st = bs_p_expect(p, (uint8_t)BS_P_RPAREN);
      if (st != BS_OK) {
        return st;
      }
      st = bs_eb_op(b, (uint8_t)BS_OP_UNARY, kind);
      if (st != BS_OK) {
        return st;
      }
      continue;
    }

    /* The argument: either a closure, or an ordinary expression. */
    if (p->tok.kind == (uint8_t)BS_TK_VARIABLE) {
      bs_lexer save_lex = p->lex;
      bs_token_t save_tok = p->tok;
      bs_span param = p->tok.text;
      st = bs_p_advance(p);
      if (st != BS_OK) {
        return st;
      }
      if (bs_p_is_punct(p, (uint8_t)BS_P_ARROW)) {
        bs_op op;
        bs_expr body;
        uint64_t sym = 0;
        st = bs_p_advance(p);
        if (st != BS_OK) {
          return st;
        }
        /* The body goes straight to the pool: it is complete before the
         * expression around it, so its run is contiguous there while the
         * enclosing one is still accumulating here. */
        st = bs_p_expression(p, b->ops + b->count, b->cap - b->count, &body);
        if (st != BS_OK) {
          return st;
        }
        st = bs_symtab_intern(p->syms, param, &sym);
        if (st != BS_OK) {
          return st;
        }
        if (p->w->sym_count >= p->w->sym_cap) {
          return BS_ERR_NOMEM;
        }
        op.tag = (uint8_t)BS_OP_CLOSURE;
        op.kind = 0;
        op.as.closure.at = (uint32_t)p->w->sym_count;
        op.as.closure.count = 1U;
        op.as.closure.body = body;
        op.as.closure.src = bs_span_make(NULL, 0);
        p->w->syms[p->w->sym_count] = sym;
        p->w->sym_count++;
        st = bs_eb_push(b, op);
        if (st != BS_OK) {
          return st;
        }
        st = bs_p_expect(p, (uint8_t)BS_P_RPAREN);
        if (st != BS_OK) {
          return st;
        }
        st = bs_eb_op(b, (uint8_t)BS_OP_BINARY, kind);
        if (st != BS_OK) {
          return st;
        }
        continue;
      }
      p->lex = save_lex;
      p->tok = save_tok;
    }

    {
      bs_expr arg;
      size_t i;
      st = bs_p_expression(p, b->ops + b->count, b->cap - b->count, &arg);
      if (st != BS_OK) {
        return st;
      }
      if (b->count + arg.count > b->cap) {
        return BS_ERR_LIMIT;
      }
      for (i = 0; i < arg.count; i++) {
        b->ops[b->count + i] = p->w->ops[arg.at + i];
      }
      b->count += arg.count;
      p->w->op_count -= arg.count;
    }
    st = bs_p_expect(p, (uint8_t)BS_P_RPAREN);
    if (st != BS_OK) {
      return st;
    }
    st = bs_eb_op(b, (uint8_t)BS_OP_BINARY, kind);
    if (st != BS_OK) {
      return st;
    }
  }
  return BS_OK;
}

static bs_status bs_p_expression(bs_parser *p, bs_op *scratch, size_t cap,
                                 bs_expr *out) {
  bs_exprbuf b;
  uint8_t opstack[BS_PARSE_SCRATCH];
  size_t nops = 0;
  unsigned int last_prec = 0;
  bs_status st;

  b.ops = scratch;
  b.count = 0;
  b.cap = cap;

  st = bs_p_operand(p, &b);
  if (st != BS_OK) {
    return st;
  }

  for (;;) {
    unsigned int prec;
    if (p->tok.kind != (uint8_t)BS_TK_PUNCT) {
      break;
    }
    prec = bs_p_prec(p->tok.punct);
    if (prec == 0U) {
      break;
    }
    /* Comparisons do not chain: `a < b < c` is refused rather than read as
     * something the author did not mean. */
    if (prec == 3U && last_prec == 3U) {
      return BS_ERR_MALFORMED;
    }
    while (nops > 0U && bs_p_prec(opstack[nops - 1U]) >= prec) {
      nops--;
      st = bs_eb_op(&b, (uint8_t)BS_OP_BINARY, bs_p_binop(opstack[nops]));
      if (st != BS_OK) {
        return st;
      }
    }
    if (nops >= (size_t)BS_PARSE_SCRATCH) {
      return BS_ERR_LIMIT;
    }
    opstack[nops] = p->tok.punct;
    nops++;
    last_prec = prec;
    st = bs_p_advance(p);
    if (st != BS_OK) {
      return st;
    }
    st = bs_p_operand(p, &b);
    if (st != BS_OK) {
      return st;
    }
  }

  while (nops > 0U) {
    nops--;
    st = bs_eb_op(&b, (uint8_t)BS_OP_BINARY, bs_p_binop(opstack[nops]));
    if (st != BS_OK) {
      return st;
    }
  }
  return bs_eb_emit(p, b.ops, b.count, out);
}
