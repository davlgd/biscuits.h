/* ---------------------------------------------------------------------------
 * Expression evaluation
 *
 * The same postfix opcode stream the printer renders, actually executed. A
 * value stack, one pass, no allocation beyond what the world's pools already
 * hold -- and every intermediate value discarded afterwards, because an
 * expression must leave exactly one boolean behind and nothing else it built
 * along the way can be referred to again.
 *
 * Three semantics from the specification are easy to get subtly wrong, and
 * each one changes authorization outcomes rather than merely erroring:
 *
 *   - Integer arithmetic must *fail* on overflow, not wrap. A token that
 *     computes its way past INT64_MAX does not get a smaller number; the
 *     expression is an error and the check that contained it fails.
 *   - Strict equality (===) is a type error across types. Lenient equality
 *     (==) is simply false across types. Confusing them turns a check that
 *     should have failed loudly into one that quietly returns false, or the
 *     reverse.
 *   - Comparison is defined on integers and dates, and on nothing else.
 *     `"a" < "b"` is not false, it is a type error.
 * ------------------------------------------------------------------------ */

/* The stack an expression may use. The specification bounds expressions
 * through the run limits rather than by depth, so this is a structural
 * ceiling: an opcode stream that needs more is refused, never accommodated. */
#ifndef BS_MAX_EVAL_STACK
#define BS_MAX_EVAL_STACK 32
#endif

typedef struct bs_eval {
  bs_world *w;
  bs_symtab *syms;
  const bs_binding *bindings;
  size_t binding_count;
  bs_term stack[BS_MAX_EVAL_STACK];
  size_t sp;
} bs_eval;

static bs_status bs_push(bs_eval *e, bs_term v) {
  if (e->sp >= (size_t)BS_MAX_EVAL_STACK) {
    return BS_ERR_LIMIT;
  }
  e->stack[e->sp] = v;
  e->sp++;
  return BS_OK;
}

static bs_status bs_pop(bs_eval *e, bs_term *out) {
  if (e->sp == 0U) {
    return BS_ERR_MALFORMED; /* the opcode stream underflows its own stack */
  }
  e->sp--;
  *out = e->stack[e->sp];
  return BS_OK;
}

/* Resolve a variable to its binding, or report that it has none. */
static bs_status bs_resolve(const bs_eval *e, bs_term in, bs_term *out) {
  size_t i;
  if (in.kind != (uint8_t)BS_T_VARIABLE) {
    *out = in;
    return BS_OK;
  }
  for (i = 0; i < e->binding_count; i++) {
    if (e->bindings[i].sym == in.as.sym) {
      *out = e->bindings[i].value;
      return BS_OK;
    }
  }
  /* An unbound variable in an expression. The specification requires every
   * variable in an expression to appear in a predicate of the same rule, so
   * reaching here means the rule was accepted when it should not have been. */
  return BS_ERR_TYPE;
}

static bs_term bs_bool(int b) {
  bs_term t;
  t.kind = (uint8_t)BS_T_BOOL;
  t.as.boolean = (b != 0);
  return t;
}

static bs_term bs_int(int64_t v) {
  bs_term t;
  t.kind = (uint8_t)BS_T_INTEGER;
  t.as.integer = v;
  return t;
}

/* Equality, without recursion.
 *
 * Comparing two nested terms is naturally a tree walk, and a tree walk is
 * naturally recursive -- which invariant 2 forbids, and for a good reason
 * here: the terms come off the wire, so their nesting is chosen by whoever
 * sent the token.
 *
 * So the walk carries an explicit frame stack. Each frame is one pending
 * comparison; `last` carries a finished frame's answer back to its parent,
 * which is what a return value would do. Arrays and maps compare position by
 * position. Sets compare as sets -- same size and every element of one present
 * in the other -- because the specification treats them as deduplicated
 * collections, so two encodings of the same set must be equal.
 */
typedef struct bs_eqframe {
  bs_term a;
  bs_term b;
  uint32_t i; /* position in a */
  uint32_t j; /* position in b, while searching for a match for a[i] */
  uint8_t mode;
} bs_eqframe;

static int bs_term_eq(const bs_world *w, bs_term a, bs_term b) {
  bs_eqframe st[BS_MAX_DEPTH + 2];
  size_t d = 1;
  int last = 1;

  st[0].a = a;
  st[0].b = b;
  st[0].i = 0;
  st[0].j = 0;

  while (d > 0U) {
    bs_eqframe *f = &st[d - 1U];

    if (f->a.kind != f->b.kind) {
      last = 0;
      d--;
      continue;
    }

    switch (f->a.kind) {
    case BS_T_VARIABLE:
    case BS_T_STRING:
      last = (f->a.as.sym == f->b.as.sym);
      d--;
      continue;
    case BS_T_INTEGER:
      last = (f->a.as.integer == f->b.as.integer);
      d--;
      continue;
    case BS_T_DATE:
      last = (f->a.as.date == f->b.as.date);
      d--;
      continue;
    case BS_T_BYTES:
      last = bs_span_eq(f->a.as.bytes, f->b.as.bytes);
      d--;
      continue;
    case BS_T_BOOL:
      last = (f->a.as.boolean == f->b.as.boolean);
      d--;
      continue;
    case BS_T_NULL:
      last = 1; /* null is always equal to itself */
      d--;
      continue;
    default:
      break;
    }

    if (f->a.as.list.count != f->b.as.list.count) {
      last = 0;
      d--;
      continue;
    }
    if (d >= sizeof st / sizeof st[0]) {
      /* Deeper than the loader would have accepted, so unreachable through
       * the public API -- and answering "unequal" rather than reading past
       * the stack is the right answer if it ever is reached. */
      BS_ASSERT(0);
      return 0;
    }

    if (f->a.kind == (uint8_t)BS_T_SET) {
      /* Searching b for a match for a[i]. */
      if (f->j > 0U && last) {
        f->i++;
        f->j = 0;
      }
      if (f->i >= f->a.as.list.count) {
        last = 1;
        d--;
        continue;
      }
      if (f->j >= f->b.as.list.count) {
        last = 0; /* a[i] is in no position of b */
        d--;
        continue;
      }
      st[d].a = w->terms[f->a.as.list.at + f->i];
      st[d].b = w->terms[f->b.as.list.at + f->j];
      st[d].i = 0;
      st[d].j = 0;
      f->j++;
      d++;
      continue;
    }

    /* Arrays, and maps whose keys and values sit adjacently, compare
     * position by position. */
    if (f->i > 0U && !last) {
      d--;
      continue;
    }
    if (f->i >= f->a.as.list.count) {
      last = 1;
      d--;
      continue;
    }
    st[d].a = w->terms[f->a.as.list.at + f->i];
    st[d].b = w->terms[f->b.as.list.at + f->i];
    st[d].i = 0;
    st[d].j = 0;
    f->i++;
    d++;
  }
  return last;
}

static int bs_run_contains(const bs_world *w, uint32_t at, uint32_t count,
                           bs_term needle) {
  uint32_t i = 0;
  for (; i < count; i++) {
    if (bs_term_eq(w, w->terms[at + i], needle)) {
      return 1;
    }
  }
  return 0;
}

/* `<`, `>`, `<=`, `>=`: integers and dates only. Anything else is a type
 * error rather than false, because "is this string less than that date" has
 * no answer and pretending it is `false` hides a mistake in the token. */
static bs_status bs_compare(bs_term a, bs_term b, int *out) {
  if (a.kind != b.kind) {
    return BS_ERR_TYPE;
  }
  if (a.kind == (uint8_t)BS_T_INTEGER) {
    *out = (a.as.integer < b.as.integer) ? -1 : (a.as.integer > b.as.integer);
    return BS_OK;
  }
  if (a.kind == (uint8_t)BS_T_DATE) {
    *out = (a.as.date < b.as.date) ? -1 : (a.as.date > b.as.date);
    return BS_OK;
  }
  return BS_ERR_TYPE;
}

/* Integer arithmetic, checked. The specification is explicit: "Integer
 * operations must have overflow checks. If it overflows, the expression
 * fails." Wrapping would let a token compute its way to a smaller number and
 * satisfy a bound it should not. */
static bs_status bs_arith(uint32_t op, int64_t x, int64_t y, int64_t *out) {
#ifdef BS_HAS_OVERFLOW_BUILTINS
  switch (op) {
  case 9U:
    return __builtin_add_overflow(x, y, out) ? BS_ERR_OVERFLOW : BS_OK;
  case 10U:
    return __builtin_sub_overflow(x, y, out) ? BS_ERR_OVERFLOW : BS_OK;
  case 11U:
    return __builtin_mul_overflow(x, y, out) ? BS_ERR_OVERFLOW : BS_OK;
  default:
    break;
  }
#else
  switch (op) {
  case 9U:
    if ((y > 0 && x > INT64_MAX - y) || (y < 0 && x < INT64_MIN - y)) {
      return BS_ERR_OVERFLOW;
    }
    *out = x + y;
    return BS_OK;
  case 10U:
    if ((y < 0 && x > INT64_MAX + y) || (y > 0 && x < INT64_MIN + y)) {
      return BS_ERR_OVERFLOW;
    }
    *out = x - y;
    return BS_OK;
  case 11U:
    if (x != 0 && y != 0) {
      int64_t r = x * y;
      if (r / x != y) {
        return BS_ERR_OVERFLOW;
      }
      *out = r;
    } else {
      *out = 0;
    }
    return BS_OK;
  default:
    break;
  }
#endif
  /* Division. Zero is an error, and so is INT64_MIN / -1, whose result has no
   * representation -- on most machines it traps rather than wrapping. */
  if (y == 0) {
    return BS_ERR_OVERFLOW;
  }
  if (x == INT64_MIN && y == -1) {
    return BS_ERR_OVERFLOW;
  }
  *out = x / y;
  return BS_OK;
}

/* The name `.type()` returns for each kind, interned on demand so the result
 * is an ordinary string term and comparisons against it are ordinary symbol
 * comparisons. */
static bs_status bs_typeof(bs_eval *e, bs_term v, bs_term *out) {
  /* Lengths from sizeof, not from a scan: a hand-written walk to the
   * terminator is an idiom the optimiser rewrites into a call to strlen,
   * which would put a str* function into the shipped object. That is not
   * hypothetical -- it is what tools/check_invariants.py caught here. */
  static const bs_static_symbol NAMES[] = {
      BS_SYM("variable"), BS_SYM("integer"), BS_SYM("string"), BS_SYM("date"),
      BS_SYM("bytes"),    BS_SYM("bool"),    BS_SYM("set"),    BS_SYM("null"),
      BS_SYM("array"),    BS_SYM("map"),
  };

  if (v.kind == (uint8_t)BS_T_VARIABLE ||
      v.kind >= (uint8_t)(sizeof NAMES / sizeof NAMES[0])) {
    /* A variable has no type of its own: it is resolved before it gets
     * here, and reaching this means it was never bound. */
    return BS_ERR_TYPE;
  }
  out->kind = (uint8_t)BS_T_STRING;
  return bs_symtab_intern(e->syms,
                          bs_span_make(NAMES[v.kind].text, NAMES[v.kind].len),
                          &out->as.sym);
}

/* `.length()`: bytes for a string, elements for a container. The
 * specification counts UTF-8 bytes rather than characters, deliberately --
 * counting grapheme clusters would give different answers in different
 * languages, which is not something an authorization decision can afford. */
static bs_status bs_length(const bs_eval *e, bs_term v, int64_t *out) {
  bs_span text;
  switch (v.kind) {
  case BS_T_STRING:
    if (!bs_symtab_get(e->syms, v.as.sym, &text)) {
      return BS_ERR_TYPE;
    }
    *out = (int64_t)text.n;
    return BS_OK;
  case BS_T_BYTES:
    *out = (int64_t)v.as.bytes.n;
    return BS_OK;
  case BS_T_SET:
  case BS_T_ARRAY:
    *out = (int64_t)v.as.list.count;
    return BS_OK;
  case BS_T_MAP:
    /* Keys and values are stored adjacently; the length of a map is its
     * number of entries, not its number of slots. */
    *out = (int64_t)(v.as.list.count / 2U);
    return BS_OK;
  default:
    return BS_ERR_TYPE;
  }
}

/* `.contains()`: membership for a container, superset for two sets, and a
 * substring test between two strings. */
static bs_status bs_contains(const bs_eval *e, bs_term hay, bs_term needle,
                             int *out) {
  uint32_t i;

  if (hay.kind == (uint8_t)BS_T_SET && needle.kind == (uint8_t)BS_T_SET) {
    /* Between two sets, whether the first is a superset of the second. */
    for (i = 0; i < needle.as.list.count; i++) {
      if (!bs_run_contains(e->w, hay.as.list.at, hay.as.list.count,
                           e->w->terms[needle.as.list.at + i])) {
        *out = 0;
        return BS_OK;
      }
    }
    *out = 1;
    return BS_OK;
  }

  switch (hay.kind) {
  case BS_T_SET:
  case BS_T_ARRAY:
    *out = bs_run_contains(e->w, hay.as.list.at, hay.as.list.count, needle);
    return BS_OK;
  case BS_T_MAP:
    /* For a map, whether the argument is one of its keys. Keys sit at even
     * offsets. Anything that is not an integer or a string cannot be a key,
     * and the answer is false rather than an error. */
    *out = 0;
    if (needle.kind != (uint8_t)BS_T_INTEGER &&
        needle.kind != (uint8_t)BS_T_STRING) {
      return BS_OK;
    }
    for (i = 0; i + 1U < hay.as.list.count; i += 2U) {
      if (bs_term_eq(e->w, e->w->terms[hay.as.list.at + i], needle)) {
        *out = 1;
        return BS_OK;
      }
    }
    return BS_OK;
  case BS_T_STRING: {
    bs_span h;
    bs_span n;
    size_t i2;
    if (needle.kind != (uint8_t)BS_T_STRING) {
      return BS_ERR_TYPE;
    }
    if (!bs_symtab_get(e->syms, hay.as.sym, &h) ||
        !bs_symtab_get(e->syms, needle.as.sym, &n)) {
      return BS_ERR_TYPE;
    }
    *out = 0;
    if (n.n > h.n) {
      return BS_OK;
    }
    for (i2 = 0; i2 + n.n <= h.n; i2++) {
      bs_span window;
      if (bs_span_slice(h, i2, n.n, &window) && bs_span_eq(window, n)) {
        *out = 1;
        return BS_OK;
      }
    }
    return BS_OK;
  }
  default:
    return BS_ERR_TYPE;
  }
}

/* `.get()`: an element of an array by position, or a value of a map by key.
 * Out of range is `null` rather than an error, which is what makes `get`
 * usable without a length check in front of it. */
static bs_status bs_get(const bs_eval *e, bs_term container, bs_term key,
                        bs_term *out) {
  out->kind = (uint8_t)BS_T_NULL;
  if (container.kind == (uint8_t)BS_T_ARRAY) {
    if (key.kind != (uint8_t)BS_T_INTEGER) {
      return BS_ERR_TYPE;
    }
    if (key.as.integer < 0 ||
        (uint64_t)key.as.integer >= (uint64_t)container.as.list.count) {
      return BS_OK;
    }
    *out = e->w->terms[container.as.list.at + (uint32_t)key.as.integer];
    return BS_OK;
  }
  if (container.kind == (uint8_t)BS_T_MAP) {
    uint32_t i;
    if (key.kind != (uint8_t)BS_T_INTEGER && key.kind != (uint8_t)BS_T_STRING) {
      return BS_ERR_TYPE;
    }
    for (i = 0; i + 1U < container.as.list.count; i += 2U) {
      if (bs_term_eq(e->w, e->w->terms[container.as.list.at + i], key)) {
        *out = e->w->terms[container.as.list.at + i + 1U];
        return BS_OK;
      }
    }
    return BS_OK;
  }
  return BS_ERR_TYPE;
}

/* Evaluate one expression to a boolean.
 *
 * The opcode stream is postfix, so this is a plain left-to-right pass over a
 * value stack -- no tree, no recursion, no lookahead. Exactly one value must
 * remain at the end and it must be a boolean, which the specification
 * requires and which is checked here rather than assumed.
 *
 * Every failure mode is a distinct status because the conformance suite
 * distinguishes them: an overflow and a type error are different outcomes,
 * and reporting both as "malformed" would pass fewer cases while looking
 * tidier. */
static bs_status bs_expr_eval(bs_eval *e, bs_expr expr, int *out) {
  uint32_t i;
  bs_term result;

  e->sp = 0;

  for (i = 0; i < expr.count; i++) {
    const bs_op *op;
    bs_term a;
    bs_term b;
    bs_status st;
    int cmp = 0;
    int flag = 0;
    int64_t n = 0;

    if ((size_t)expr.at + (size_t)i >= e->w->op_count) {
      return BS_ERR_MALFORMED;
    }
    op = &e->w->ops[expr.at + i];

    if (op->tag == (uint8_t)BS_OP_VALUE) {
      if ((size_t)op->as.term >= e->w->term_count) {
        return BS_ERR_MALFORMED;
      }
      st = bs_resolve(e, e->w->terms[op->as.term], &a);
      if (st != BS_OK) {
        return st;
      }
      st = bs_push(e, a);
      if (st != BS_OK) {
        return st;
      }
      continue;
    }

    if (op->tag == (uint8_t)BS_OP_CLOSURE) {
      /* Closures are only meaningful as the operand of the operator that
       * consumes them, and those operators are not implemented yet. Refusing
       * is what keeps a half-evaluated expression from being reported as a
       * decision. */
      return BS_ERR_UNSUPPORTED;
    }

    if (op->tag == (uint8_t)BS_OP_UNARY) {
      st = bs_pop(e, &a);
      if (st != BS_OK) {
        return st;
      }
      switch (op->kind) {
      case BS_U_NEGATE:
        if (a.kind != (uint8_t)BS_T_BOOL) {
          return BS_ERR_TYPE;
        }
        st = bs_push(e, bs_bool(!a.as.boolean));
        break;
      case BS_U_PARENS:
        /* Present only so the printer can reproduce the source. */
        st = bs_push(e, a);
        break;
      case BS_U_LENGTH:
        st = bs_length(e, a, &n);
        if (st == BS_OK) {
          st = bs_push(e, bs_int(n));
        }
        break;
      case BS_U_TYPEOF:
        st = bs_typeof(e, a, &b);
        if (st == BS_OK) {
          st = bs_push(e, b);
        }
        break;
      default:
        return BS_ERR_UNSUPPORTED; /* external calls */
      }
      if (st != BS_OK) {
        return st;
      }
      continue;
    }

    /* Binary. The right-hand side was pushed last. */
    st = bs_pop(e, &b);
    if (st != BS_OK) {
      return st;
    }
    st = bs_pop(e, &a);
    if (st != BS_OK) {
      return st;
    }

    switch (op->kind) {
    case 0U: /* < */
    case 1U: /* > */
    case 2U: /* <= */
    case 3U: /* >= */
      st = bs_compare(a, b, &cmp);
      if (st != BS_OK) {
        return st;
      }
      flag = (op->kind == 0U)   ? (cmp < 0)
             : (op->kind == 1U) ? (cmp > 0)
             : (op->kind == 2U) ? (cmp <= 0)
                                : (cmp >= 0);
      st = bs_push(e, bs_bool(flag));
      break;

    case 4U:  /* === */
    case 20U: /* !== */
      /* Strict: comparing different types is an error, not false. */
      if (a.kind != b.kind) {
        return BS_ERR_TYPE;
      }
      flag = bs_term_eq(e->w, a, b);
      st = bs_push(e, bs_bool((op->kind == 4U) ? flag : !flag));
      break;

    case 21U: /* == */
    case 22U: /* != */
      /* Lenient: different types are simply unequal. */
      flag = (a.kind == b.kind) && bs_term_eq(e->w, a, b);
      st = bs_push(e, bs_bool((op->kind == 21U) ? flag : !flag));
      break;

    case 5U: /* .contains() */
      st = bs_contains(e, a, b, &flag);
      if (st == BS_OK) {
        st = bs_push(e, bs_bool(flag));
      }
      break;

    case 9U:  /* + */
    case 10U: /* - */
    case 11U: /* * */
    case 12U: /* / */
      if (a.kind != (uint8_t)BS_T_INTEGER || b.kind != (uint8_t)BS_T_INTEGER) {
        /* `+` also concatenates strings, which needs somewhere to put the
         * result; that arrives with the rest of the string operations. */
        return (op->kind == 9U) ? BS_ERR_UNSUPPORTED : BS_ERR_TYPE;
      }
      st = bs_arith(op->kind, a.as.integer, b.as.integer, &n);
      if (st == BS_OK) {
        st = bs_push(e, bs_int(n));
      }
      break;

    case 13U: /* &&, eager */
    case 14U: /* ||, eager */
      if (a.kind != (uint8_t)BS_T_BOOL || b.kind != (uint8_t)BS_T_BOOL) {
        return BS_ERR_TYPE;
      }
      flag = (op->kind == 13U) ? (a.as.boolean && b.as.boolean)
                               : (a.as.boolean || b.as.boolean);
      st = bs_push(e, bs_bool(flag));
      break;

    case 17U: /* & */
    case 18U: /* | */
    case 19U: /* ^ */
      if (a.kind != (uint8_t)BS_T_INTEGER || b.kind != (uint8_t)BS_T_INTEGER) {
        return BS_ERR_TYPE;
      }
      {
        uint64_t x = (uint64_t)a.as.integer;
        uint64_t y = (uint64_t)b.as.integer;
        uint64_t r = (op->kind == 17U)   ? (x & y)
                     : (op->kind == 18U) ? (x | y)
                                         : (x ^ y);
        st = bs_push(e, bs_int((int64_t)r));
      }
      break;

    case 27U: /* .get() */
      st = bs_get(e, a, b, &result);
      if (st == BS_OK) {
        st = bs_push(e, result);
      }
      break;

    default:
      /* String operations, set algebra, closures and external calls. Refused
       * rather than approximated: an operator that silently returns false is
       * a check that silently passes. */
      return BS_ERR_UNSUPPORTED;
    }
    if (st != BS_OK) {
      return st;
    }
  }

  if (e->sp != 1U) {
    return BS_ERR_MALFORMED;
  }
  if (e->stack[0].kind != (uint8_t)BS_T_BOOL) {
    /* "After executing, the stack must contain only one value, of the boolean
     * type." An expression that leaves an integer is not false, it is wrong. */
    return BS_ERR_TYPE;
  }
  *out = e->stack[0].as.boolean;
  return BS_OK;
}

/* Evaluate one expression of the world, with the given variable bindings. */
BS_API bs_status bs_expr_evaluate(bs_world *w, bs_symtab *syms, bs_expr expr,
                                  const bs_binding *bindings,
                                  size_t binding_count, int *out) {
  bs_eval e;
  if (w == NULL || syms == NULL || out == NULL) {
    return BS_ERR_ARGUMENT;
  }
  e.w = w;
  e.syms = syms;
  e.bindings = bindings;
  e.binding_count = binding_count;
  e.sp = 0;
  return bs_expr_eval(&e, expr, out);
}
