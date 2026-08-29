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
  bs_arena *arena; /* scratch for values an operator builds, rewound after */
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

/* Prefix and suffix, on strings and on arrays.
 *
 * The array case compares element by element rather than by run, because two
 * arrays holding equal values may hold them at different pool offsets. */
static bs_status bs_affix(const bs_eval *e, bs_term whole, bs_term part,
                          int suffix, int *out) {
  if (whole.kind != part.kind) {
    return BS_ERR_TYPE;
  }
  if (whole.kind == (uint8_t)BS_T_STRING) {
    bs_span h;
    bs_span n;
    bs_span window;
    if (!bs_symtab_get(e->syms, whole.as.sym, &h) ||
        !bs_symtab_get(e->syms, part.as.sym, &n)) {
      return BS_ERR_TYPE;
    }
    if (n.n > h.n) {
      *out = 0;
      return BS_OK;
    }
    *out = bs_span_slice(h, suffix ? (h.n - n.n) : 0U, n.n, &window) &&
           bs_span_eq(window, n);
    return BS_OK;
  }
  if (whole.kind == (uint8_t)BS_T_ARRAY) {
    uint32_t i;
    uint32_t off;
    if (part.as.list.count > whole.as.list.count) {
      *out = 0;
      return BS_OK;
    }
    off = suffix ? (whole.as.list.count - part.as.list.count) : 0U;
    for (i = 0; i < part.as.list.count; i++) {
      if (!bs_term_eq(e->w, e->w->terms[whole.as.list.at + off + i],
                      e->w->terms[part.as.list.at + i])) {
        *out = 0;
        return BS_OK;
      }
    }
    *out = 1;
    return BS_OK;
  }
  return BS_ERR_TYPE;
}

/* String concatenation.
 *
 * The result is a string, and strings are symbol indices, so the joined text
 * has to live somewhere and then be interned. It goes in the evaluation
 * arena, which is rewound when the expression finishes -- along with the
 * symbol table, so a symbol invented mid-expression does not outlive it and
 * leave the table holding a span into reclaimed scratch. */
static bs_status bs_str_concat(bs_eval *e, bs_term a, bs_term b, bs_term *out) {
  bs_span x;
  bs_span y;
  size_t total;
  uint8_t *buf;

  if (a.kind != (uint8_t)BS_T_STRING || b.kind != (uint8_t)BS_T_STRING) {
    return BS_ERR_TYPE;
  }
  if (!bs_symtab_get(e->syms, a.as.sym, &x) ||
      !bs_symtab_get(e->syms, b.as.sym, &y)) {
    return BS_ERR_TYPE;
  }
  if (!bs_size_add(x.n, y.n, &total)) {
    return BS_ERR_OVERFLOW;
  }
  buf = (uint8_t *)bs_arena_alloc(e->arena, (total == 0U) ? 1U : total, 1U);
  if (buf == NULL) {
    return BS_ERR_NOMEM;
  }
  if (x.n != 0U) {
    memcpy(buf, x.p, x.n);
  }
  if (y.n != 0U) {
    memcpy(&buf[x.n], y.p, y.n);
  }
  out->kind = (uint8_t)BS_T_STRING;
  return bs_symtab_intern(e->syms, bs_span_make(buf, total), &out->as.sym);
}

/* Intersection and union, which build a new set in the term pool.
 *
 * Both deduplicate as they go, because a set is a deduplicated collection and
 * a result that repeated an element would not compare equal to the same set
 * written by hand. */
static bs_status bs_set_op(bs_eval *e, bs_term a, bs_term b, int is_union,
                           bs_term *out) {
  uint32_t start;
  uint32_t i;

  if (a.kind != (uint8_t)BS_T_SET || b.kind != (uint8_t)BS_T_SET) {
    return BS_ERR_TYPE;
  }
  start = (uint32_t)e->w->term_count;

  for (i = 0; i < a.as.list.count; i++) {
    bs_term v = e->w->terms[a.as.list.at + i];
    int keep =
        is_union ? 1 : bs_run_contains(e->w, b.as.list.at, b.as.list.count, v);
    if (!keep ||
        bs_run_contains(e->w, start, (uint32_t)e->w->term_count - start, v)) {
      continue;
    }
    if (e->w->term_count >= e->w->term_cap) {
      return BS_ERR_NOMEM;
    }
    e->w->terms[e->w->term_count] = v;
    e->w->term_count++;
  }

  if (is_union) {
    for (i = 0; i < b.as.list.count; i++) {
      bs_term v = e->w->terms[b.as.list.at + i];
      if (bs_run_contains(e->w, start, (uint32_t)e->w->term_count - start, v)) {
        continue;
      }
      if (e->w->term_count >= e->w->term_cap) {
        return BS_ERR_NOMEM;
      }
      e->w->terms[e->w->term_count] = v;
      e->w->term_count++;
    }
  }

  out->kind = (uint8_t)BS_T_SET;
  out->as.list.at = start;
  out->as.list.count = (uint32_t)e->w->term_count - start;
  return BS_OK;
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

/* ---------------------------------------------------------------------------
 * The machine
 *
 * Postfix opcodes over a value stack. What makes this more than a loop is
 * closures: `a && b` encodes b as a zero-parameter closure so it can be
 * skipped, and `.all()` runs its closure once per element. Evaluating a
 * closure body from inside the evaluator would be recursion, which invariant
 * 2 forbids -- and forbids for a reason, since the nesting is chosen by
 * whoever sent the token.
 *
 * So the evaluator carries an explicit frame stack. A frame is one opcode run
 * being executed, plus at most one *pending* operator: the one that asked for
 * a closure body to be run and is waiting for its result. When a body frame
 * finishes, its value is on the stack and the parent's pending operator picks
 * it up -- exactly what a return value and a resumed call would do, laid out
 * where it can be bounded.
 * ------------------------------------------------------------------------ */

#define BS_PEND_NONE 0U
#define BS_PEND_LAZY 1U
#define BS_PEND_ALL 2U
#define BS_PEND_ANY 3U
#define BS_PEND_TRY 4U

#ifndef BS_MAX_EVAL_FRAMES
#define BS_MAX_EVAL_FRAMES 16
#endif

#ifndef BS_MAX_BINDINGS
#define BS_MAX_BINDINGS 32
#endif

typedef struct bs_frame {
  bs_expr expr;
  uint32_t pc;
  size_t bind_base; /* bindings above this belong to this frame */
  size_t sp_base;   /* value stack height when the pending child was entered */
  uint8_t pending;  /* the operator waiting on this frame's child */
  bs_term subject;  /* the container being walked, for all and any */
  bs_term fallback; /* what try_or returns when its closure fails */
  uint32_t index;   /* position in `subject` */
  uint32_t closure; /* the closure op being applied */
} bs_frame;

typedef struct bs_machine {
  bs_frame frames[BS_MAX_EVAL_FRAMES];
  bs_binding binds[BS_MAX_BINDINGS];
  size_t depth;
  size_t bind_count;
} bs_machine;

/* Push a frame for a closure's body, binding its parameter when it takes one.
 */
static bs_status bs_enter_closure(bs_eval *e, bs_machine *m,
                                  uint32_t closure_op, const bs_term *arg) {
  const bs_op *op;
  size_t base = m->bind_count;

  if (m->depth >= (size_t)BS_MAX_EVAL_FRAMES) {
    return BS_ERR_DEPTH;
  }
  if ((size_t)closure_op >= e->w->op_count) {
    return BS_ERR_MALFORMED;
  }
  op = &e->w->ops[closure_op];
  if (op->tag != (uint8_t)BS_OP_CLOSURE) {
    return BS_ERR_MALFORMED;
  }

  if (arg != NULL) {
    uint64_t sym;
    size_t i;
    if (op->as.closure.count != 1U) {
      return BS_ERR_MALFORMED; /* all and any pass exactly one element */
    }
    if ((size_t)op->as.closure.at >= e->w->sym_count) {
      return BS_ERR_MALFORMED;
    }
    if (m->bind_count >= (size_t)BS_MAX_BINDINGS) {
      return BS_ERR_LIMIT;
    }
    sym = e->w->syms[op->as.closure.at];
    /* "Shadowing (defining a parameter with the same name as a variable
     * already in scope) is not allowed and should be rejected before starting
     * the evaluation." */
    for (i = 0; i < m->bind_count; i++) {
      if (m->binds[i].sym == sym) {
        return BS_ERR_SHADOWED;
      }
    }
    m->binds[m->bind_count].sym = sym;
    m->binds[m->bind_count].value = *arg;
    m->bind_count++;
  } else if (op->as.closure.count != 0U) {
    /* A short-circuiting operator's right-hand side takes no parameters. */
    return BS_ERR_MALFORMED;
  }

  m->frames[m->depth].expr = op->as.closure.body;
  m->frames[m->depth].pc = 0;
  m->frames[m->depth].bind_base = base;
  m->frames[m->depth].pending = (uint8_t)BS_PEND_NONE;
  m->frames[m->depth].index = 0;
  m->frames[m->depth].closure = 0;
  m->depth++;
  e->bindings = m->binds;
  e->binding_count = m->bind_count;
  return BS_OK;
}

/* Evaluate one expression to a boolean. */
static bs_status bs_expr_eval(bs_eval *e, bs_expr expr, int *out) {
  bs_machine m;
  size_t i;
  bs_status st;

  if (e->binding_count > (size_t)BS_MAX_BINDINGS) {
    st = BS_ERR_LIMIT;
    goto failed;
  }
  /* The caller's bindings sit at the bottom, visible to every frame. */
  for (i = 0; i < e->binding_count; i++) {
    m.binds[i] = e->bindings[i];
  }
  m.bind_count = e->binding_count;
  m.depth = 1;
  e->sp = 0;
  e->bindings = m.binds;
  e->binding_count = m.bind_count;

  m.frames[0].expr = expr;
  m.frames[0].pc = 0;
  m.frames[0].bind_base = m.bind_count;
  m.frames[0].pending = (uint8_t)BS_PEND_NONE;
  m.frames[0].sp_base = 0;
  m.frames[0].index = 0;
  m.frames[0].closure = 0;

again:
  while (m.depth > 0U) {
    bs_frame *f = &m.frames[m.depth - 1U];
    const bs_op *op;
    bs_term a;
    bs_term b;
    bs_term result;
    int flag = 0;
    int cmp = 0;
    int64_t n = 0;

    /* A closure body has finished; its value is on the stack, and the
     * operator that asked for it decides what that means. */
    if (f->pending != (uint8_t)BS_PEND_NONE) {
      uint8_t pend = f->pending;
      st = bs_pop(e, &a);
      if (st != BS_OK) {
        goto failed;
      }
      m.bind_count = f->bind_base;
      e->binding_count = m.bind_count;

      if (pend == (uint8_t)BS_PEND_LAZY || pend == (uint8_t)BS_PEND_TRY) {
        if (pend == (uint8_t)BS_PEND_LAZY && a.kind != (uint8_t)BS_T_BOOL) {
          st = BS_ERR_TYPE;
          goto failed;
        }
        f->pending = (uint8_t)BS_PEND_NONE;
        st = bs_push(e, a);
        if (st != BS_OK) {
          goto failed;
        }
        continue;
      }

      if (a.kind != (uint8_t)BS_T_BOOL) {
        st = BS_ERR_TYPE;
        goto failed;
      }
      if ((pend == (uint8_t)BS_PEND_ALL && !a.as.boolean) ||
          (pend == (uint8_t)BS_PEND_ANY && a.as.boolean)) {
        /* Decided: the rest of the container cannot change the answer. */
        f->pending = (uint8_t)BS_PEND_NONE;
        st = bs_push(e, bs_bool(pend == (uint8_t)BS_PEND_ANY));
        if (st != BS_OK) {
          goto failed;
        }
        continue;
      }
      f->index++;
      if (f->index >= f->subject.as.list.count) {
        f->pending = (uint8_t)BS_PEND_NONE;
        st = bs_push(e, bs_bool(pend == (uint8_t)BS_PEND_ALL));
        if (st != BS_OK) {
          goto failed;
        }
        continue;
      }
      st = bs_enter_closure(e, &m, f->closure,
                            &e->w->terms[f->subject.as.list.at + f->index]);
      if (st != BS_OK) {
        goto failed;
      }
      continue;
    }

    if (f->pc >= f->expr.count) {
      m.depth--;
      continue;
    }
    if ((size_t)f->expr.at + (size_t)f->pc >= e->w->op_count) {
      st = BS_ERR_MALFORMED;
      goto failed;
    }
    op = &e->w->ops[f->expr.at + f->pc];
    f->pc++;

    if (op->tag == (uint8_t)BS_OP_VALUE) {
      if ((size_t)op->as.term >= e->w->term_count) {
        st = BS_ERR_MALFORMED;
        goto failed;
      }
      st = bs_resolve(e, e->w->terms[op->as.term], &a);
      if (st != BS_OK) {
        goto failed;
      }
      st = bs_push(e, a);
      if (st != BS_OK) {
        goto failed;
      }
      continue;
    }

    if (op->tag == (uint8_t)BS_OP_CLOSURE) {
      /* A closure is a value until an operator decides what to do with it. */
      result.kind = (uint8_t)BS_T_CLOSURE;
      result.as.list.at = (uint32_t)((size_t)f->expr.at + (size_t)f->pc - 1U);
      result.as.list.count = op->as.closure.count;
      st = bs_push(e, result);
      if (st != BS_OK) {
        goto failed;
      }
      continue;
    }

    if (op->tag == (uint8_t)BS_OP_UNARY) {
      st = bs_pop(e, &a);
      if (st != BS_OK) {
        goto failed;
      }
      switch (op->kind) {
      case BS_U_NEGATE:
        if (a.kind != (uint8_t)BS_T_BOOL) {
          st = BS_ERR_TYPE;
          goto failed;
        }
        st = bs_push(e, bs_bool(!a.as.boolean));
        break;
      case BS_U_PARENS:
        st = bs_push(e, a);
        break;
      case BS_U_LENGTH:
        st = bs_length(e, a, &n);
        if (st == BS_OK) {
          st = bs_push(e, bs_int(n));
        }
        break;
      case BS_U_TYPEOF:
        st = bs_typeof(e, a, &result);
        if (st == BS_OK) {
          st = bs_push(e, result);
        }
        break;
      default:
        st = BS_ERR_UNSUPPORTED;
        goto failed; /* external calls */
      }
      if (st != BS_OK) {
        goto failed;
      }
      continue;
    }

    /* Binary. The right-hand side was pushed last. */
    st = bs_pop(e, &b);
    if (st != BS_OK) {
      goto failed;
    }
    st = bs_pop(e, &a);
    if (st != BS_OK) {
      goto failed;
    }

    switch (op->kind) {
    case 0U:
    case 1U:
    case 2U:
    case 3U:
      st = bs_compare(a, b, &cmp);
      if (st != BS_OK) {
        goto failed;
      }
      flag = (op->kind == 0U)   ? (cmp < 0)
             : (op->kind == 1U) ? (cmp > 0)
             : (op->kind == 2U) ? (cmp <= 0)
                                : (cmp >= 0);
      st = bs_push(e, bs_bool(flag));
      break;

    case 4U:
    case 20U:
      /* Strict: comparing different types is an error, not false. */
      if (a.kind != b.kind) {
        st = BS_ERR_TYPE;
        goto failed;
      }
      flag = bs_term_eq(e->w, a, b);
      st = bs_push(e, bs_bool((op->kind == 4U) ? flag : !flag));
      break;

    case 21U:
    case 22U:
      /* Lenient: different types are simply unequal. */
      flag = (a.kind == b.kind) && bs_term_eq(e->w, a, b);
      st = bs_push(e, bs_bool((op->kind == 21U) ? flag : !flag));
      break;

    case 5U:
      st = bs_contains(e, a, b, &flag);
      if (st == BS_OK) {
        st = bs_push(e, bs_bool(flag));
      }
      break;

    case 8U: /* .matches() */
      if (a.kind != (uint8_t)BS_T_STRING || b.kind != (uint8_t)BS_T_STRING) {
        st = BS_ERR_TYPE;
        goto failed;
      }
      st = bs_re_match(e->syms, e->arena, a, b, &flag);
      if (st == BS_OK) {
        st = bs_push(e, bs_bool(flag));
      }
      break;

    case 6U: /* .starts_with() */
    case 7U: /* .ends_with() */
      st = bs_affix(e, a, b, (op->kind == 7U), &flag);
      if (st == BS_OK) {
        st = bs_push(e, bs_bool(flag));
      }
      break;

    case 15U: /* .intersection() */
    case 16U: /* .union() */
      st = bs_set_op(e, a, b, (op->kind == 16U), &result);
      if (st == BS_OK) {
        st = bs_push(e, result);
      }
      break;

    case 9U:
    case 10U:
    case 11U:
    case 12U:
      if (op->kind == 9U && a.kind == (uint8_t)BS_T_STRING) {
        /* `+` joins strings as well as adding integers. */
        st = bs_str_concat(e, a, b, &result);
        if (st == BS_OK) {
          st = bs_push(e, result);
        }
        break;
      }
      if (a.kind != (uint8_t)BS_T_INTEGER || b.kind != (uint8_t)BS_T_INTEGER) {
        /* A plain `return` here would step around the try_or unwinding
         * below, which is exactly what an error inside a try_or must not do. */
        st = BS_ERR_TYPE;
        goto failed;
      }
      st = bs_arith(op->kind, a.as.integer, b.as.integer, &n);
      if (st == BS_OK) {
        st = bs_push(e, bs_int(n));
      }
      break;

    case 13U:
    case 14U:
      if (a.kind != (uint8_t)BS_T_BOOL || b.kind != (uint8_t)BS_T_BOOL) {
        st = BS_ERR_TYPE;
        goto failed;
      }
      flag = (op->kind == 13U) ? (a.as.boolean && b.as.boolean)
                               : (a.as.boolean || b.as.boolean);
      st = bs_push(e, bs_bool(flag));
      break;

    case 17U:
    case 18U:
    case 19U:
      if (a.kind != (uint8_t)BS_T_INTEGER || b.kind != (uint8_t)BS_T_INTEGER) {
        st = BS_ERR_TYPE;
        goto failed;
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

    case 23U: /* && short-circuiting */
    case 24U: /* || short-circuiting */
      if (a.kind != (uint8_t)BS_T_BOOL || b.kind != (uint8_t)BS_T_CLOSURE) {
        st = BS_ERR_TYPE;
        goto failed;
      }
      /* The whole point: the right-hand side is not evaluated when the left
       * already decides the answer. */
      if ((op->kind == 23U && !a.as.boolean) ||
          (op->kind == 24U && a.as.boolean)) {
        st = bs_push(e, a);
        break;
      }
      f->pending = (uint8_t)BS_PEND_LAZY;
      f->bind_base = m.bind_count;
      f->sp_base = e->sp;
      st = bs_enter_closure(e, &m, b.as.list.at, NULL);
      break;

    case 25U: /* .all() */
    case 26U: /* .any() */
      if (b.kind != (uint8_t)BS_T_CLOSURE) {
        st = BS_ERR_TYPE;
        goto failed;
      }
      if (a.kind != (uint8_t)BS_T_SET && a.kind != (uint8_t)BS_T_ARRAY) {
        /* A map is walked too, each entry passed as a two-element array;
         * building that pair needs pool space and arrives with the rest of
         * the container construction. */
        return (a.kind == (uint8_t)BS_T_MAP) ? BS_ERR_UNSUPPORTED : BS_ERR_TYPE;
      }
      if (a.as.list.count == 0U) {
        /* Vacuously true for all, vacuously false for any. */
        st = bs_push(e, bs_bool(op->kind == 25U));
        break;
      }
      f->pending =
          (op->kind == 25U) ? (uint8_t)BS_PEND_ALL : (uint8_t)BS_PEND_ANY;
      f->subject = a;
      f->index = 0;
      f->closure = b.as.list.at;
      f->bind_base = m.bind_count;
      f->sp_base = e->sp;
      st = bs_enter_closure(e, &m, b.as.list.at, &e->w->terms[a.as.list.at]);
      break;

    case 27U:
      st = bs_get(e, a, b, &result);
      if (st == BS_OK) {
        st = bs_push(e, result);
      }
      break;

    case 29U: /* .try_or() */
      /* The closure is the left operand and the fallback the right, so the
       * fallback is already evaluated when we get here -- which is fine,
       * since it is a value and cannot fail. */
      if (a.kind != (uint8_t)BS_T_CLOSURE) {
        st = BS_ERR_TYPE;
        goto failed;
      }
      f->pending = (uint8_t)BS_PEND_TRY;
      f->fallback = b;
      f->bind_base = m.bind_count;
      f->sp_base = e->sp;
      st = bs_enter_closure(e, &m, a.as.list.at, NULL);
      break;

    default:
      /* String operations, set algebra and external calls. Refused rather
       * than approximated: an operator that silently returns false is a check
       * that silently passes. */
      st = BS_ERR_UNSUPPORTED;
      goto failed;
    }
    if (st != BS_OK) {
      goto failed;
    }
  }

  if (e->sp != 1U) {
    st = BS_ERR_MALFORMED;
    goto failed;
  }
  if (e->stack[0].kind != (uint8_t)BS_T_BOOL) {
    /* "After executing, the stack must contain only one value, of the boolean
     * type." An expression that leaves an integer is not false; it is wrong. */
    st = BS_ERR_TYPE;
    goto failed;
  }
  *out = e->stack[0].as.boolean;
  return BS_OK;

failed:
  /* `try_or` is the one operator that turns a failure into a value. Unwind to
   * the nearest frame waiting on one, restore the stack to where that frame
   * left it, and hand it the fallback -- the closure's own error goes no
   * further. Without a try_or in scope the failure is the answer. */
  while (m.depth > 0U) {
    bs_frame *g = &m.frames[m.depth - 1U];
    if (g->pending == (uint8_t)BS_PEND_TRY) {
      g->pending = (uint8_t)BS_PEND_NONE;
      m.bind_count = g->bind_base;
      e->binding_count = m.bind_count;
      e->sp = g->sp_base;
      if (bs_push(e, g->fallback) != BS_OK) {
        return BS_ERR_LIMIT;
      }
      goto again;
    }
    m.depth--;
  }
  return st;
}

/* Evaluate one expression of the world, with the given variable bindings. */
BS_API bs_status bs_expr_evaluate(bs_world *w, bs_symtab *syms, bs_arena *a,
                                  bs_expr expr, const bs_binding *bindings,
                                  size_t binding_count, int *out) {
  bs_eval e;
  size_t term_mark;
  size_t sym_mark;
  size_t arena_mark;
  bs_status st;

  if (w == NULL || syms == NULL || a == NULL || out == NULL) {
    return BS_ERR_ARGUMENT;
  }
  e.w = w;
  e.syms = syms;
  e.arena = a;
  e.bindings = bindings;
  e.binding_count = binding_count;
  e.sp = 0;

  /* An expression leaves exactly one boolean behind, so every value it built
   * on the way -- a joined string, an intersected set, the symbol either of
   * them needed -- is unreachable the moment it returns. Giving all of it
   * back here is what stops a block with twenty expressions from costing
   * twenty times what one costs.
   *
   * The symbol table is rewound with the rest, and it has to be: its entries
   * are spans, and a symbol interned from arena scratch would otherwise
   * outlive the bytes it points at. */
  term_mark = w->term_count;
  sym_mark = syms->count;
  arena_mark = bs_arena_mark(a);

  st = bs_expr_eval(&e, expr, out);

  /* cppcheck-suppress redundantAssignment ; only redundant for an expression
   * that built nothing. One that intersects two sets or joins two strings
   * moves both counters, and cppcheck cannot see that path from here. */
  w->term_count = term_mark;
  /* cppcheck-suppress redundantAssignment ; as above */
  syms->count = sym_mark;
  bs_arena_rewind(a, arena_mark);
  return st;
}
