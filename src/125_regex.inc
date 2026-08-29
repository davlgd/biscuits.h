/* ---------------------------------------------------------------------------
 * Regular expressions
 *
 * `.matches()` is the one operator whose argument is a small program written
 * by whoever made the token, run against text that also came from the token.
 * A backtracking matcher would be far less code and would be the wrong
 * answer: `(a+)+b` against a string of a's is exponential, and both halves of
 * that are attacker-chosen. So this is a Thompson simulation -- every thread
 * advanced in lockstep, one pass over the input, no backtracking -- which is
 * linear in the product of pattern and input length whatever either contains.
 *
 * The compiler is two passes, both iterative because invariant 2 forbids the
 * recursive descent this would normally be written as. First the pattern is
 * tokenised into atoms and operators with the implicit concatenations made
 * explicit; then shunting-yard turns that into postfix; then a fragment stack
 * assembles the program. Groups and alternation cost a stack entry each
 * rather than a call frame.
 *
 * Supported: literals, `.`, `[...]` with ranges and negation, `*`, `+`, `?`,
 * `|`, `(...)`, `^`, `$`, and backslash escapes.
 *
 * Not supported, and refused rather than approximated: repetition counts
 * (`{n,m}`), backreferences, lookaround, named classes (`\d`, `\w`). A
 * pattern using one of those is BS_ERR_UNSUPPORTED, never a silent mismatch,
 * because an expression that quietly answers "no" is a check that quietly
 * passes.
 *
 * One divergence to record: `.` and the classes match a *byte*, where the
 * reference implementation matches a Unicode scalar. For an ASCII pattern the
 * two agree exactly; for a pattern with a multi-byte character in a class, or
 * a `.` expected to consume one accented character, they do not. Every
 * pattern in the specification's own suite is ASCII.
 * ------------------------------------------------------------------------ */

#ifndef BS_RE_MAX_INSTS
#define BS_RE_MAX_INSTS 256
#endif

#ifndef BS_RE_MAX_CLASSES
#define BS_RE_MAX_CLASSES 16
#endif

#define BS_RE_CHAR 0U
#define BS_RE_ANY 1U
#define BS_RE_CLASS 2U
#define BS_RE_SPLIT 3U
#define BS_RE_JMP 4U
#define BS_RE_MATCH 5U
#define BS_RE_BOL 6U
#define BS_RE_EOL 7U

typedef struct bs_re_inst {
  uint8_t op;
  uint8_t ch;  /* BS_RE_CHAR */
  uint8_t cls; /* BS_RE_CLASS: which bitmap */
  uint32_t x;  /* next, or the first branch of a split */
  uint32_t y;  /* the second branch of a split */
} bs_re_inst;

/* --------------------------------------------------------------------------
 * Tokens and fragments
 * ----------------------------------------------------------------------- */

#define BS_RE_T_ATOM 0U /* a literal, `.`, or a class */
#define BS_RE_T_CONCAT 1U
#define BS_RE_T_ALT 2U
#define BS_RE_T_STAR 3U
#define BS_RE_T_PLUS 4U
#define BS_RE_T_OPT 5U
#define BS_RE_T_LPAREN 6U
#define BS_RE_T_RPAREN 7U
#define BS_RE_T_BOL 8U
#define BS_RE_T_EOL 9U

typedef struct bs_re_tok {
  uint8_t kind;
  uint8_t op; /* for atoms: BS_RE_CHAR, BS_RE_ANY or BS_RE_CLASS */
  uint8_t ch;
  uint8_t cls;
} bs_re_tok;

#ifndef BS_RE_MAX_TOKENS
#define BS_RE_MAX_TOKENS 256
#endif

/* A fragment: an entry point, and the list of instruction slots that still
 * need to be told where to go next. The dangling slots are threaded through
 * the instructions themselves, as in Thompson's original construction. */
typedef struct bs_re_frag {
  uint32_t start;
  uint32_t out; /* head of the patch list, or BS_RE_NONE */
} bs_re_frag;

#define BS_RE_NONE 0xFFFFFFFFU
/* A patch entry names an instruction and which of its two successors is the
 * hole: the low bit says x or y, the rest is the index. */
#define BS_RE_PATCH(i, is_y) (((i) << 1U) | (is_y))

/* The compiled program and everything the simulation needs to run it.
 *
 * The thread lists live here rather than as locals because a library that
 * advertises a bounded, small stack cannot spend three kilobytes of it on one
 * operator. This object comes from the evaluation arena, where its size is
 * the caller's choice rather than the C stack's. */
typedef struct bs_regex {
  bs_re_inst prog[BS_RE_MAX_INSTS];
  uint8_t classes[BS_RE_MAX_CLASSES][32]; /* 256 bits each */
  size_t count;
  size_t class_count;
  /* Simulation state. */
  uint32_t cur[BS_RE_MAX_INSTS];
  uint32_t next[BS_RE_MAX_INSTS];
  uint32_t work[BS_RE_MAX_INSTS]; /* the epsilon-closure walk */
  uint8_t seen[BS_RE_MAX_INSTS];
  /* Compilation scratch. Here for the same reason as the thread lists: as
   * locals they cost five kilobytes of stack, and the stack bound is a
   * documented number this project is measured against. */
  bs_re_tok toks[BS_RE_MAX_TOKENS];
  bs_re_tok post[BS_RE_MAX_TOKENS];
  bs_re_tok opstack[BS_RE_MAX_TOKENS];
  bs_re_frag frags[BS_RE_MAX_TOKENS];
} bs_regex;

/* --------------------------------------------------------------------------
 * Tokenising
 * ----------------------------------------------------------------------- */

/* Read a character class, `[` already consumed. */
static bs_status bs_re_class(bs_regex *re, bs_span p, size_t *i, uint8_t *out) {
  uint8_t *set;
  int negate = 0;
  size_t k;
  int first = 1;

  if (re->class_count >= (size_t)BS_RE_MAX_CLASSES) {
    return BS_ERR_LIMIT;
  }
  set = re->classes[re->class_count];
  for (k = 0; k < 32U; k++) {
    set[k] = 0;
  }

  if (*i < p.n && p.p[*i] == (uint8_t)'^') {
    negate = 1;
    (*i)++;
  }

  while (*i < p.n) {
    uint8_t lo;
    uint8_t hi;

    if (p.p[*i] == (uint8_t)']' && !first) {
      (*i)++;
      if (negate) {
        for (k = 0; k < 32U; k++) {
          set[k] = (uint8_t)~set[k];
        }
      }
      *out = (uint8_t)re->class_count;
      re->class_count++;
      return BS_OK;
    }
    first = 0;

    lo = p.p[*i];
    if (lo == (uint8_t)'\\') {
      (*i)++;
      if (*i >= p.n) {
        return BS_ERR_MALFORMED;
      }
      lo = p.p[*i];
    }
    (*i)++;

    hi = lo;
    /* A range, unless the `-` is the last character before the bracket. */
    if (*i + 1U < p.n && p.p[*i] == (uint8_t)'-' &&
        p.p[*i + 1U] != (uint8_t)']') {
      (*i)++;
      hi = p.p[*i];
      if (hi == (uint8_t)'\\') {
        (*i)++;
        if (*i >= p.n) {
          return BS_ERR_MALFORMED;
        }
        hi = p.p[*i];
      }
      (*i)++;
      if (hi < lo) {
        return BS_ERR_MALFORMED;
      }
    }

    for (k = (size_t)lo; k <= (size_t)hi; k++) {
      set[k >> 3U] |= (uint8_t)(1U << (k & 7U));
    }
  }
  return BS_ERR_MALFORMED; /* unterminated class */
}

/* Tokenise, inserting the concatenations the syntax leaves implicit. */
static bs_status bs_re_tokenise(bs_regex *re, bs_span p, bs_re_tok *out,
                                size_t *count) {
  size_t i = 0;
  size_t n = 0;
  int prev_atom = 0; /* whether a concatenation may precede the next token */

  while (i < p.n) {
    uint8_t c = p.p[i];
    bs_re_tok t;
    int is_atom = 0;

    t.op = 0;
    t.ch = 0;
    t.cls = 0;

    switch (c) {
    case (uint8_t)'(':
      t.kind = (uint8_t)BS_RE_T_LPAREN;
      is_atom = 1;
      i++;
      break;
    case (uint8_t)')':
      t.kind = (uint8_t)BS_RE_T_RPAREN;
      i++;
      prev_atom = 1;
      goto emit;
    case (uint8_t)'|':
      t.kind = (uint8_t)BS_RE_T_ALT;
      i++;
      prev_atom = 0;
      goto emit;
    case (uint8_t)'*':
    case (uint8_t)'+':
    case (uint8_t)'?':
      t.kind = (c == (uint8_t)'*')   ? (uint8_t)BS_RE_T_STAR
               : (c == (uint8_t)'+') ? (uint8_t)BS_RE_T_PLUS
                                     : (uint8_t)BS_RE_T_OPT;
      i++;
      prev_atom = 1;
      goto emit;
    case (uint8_t)'{':
      /* Repetition counts are not implemented. Refused, so a pattern using
       * one is an error rather than a mismatch. */
      return BS_ERR_UNSUPPORTED;
    case (uint8_t)'^':
      t.kind = (uint8_t)BS_RE_T_BOL;
      is_atom = 1;
      i++;
      break;
    case (uint8_t)'$':
      t.kind = (uint8_t)BS_RE_T_EOL;
      is_atom = 1;
      i++;
      break;
    case (uint8_t)'.':
      t.kind = (uint8_t)BS_RE_T_ATOM;
      t.op = (uint8_t)BS_RE_ANY;
      is_atom = 1;
      i++;
      break;
    case (uint8_t)'[': {
      bs_status st;
      i++;
      t.kind = (uint8_t)BS_RE_T_ATOM;
      t.op = (uint8_t)BS_RE_CLASS;
      st = bs_re_class(re, p, &i, &t.cls);
      if (st != BS_OK) {
        return st;
      }
      is_atom = 1;
      break;
    }
    case (uint8_t)'\\':
      i++;
      if (i >= p.n) {
        return BS_ERR_MALFORMED;
      }
      /* Only literal escapes. A named class such as \\d would need Unicode
       * tables to match the reference, so it is refused. */
      if ((p.p[i] >= (uint8_t)'a' && p.p[i] <= (uint8_t)'z') ||
          (p.p[i] >= (uint8_t)'A' && p.p[i] <= (uint8_t)'Z')) {
        return BS_ERR_UNSUPPORTED;
      }
      t.kind = (uint8_t)BS_RE_T_ATOM;
      t.op = (uint8_t)BS_RE_CHAR;
      t.ch = p.p[i];
      is_atom = 1;
      i++;
      break;
    default:
      t.kind = (uint8_t)BS_RE_T_ATOM;
      t.op = (uint8_t)BS_RE_CHAR;
      t.ch = c;
      is_atom = 1;
      i++;
      break;
    }

    /* Two adjacent atoms are a concatenation, and the grammar never writes
     * the operator down. */
    if (is_atom && prev_atom) {
      if (n >= (size_t)BS_RE_MAX_TOKENS) {
        return BS_ERR_LIMIT;
      }
      out[n].kind = (uint8_t)BS_RE_T_CONCAT;
      out[n].op = 0;
      out[n].ch = 0;
      out[n].cls = 0;
      n++;
    }
    prev_atom = (t.kind != (uint8_t)BS_RE_T_LPAREN);

  emit:
    if (n >= (size_t)BS_RE_MAX_TOKENS) {
      return BS_ERR_LIMIT;
    }
    out[n] = t;
    n++;
  }
  *count = n;
  return BS_OK;
}

/* --------------------------------------------------------------------------
 * Shunting-yard, then assembly
 * ----------------------------------------------------------------------- */

static unsigned int bs_re_prec(uint8_t kind) {
  switch (kind) {
  case BS_RE_T_ALT:
    return 1U;
  case BS_RE_T_CONCAT:
    return 2U;
  default:
    return 3U; /* the postfix repetitions bind tightest */
  }
}

static bs_status bs_re_emit(bs_regex *re, uint8_t op, uint8_t ch, uint8_t cls,
                            uint32_t *at) {
  if (re->count >= (size_t)BS_RE_MAX_INSTS) {
    return BS_ERR_LIMIT;
  }
  re->prog[re->count].op = op;
  re->prog[re->count].ch = ch;
  re->prog[re->count].cls = cls;
  re->prog[re->count].x = 0;
  re->prog[re->count].y = 0;
  *at = (uint32_t)re->count;
  re->count++;
  return BS_OK;
}

static uint32_t *bs_re_slot(bs_regex *re, uint32_t patch) {
  bs_re_inst *in = &re->prog[patch >> 1U];
  return ((patch & 1U) != 0U) ? &in->y : &in->x;
}

static void bs_re_patch(bs_regex *re, uint32_t list, uint32_t target) {
  while (list != BS_RE_NONE) {
    uint32_t *slot = bs_re_slot(re, list);
    uint32_t next = *slot;
    *slot = target;
    list = next;
  }
}

static uint32_t bs_re_append(bs_regex *re, uint32_t a, uint32_t b) {
  uint32_t head = a;
  uint32_t cur;
  if (a == BS_RE_NONE) {
    return b;
  }
  cur = a;
  for (;;) {
    uint32_t *slot = bs_re_slot(re, cur);
    if (*slot == BS_RE_NONE) {
      *slot = b;
      return head;
    }
    cur = *slot;
  }
}

static bs_status bs_re_build(bs_regex *re, const bs_re_tok *post, size_t n) {
  bs_re_frag *stack = re->frags;
  size_t sp = 0;
  size_t i;
  bs_status st;
  uint32_t at;

  for (i = 0; i < n; i++) {
    const bs_re_tok *t = &post[i];
    bs_re_frag a;
    bs_re_frag b;

    switch (t->kind) {
    case BS_RE_T_ATOM:
      st = bs_re_emit(re, t->op, t->ch, t->cls, &at);
      if (st != BS_OK) {
        return st;
      }
      re->prog[at].x = BS_RE_NONE;
      stack[sp].start = at;
      stack[sp].out = BS_RE_PATCH(at, 0U);
      sp++;
      break;

    case BS_RE_T_BOL:
    case BS_RE_T_EOL:
      st = bs_re_emit(re,
                      (t->kind == (uint8_t)BS_RE_T_BOL) ? (uint8_t)BS_RE_BOL
                                                        : (uint8_t)BS_RE_EOL,
                      0, 0, &at);
      if (st != BS_OK) {
        return st;
      }
      re->prog[at].x = BS_RE_NONE;
      stack[sp].start = at;
      stack[sp].out = BS_RE_PATCH(at, 0U);
      sp++;
      break;

    case BS_RE_T_CONCAT:
      if (sp < 2U) {
        return BS_ERR_MALFORMED;
      }
      b = stack[--sp];
      a = stack[--sp];
      bs_re_patch(re, a.out, b.start);
      stack[sp].start = a.start;
      stack[sp].out = b.out;
      sp++;
      break;

    case BS_RE_T_ALT:
      if (sp < 2U) {
        return BS_ERR_MALFORMED;
      }
      b = stack[--sp];
      a = stack[--sp];
      st = bs_re_emit(re, (uint8_t)BS_RE_SPLIT, 0, 0, &at);
      if (st != BS_OK) {
        return st;
      }
      re->prog[at].x = a.start;
      re->prog[at].y = b.start;
      stack[sp].start = at;
      stack[sp].out = bs_re_append(re, a.out, b.out);
      sp++;
      break;

    case BS_RE_T_STAR:
    case BS_RE_T_PLUS:
    case BS_RE_T_OPT:
      if (sp < 1U) {
        return BS_ERR_MALFORMED;
      }
      a = stack[--sp];
      st = bs_re_emit(re, (uint8_t)BS_RE_SPLIT, 0, 0, &at);
      if (st != BS_OK) {
        return st;
      }
      re->prog[at].x = a.start;
      re->prog[at].y = BS_RE_NONE;
      if (t->kind == (uint8_t)BS_RE_T_STAR) {
        bs_re_patch(re, a.out, at);
        stack[sp].start = at;
        stack[sp].out = BS_RE_PATCH(at, 1U);
      } else if (t->kind == (uint8_t)BS_RE_T_PLUS) {
        bs_re_patch(re, a.out, at);
        stack[sp].start = a.start;
        stack[sp].out = BS_RE_PATCH(at, 1U);
      } else {
        stack[sp].start = at;
        stack[sp].out = bs_re_append(re, a.out, BS_RE_PATCH(at, 1U));
      }
      sp++;
      break;

    default:
      return BS_ERR_MALFORMED;
    }
  }

  if (sp == 0U) {
    /* An empty pattern matches everywhere. */
    st = bs_re_emit(re, (uint8_t)BS_RE_MATCH, 0, 0, &at);
    return st;
  }
  if (sp != 1U) {
    return BS_ERR_MALFORMED;
  }
  st = bs_re_emit(re, (uint8_t)BS_RE_MATCH, 0, 0, &at);
  if (st != BS_OK) {
    return st;
  }
  bs_re_patch(re, stack[0].out, at);
  /* The program's entry point is the fragment's start, which the simulation
   * below reads from prog[0].x of a synthesised jump so that entry is always
   * instruction zero's target. */
  if (re->count >= (size_t)BS_RE_MAX_INSTS) {
    return BS_ERR_LIMIT;
  }
  re->prog[re->count].op = (uint8_t)BS_RE_JMP;
  re->prog[re->count].ch = 0;
  re->prog[re->count].cls = 0;
  re->prog[re->count].x = stack[0].start;
  re->prog[re->count].y = 0;
  re->count++;
  return BS_OK;
}

static bs_status bs_re_compile(bs_regex *re, bs_span pattern) {
  bs_re_tok *toks = re->toks;
  bs_re_tok *post = re->post;
  bs_re_tok *ops = re->opstack;
  size_t ntok = 0;
  size_t npost = 0;
  size_t nops = 0;
  size_t i;
  bs_status st;

  re->count = 0;
  re->class_count = 0;

  st = bs_re_tokenise(re, pattern, toks, &ntok);
  if (st != BS_OK) {
    return st;
  }

  /* Shunting-yard: operators to a stack, atoms straight out, parentheses
   * flushing back to the matching opener. */
  for (i = 0; i < ntok; i++) {
    bs_re_tok t = toks[i];
    if (t.kind == (uint8_t)BS_RE_T_ATOM || t.kind == (uint8_t)BS_RE_T_BOL ||
        t.kind == (uint8_t)BS_RE_T_EOL) {
      post[npost] = t;
      npost++;
      continue;
    }
    if (t.kind == (uint8_t)BS_RE_T_LPAREN) {
      ops[nops] = t;
      nops++;
      continue;
    }
    if (t.kind == (uint8_t)BS_RE_T_RPAREN) {
      while (nops > 0U && ops[nops - 1U].kind != (uint8_t)BS_RE_T_LPAREN) {
        nops--;
        post[npost] = ops[nops];
        npost++;
      }
      if (nops == 0U) {
        return BS_ERR_MALFORMED; /* unbalanced */
      }
      nops--; /* discard the opener */
      continue;
    }
    while (nops > 0U && ops[nops - 1U].kind != (uint8_t)BS_RE_T_LPAREN &&
           bs_re_prec(ops[nops - 1U].kind) >= bs_re_prec(t.kind)) {
      nops--;
      post[npost] = ops[nops];
      npost++;
    }
    ops[nops] = t;
    nops++;
  }
  while (nops > 0U) {
    nops--;
    if (ops[nops].kind == (uint8_t)BS_RE_T_LPAREN) {
      return BS_ERR_MALFORMED;
    }
    post[npost] = ops[nops];
    npost++;
  }

  return bs_re_build(re, post, npost);
}

/* --------------------------------------------------------------------------
 * Simulation
 * ----------------------------------------------------------------------- */

/* Add a thread and everything reachable from it without consuming input.
 * `seen` keeps each instruction to one thread per position, which is what
 * bounds the work and removes backtracking entirely. */
static void bs_re_add(bs_regex *re, uint32_t pc, uint32_t *list, size_t *n,
                      uint8_t *seen, size_t pos, size_t len) {
  uint32_t *stack = re->work;
  size_t sp = 0;

  stack[sp] = pc;
  sp++;
  while (sp > 0U) {
    const bs_re_inst *in;
    sp--;
    pc = stack[sp];
    if (pc == BS_RE_NONE || (size_t)pc >= re->count || seen[pc]) {
      continue;
    }
    seen[pc] = 1;
    in = &re->prog[pc];
    if (in->op == (uint8_t)BS_RE_SPLIT || in->op == (uint8_t)BS_RE_JMP) {
      if (in->op == (uint8_t)BS_RE_SPLIT && sp < (size_t)BS_RE_MAX_INSTS) {
        stack[sp] = in->y;
        sp++;
      }
      if (sp < (size_t)BS_RE_MAX_INSTS) {
        stack[sp] = in->x;
        sp++;
      }
      continue;
    }
    if (in->op == (uint8_t)BS_RE_BOL) {
      if (pos == 0U && sp < (size_t)BS_RE_MAX_INSTS) {
        stack[sp] = in->x;
        sp++;
      }
      continue;
    }
    if (in->op == (uint8_t)BS_RE_EOL) {
      if (pos == len && sp < (size_t)BS_RE_MAX_INSTS) {
        stack[sp] = in->x;
        sp++;
      }
      continue;
    }
    list[*n] = pc;
    (*n)++;
  }
}

/* Does the pattern match anywhere in `text`?
 *
 * Unanchored, like the reference: a new thread starts at every position, all
 * of them advanced together. One pass, no backtracking, and the work is
 * bounded by pattern length times input length however hostile either is. */
static bs_status bs_re_search(bs_regex *re, bs_span text, int *out) {
  uint32_t *cur = re->cur;
  uint32_t *next = re->next;
  uint8_t *seen = re->seen;
  size_t ncur = 0;
  size_t nnext;
  size_t pos;
  size_t k;
  uint32_t entry;

  if (re->count == 0U) {
    return BS_ERR_MALFORMED;
  }
  entry = re->prog[re->count - 1U].x;

  for (k = 0; k < re->count; k++) {
    seen[k] = 0;
  }
  bs_re_add(re, entry, cur, &ncur, seen, 0U, text.n);
  for (k = 0; k < ncur; k++) {
    if (re->prog[cur[k]].op == (uint8_t)BS_RE_MATCH) {
      *out = 1;
      return BS_OK;
    }
  }

  for (pos = 0; pos < text.n; pos++) {
    uint8_t c = text.p[pos];
    size_t j;

    nnext = 0;
    for (k = 0; k < re->count; k++) {
      seen[k] = 0;
    }

    for (j = 0; j < ncur; j++) {
      const bs_re_inst *in = &re->prog[cur[j]];
      int hit = 0;
      switch (in->op) {
      case BS_RE_CHAR:
        hit = (c == in->ch);
        break;
      case BS_RE_ANY:
        /* As in the reference, `.` does not cross a newline. */
        hit = (c != (uint8_t)'\n');
        break;
      case BS_RE_CLASS:
        hit =
            ((re->classes[in->cls][c >> 3U] & (uint8_t)(1U << (c & 7U))) != 0U);
        break;
      default:
        break;
      }
      if (hit) {
        bs_re_add(re, in->x, next, &nnext, seen, pos + 1U, text.n);
      }
    }

    /* Unanchored: a match may start here too. */
    bs_re_add(re, entry, next, &nnext, seen, pos + 1U, text.n);

    for (k = 0; k < nnext; k++) {
      cur[k] = next[k];
      if (re->prog[next[k]].op == (uint8_t)BS_RE_MATCH) {
        *out = 1;
        return BS_OK;
      }
    }
    ncur = nnext;
  }

  *out = 0;
  return BS_OK;
}

/* Compile and run in one call.
 *
 * The compiled program is a few kilobytes -- an instruction array and the
 * class bitmaps -- which is more than belongs on the stack in a library that
 * advertises a bounded one. It comes from the evaluation arena instead, and
 * goes back with everything else when the expression finishes.
 *
 * Nothing is cached between calls. A rule evaluated against a thousand facts
 * recompiles its pattern a thousand times, which is the honest trade for now:
 * a cache is state, and state that outlives one expression is the thing this
 * design has been avoiding everywhere else. */
static bs_status bs_re_match(const bs_symtab *syms, bs_arena *arena,
                             bs_term subject, bs_term pattern, int *out) {
  bs_span text;
  bs_span pat;
  bs_regex *re;
  bs_status st;

  if (!bs_symtab_get(syms, subject.as.sym, &text) ||
      !bs_symtab_get(syms, pattern.as.sym, &pat)) {
    return BS_ERR_TYPE;
  }
  re = (bs_regex *)bs_arena_alloc(arena, sizeof(bs_regex), BS_ALIGN_MAX);
  if (re == NULL) {
    return BS_ERR_NOMEM;
  }
  st = bs_re_compile(re, pat);
  if (st != BS_OK) {
    return st;
  }
  return bs_re_search(re, text, out);
}
