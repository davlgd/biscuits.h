/* ---------------------------------------------------------------------------
 * Version
 * ------------------------------------------------------------------------ */

#define BS_VERSION_MAJOR 0
#define BS_VERSION_MINOR 1
#define BS_VERSION_PATCH 0
#define BS_VERSION_STRING "0.1.0-dev"

/* ---------------------------------------------------------------------------
 * Status codes
 *
 * Every fallible entry point returns a bs_status. There is no errno, no
 * out-of-band error state and no partially-constructed value handed back on
 * failure: on anything other than BS_OK, output parameters are untouched.
 * ------------------------------------------------------------------------ */

typedef enum bs_status {
  BS_OK = 0,
  BS_ERR_ARGUMENT,    /* caller passed a null or nonsensical argument */
  BS_ERR_NOMEM,       /* the caller-provided arena is exhausted */
  BS_ERR_MALFORMED,   /* input violates the wire format, truncation included */
  BS_ERR_DEPTH,       /* nesting deeper than BS_MAX_DEPTH */
  BS_ERR_OVERFLOW,    /* an arithmetic operation overflowed */
  BS_ERR_LIMIT,       /* a configured evaluation limit was reached */
  BS_ERR_UNSUPPORTED, /* well-formed, but this build cannot handle it */
  BS_ERR_SIGNATURE,   /* a signature did not verify */
  BS_STATUS_COUNT,    /* not a status; keep last */
} bs_status;

/* Short, stable, allocation-free description. Never NULL, even for a value
 * outside the enum -- a corrupted status must not become a crash. */
BS_API BS_MUST_USE const char *bs_strstatus(bs_status st);

/* ---------------------------------------------------------------------------
 * Byte ranges
 *
 * bs_span is the only way this library refers to a range of bytes. Raw pointer
 * arithmetic is confined to the accessors below (invariant 4), so an
 * out-of-bounds access has exactly one place it can originate from, and that
 * place is a hundred lines long and model-checked.
 *
 * A span does not own its bytes. It is valid for as long as the buffer the
 * caller handed in is valid.
 * ------------------------------------------------------------------------ */

typedef struct bs_span {
  const uint8_t *p;
  size_t n;
} bs_span;

BS_API BS_MUST_USE bs_span bs_span_make(const void *p, size_t n);

/* Byte at index i. Returns 0 and leaves *out untouched if i is out of range. */
BS_API BS_MUST_USE int bs_span_at(bs_span s, size_t i, uint8_t *out);

/* Sub-range [off, off+len). Returns 0 on any overflow or overrun. */
BS_API BS_MUST_USE int bs_span_slice(bs_span s, size_t off, size_t len,
                                     bs_span *out);

/* Content equality. Two empty spans are equal regardless of their pointers. */
BS_API BS_MUST_USE int bs_span_eq(bs_span a, bs_span b);

/* ---------------------------------------------------------------------------
 * Cursor
 *
 * A forward-only reader over a span. Every take_* either advances the cursor
 * and reports success, or leaves it exactly where it was. There is no
 * "partially consumed" state to reason about, which is what makes the decoder
 * safe to write as a straight line of unchecked-looking calls followed by a
 * single error test.
 * ------------------------------------------------------------------------ */

typedef struct bs_cursor {
  bs_span s;
  size_t off;
} bs_cursor;

BS_API BS_MUST_USE bs_cursor bs_cursor_make(bs_span s);
BS_API BS_MUST_USE size_t bs_cursor_left(const bs_cursor *c);
BS_API BS_MUST_USE int bs_cursor_done(const bs_cursor *c);

BS_API BS_MUST_USE int bs_take_u8(bs_cursor *c, uint8_t *out);
BS_API BS_MUST_USE int bs_take_bytes(bs_cursor *c, size_t n, bs_span *out);

/* ---------------------------------------------------------------------------
 * Arena
 *
 * All memory used by this library comes from one caller-provided buffer.
 * There is no free: the arena is reset or discarded as a whole. Use-after-free
 * and double-free are therefore not bugs this code can express (invariant 1).
 *
 * Exhaustion is sticky. Once an allocation fails the arena stays failed, so a
 * long chain of allocations can be written without a branch after each one and
 * checked once at the end. Forgetting that final check cannot corrupt memory:
 * every failed allocation returns NULL, and NULL is never written through.
 * ------------------------------------------------------------------------ */

typedef struct bs_arena {
  uint8_t *base;
  size_t cap;
  size_t off;
  size_t peak; /* high-water mark, to size buffers from real workloads */
  int failed;  /* sticky exhaustion flag */
} bs_arena;

/* Widest scalar this library ever stores. No floating point (invariant 5),
 * so no long double, and the alignment stays 8 on every target we support. */
typedef union bs_max_align {
  long long ll;
  void *p;
  void (*fp)(void);
} bs_max_align;

#define BS_ALIGN_MAX (sizeof(bs_max_align))

/* buf may be NULL only if cap is 0, which yields an arena that fails every
 * allocation -- useful for measuring how much memory a workload would need.
 *
 * A misaligned buffer is accepted: the leading pad is absorbed and the usable
 * capacity shrinks accordingly, so carving an arena out of a larger buffer is
 * safe. On a target without uintptr_t the base cannot be inspected portably
 * and the caller must supply a BS_ALIGN_MAX-aligned buffer. */
BS_API BS_MUST_USE bs_status bs_arena_init(bs_arena *a, void *buf, size_t cap);

/* align must be a power of two and at most BS_ALIGN_MAX. Returns NULL on
 * exhaustion, on overflow, or if the arena has already failed. */
BS_API BS_MUST_USE void *bs_arena_alloc(bs_arena *a, size_t size, size_t align);

/* Zero-initialised array of n elements of the given size. Guards the
 * multiplication; a hostile count cannot wrap into a small allocation. */
BS_API BS_MUST_USE void *bs_arena_array(bs_arena *a, size_t n, size_t size,
                                        size_t align);

/* Rewind to empty. Keeps the peak, clears the failure flag. */
BS_API void bs_arena_reset(bs_arena *a);

BS_API BS_MUST_USE size_t bs_arena_used(const bs_arena *a);
BS_API BS_MUST_USE size_t bs_arena_peak(const bs_arena *a);
BS_API BS_MUST_USE int bs_arena_failed(const bs_arena *a);

/* ---------------------------------------------------------------------------
 * Tokens
 *
 * A parsed token borrows every byte from the caller's input buffer: spans
 * point into it, nothing is copied. The arena holds only the block array. So
 * a bs_token is valid exactly as long as both the input and the arena are,
 * and neither may be reused underneath it.
 * ------------------------------------------------------------------------ */

typedef enum bs_alg {
  BS_ALG_ED25519 = 0,
  BS_ALG_SECP256R1 = 1,
} bs_alg;

typedef struct bs_public_key {
  bs_alg alg;
  bs_span key;
} bs_public_key;

typedef struct bs_signed_block {
  bs_span block; /* the serialized Block, still encoded */
  bs_public_key next_key;
  bs_span signature;
  bs_span external_signature;
  bs_public_key external_key;
  int has_external;
  uint32_t version; /* signature payload version; absent means 0 */
} bs_signed_block;

typedef struct bs_token {
  bs_signed_block *blocks; /* blocks[0] is the authority block */
  size_t block_count;
  bs_span proof; /* nextSecret, or finalSignature when sealed */
  uint32_t root_key_id;
  int has_root_key_id;
  int sealed;
} bs_token;

/* Decode the container. Does not verify anything: a BS_OK here means the
 * token is well-formed, not that it is authentic.
 *
 * Returns BS_ERR_UNSUPPORTED for a token whose keys use an algorithm this
 * build does not implement, so an unverifiable token can never be confused
 * with a verified one. */
BS_API BS_MUST_USE bs_status bs_token_parse(bs_arena *a, bs_span input,
                                            bs_token *out);

/* Decode a token from its text form -- URL-safe base64, with an optional
 * `biscuit:` prefix -- and parse it. The decoded bytes come from the arena, so
 * the arena rather than the text is what must outlive the token. */
BS_API BS_MUST_USE bs_status bs_token_parse_text(bs_arena *a, bs_span text,
                                                 bs_token *out);

/* Decode URL-safe base64 into arena memory.
 *
 * Strict: padding must be canonical, the bits a partial final group leaves
 * over must be zero, and whitespace is not skipped. A lenient decoder accepts
 * several strings for one token, which turns "have I seen this token before?"
 * into a question with more than one answer -- and any cache, rate limiter or
 * deny-list keyed on the string form is then wrong in a way nobody notices
 * until it matters. */
BS_API BS_MUST_USE bs_status bs_base64url_decode(bs_arena *a, bs_span text,
                                                 bs_span *out);

/* The revocation identifier of a block: its signature, verbatim. Returns an
 * empty span for an out-of-range index. */
BS_API BS_MUST_USE bs_span bs_token_revocation_id(const bs_token *t,
                                                  size_t index);

/* ---------------------------------------------------------------------------
 * Output writer
 *
 * Rendering Datalog needs somewhere to put the bytes, and this library does
 * not allocate. The caller supplies the buffer; overflow is sticky and
 * reported once at the end rather than checked on every append.
 * ------------------------------------------------------------------------ */

typedef struct bs_writer {
  uint8_t *buf;
  size_t cap;
  size_t len;
  int overflow;
} bs_writer;

BS_API BS_MUST_USE bs_status bs_writer_init(bs_writer *w, void *buf,
                                            size_t cap);
BS_API BS_MUST_USE int bs_writer_overflow(const bs_writer *w);
BS_API BS_MUST_USE size_t bs_writer_len(const bs_writer *w);

/* ---------------------------------------------------------------------------
 * Symbol table
 *
 * Predicate names and string terms travel as indices. Indices below 1024 name
 * a well-known symbol shared by every implementation; the rest name a symbol
 * the token carries, numbered across all its blocks in order.
 *
 * `entries` is not owned: it points at spans into the token's own bytes.
 * ------------------------------------------------------------------------ */

typedef struct bs_symbols {
  const bs_span *entries; /* token-provided symbols, in block order */
  size_t count;
} bs_symbols;

/* Resolve an index to its text. Returns 0 for an index this build cannot
 * name, which includes a reserved index a future specification may define --
 * guessing would make the token read differently here than elsewhere. */
BS_API BS_MUST_USE int bs_symbol_get(const bs_symbols *s, uint64_t index,
                                     bs_span *out);

/* How many well-known symbols this build knows. */
BS_API BS_MUST_USE size_t bs_symbol_default_count(void);

/* ---------------------------------------------------------------------------
 * Datalog rendering
 * ------------------------------------------------------------------------ */

/* Render one encoded Term as Datalog source into `w`.
 *
 * `term` is the bytes of a protobuf Term message, as they appear inside a
 * block. Nesting deeper than BS_MAX_DEPTH returns BS_ERR_DEPTH rather than
 * consuming stack.
 *
 * On any error the bytes already written to `w` are undefined: the caller
 * discards the whole rendering, never a prefix of it. */
BS_API BS_MUST_USE bs_status bs_term_print(bs_writer *w, const bs_symbols *sym,
                                           bs_span term);

/* ---------------------------------------------------------------------------
 * Token-wide tables
 *
 * Symbols and public keys are referenced by index, and the indices span the
 * whole token: each block's arrays are appended in block order, authority
 * first. So they cannot be read one block at a time -- the tables are built
 * once from the parsed token, then every block is read against them.
 *
 * Like bs_token, these borrow: the spans point into the token's own bytes,
 * and only the two index arrays come from the arena.
 * ------------------------------------------------------------------------ */

typedef struct bs_tables {
  bs_symbols symbols;
  bs_public_key *public_keys;
  size_t public_key_count;
} bs_tables;

BS_API BS_MUST_USE bs_status bs_tables_build(bs_arena *a, const bs_token *t,
                                             bs_tables *out);

/* The tables of a single block, standing alone.
 *
 * Use these, not the token-wide ones, for a block carrying an external key: a
 * third-party signer never saw the rest of the token, so its indices number
 * only its own symbols and keys. Reading such a block against the token-wide
 * tables silently resolves every index to the wrong entry. */
BS_API BS_MUST_USE bs_status bs_tables_build_block(bs_arena *a, bs_span block,
                                                   bs_tables *out);

/* Render one encoded Predicate as `name(term, ...)`. */
BS_API BS_MUST_USE bs_status bs_predicate_print(bs_writer *w,
                                                const bs_tables *tab,
                                                bs_span pred);

/* Render one encoded Fact. Identical output to its predicate; the wrapper
 * exists because the wire format has one. */
BS_API BS_MUST_USE bs_status bs_fact_print(bs_writer *w, const bs_tables *tab,
                                           bs_span fact);

/* Render one encoded Scope: `authority`, `previous`, or `<alg>/<hex key>`. */
BS_API BS_MUST_USE bs_status bs_scope_print(bs_writer *w, const bs_tables *tab,
                                            bs_span scope);

/* Render one encoded Expression as Datalog source.
 *
 * Needs the arena: reconstructing the tree from the opcode stream costs one
 * node array and one stack, both sized from the expression's own length. The
 * alternative -- rendering operands to text and concatenating -- is quadratic
 * on a long chain of operators, which is a shape an attacker can choose. */
BS_API BS_MUST_USE bs_status bs_expr_print(bs_writer *w, bs_arena *a,
                                           const bs_tables *tab, bs_span expr);

/* Render one encoded Rule as `head <- body`. */
BS_API BS_MUST_USE bs_status bs_rule_print(bs_writer *w, bs_arena *a,
                                           const bs_tables *tab, bs_span rule);

/* Render one encoded Check: `check if`, `check all`, or `reject if`. */
BS_API BS_MUST_USE bs_status bs_check_print(bs_writer *w, bs_arena *a,
                                            const bs_tables *tab,
                                            bs_span check);

/* Render a whole block as Datalog source: facts, then rules, then checks.
 *
 * `block` is the serialized Block message, which is what bs_signed_block
 * carries. Returns BS_ERR_UNSUPPORTED for a block-level scope: no sample in
 * the specification carries one, so its printed form cannot be confirmed, and
 * guessing would produce output that disagrees with every other reader. */
BS_API BS_MUST_USE bs_status bs_block_print(bs_writer *w, bs_arena *a,
                                            const bs_tables *tab,
                                            bs_span block);

/* ---------------------------------------------------------------------------
 * Verification
 *
 * With BISCUITS_NO_BUNDLED_CRYPTO you supply the two primitives below; see
 * the note in the configuration section for why they take the message in
 * pieces rather than as one buffer.
 * ------------------------------------------------------------------------ */

#ifndef BS_BUNDLED_CRYPTO
bs_status bs_ed25519_verify_parts(bs_span pubkey, bs_span sig,
                                  const bs_span *parts, size_t count);
bs_status bs_ed25519_public_from_secret(bs_span seed, uint8_t out[32]);
#endif

/* Check a token's signature chain against a root public key.
 *
 * BS_OK means every block signature verifies, every third-party signature
 * verifies, and the proof at the end of the token matches -- so the token is
 * authentic and has not been truncated. Every other status means it is not
 * authentic; none of them means "probably fine".
 *
 * This says nothing about whether the token authorizes anything: that is a
 * separate question with a separate answer, and keeping them apart is what
 * stops an authentic token from being mistaken for an authorized one. */
BS_API BS_MUST_USE bs_status bs_token_verify(const bs_token *t,
                                             bs_span root_key);

/* ---------------------------------------------------------------------------
 * The world
 *
 * Everything so far has read the wire format in place: decode a span, print
 * it, never build anything. That works for printing and it does not work for
 * evaluation, because Datalog generates facts that were never on any wire,
 * and because it has to compare facts that arrived from different blocks.
 *
 * So this is the in-memory form, and it is deliberately flat. Terms, ops,
 * predicates, facts and rules each live in one arena-allocated pool, and
 * everything refers to everything else by index rather than by pointer. Three
 * reasons, in order of how much they matter:
 *
 *   - Comparing two facts is comparing two runs of a pool, which is what the
 *     fixpoint loop does more than anything else.
 *   - An index is stable when a pool is refilled; a pointer is not.
 *   - There is nothing to free, which is the whole arena story, and nothing
 *     that can dangle.
 *
 * The cost is that reading this code means holding "index into which pool?"
 * in your head. The pools are named for what they hold, and every index field
 * says which pool it indexes.
 * ------------------------------------------------------------------------ */

/* Term kinds, matching the wire format's oneof but numbered independently:
 * the wire numbers are field tags and would tie this representation to the
 * encoding it is meant to be free of. */
#define BS_T_VARIABLE 0U
#define BS_T_INTEGER 1U
#define BS_T_STRING 2U
#define BS_T_DATE 3U
#define BS_T_BYTES 4U
#define BS_T_BOOL 5U
#define BS_T_SET 6U
#define BS_T_NULL 7U
#define BS_T_ARRAY 8U
#define BS_T_MAP 9U

typedef struct bs_term {
  uint8_t kind;
  union {
    uint64_t sym; /* BS_T_VARIABLE, BS_T_STRING: a symbol table index */
    int64_t integer;
    uint64_t date; /* seconds since the epoch, unsigned per the specification */
    bs_span bytes; /* borrowed from the token, never copied */
    int boolean;
    /* SET, ARRAY: a run in the term pool. MAP: a run of key/value pairs,
     * stored adjacently, so count is always even. */
    struct {
      uint32_t at;
      uint32_t count;
    } list;
  } as;
} bs_term;

/* `name(t0, t1, ...)`, with the terms in a run of the term pool. */
typedef struct bs_predicate {
  uint64_t name; /* symbol table index */
  uint32_t at;   /* into the term pool */
  uint32_t count;
} bs_predicate;

/* Which blocks a fact came from.
 *
 * A fact stated in block n has origin {n}. A fact a rule produced has the
 * union of the rule's block and the origins of every fact it matched. That
 * union is what `trusting` filters on, and getting it wrong does not fail --
 * it silently authorizes things.
 *
 * A bitset, because BS_MAX_BLOCKS is 64 and a union is then one OR. */
typedef uint64_t bs_origin;

#define BS_ORIGIN_NONE ((bs_origin)0)
#define BS_ORIGIN_ONE(block) ((bs_origin)1 << (block))

/* The authorizer's own facts and rules are not in any block. They are given
 * the highest bit, which keeps `origin` a single word and keeps "authorizer"
 * expressible in a trust mask like any other source. */
#define BS_ORIGIN_AUTHORIZER BS_ORIGIN_ONE(63U)

typedef struct bs_fact {
  bs_predicate pred;
  bs_origin origin;
} bs_fact;

/* An expression, as a run of the op pool. Ops are postfix, exactly as the
 * wire format carries them -- and exactly what the text parser will produce,
 * so the evaluator has one input shape rather than two. */
typedef struct bs_expr {
  uint32_t at;
  uint32_t count;
} bs_expr;

#define BS_OP_VALUE 0U
#define BS_OP_UNARY 1U
#define BS_OP_BINARY 2U
#define BS_OP_CLOSURE 3U

typedef struct bs_op {
  uint8_t tag;
  uint32_t kind;  /* the unary or binary opcode */
  uint64_t ffi;   /* symbol index of an external call's name */
  uint32_t term;  /* BS_OP_VALUE: into the term pool */
  uint32_t at;    /* BS_OP_CLOSURE: parameters, into the symbol run pool */
  uint32_t count; /* BS_OP_CLOSURE: parameter count */
  bs_expr body;   /* BS_OP_CLOSURE: the closure's own ops */
} bs_op;

typedef struct bs_rule {
  bs_predicate head;
  uint32_t body_at; /* into the predicate pool */
  uint32_t body_count;
  uint32_t expr_at; /* into the expression pool */
  uint32_t expr_count;
  bs_origin trust; /* which blocks this rule's premises may come from */
  uint32_t block;  /* the block that stated it */
} bs_rule;

#define BS_CHECK_KIND_ONE 0U
#define BS_CHECK_KIND_ALL 1U
#define BS_CHECK_KIND_REJECT 2U

typedef struct bs_check {
  uint32_t query_at; /* into the rule pool: one rule per query */
  uint32_t query_count;
  uint8_t kind;
  uint32_t block; /* the block that stated it, for reporting */
} bs_check;

#define BS_POLICY_ALLOW 0U
#define BS_POLICY_DENY 1U

typedef struct bs_policy {
  uint32_t query_at;
  uint32_t query_count;
  uint8_t kind;
} bs_policy;

/* The pools.
 *
 * Sized once from the caller's arena and never grown: the counting pass that
 * fills each capacity runs before anything is allocated, which is what lets
 * the arena stay a bump allocator with no growth strategy anywhere.
 *
 * Every `*_count` is how much is used; every `*_cap` is how much was
 * reserved. Running out is BS_ERR_NOMEM, and it is the caller's arena that
 * ran out, not the library's. */
typedef struct bs_world {
  bs_term *terms;
  size_t term_count;
  size_t term_cap;

  bs_op *ops;
  size_t op_count;
  size_t op_cap;

  bs_expr *exprs;
  size_t expr_count;
  size_t expr_cap;

  bs_predicate *preds; /* rule bodies */
  size_t pred_count;
  size_t pred_cap;

  uint64_t *syms; /* closure parameter runs */
  size_t sym_count;
  size_t sym_cap;

  bs_fact *facts;
  size_t fact_count;
  size_t fact_cap;

  bs_rule *rules;
  size_t rule_count;
  size_t rule_cap;

  bs_check *checks;
  size_t check_count;
  size_t check_cap;

  bs_policy *policies;
  size_t policy_count;
  size_t policy_cap;

  const bs_tables *tables; /* symbols and public keys, borrowed */
  size_t block_count;
} bs_world;

/* Reserve every pool in one go.
 *
 * The capacities are the caller's to choose because only the caller knows
 * what it is willing to spend. A gateway with a 64 KB scratch buffer and a
 * batch job with a megabyte want different answers, and a library that picks
 * for them is wrong for one of them. */
typedef struct bs_limits {
  size_t max_terms;
  size_t max_ops;
  size_t max_exprs;
  size_t max_preds;
  size_t max_syms;
  size_t max_facts;
  size_t max_rules;
  size_t max_checks;
  size_t max_policies;
  size_t
      max_iterations; /* fixpoint rounds, per the specification's run limits */
} bs_limits;

/* Defaults sized for the tokens the specification's own suite contains, with
 * room to spare. A starting point, not a recommendation: measure with
 * bs_arena_peak() against your own traffic. */
BS_API BS_MUST_USE bs_limits bs_limits_default(void);

/* Reserve the pools from the arena. Everything the evaluator will need is
 * allocated here and never grown, so an arena that survives this call is an
 * arena that cannot run out later. */
BS_API BS_MUST_USE bs_status bs_world_init(bs_world *w, bs_arena *a,
                                           const bs_tables *tab,
                                           size_t block_count,
                                           const bs_limits *lim);
