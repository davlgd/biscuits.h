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
