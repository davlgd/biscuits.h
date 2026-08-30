/* Conformance shim for biscuits.h.
 *
 * Speaks the protocol in README.md so tests/conformance/run.py can score this
 * implementation against the official specification samples. This is a test
 * tool, not part of the library: it may use stdio and it may allocate on the
 * stack freely. The library it exercises does neither.
 *
 * Capabilities are declared, not assumed. The runner skips any tier this shim
 * does not claim, so the suite gives a useful signal from the first day rather
 * than a flat zero until the last.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BISCUITS_IMPLEMENTATION
#include "biscuits.h"

/* Grows as the library does. Each name here is a promise the runner will
 * hold us to; adding one before it works turns a skip into a failure. */
static const char *const CAPABILITIES[] = {
    "decode", "revocation_ids", "signatures", "blocks", "authorize", NULL,
};

/* The arena for one token, and for the whole evaluation. The default limits
 * reserve every pool up front -- 4096 terms, 4096 opcodes, 1024 facts and so
 * on -- so this is sized for those, not for the token. A deployment that
 * knows its own authorizer can pass much smaller limits and use a much
 * smaller arena; this tool cannot know, so it takes the defaults. */
static uint8_t g_arena_buf[1024 * 1024];

static void emit_capabilities(void) {
  size_t i;
  (void)printf("{\"capabilities\":[");
  for (i = 0; CAPABILITIES[i] != NULL; i++) {
    (void)printf("%s\"%s\"", (i > 0) ? "," : "", CAPABILITIES[i]);
  }
  (void)printf("]}\n");
}

static int read_file(const char *path, uint8_t *buf, size_t cap, size_t *len) {
  FILE *f = fopen(path, "rb");
  size_t n;
  if (f == NULL) {
    return 0;
  }
  n = fread(buf, 1, cap, f);
  /* A token that exactly fills the buffer is indistinguishable from one that
   * was truncated, so refuse both rather than silently testing the wrong
   * bytes. */
  if (!feof(f) || ferror(f)) {
    (void)fclose(f);
    return 0;
  }
  (void)fclose(f);
  *len = n;
  return 1;
}

static const char *error_kind(bs_status st);

/* A token that never decoded still has a result: it was not authorized, and
 * the reason is that it is not a token. Reporting only the decode failure
 * would leave the authorize tier with nothing to compare. */
static void emit_decode_error(bs_status st) {
  (void)printf("{\"decode\":{\"error\":\"%s\"},"
               "\"result\":{\"ok\":false,\"kind\":\"%s\"}}\n",
               bs_strstatus(st), error_kind(st));
}

static void emit_hex(bs_span s) {
  static const char digits[] = "0123456789abcdef";
  size_t i;
  for (i = 0; i < s.n; i++) {
    unsigned byte = s.p[i];
    (void)putchar(digits[byte >> 4U]);
    (void)putchar(digits[byte & 0x0FU]);
  }
}

/* JSON string escaping. The block source contains newlines and quotes, and
 * the runner parses this with a real JSON parser, so it has to be right. */
static void emit_json_string(const char *p, size_t n) {
  size_t i;
  (void)putchar('"');
  for (i = 0; i < n; i++) {
    unsigned char ch = (unsigned char)p[i];
    switch (ch) {
    case '"':
      (void)fputs("\\\"", stdout);
      break;
    case '\\':
      (void)fputs("\\\\", stdout);
      break;
    case '\n':
      (void)fputs("\\n", stdout);
      break;
    case '\r':
      (void)fputs("\\r", stdout);
      break;
    case '\t':
      (void)fputs("\\t", stdout);
      break;
    default:
      if (ch < 0x20U) {
        (void)printf("\\u%04x", ch);
      } else {
        (void)putchar((int)ch);
      }
      break;
    }
  }
  (void)putchar('"');
}

static char block_buf[64 * 1024];
static char authorizer_src[64 * 1024];
static size_t authorizer_len;
static uint8_t g_root_key[32];
static size_t g_root_key_len;

/* Hex to bytes, for the root key the runner passes on the command line. */
static size_t unhex(const char *h, uint8_t *out, size_t cap) {
  size_t n = 0;
  while (h[0] != '\0' && h[1] != '\0' && n < cap) {
    unsigned int v = 0;
    size_t k;
    for (k = 0; k < 2U; k++) {
      unsigned int c = (unsigned int)(unsigned char)h[k];
      unsigned int d = (c >= (unsigned int)'0' && c <= (unsigned int)'9')
                           ? c - (unsigned int)'0'
                           : (c | 0x20U) - (unsigned int)'a' + 10U;
      v = (v << 4U) | d;
    }
    out[n++] = (uint8_t)v;
    h += 2;
  }
  return n;
}

/* The tables a block's indices are numbered against.
 *
 * A third-party block numbers both its symbols and its public keys against
 * its own tables, not the token's. Using the token's does not fail: it
 * renames predicates and resolves `trusting ed25519/...` to the wrong key,
 * which authorizes the wrong things quietly. */
static const bs_tables *tables_for(const bs_token *t, const bs_tables *tab,
                                   size_t i, bs_tables *own, bs_arena *arena) {
  if (t->blocks[i].has_external &&
      bs_tables_build_block(arena, t->blocks[i].block, own) == BS_OK) {
    return own;
  }
  return tab;
}

/* The result vocabulary in tests/conformance/README.md. The runner normalises
 * the reference's error enum to the same words, so both sides are compared on
 * what the specification says rather than on one language's struct shapes. */
static const char *error_kind(bs_status st) {
  switch (st) {
  case BS_ERR_OVERFLOW:
    return "overflow";
  case BS_ERR_TYPE:
    return "invalid_type";
  case BS_ERR_SHADOWED:
    return "shadowed_variable";
  case BS_ERR_SIGNATURE:
    return "signature";
  case BS_ERR_UNBOUND:
    return "invalid_block_rule";
  case BS_OK:
  case BS_ERR_MALFORMED:
  case BS_ERR_ARGUMENT:
  case BS_ERR_NOMEM:
  case BS_ERR_DEPTH:
  case BS_ERR_LIMIT:
  case BS_ERR_UNSUPPORTED:
  case BS_STATUS_COUNT:
  default:
    return "format";
  }
}

static void emit_result_error(const char *kind) {
  (void)printf(",\"result\":{\"ok\":false,\"kind\":\"%s\"}", kind);
}

/* Where a generic failure came from, for debugging the shim itself. */
static void note(const char *where, bs_status st) {
  if (getenv("SHIM_TRACE") != NULL) {
    (void)fprintf(stderr, "shim: %s -> %s\n", where, bs_strstatus(st));
  }
}

/* The external call the specification's own sample reaches.
 *
 * `extern::test` is not part of the Biscuit specification: the specification
 * defines the opcode and says the meaning is supplied by the host language,
 * and the sample was produced by a harness that registered this one. So it
 * lives here, in the harness, exactly as it does there -- a built-in
 * `extern::test` inside the library would be this implementation inventing
 * semantics the specification declines to fix.
 *
 * With no argument it returns its receiver; with one it reports whether the
 * two are equal, which is what `test035_ffi.bc` asks of it. */
static bs_status extern_test(void *ctx, bs_term left, const bs_term *right,
                             bs_symtab *syms, bs_term *out) {
  (void)ctx;
  if (right == NULL) {
    *out = left;
    return BS_OK;
  }
  {
    const char *answer = "different strings";
    size_t n = sizeof "different strings" - 1U;
    if (left.kind == right->kind && left.kind == (uint8_t)BS_T_STRING &&
        left.as.sym == right->as.sym) {
      answer = "equal strings";
      n = sizeof "equal strings" - 1U;
    }
    out->kind = (uint8_t)BS_T_STRING;
    return bs_symtab_intern(syms, bs_span_make(answer, n), &out->as.sym);
  }
}

/* Load every block into the world, add the authorizer's own statements, and
 * decide. */
static void emit_authorize(const bs_token *t, const bs_tables *tab,
                           bs_arena *arena) {
  static bs_world world;
  static bs_symtab syms;
  static char check_buf[8 * 1024];
  bs_verdict v;
  bs_limits lim = bs_limits_default();
  bs_status st;
  size_t i;

  if (bs_symtab_init(&syms, arena, &tab->symbols, lim.max_syms) != BS_OK ||
      bs_world_init(&world, arena, tab, t->block_count, &lim) != BS_OK) {
    note("init", BS_ERR_NOMEM);
    emit_result_error("format");
    return;
  }

  {
    static bs_extern externs[1];
    if (bs_symtab_intern(&syms, bs_span_make("test", 4U), &externs[0].name) !=
            BS_OK ||
        bs_world_set_externs(&world, externs, 1U) != BS_OK) {
      emit_result_error("format");
      return;
    }
    externs[0].fn = extern_test;
    externs[0].ctx = NULL;
  }

  /* Facts first, then rules and checks: a rule may only be loaded once the
   * symbols its predicates name are interned, and facts do that interning. */
  for (i = 0; i < t->block_count; i++) {
    bs_tables own;
    const bs_tables *use = tables_for(t, tab, i, &own, arena);
    st = bs_world_load_facts(&world, &syms, &use->symbols, t->blocks[i].block,
                             i);
    if (st != BS_OK) {
      note("load_facts", st);
      emit_result_error(error_kind(st));
      return;
    }
  }
  for (i = 0; i < t->block_count; i++) {
    bs_tables own;
    const bs_tables *use = tables_for(t, tab, i, &own, arena);
    st = bs_world_load_logic(&world, &syms, &use->symbols, t, use,
                             t->blocks[i].block, i);
    if (st != BS_OK) {
      note("load_logic", st);
      emit_result_error(error_kind(st));
      return;
    }
  }

  st = bs_world_parse(&world, &syms, arena,
                      bs_span_make(authorizer_src, authorizer_len),
                      (size_t)BS_MAX_BLOCKS, t, tab);
  if (st != BS_OK) {
    note("parse", st);
    emit_result_error(error_kind(st));
    return;
  }

  st = bs_authorize(&world, &syms, arena, lim.max_iterations, &v);
  if (st != BS_OK) {
    note("authorize", st);
    emit_result_error(error_kind(st));
    return;
  }

  if (v.kind == (uint8_t)BS_VERDICT_ALLOW) {
    (void)printf(",\"result\":{\"ok\":true,\"policy\":%u}", (unsigned)v.policy);
    return;
  }
  (void)printf(",\"result\":{\"ok\":false,\"kind\":\"%s\"",
               (v.kind == (uint8_t)BS_VERDICT_NO_POLICY) ? "no_matching_policy"
                                                         : "unauthorized");
  (void)printf(",\"failed_checks\":[");
  for (i = 0; i < v.failed_count; i++) {
    bs_writer w;
    bs_tables own;
    const bs_tables *use = tab;
    if (v.failed[i].block < t->block_count) {
      use = tables_for(t, tab, v.failed[i].block, &own, arena);
    }
    (void)bs_writer_init(&w, check_buf, sizeof check_buf);
    if (bs_failed_check_print(&w, arena, use, &v.failed[i]) != BS_OK) {
      continue;
    }
    if (i > 0) {
      (void)putchar(',');
    }
    emit_json_string(check_buf, bs_writer_len(&w));
  }
  (void)printf("]}");
}

static void emit_token(const bs_token *t, bs_arena *arena) {
  bs_tables tab;
  size_t i;
  int verified = 0;
  int have_tables = 0;

  (void)printf("{\"decode\":\"ok\",\"revocation_ids\":[");
  for (i = 0; i < t->block_count; i++) {
    (void)printf("%s\"", (i > 0) ? "," : "");
    emit_hex(bs_token_revocation_id(t, i));
    (void)putchar('"');
  }
  (void)printf("]");

  {
    bs_status st = bs_token_verify(t, bs_span_make(g_root_key, g_root_key_len));
    verified = (st == BS_OK);
    if (verified) {
      (void)printf(",\"signatures\":\"ok\"");
    } else {
      (void)printf(",\"signatures\":{\"error\":\"%s\"}", bs_strstatus(st));
    }
  }

  if (bs_tables_build(arena, t, &tab) == BS_OK) {
    (void)printf(",\"blocks\":[");
    for (i = 0; i < t->block_count; i++) {
      bs_writer w;
      bs_tables own;
      const bs_tables *use = tables_for(t, &tab, i, &own, arena);
      (void)bs_writer_init(&w, block_buf, sizeof block_buf);
      if (bs_block_print(&w, arena, use, t->blocks[i].block) != BS_OK) {
        (void)printf("%snull", (i > 0) ? "," : "");
        continue;
      }
      if (i > 0) {
        (void)putchar(',');
      }
      emit_json_string(block_buf, bs_writer_len(&w));
    }
    (void)printf("]");
    have_tables = 1;
  }

  /* A token whose chain does not verify is never authorized: whatever it
   * claims, nothing vouches for it. */
  if (!verified) {
    emit_result_error("signature");
  } else if (have_tables) {
    emit_authorize(t, &tab, arena);
  } else {
    emit_result_error("format");
  }

  (void)printf("}\n");
}

int main(int argc, char **argv) {
  static uint8_t token_buf[1024 * 1024];
  const char *token_path = NULL;
  size_t token_len = 0;
  bs_arena arena;
  int i;

  for (i = 1; i < argc; i++) {
    if (strcmp(argv[i], "--capabilities") == 0) {
      emit_capabilities();
      return 0;
    }
    if (strcmp(argv[i], "--version") == 0) {
      (void)printf("biscuits.h %s\n", BS_VERSION_STRING);
      return 0;
    }
    if (strcmp(argv[i], "--token") == 0 && i + 1 < argc) {
      token_path = argv[++i];
    } else if (strcmp(argv[i], "--root-key") == 0 && i + 1 < argc) {
      g_root_key_len = unhex(argv[++i], g_root_key, sizeof g_root_key);
    } else if (strcmp(argv[i], "--authorizer-stdin") == 0) {
      /* Read to EOF, always: the runner writes the whole authorizer before
       * waiting for output, so stopping early would deadlock on a full pipe
       * even in a build that ignored the text. */
      int ch;
      while ((ch = getchar()) != EOF) {
        if (authorizer_len + 1U < sizeof authorizer_src) {
          authorizer_src[authorizer_len] = (char)ch;
          authorizer_len++;
        }
      }
    }
  }

  if (token_path == NULL) {
    (void)fprintf(stderr, "usage: shim --token FILE --root-key HEX "
                          "[--authorizer-stdin] | --capabilities\n");
    return 2;
  }
  if (!read_file(token_path, token_buf, sizeof token_buf, &token_len)) {
    (void)fprintf(stderr, "shim: cannot read %s\n", token_path);
    return 2;
  }

  if (bs_arena_init(&arena, g_arena_buf, sizeof g_arena_buf) != BS_OK) {
    (void)fprintf(stderr, "shim: arena init failed\n");
    return 2;
  }

  {
    bs_token token;
    bs_status st =
        bs_token_parse(&arena, bs_span_make(token_buf, token_len), &token);
    if (st != BS_OK) {
      emit_decode_error(st);
      return 0;
    }
    emit_token(&token, &arena);
  }
  return 0;
}
