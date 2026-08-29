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
    "decode",
    "revocation_ids",
    "blocks",
    NULL,
};

/* The arena for one token. Sized generously for a test tool; the point of the
 * peak reporting is to learn what a real deployment would need. */
static uint8_t g_arena_buf[256 * 1024];

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

static void emit_decode_error(bs_status st) {
  (void)printf("{\"decode\":{\"error\":\"%s\"}}\n", bs_strstatus(st));
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

static void emit_token(const bs_token *t, bs_arena *arena) {
  bs_tables tab;
  size_t i;

  (void)printf("{\"decode\":\"ok\",\"revocation_ids\":[");
  for (i = 0; i < t->block_count; i++) {
    (void)printf("%s\"", (i > 0) ? "," : "");
    emit_hex(bs_token_revocation_id(t, i));
    (void)putchar('"');
  }
  (void)printf("]");

  if (bs_tables_build(arena, t, &tab) == BS_OK) {
    (void)printf(",\"blocks\":[");
    for (i = 0; i < t->block_count; i++) {
      bs_writer w;
      bs_tables own;
      const bs_tables *use = &tab;
      /* A third-party block numbers only its own symbols and keys. */
      if (t->blocks[i].has_external &&
          bs_tables_build_block(arena, t->blocks[i].block, &own) == BS_OK) {
        use = &own;
      }
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
      i++; /* consumed once signature verification exists */
    } else if (strcmp(argv[i], "--authorizer-stdin") == 0) {
      /* Drain stdin so the runner never blocks writing to a full pipe. */
      int ch;
      do {
        ch = getchar();
      } while (ch != EOF);
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
