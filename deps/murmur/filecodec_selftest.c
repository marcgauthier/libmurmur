/* filecodec_selftest - postcard + file codecs against Go vectors.
 * Usage: ./build/filecodectest [vectors-file]
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "filecodec.h"
#include "postcard.h"

static int failures = 0;

#define CHECK(cond, ...)                                                 \
  do {                                                                   \
    if (!(cond)) {                                                       \
      printf("FAIL %s:%d: ", __func__, __LINE__);                        \
      printf(__VA_ARGS__);                                               \
      printf("\n");                                                      \
      failures++;                                                        \
    }                                                                    \
  } while (0)

static int hexval(char c) {
  if (c >= '0' && c <= '9') {
    return c - '0';
  }
  if (c >= 'a' && c <= 'f') {
    return c - 'a' + 10;
  }
  return -1;
}

static uint8_t *unhex(const char *s, size_t *n) {
  size_t l = strlen(s);
  if (l % 2 != 0) {
    return NULL;
  }
  uint8_t *b = (uint8_t *)malloc(l / 2 ? l / 2 : 1);
  if (!b) {
    return NULL;
  }
  for (size_t i = 0; i < l / 2; i++) {
    int a = hexval(s[2 * i]), c = hexval(s[2 * i + 1]);
    if (a < 0 || c < 0) {
      free(b);
      return NULL;
    }
    b[i] = (uint8_t)((a << 4) | c);
  }
  *n = l / 2;
  return b;
}

static char *rehex(const uint8_t *b, size_t n) {
  static const char *d = "0123456789abcdef";
  char *s = (char *)malloc(2 * n + 1);
  if (!s) {
    return NULL;
  }
  for (size_t i = 0; i < n; i++) {
    s[2 * i] = d[b[i] >> 4];
    s[2 * i + 1] = d[b[i] & 15];
  }
  s[2 * n] = '\0';
  return s;
}

/* Decodes one vector by tag, re-encodes, byte-compares. */
static void check_vector(const char *tag, const uint8_t *b, size_t n,
                         const char *hex) {
  murmur_pc_dec_t d;
  murmur_pc_dec_init(&d, b, n);
  murmur_pc_enc_t e;
  murmur_pc_enc_init(&e);
  if (!strcmp(tag, "u64")) {
    uint64_t v = murmur_pc_g_u64(&d);
    if (murmur_pc_end(&d) == MURMUR_PC_OK) {
      murmur_pc_u64(&e, v);
    }
  } else if (!strcmp(tag, "i16")) {
    int16_t v = murmur_pc_g_i16(&d);
    if (murmur_pc_end(&d) == MURMUR_PC_OK) {
      murmur_pc_i16(&e, v);
    }
  } else if (!strcmp(tag, "i32")) {
    int32_t v = murmur_pc_g_i32(&d);
    if (murmur_pc_end(&d) == MURMUR_PC_OK) {
      murmur_pc_i32(&e, v);
    }
  } else if (!strcmp(tag, "i64")) {
    int64_t v = murmur_pc_g_i64(&d);
    if (murmur_pc_end(&d) == MURMUR_PC_OK) {
      murmur_pc_i64(&e, v);
    }
  } else if (!strcmp(tag, "bool")) {
    int v = murmur_pc_g_bool(&d);
    if (murmur_pc_end(&d) == MURMUR_PC_OK) {
      murmur_pc_bool(&e, v);
    }
  } else if (!strcmp(tag, "f32")) {
    float v = murmur_pc_g_f32(&d);
    if (murmur_pc_end(&d) == MURMUR_PC_OK) {
      murmur_pc_f32(&e, v);
    }
  } else if (!strcmp(tag, "f64")) {
    double v = murmur_pc_g_f64(&d);
    if (murmur_pc_end(&d) == MURMUR_PC_OK) {
      murmur_pc_f64(&e, v);
    }
  } else if (!strcmp(tag, "str")) {
    size_t m = 0;
    const uint8_t *s = murmur_pc_g_str(&d, &m);
    if (murmur_pc_end(&d) == MURMUR_PC_OK) {
      murmur_pc_str(&e, s, m);
    }
  } else if (!strcmp(tag, "bytes")) {
    size_t m = 0;
    const uint8_t *s = murmur_pc_g_bytes(&d, &m);
    if (murmur_pc_end(&d) == MURMUR_PC_OK) {
      murmur_pc_bytes(&e, s, m);
    }
  } else if (!strcmp(tag, "frame")) {
    murmur_file_frame_t f;
    if (murmur_file_frame_decode(b, n, &f) == MURMUR_PC_OK) {
      murmur_file_frame_encode(&e, &f);
    }
  } else if (!strcmp(tag, "meta")) {
    murmur_file_meta_t m;
    if (murmur_file_meta_decode(b, n, &m) == MURMUR_PC_OK) {
      murmur_file_meta_encode(&e, &m);
    }
  } else if (!strcmp(tag, "avail")) {
    murmur_file_avail_t a;
    if (murmur_file_avail_decode(b, n, &a) == MURMUR_PC_OK) {
      murmur_file_avail_encode(&e, &a);
      murmur_file_avail_free(&a);
    }
  } else if (!strcmp(tag, "rot")) {
    murmur_file_keyrot_t s;
    if (murmur_file_keyrot_decode(b, n, &s) == MURMUR_PC_OK) {
      murmur_file_keyrot_encode(&e, &s);
    }
  } else {
    CHECK(0, "unknown tag %s", tag);
    murmur_pc_enc_finish(&e);
    return;
  }
  char *back = rehex(e.b, e.len);
  CHECK(back && !strcmp(back, hex), "%s roundtrip %s", tag, hex);
  free(back);
  murmur_pc_enc_finish(&e);
}

static void test_vectors(const char *path) {
  FILE *f = fopen(path, "r");
  CHECK(f != NULL, "open %s", path);
  if (!f) {
    return;
  }
  char line[300000];
  int n = 0;
  while (fgets(line, sizeof(line), f)) {
    char *sp = strchr(line, ' ');
    CHECK(sp != NULL, "vector shape");
    if (!sp) {
      continue;
    }
    *sp = '\0';
    char *hex = sp + 1;
    hex[strcspn(hex, "\r\n")] = '\0';
    size_t m = 0;
    uint8_t *b = unhex(hex, &m);
    CHECK(b != NULL, "vector hex");
    if (!b) {
      continue;
    }
    check_vector(line, b, m, hex);
    free(b);
    n++;
  }
  fclose(f);
  CHECK(n > 50, "vector count %d", n);
}

static void test_fields(void) {
  /* Request frame field layout. */
  murmur_pc_enc_t e;
  murmur_pc_enc_init(&e);
  murmur_file_frame_t f;
  memset(&f, 0, sizeof(f));
  f.kind = MURMUR_FILE_REQUEST;
  for (int i = 0; i < 16; i++) {
    f.database.b[i] = (uint8_t)i;
  }
  for (int i = 0; i < 32; i++) {
    f.digest[i] = (uint8_t)(0xA0 + i);
  }
  f.generation = 7;
  f.offset = 65536;
  murmur_file_frame_encode(&e, &f);
  murmur_file_frame_t g;
  CHECK(murmur_file_frame_decode(e.b, e.len, &g) == MURMUR_PC_OK,
        "request decode");
  CHECK(g.kind == MURMUR_FILE_REQUEST, "request kind");
  CHECK(!memcmp(g.database.b, f.database.b, 16), "request db");
  CHECK(!memcmp(g.digest, f.digest, 32), "request digest");
  CHECK(g.generation == 7 && g.offset == 65536, "request nums");
  murmur_pc_enc_finish(&e);
  /* Metadata deleted flag + name borrow. */
  murmur_pc_enc_init(&e);
  murmur_file_meta_t m;
  memset(&m, 0, sizeof(m));
  static const uint8_t nm[] = "gone.txt";
  m.name = nm;
  m.name_len = sizeof(nm) - 1;
  m.deleted = 1;
  murmur_file_meta_encode(&e, &m);
  murmur_file_meta_t h;
  CHECK(murmur_file_meta_decode(e.b, e.len, &h) == MURMUR_PC_OK,
        "meta decode");
  CHECK(h.deleted == 1, "meta deleted");
  CHECK(h.name_len == 8 && !memcmp(h.name, "gone.txt", 8), "meta name");
  murmur_pc_enc_finish(&e);
  /* Remote availability list. */
  murmur_pc_enc_init(&e);
  murmur_file_avail_t a;
  memset(&a, 0, sizeof(a));
  a.kind = MURMUR_FILE_REMOTE;
  murmur_node_t rs[2];
  memset(rs, 0, sizeof(rs));
  rs[0].b[0] = 1;
  rs[1].b[15] = 2;
  a.remote = rs;
  a.n_remote = 2;
  murmur_file_avail_encode(&e, &a);
  murmur_file_avail_t b;
  CHECK(murmur_file_avail_decode(e.b, e.len, &b) == MURMUR_PC_OK,
        "avail decode");
  CHECK(b.kind == MURMUR_FILE_REMOTE && b.n_remote == 2, "avail shape");
  CHECK(b.remote[0].b[0] == 1 && b.remote[1].b[15] == 2, "avail nodes");
  murmur_file_avail_free(&b);
  murmur_pc_enc_finish(&e);
}

static void test_errors(void) {
  murmur_pc_dec_t d;
  /* Truncated varint. */
  static const uint8_t t1[] = {0x80};
  murmur_pc_dec_init(&d, t1, sizeof(t1));
  murmur_pc_g_u64(&d);
  CHECK(murmur_pc_end(&d) == MURMUR_PC_TRUNCATED, "truncated varint");
  /* Tenth byte may only carry bit 63. */
  static const uint8_t t2[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                               0xFF, 0xFF, 0xFF, 0xFF, 0x02};
  murmur_pc_dec_init(&d, t2, sizeof(t2));
  murmur_pc_g_u64(&d);
  CHECK(murmur_pc_end(&d) == MURMUR_PC_OVERFLOW, "varint overflow");
  /* U16 range. */
  static const uint8_t t3[] = {0x80, 0x80, 0x04}; /* 65536 */
  murmur_pc_dec_init(&d, t3, sizeof(t3));
  CHECK(murmur_pc_g_u16(&d) == 0, "u16 zero");
  CHECK(murmur_pc_end(&d) == MURMUR_PC_OVERFLOW, "u16 overflow");
  /* Bool tag. */
  static const uint8_t t4[] = {0x02};
  murmur_pc_dec_init(&d, t4, sizeof(t4));
  CHECK(murmur_pc_g_bool(&d) == 0, "bool zero");
  CHECK(murmur_pc_end(&d) == MURMUR_PC_VALUE, "bool value");
  /* Trailing bytes. */
  static const uint8_t t5[] = {0x01, 0x00};
  murmur_pc_dec_init(&d, t5, sizeof(t5));
  murmur_pc_g_bool(&d);
  CHECK(murmur_pc_end(&d) == MURMUR_PC_TRAILING, "trailing");
  /* Bad frame discriminant. */
  static const uint8_t t6[] = {0x05};
  murmur_file_frame_t f;
  CHECK(murmur_file_frame_decode(t6, sizeof(t6), &f) == MURMUR_PC_VALUE,
        "frame discriminant");
  /* Bad availability discriminant. */
  murmur_file_avail_t a;
  CHECK(murmur_file_avail_decode(t6, sizeof(t6), &a) == MURMUR_PC_VALUE,
        "avail discriminant");
  /* Invalid UTF-8 string. */
  static const uint8_t t7[] = {0x01, 0xFF};
  murmur_pc_dec_init(&d, t7, sizeof(t7));
  size_t m = 0;
  CHECK(murmur_pc_g_str(&d, &m) == NULL, "str null");
  CHECK(murmur_pc_end(&d) == MURMUR_PC_VALUE, "str value");
  /* Sticky error: values after failure read zero. */
  murmur_pc_dec_init(&d, t1, sizeof(t1));
  murmur_pc_g_u64(&d);
  CHECK(murmur_pc_g_u64(&d) == 0, "sticky zero");
  CHECK(murmur_pc_end(&d) == MURMUR_PC_TRUNCATED, "sticky err");
}

/* Minimal in-memory stream for frame IO. */
typedef struct {
  uint8_t *b;
  size_t len, cap, pos;
  int fail_after;
} memio_t;

static int mem_write(void *ctx, const uint8_t *b, size_t n) {
  memio_t *m = (memio_t *)ctx;
  if (m->fail_after >= 0 && m->len + n > (size_t)m->fail_after) {
    return 1;
  }
  if (m->len + n > m->cap) {
    size_t nc = m->cap ? m->cap * 2 : 256;
    while (nc < m->len + n) {
      nc *= 2;
    }
    uint8_t *nb = (uint8_t *)realloc(m->b, nc);
    if (!nb) {
      return 1;
    }
    m->b = nb;
    m->cap = nc;
  }
  memcpy(m->b + m->len, b, n);
  m->len += n;
  return 0;
}

static int mem_read(void *ctx, uint8_t *b, size_t n) {
  memio_t *m = (memio_t *)ctx;
  if (m->len - m->pos < n) {
    return 1;
  }
  memcpy(b, m->b + m->pos, n);
  m->pos += n;
  return 0;
}

static const char *mem_err(void *ctx) {
  (void)ctx;
  return "short";
}

static void test_frame_io(void) {
  memio_t m;
  memset(&m, 0, sizeof(m));
  m.fail_after = -1;
  murmur_stream_io_t io;
  io.write = mem_write;
  io.read_full = mem_read;
  io.close = NULL;
  io.error_text = mem_err;
  io.ctx = &m;
  murmur_file_frame_t f;
  memset(&f, 0, sizeof(f));
  f.kind = MURMUR_FILE_HEADER;
  f.bytes = 42;
  memset(f.identity, 0xCC, 32);
  char *detail = NULL;
  int sqlrc = -1;
  CHECK(murmur_file_write_frame(&io, &f, &detail, &sqlrc) ==
            MURMUR_SYNC_OK,
        "frame write");
  CHECK(detail == NULL && sqlrc == 0, "frame write rc");
  CHECK(m.len == 12 + 1 + 1 + 32, "frame wire len %zu", m.len);
  CHECK(m.b[0] == 'F' && m.b[1] == 'F' && m.b[3] == 1, "frame magic");
  CHECK(m.b[4] == 0 && m.b[7] == 0, "frame reserved");
  m.pos = 0;
  murmur_file_frame_t g;
  uint8_t *owned = NULL;
  CHECK(murmur_file_read_frame(&io, &g, &owned, &detail, &sqlrc) ==
            MURMUR_SYNC_OK,
        "frame read");
  CHECK(g.kind == MURMUR_FILE_HEADER && g.bytes == 42, "frame back");
  CHECK(g.identity[0] == 0xCC && g.identity[31] == 0xCC, "frame ident");
  free(owned);
  free(detail);
  detail = NULL;
  /* Oversize encode refuses. */
  murmur_file_frame_t big;
  memset(&big, 0, sizeof(big));
  big.kind = MURMUR_FILE_CHUNK_FRAME;
  static uint8_t huge[200 << 10];
  big.data = huge;
  big.data_len = sizeof(huge);
  CHECK(murmur_file_write_frame(&io, &big, &detail, &sqlrc) ==
            MURMUR_SYNC_OVERLOADED,
        "frame oversize");
  free(detail);
  detail = NULL;
  /* Bad magic rejects. */
  free(m.b);
  memset(&m, 0, sizeof(m));
  m.fail_after = -1;
  static const uint8_t bad[12] = {'X', 'X', 0, 1, 0, 0, 0, 0, 0, 0, 0, 1};
  mem_write(&m, bad, 12);
  mem_write(&m, (const uint8_t *)"X", 1);
  CHECK(murmur_file_read_frame(&io, &g, &owned, &detail, &sqlrc) ==
            MURMUR_SYNC_PROTOCOL,
        "frame magic status");
  CHECK(detail && !strcmp(detail, "file frame"), "frame magic detail");
  free(detail);
  detail = NULL;
  /* Short body reports the stream text. */
  free(m.b);
  memset(&m, 0, sizeof(m));
  m.fail_after = -1;
  static const uint8_t sh[12] = {'F', 'F', 0, 1, 0, 0, 0, 0,
                                 0, 0, 0, 10};
  mem_write(&m, sh, 12);
  mem_write(&m, (const uint8_t *)"ab", 2);
  CHECK(murmur_file_read_frame(&io, &g, &owned, &detail, &sqlrc) ==
            MURMUR_SYNC_PROTOCOL,
        "frame short status");
  CHECK(detail && !strcmp(detail, "short"), "frame short detail");
  free(detail);
  free(m.b);
}

int main(int argc, char **argv) {
  const char *vec =
      argc > 1 ? argv[1] : "deps/murmur/testdata/pcvec.txt";
  test_vectors(vec);
  test_fields();
  test_errors();
  test_frame_io();
  if (failures == 0) {
    printf("PC-OK (4 suites)\n");
    return 0;
  }
  printf("PC-FAIL (%d)\n", failures);
  return 1;
}
