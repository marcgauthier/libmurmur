/* msgcodec_selftest - ports TestGoldenKey, TestGoldenCursors,
 * TestGoldenMessages, TestGoldenCells, TestGoldenKV and TestFrameIO
 * (protocol_test.go) against the msg/key/cursor/cell/u64 goldens.
 *
 * Usage: msgcodectest [testdata-dir]
 * Or: make selftest
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "member.h"
#include "msgcodec.h"

static int failures = 0;
static const char *vecdir = "clients/go/pkgs/replication/testdata";

#define CHECK(cond, ...)                                                 \
  do {                                                                   \
    if (!(cond)) {                                                       \
      printf("FAIL %s:%d: ", __func__, __LINE__);                        \
      printf(__VA_ARGS__);                                               \
      printf("\n");                                                      \
      failures++;                                                        \
    }                                                                    \
  } while (0)

static murmur_node_t vec_node(uint8_t b) {
  murmur_node_t n;
  for (int i = 0; i < 16; i++) {
    n.b[i] = (uint8_t)(b + i);
  }
  return n;
}

static uint8_t *load_vec(const char *name, size_t *len) {
  char path[512];
  snprintf(path, sizeof(path), "%s/%s", vecdir, name);
  FILE *f = fopen(path, "rb");
  if (!f) {
    return NULL;
  }
  fseek(f, 0, SEEK_END);
  long n = ftell(f);
  fseek(f, 0, SEEK_SET);
  if (n < 0 || n > 1 << 20) {
    fclose(f);
    return NULL;
  }
  uint8_t *b = (uint8_t *)malloc((size_t)n ? (size_t)n : 1);
  if (n > 0 && fread(b, 1, (size_t)n, f) != (size_t)n) {
    free(b);
    fclose(f);
    return NULL;
  }
  fclose(f);
  *len = (size_t)n;
  return b;
}

static int bytes_eq(const uint8_t *a, size_t an, const uint8_t *b,
                    size_t bn) {
  return an == bn && (an == 0 || memcmp(a, b, an) == 0);
}

static int key_eq(const murmur_key_t *a, const murmur_key_t *b) {
  return a->version == b->version && a->seq == b->seq &&
         bytes_eq(a->table, a->table_len, b->table, b->table_len) &&
         bytes_eq(a->pk, a->pk_len, b->pk, b->pk_len) &&
         bytes_eq(a->cid, a->cid_len, b->cid, b->cid_len);
}

/* Fixture mirror of Go vecKey(): {42, 7, "t", {1,2,3}, "b"}. */
static void fixture_key(murmur_key_t *k) {
  static const uint8_t pk[] = {1, 2, 3};
  memset(k, 0, sizeof(*k));
  k->version = 42;
  k->seq = 7;
  k->table = (const uint8_t *)"t";
  k->table_len = 1;
  k->pk = pk;
  k->pk_len = sizeof(pk);
  k->cid = (const uint8_t *)"b";
  k->cid_len = 1;
}

static void test_keys(void) {
  murmur_key_t k;
  fixture_key(&k);
  size_t want_len = 0;
  uint8_t *want = load_vec("key.bin", &want_len);
  CHECK(want != NULL, "load key.bin");
  if (want) {
    uint8_t got[256];
    size_t n = murmur_key_encode(&k, got, sizeof(got));
    CHECK(n == want_len && memcmp(got, want, n) == 0, "key bytes");
    murmur_key_t back;
    CHECK(murmur_key_decode(want, want_len, &back) == MURMUR_OK,
          "key decode");
    CHECK(key_eq(&back, &k), "key fields");
    free(want);
  }
  size_t neg_len = 0;
  uint8_t *neg = load_vec("key_neg.bin", &neg_len);
  CHECK(neg != NULL, "load key_neg.bin");
  if (neg) {
    murmur_key_t back;
    CHECK(murmur_key_decode(neg, neg_len, &back) == MURMUR_OK,
          "neg decode");
    CHECK(back.version == -7 && back.seq == -1 && back.table_len == 0 &&
              back.pk_len == 0 && back.cid_len == 0,
          "neg fields");
    uint8_t rt[256];
    size_t n = murmur_key_encode(&back, rt, sizeof(rt));
    CHECK(n == neg_len && memcmp(rt, neg, n) == 0, "neg re-encode");
    free(neg);
  }
  /* Invalid UTF-8 table fails closed. */
  uint8_t bad[] = {0x54, 0x0e, 0x01, 0xff, 0x00, 0x00};
  murmur_key_t junk;
  CHECK(murmur_key_decode(bad, sizeof(bad), &junk) == MURMUR_MSHIP_PROTOCOL,
        "bad table utf8 accepted");
  CHECK(murmur_key_decode(NULL, 0, &junk) != MURMUR_OK, "null key accepted");
}

static int cursor_eq(const murmur_cursor_t *a, const murmur_cursor_t *b) {
  if (a->from != b->from || a->has_through != b->has_through ||
      a->has_after != b->has_after) {
    return 0;
  }
  if (a->has_through && a->through != b->through) {
    return 0;
  }
  return !a->has_after || key_eq(&a->after, &b->after);
}

static void test_cursors(void) {
  murmur_cursor_t def;
  memset(&def, 0, sizeof(def));
  size_t d_len = 0;
  uint8_t *d = load_vec("cursor_default.bin", &d_len);
  CHECK(d != NULL, "load cursor_default.bin");
  if (d) {
    uint8_t got[256];
    size_t n = murmur_cursor_encode(&def, got, sizeof(got));
    CHECK(n == d_len && memcmp(got, d, n) == 0, "default cursor");
    free(d);
  }
  murmur_cursor_t full;
  memset(&full, 0, sizeof(full));
  full.from = 42;
  full.has_through = 1;
  full.through = 100;
  full.has_after = 1;
  fixture_key(&full.after);
  size_t f_len = 0;
  uint8_t *f = load_vec("cursor_full.bin", &f_len);
  CHECK(f != NULL, "load cursor_full.bin");
  if (f) {
    uint8_t got[256];
    size_t n = murmur_cursor_encode(&full, got, sizeof(got));
    CHECK(n == f_len && memcmp(got, f, n) == 0, "full cursor");
    murmur_cursor_t back;
    CHECK(murmur_cursor_decode(f, f_len, &back) == MURMUR_OK,
          "cursor decode");
    CHECK(cursor_eq(&back, &full), "cursor fields");
    uint8_t trail[256];
    memcpy(trail, f, f_len);
    trail[f_len] = 0;
    CHECK(murmur_cursor_decode(trail, f_len + 1, &back) ==
              MURMUR_MSHIP_PROTOCOL,
          "trailing cursor byte accepted");
    /* Bad option discriminant. */
    uint8_t badopt[256];
    memcpy(badopt, f, f_len);
    badopt[1] = 2;
    CHECK(murmur_cursor_decode(badopt, f_len, &back) ==
              MURMUR_MSHIP_PROTOCOL,
          "bad option accepted");
    free(f);
  }
}

static void fill_schema(uint8_t s[32]) { memset(s, 0xaa, 32); }
static void fill_digest(uint8_t d[32]) { memset(d, 0xbb, 32); }

/* Builds the 11 golden fixtures; returns the message count. */
static size_t fixture_messages(murmur_msg_t *m, const char **names) {
  static uint8_t chunk_data[100];
  static int chunk_init = 0;
  if (!chunk_init) {
    for (int i = 0; i < 100; i++) {
      chunk_data[i] = (uint8_t)i;
    }
    chunk_init = 1;
  }
  murmur_node_t g = vec_node(1), n = vec_node(2), s = vec_node(3);
  memset(m, 0, 11 * sizeof(*m));
  /* hello v4 */
  m[0].tag = MURMUR_MSG_HELLO;
  m[0].group = g;
  m[0].node = n;
  m[0].site = s;
  fill_schema(m[0].schema);
  m[0].incarnation = 9;
  murmur_addr_parse(&m[0].addr, "127.0.0.1:4401");
  names[0] = "msg_hello.bin";
  /* hello v6 */
  m[1] = m[0];
  murmur_addr_parse(&m[1].addr, "[::1]:4401");
  names[1] = "msg_hello_v6.bin";
  /* pull */
  m[2].tag = MURMUR_MSG_PULL;
  m[2].group = g;
  m[2].node = n;
  m[2].site = s;
  fill_schema(m[2].schema);
  m[2].has_expected = 1;
  m[2].expected = s;
  m[2].cursor.from = 42;
  m[2].cursor.has_after = 1;
  fixture_key(&m[2].cursor.after);
  names[2] = "msg_pull.bin";
  /* batch */
  m[3].tag = MURMUR_MSG_BATCH;
  m[3].site = s;
  m[3].cursor.from = 100;
  m[3].bytes = 12345;
  fill_digest(m[3].digest);
  names[3] = "msg_batch.bin";
  /* chunk */
  m[4].tag = MURMUR_MSG_CHUNK;
  m[4].index = 3;
  m[4].data = chunk_data;
  m[4].data_len = sizeof(chunk_data);
  names[4] = "msg_chunk.bin";
  /* ack */
  m[5].tag = MURMUR_MSG_ACK;
  fill_digest(m[5].digest);
  names[5] = "msg_ack.bin";
  /* idle, end */
  m[6].tag = MURMUR_MSG_IDLE;
  names[6] = "msg_idle.bin";
  m[7].tag = MURMUR_MSG_END;
  names[7] = "msg_end.bin";
  /* reset */
  m[8].tag = MURMUR_MSG_RESET;
  m[8].site = s;
  names[8] = "msg_reset.bin";
  /* error */
  m[9].tag = MURMUR_MSG_ERROR;
  m[9].data = (const uint8_t *)"boom";
  m[9].data_len = 4;
  names[9] = "msg_error.bin";
  /* snapshot request */
  m[10].tag = MURMUR_MSG_SNAPSHOT_REQUEST;
  m[10].group = g;
  m[10].node = n;
  m[10].site = s;
  fill_schema(m[10].schema);
  names[10] = "msg_snapshot_request.bin";
  return 11;
}

static void test_messages(void) {
  murmur_msg_t m[11];
  const char *names[11];
  size_t count = fixture_messages(m, names);
  for (size_t i = 0; i < count; i++) {
    size_t want_len = 0;
    uint8_t *want = load_vec(names[i], &want_len);
    if (!want) {
      CHECK(0, "%s: cannot load", names[i]);
      continue;
    }
    uint8_t got[2048];
    size_t n = murmur_msg_encode(&m[i], got, sizeof(got));
    CHECK(n == want_len && memcmp(got, want, n) == 0, "%s: encode mismatch",
          names[i]);
    murmur_msg_t back;
    CHECK(murmur_msg_decode(want, want_len, &back) == MURMUR_OK,
          "%s: decode", names[i]);
    uint8_t rt[2048];
    size_t n2 = murmur_msg_encode(&back, rt, sizeof(rt));
    CHECK(n2 == want_len && memcmp(rt, want, n2) == 0, "%s: unstable",
          names[i]);
    free(want);
  }
  /* Unit shapes round-trip without vectors. */
  static const uint8_t man1[] = {1, 2}, man2[] = {3};
  murmur_msg_t units[5];
  memset(units, 0, sizeof(units));
  units[0].tag = MURMUR_MSG_SCHEMA_REQUEST;
  units[1].tag = MURMUR_MSG_SCHEMA_MANIFEST;
  units[1].data = man1;
  units[1].data_len = sizeof(man1);
  units[2].tag = MURMUR_MSG_SNAPSHOT_MANIFEST;
  units[2].data = man2;
  units[2].data_len = sizeof(man2);
  units[3].tag = MURMUR_MSG_SCHEMA_ACK;
  fill_digest(units[3].digest);
  units[3].sequence = 9;
  units[4].tag = MURMUR_MSG_PULL;
  units[4].group = vec_node(1);
  for (int i = 0; i < 5; i++) {
    uint8_t enc[2048];
    size_t n = murmur_msg_encode(&units[i], enc, sizeof(enc));
    CHECK(n > 0, "unit %d encode", i);
    murmur_msg_t back;
    CHECK(murmur_msg_decode(enc, n, &back) == MURMUR_OK, "unit %d decode",
          i);
    uint8_t rt[2048];
    size_t n2 = murmur_msg_encode(&back, rt, sizeof(rt));
    CHECK(n2 == n && memcmp(rt, enc, n) == 0, "unit %d unstable", i);
  }
  /* Strictness. */
  murmur_msg_t junk;
  CHECK(murmur_msg_decode((const uint8_t *)"\x63", 1, &junk) ==
            MURMUR_MSHIP_PROTOCOL,
        "unknown tag accepted");
  size_t idle_len = 0;
  uint8_t *idle = load_vec("msg_idle.bin", &idle_len);
  CHECK(idle != NULL, "load msg_idle.bin");
  if (idle) {
    uint8_t trail[16];
    memcpy(trail, idle, idle_len);
    trail[idle_len] = 0;
    CHECK(murmur_msg_decode(trail, idle_len + 1, &junk) ==
              MURMUR_MSHIP_PROTOCOL,
          "trailing message byte accepted");
    free(idle);
  }
  /* Chunk index overflow: tag 5 + varint 2^32. */
  const uint8_t bigidx[] = {5, 0x80, 0x80, 0x80, 0x80, 0x10, 0x00};
  CHECK(murmur_msg_decode(bigidx, sizeof(bigidx), &junk) ==
            MURMUR_MSHIP_PROTOCOL,
        "chunk index overflow accepted");
  /* Short encode buffer fails cleanly. */
  uint8_t tiny[2];
  CHECK(murmur_msg_encode(&m[0], tiny, sizeof(tiny)) == 0, "short encode");
}

static void test_cells(void) {
  size_t len = 0;
  uint8_t *blob = load_vec("crsb_cells.bin", &len);
  CHECK(blob != NULL, "load crsb_cells.bin");
  if (!blob) {
    return;
  }
  murmur_cell_t cells[8];
  size_t n = 0;
  CHECK(murmur_cells_decode(blob, len, cells, 8, &n) == MURMUR_OK,
        "cells decode");
  CHECK(n == 5, "count = %zu", n);
  if (n == 5) {
    CHECK(cells[0].val_tag == 0, "cell0 tag");
    CHECK(cells[1].val_tag == 1 && cells[1].val_int == -7, "cell1 val");
    CHECK(cells[1].table_len == 1 && cells[1].table[0] == 't' &&
              cells[1].cid_len == 1 && cells[1].cid[0] == 'b' &&
              cells[1].col_version == 5 && cells[1].db_version == 6 &&
              cells[1].cl == 7 && cells[1].seq == 8,
          "cell1 fields");
    CHECK(cells[2].val_tag == 2 && cells[2].val_real == 1.5, "cell2 real");
    CHECK(cells[3].val_tag == 3 && cells[3].val_blob_len == 2 &&
              memcmp(cells[3].val_blob, "hi", 2) == 0,
          "cell3 text");
    static const uint8_t want4[] = {0, 1, 2};
    CHECK(cells[4].val_tag == 4 && cells[4].val_blob_len == 3 &&
              memcmp(cells[4].val_blob, want4, 3) == 0,
          "cell4 blob");
    uint8_t rt[4096];
    size_t n2 = murmur_cells_encode(cells, n, rt, sizeof(rt));
    CHECK(n2 == len && memcmp(rt, blob, n2) == 0, "cells re-encode");
  }
  /* Strictness: bad magic, bad version, truncation, trailing bytes. */
  uint8_t bad[4096];
  memcpy(bad, blob, len);
  bad[0] = 'X';
  CHECK(murmur_cells_decode(bad, len, cells, 8, &n) == MURMUR_MSHIP_PROTOCOL,
        "bad magic accepted");
  memcpy(bad, blob, len);
  bad[4] = 2;
  CHECK(murmur_cells_decode(bad, len, cells, 8, &n) == MURMUR_MSHIP_PROTOCOL,
        "bad version accepted");
  CHECK(murmur_cells_decode(blob, len - 1, cells, 8, &n) ==
            MURMUR_MSHIP_PROTOCOL,
        "truncation accepted");
  memcpy(bad, blob, len);
  bad[len] = 0;
  CHECK(murmur_cells_decode(bad, len + 1, cells, 8, &n) ==
            MURMUR_MSHIP_PROTOCOL,
        "trailing byte accepted");
  /* Short cell array reports OVERLOADED. */
  CHECK(murmur_cells_decode(blob, len, cells, 2, &n) ==
            MURMUR_MSHIP_OVERLOADED,
        "short array not reported");
  free(blob);
}

static void test_kv(void) {
  size_t len = 0;
  uint8_t *v300 = load_vec("u64_300.bin", &len);
  CHECK(v300 != NULL, "load u64_300.bin");
  if (v300) {
    uint8_t got[16];
    size_t n = murmur_u64_encode(300, got, sizeof(got));
    CHECK(n == len && memcmp(got, v300, n) == 0, "u64 300");
    uint64_t v = 0;
    CHECK(murmur_u64_decode(v300, len, &v) == MURMUR_OK && v == 300,
          "u64 300 decode");
    free(v300);
  }
  size_t mlen = 0;
  uint8_t *vmax = load_vec("u64_max.bin", &mlen);
  CHECK(vmax != NULL, "load u64_max.bin");
  if (vmax) {
    uint8_t got[16];
    size_t n = murmur_u64_encode(~0ULL, got, sizeof(got));
    CHECK(n == mlen && memcmp(got, vmax, n) == 0, "u64 max");
    free(vmax);
  }
  murmur_node_t o = vec_node(4);
  size_t p_len = 0;
  uint8_t *p = load_vec("progress_key.txt", &p_len);
  CHECK(p != NULL, "load progress_key.txt");
  if (p) {
    /* Text vectors carry a trailing newline; the key is the line. */
    while (p_len > 0 && (p[p_len - 1] == '\n' || p[p_len - 1] == '\r')) {
      p_len--;
    }
    char got[128];
    size_t n = murmur_progress_key(&o, got, sizeof(got));
    CHECK(n == p_len && memcmp(got, p, n) == 0, "progress key");
    free(p);
  }
  size_t o_len = 0;
  uint8_t *ob = load_vec("observed_key.txt", &o_len);
  CHECK(ob != NULL, "load observed_key.txt");
  if (ob) {
    while (o_len > 0 && (ob[o_len - 1] == '\n' || ob[o_len - 1] == '\r')) {
      o_len--;
    }
    char got[128];
    size_t n = murmur_observed_key(&o, got, sizeof(got));
    CHECK(n == o_len && memcmp(got, ob, n) == 0, "observed key");
    free(ob);
  }
}

static uint8_t big_data[MURMUR_FRAME_BYTES];

static void test_frames(void) {
  static const uint8_t payload[] = "payload";
  murmur_msg_t msgs[3];
  memset(msgs, 0, sizeof(msgs));
  msgs[0].tag = MURMUR_MSG_IDLE;
  msgs[1].tag = MURMUR_MSG_CHUNK;
  msgs[1].index = 1;
  msgs[1].data = payload;
  msgs[1].data_len = sizeof(payload) - 1;
  msgs[2].tag = MURMUR_MSG_ERROR;
  msgs[2].data = (const uint8_t *)"x";
  msgs[2].data_len = 1;
  for (int i = 0; i < 3; i++) {
    uint8_t frame[2048];
    size_t n = murmur_frame_encode(&msgs[i], frame, sizeof(frame));
    CHECK(n > 4, "frame %d encode", i);
    murmur_msg_t back;
    CHECK(murmur_frame_decode(frame, n, &back) == MURMUR_OK,
          "frame %d decode", i);
    uint8_t a[2048], b[2048];
    size_t na = murmur_msg_encode(&back, a, sizeof(a));
    size_t nb = murmur_msg_encode(&msgs[i], b, sizeof(b));
    CHECK(na == nb && memcmp(a, b, na) == 0, "frame %d mismatch", i);
  }
  /* Oversized payload fails before touching the stream. */
  murmur_msg_t big;
  memset(&big, 0, sizeof(big));
  big.tag = MURMUR_MSG_CHUNK;
  big.data = big_data;
  big.data_len = sizeof(big_data);
  static uint8_t big_out[MURMUR_FRAME_BYTES + 1024];
  CHECK(murmur_frame_encode(&big, big_out, sizeof(big_out)) == 0,
        "oversized frame accepted");
  /* Empty and invalid frames fail closed. */
  murmur_msg_t junk;
  const uint8_t empty[] = {0, 0, 0, 0};
  CHECK(murmur_frame_decode(empty, sizeof(empty), &junk) ==
            MURMUR_MSHIP_PROTOCOL,
        "empty frame accepted");
  const uint8_t invalid[] = {0, 0, 0, 3, 0xff};
  CHECK(murmur_frame_decode(invalid, sizeof(invalid), &junk) ==
            MURMUR_MSHIP_PROTOCOL,
        "invalid frame accepted");
}

static void test_schema_pairs(void) {
  murmur_schema_pair_t pairs[2];
  pairs[0].table = (const uint8_t *)"a";
  pairs[0].table_len = 1;
  pairs[0].ddl = (const uint8_t *)"b";
  pairs[0].ddl_len = 1;
  pairs[1].table = (const uint8_t *)"Sticky Notes!";
  pairs[1].table_len = 13;
  pairs[1].ddl = (const uint8_t *)"CREATE TABLE t(x)";
  pairs[1].ddl_len = 17;
  size_t len = 0;
  uint8_t *want = load_vec("vec_schema_pairs.bin", &len);
  CHECK(want != NULL, "load vec_schema_pairs.bin");
  if (!want) {
    return;
  }
  uint8_t got[256];
  size_t n = murmur_schema_pairs_encode(pairs, 2, got, sizeof(got));
  CHECK(n == len && memcmp(got, want, n) == 0, "schema pairs encode");
  murmur_schema_pair_t back[4];
  size_t nb = 0;
  CHECK(murmur_schema_pairs_decode(want, len, back, 4, &nb) == MURMUR_OK,
        "schema pairs decode");
  CHECK(nb == 2, "schema pairs count = %zu", nb);
  if (nb == 2) {
    CHECK(bytes_eq(back[0].table, back[0].table_len,
                   pairs[0].table, pairs[0].table_len) &&
              bytes_eq(back[0].ddl, back[0].ddl_len,
                       pairs[0].ddl, pairs[0].ddl_len),
          "pair 0 fields");
    CHECK(bytes_eq(back[1].table, back[1].table_len,
                   pairs[1].table, pairs[1].table_len) &&
              bytes_eq(back[1].ddl, back[1].ddl_len,
                       pairs[1].ddl, pairs[1].ddl_len),
          "pair 1 fields");
    uint8_t rt[256];
    size_t n2 = murmur_schema_pairs_encode(back, nb, rt, sizeof(rt));
    CHECK(n2 == len && memcmp(rt, want, n2) == 0, "schema pairs unstable");
  }
  /* Strictness: truncation, trailing bytes, short array. */
  CHECK(murmur_schema_pairs_decode(want, len - 1, back, 4, &nb) ==
            MURMUR_MSHIP_INVALID,
        "truncation accepted");
  uint8_t trail[256];
  memcpy(trail, want, len);
  trail[len] = 0;
  CHECK(murmur_schema_pairs_decode(trail, len + 1, back, 4, &nb) ==
            MURMUR_MSHIP_INVALID,
        "trailing byte accepted");
  CHECK(murmur_schema_pairs_decode(want, len, back, 1, &nb) ==
            MURMUR_MSHIP_OVERLOADED,
        "short array not reported");
  free(want);
}

int main(int argc, char **argv) {
  if (argc > 1) {
    vecdir = argv[1];
  }
  test_keys();
  test_cursors();
  test_messages();
  test_cells();
  test_kv();
  test_frames();
  test_schema_pairs();
  if (failures == 0) {
    printf("MSGCODEC-OK (7 suites)\n");
    return 0;
  }
  printf("MSGCODEC-FAIL (%d)\n", failures);
  return 1;
}

