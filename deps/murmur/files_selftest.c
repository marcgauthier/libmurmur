/* files_selftest - native FileObjects store suites (FILES-OK). */
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "aesgcm.h"
#include "files.h"
#include "hkdf.h"
#include "sha256.h"
#include "sqlite_murmur_crsqlite.h"
#include "sqlite3.h"
#include "sync.h"

static int failures = 0;
static int suites = 0;

#define CHECK(cond, msg)                                                 \
  do {                                                                   \
    if (!(cond)) {                                                       \
      printf("FAIL %s:%d: %s\n", __func__, __LINE__, msg);                \
      failures++;                                                        \
    }                                                                    \
  } while (0)

#define CHECK_ST(got, want, detail, msg)                                 \
  do {                                                                   \
    if ((got) != (want)) {                                               \
      printf("FAIL %s:%d: %s: want %s got %s (%s)\n", __func__, __LINE__, \
             msg, murmur_files_status_str(want),                         \
             murmur_files_status_str(got), (detail) ? (detail) : "-");   \
      failures++;                                                        \
    }                                                                    \
    free(detail);                                                        \
    (detail) = NULL;                                                     \
  } while (0)

static sqlite3 *open_db(void) {
  sqlite3 *db = NULL;
  if (sqlite3_open(":memory:", &db) != SQLITE_OK) {
    return NULL;
  }
  char *err = NULL;
  if (sqlite3_crsqlite_init(db, &err, NULL) != SQLITE_OK) {
    sqlite3_free(err);
    sqlite3_close(db);
    return NULL;
  }
  int sqlrc = 0;
  if (murmur_sync_ensure_schema(db, &sqlrc) != MURMUR_SYNC_OK) {
    sqlite3_close(db);
    return NULL;
  }
  return db;
}

static murmur_node_t test_self(void) {
  murmur_node_t n;
  for (int i = 0; i < 16; i++) {
    n.b[i] = (uint8_t)(0xA0 + i);
  }
  return n;
}

static char *make_tmpdir(void) {
  char *t = strdup("/tmp/murmur-files-XXXXXX");
  if (!t || !mkdtemp(t)) {
    free(t);
    return NULL;
  }
  return t;
}

static murmur_files_t *open_store(const char *dir, const uint8_t key[32],
                                  uint64_t gen, sqlite3 *db,
                                  const murmur_node_t *self) {
  murmur_files_config_t c;
  murmur_files_config_default(&c, dir, key);
  c.generation = gen;
  murmur_files_t *o = NULL;
  char *detail = NULL;
  int sqlrc = 0;
  murmur_files_status_t st =
      murmur_files_open(&c, db, self, &o, &detail, &sqlrc);
  if (st != MURMUR_FILES_OK) {
    printf("FAIL open store: %s (%s)\n", murmur_files_status_str(st),
           detail ? detail : "-");
    failures++;
    free(detail);
    return NULL;
  }
  free(detail);
  return o;
}

/* ---------- memory reader/writer ---------- */

typedef struct {
  const uint8_t *p;
  size_t n;
  size_t off;
  size_t quantum; /* max bytes per read; 0 = all */
} mem_reader_t;

static int mem_read(void *ctx, uint8_t *buf, size_t cap, size_t *n_out,
                    int *eof_out) {
  mem_reader_t *r = ctx;
  size_t left = r->n - r->off;
  size_t take = left < cap ? left : cap;
  if (r->quantum && take > r->quantum) {
    take = r->quantum;
  }
  memcpy(buf, r->p + r->off, take);
  r->off += take;
  *n_out = take;
  *eof_out = (r->off == r->n);
  return 0;
}

typedef struct {
  uint8_t *p;
  size_t n;
  size_t cap;
} mem_writer_t;

static int mem_write(void *ctx, const uint8_t *buf, size_t n) {
  mem_writer_t *w = ctx;
  if (w->n + n > w->cap) {
    size_t ncap = w->cap ? w->cap * 2 : 1024;
    while (ncap < w->n + n) {
      ncap *= 2;
    }
    uint8_t *next = realloc(w->p, ncap);
    if (!next) {
      return -1;
    }
    w->p = next;
    w->cap = ncap;
  }
  memcpy(w->p + w->n, buf, n);
  w->n += n;
  return 0;
}

/* Deterministic payload. */
static void fill_payload(uint8_t *p, size_t n, unsigned seed) {
  unsigned x = 0x12345678u + seed;
  for (size_t i = 0; i < n; i++) {
    x = x * 1103515245u + 12345u;
    p[i] = (uint8_t)(x >> 16);
  }
}

static int file_present(const char *path) {
  struct stat st;
  return stat(path, &st) == 0 && !S_ISDIR(st.st_mode);
}

/* Finds the single object file in dir (NULL unless exactly one). */
static char *find_object(const char *dir) {
  DIR *d = opendir(dir);
  if (!d) {
    return NULL;
  }
  char *found = NULL;
  struct dirent *e;
  while ((e = readdir(d)) != NULL) {
    size_t n = strlen(e->d_name);
    if (n > 5 && strcmp(e->d_name + n - 5, ".spfo") == 0) {
      char *full = malloc(strlen(dir) + 1 + n + 1);
      sprintf(full, "%s/%s", dir, e->d_name);
      if (found) {
        free(found);
        free(full);
        found = NULL;
        break;
      }
      found = full;
    }
  }
  closedir(d);
  return found;
}

/* ---------- suite 1: crypto known answers ---------- */

static void suite_crypto(void) {
  suites++;
  uint8_t abc[32];
  murmur_sha256((const uint8_t *)"abc", 3, abc);
  static const char *want_abc =
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
  char hex[65];
  for (int i = 0; i < 32; i++) {
    sprintf(hex + 2 * i, "%02x", abc[i]);
  }
  CHECK(strcmp(hex, want_abc) == 0, "sha256 abc vector");

  murmur_sha256_t s;
  murmur_sha256_init(&s);
  murmur_sha256_update(&s, (const uint8_t *)"a", 1);
  murmur_sha256_update(&s, (const uint8_t *)"bc", 2);
  uint8_t abc2[32];
  murmur_sha256_final(&s, abc2);
  CHECK(memcmp(abc, abc2, 32) == 0, "sha streaming == one-shot");

  /* RFC 5869 test case 1 (SHA-256). */
  uint8_t ikm[22], salt[13], info[10];
  memset(ikm, 0x0b, sizeof(ikm));
  for (int i = 0; i < 13; i++) {
    salt[i] = (uint8_t)i;
  }
  for (int i = 0; i < 10; i++) {
    info[i] = (uint8_t)(0xf0 + i);
  }
  uint8_t okm[42];
  CHECK(murmur_hkdf(ikm, sizeof(ikm), salt, sizeof(salt), info,
                    sizeof(info), okm, sizeof(okm)) == 0,
        "hkdf");
  static const char *want_okm =
      "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208"
      "d5b887185865";
  char okmhex[85];
  for (int i = 0; i < 42; i++) {
    sprintf(okmhex + 2 * i, "%02x", okm[i]);
  }
  CHECK(strcmp(okmhex, want_okm) == 0, "hkdf rfc5869 vector");

  uint8_t key[32], nonce[12], pt[48], ct[64], back[48];
  memset(key, 0x11, 32);
  memset(nonce, 0x22, 12);
  fill_payload(pt, sizeof(pt), 1);
  CHECK(murmur_aes256gcm_seal(key, nonce, pt, sizeof(pt),
                              (const uint8_t *)"aad", 3, ct) == 0,
        "seal");
  CHECK(murmur_aes256gcm_open(key, nonce, ct, sizeof(ct),
                              (const uint8_t *)"aad", 3, back) == 0,
        "open");
  CHECK(memcmp(pt, back, sizeof(pt)) == 0, "seal roundtrip");
  ct[7] ^= 0x80;
  CHECK(murmur_aes256gcm_open(key, nonce, ct, sizeof(ct),
                              (const uint8_t *)"aad", 3, back) == -2,
        "tamper fails");
  CHECK(murmur_aes256gcm_open(key, nonce, ct, 10, (const uint8_t *)"aad", 3,
                              back) == -1,
        "short fails closed");
}

/* ---------- suite 2: upload/verify roundtrip ---------- */

static void suite_roundtrip(void) {
  suites++;
  static const size_t sizes[] = {0, 1, 65535, 65536, 65537, 200000};
  for (size_t si = 0; si < sizeof(sizes) / sizeof(sizes[0]); si++) {
    size_t n = sizes[si];
    uint8_t key[32];
    memset(key, 0x3c, 32);
    sqlite3 *db = open_db();
    char *dir = make_tmpdir();
    murmur_node_t self = test_self();
    murmur_files_t *o = open_store(dir, key, 7, db, &self);
    CHECK(o != NULL, "open");
    if (!o) {
      sqlite3_close(db);
      free(dir);
      continue;
    }
    uint8_t *payload = malloc(n ? n : 1);
    fill_payload(payload, n, (unsigned)si);
    uint8_t digest[32];
    murmur_sha256(payload, n, digest);

    char name[64];
    snprintf(name, sizeof(name), "file-%zu", n);
    mem_reader_t r;
    memset(&r, 0, sizeof(r));
    r.p = payload;
    r.n = n;
    r.quantum = 1000;
    murmur_files_meta_t meta;
    memset(&meta, 0, sizeof(meta));
    char *detail = NULL;
    int sqlrc = 0;
    murmur_files_status_t st = murmur_files_upload_one(
        o, name, mem_read, &r, &meta, &detail, &sqlrc);
    CHECK_ST(st, MURMUR_FILES_OK, detail, "upload");
    free(detail);
    detail = NULL;
    CHECK(meta.bytes == (uint64_t)n, "meta bytes");
    CHECK(memcmp(meta.digest, digest, 32) == 0, "meta digest");
    CHECK(meta.generation == 7, "meta generation");
    CHECK(memcmp(meta.node.b, self.b, 16) == 0, "meta node");
    CHECK(!meta.deleted, "meta live");
    CHECK(meta.millis > 0, "meta millis");

    int avail = 0;
    st = murmur_files_available(o, name, &avail, &detail, &sqlrc);
    CHECK_ST(st, MURMUR_FILES_OK, detail, "available");
    CHECK(avail, "available true");
    free(detail);
    detail = NULL;

    mem_writer_t w;
    memset(&w, 0, sizeof(w));
    murmur_files_meta_t back;
    memset(&back, 0, sizeof(back));
    st = murmur_files_read(o, name, mem_write, &w, &back, &detail, &sqlrc);
    CHECK_ST(st, MURMUR_FILES_OK, detail, "read");
    free(detail);
    detail = NULL;
    CHECK(w.n == n && memcmp(w.p, payload, n) == 0, "read bytes exact");
    CHECK(memcmp(back.digest, digest, 32) == 0, "read meta");
    murmur_files_meta_free(&back);

    char *obj = find_object(dir);
    CHECK(obj != NULL, "single object file");
    /* Object name shape: <64hex>.g7.spfo */
    if (obj) {
      const char *base = strrchr(obj, '/') + 1;
      CHECK(strlen(base) == 64 + 2 + 1 + 5, "object name length");
      CHECK(strstr(base, ".g7.spfo") != NULL, "object name gen");
    }
    free(obj);
    free(w.p);
    murmur_files_meta_free(&meta);
    free(payload);
    murmur_files_close(o);
    sqlite3_close(db);
    free(dir);
  }
}

/* ---------- suite 3: validation and limits ---------- */

static void suite_limits(void) {
  suites++;
  uint8_t key[32];
  memset(key, 1, 32);
  sqlite3 *db = open_db();
  char *dir = make_tmpdir();
  murmur_node_t self = test_self();
  murmur_files_t *o = open_store(dir, key, 0, db, &self);
  CHECK(o != NULL, "open");
  char *detail = NULL;
  int sqlrc = 0;
  uint8_t one[1] = {9};

  mem_reader_t r;
  memset(&r, 0, sizeof(r));
  r.p = one;
  r.n = 1;
  murmur_files_meta_t meta;
  memset(&meta, 0, sizeof(meta));
  murmur_files_status_t st =
      murmur_files_upload_one(o, "", mem_read, &r, &meta, &detail, &sqlrc);
  CHECK_ST(st, MURMUR_FILES_INVALID, detail, "empty name");
  free(detail);
  detail = NULL;

  char *longname = malloc(4098);
  memset(longname, 'x', 4097);
  longname[4097] = 0;
  memset(&r, 0, sizeof(r));
  r.p = one;
  r.n = 1;
  st = murmur_files_upload_one(o, longname, mem_read, &r, &meta, &detail,
                               &sqlrc);
  CHECK_ST(st, MURMUR_FILES_INVALID, detail, "long name");
  free(detail);
  detail = NULL;
  free(longname);

  murmur_files_close(o);

  /* Tiny file cap. */
  murmur_files_config_t c;
  murmur_files_config_default(&c, dir, key);
  c.max_file_bytes = 10;
  murmur_files_t *o2 = NULL;
  st = murmur_files_open(&c, db, &self, &o2, &detail, &sqlrc);
  CHECK_ST(st, MURMUR_FILES_OK, detail, "open capped");
  free(detail);
  detail = NULL;
  uint8_t eleven[11];
  memset(&r, 0, sizeof(r));
  r.p = eleven;
  r.n = 11;
  st = murmur_files_upload_one(o2, "big", mem_read, &r, &meta, &detail,
                               &sqlrc);
  CHECK_ST(st, MURMUR_FILES_OVERLOADED, detail, "file cap");
  free(detail);
  detail = NULL;
  murmur_files_close(o2);

  /* Tiny staging cap: 128 (new) + 100 payload + 20 overhead > 150. */
  murmur_files_config_default(&c, dir, key);
  c.max_staging_bytes = 150;
  /* 150 < FileChunk: invalid. */
  murmur_files_t *o3 = NULL;
  st = murmur_files_open(&c, db, &self, &o3, &detail, &sqlrc);
  CHECK_ST(st, MURMUR_FILES_INVALID, detail, "staging floor");
  free(detail);
  detail = NULL;

  /* Exhaustion via reservations instead: max_staging = 64KiB. */
  murmur_files_config_default(&c, dir, key);
  c.max_staging_bytes = 64u << 10;
  st = murmur_files_open(&c, db, &self, &o3, &detail, &sqlrc);
  CHECK_ST(st, MURMUR_FILES_OK, detail, "open staging cap");
  free(detail);
  detail = NULL;
  murmur_staging_reservation_t *res = NULL;
  st = murmur_files_reserve_staging(o3, (64u << 10) - 100, &res);
  CHECK_ST(st, MURMUR_FILES_OK, detail, "reserve bulk");
  uint8_t hundred[100];
  memset(&r, 0, sizeof(r));
  r.p = hundred;
  r.n = 100;
  st = murmur_files_upload_one(o3, "s", mem_read, &r, &meta, &detail, &sqlrc);
  CHECK_ST(st, MURMUR_FILES_OVERLOADED, detail, "staging exhausted");
  free(detail);
  detail = NULL;
  murmur_files_staging_release(res);
  memset(&r, 0, sizeof(r));
  r.p = hundred;
  r.n = 100;
  st = murmur_files_upload_one(o3, "s", mem_read, &r, &meta, &detail, &sqlrc);
  CHECK_ST(st, MURMUR_FILES_OK, detail, "staging after release");
  free(detail);
  murmur_files_meta_free(&meta);
  murmur_files_close(o3);

  /* Bad config surface. */
  murmur_files_config_default(&c, dir, key);
  c.max_file_bytes = 0;
  murmur_files_t *bad = NULL;
  st = murmur_files_open(&c, db, &self, &bad, &detail, &sqlrc);
  CHECK_ST(st, MURMUR_FILES_INVALID, detail, "zero max file");
  free(detail);
  detail = NULL;
  murmur_files_config_default(&c, dir, key);
  c.concurrent_fetches = 0;
  st = murmur_files_open(&c, db, &self, &bad, &detail, &sqlrc);
  CHECK_ST(st, MURMUR_FILES_INVALID, detail, "zero fetches");
  free(detail);

  sqlite3_close(db);
  free(dir);
}

/* ---------- suite 4: download ---------- */

static void suite_download(void) {
  suites++;
  uint8_t key[32];
  memset(key, 0x55, 32);
  sqlite3 *db = open_db();
  char *dir = make_tmpdir();
  murmur_node_t self = test_self();
  murmur_files_t *o = open_store(dir, key, 0, db, &self);
  size_t n = 150000;
  uint8_t *payload = malloc(n);
  fill_payload(payload, n, 42);
  mem_reader_t r;
  memset(&r, 0, sizeof(r));
  r.p = payload;
  r.n = n;
  char *detail = NULL;
  int sqlrc = 0;
  murmur_files_meta_t meta;
  memset(&meta, 0, sizeof(meta));
  murmur_files_status_t st =
      murmur_files_upload_one(o, "dl", mem_read, &r, &meta, &detail, &sqlrc);
  CHECK_ST(st, MURMUR_FILES_OK, detail, "upload");
  free(detail);
  detail = NULL;
  murmur_files_meta_free(&meta);

  murmur_file_download_t *d = NULL;
  st = murmur_files_download(o, "dl", &d, &detail, &sqlrc);
  CHECK_ST(st, MURMUR_FILES_OK, detail, "download");
  free(detail);
  detail = NULL;
  CHECK(d && murmur_files_download_bytes(d) == (uint64_t)n, "download bytes");

  uint8_t *reassembled = malloc(n);
  size_t got = 0;
  uint64_t expect_off = 0;
  int done = 0;
  /* Odd limits to cross chunk boundaries. */
  static const size_t limits[] = {1, 7, 4096, 65536, 100000};
  size_t li = 0;
  while (!done) {
    size_t limit = limits[li++ % (sizeof(limits) / sizeof(limits[0]))];
    uint64_t start = 0;
    size_t m = 0;
    st = murmur_files_download_next(d, limit, &start, reassembled + got, &m,
                                    &done, &detail);
    CHECK_ST(st, MURMUR_FILES_OK, detail, "next");
    free(detail);
    detail = NULL;
    CHECK(start == expect_off, "next offset");
    expect_off += m;
    got += m;
    if (failures) {
      break;
    }
  }
  CHECK(got == n, "download length");
  CHECK(memcmp(reassembled, payload, n) == 0, "download exact");
  free(reassembled);
  murmur_files_download_close(d);

  /* Missing file. */
  d = NULL;
  st = murmur_files_download(o, "nope", &d, &detail, &sqlrc);
  CHECK_ST(st, MURMUR_FILES_UNAVAILABLE, detail, "missing download");
  free(detail);
  detail = NULL;

  /* Limit errors. */
  st = murmur_files_download(o, "dl", &d, &detail, &sqlrc);
  CHECK_ST(st, MURMUR_FILES_OK, detail, "re-download");
  free(detail);
  detail = NULL;
  uint64_t start = 0;
  size_t m = 0;
  uint8_t one[8];
  st = murmur_files_download_next(d, 0, &start, one, &m, &done, &detail);
  CHECK_ST(st, MURMUR_FILES_INVALID, detail, "zero limit");
  free(detail);
  detail = NULL;
  st = murmur_files_download_next(d, (1u << 20) + 1, &start, one, &m, &done,
                                  &detail);
  CHECK_ST(st, MURMUR_FILES_INVALID, detail, "huge limit");
  free(detail);
  murmur_files_download_close(d);

  free(payload);
  murmur_files_close(o);
  sqlite3_close(db);
  free(dir);
}

/* ---------- suite 5: stream plain chunks ---------- */

typedef struct {
  const uint8_t *expect;
  size_t n;
  uint64_t skip;
  uint64_t next_off;
  size_t chunk_size;
  int calls;
  int fail_after; /* abort after this many calls; -1 never */
} emit_ctx_t;

static murmur_files_status_t test_emit(void *ctx, uint64_t off,
                                       const uint8_t *buf, size_t n,
                                       char **detail_out) {
  emit_ctx_t *e = ctx;
  if (e->fail_after >= 0 && e->calls >= e->fail_after) {
    if (detail_out) {
      *detail_out = strdup("boom");
    }
    return MURMUR_FILES_IO;
  }
  CHECK(off == e->next_off, "emit offset");
  CHECK(off + n <= e->n, "emit bounds");
  if (off + n <= e->n) {
    CHECK(memcmp(buf, e->expect + off, n) == 0, "emit bytes");
  }
  CHECK(n <= e->chunk_size, "emit size");
  e->next_off = off + n;
  e->calls++;
  return MURMUR_FILES_OK;
}

static void suite_stream(void) {
  suites++;
  uint8_t key[32];
  memset(key, 0x66, 32);
  sqlite3 *db = open_db();
  char *dir = make_tmpdir();
  murmur_node_t self = test_self();
  murmur_files_t *o = open_store(dir, key, 0, db, &self);
  size_t n = 100000;
  uint8_t *payload = malloc(n);
  fill_payload(payload, n, 7);
  mem_reader_t r;
  memset(&r, 0, sizeof(r));
  r.p = payload;
  r.n = n;
  char *detail = NULL;
  int sqlrc = 0;
  murmur_files_meta_t meta;
  memset(&meta, 0, sizeof(meta));
  murmur_files_status_t st =
      murmur_files_upload_one(o, "s", mem_read, &r, &meta, &detail, &sqlrc);
  CHECK_ST(st, MURMUR_FILES_OK, detail, "upload");
  free(detail);
  detail = NULL;
  murmur_files_meta_free(&meta);

  static const uint64_t skips[] = {0, 1, 65536, 99999, 100000};
  static const size_t chunks[] = {1, 1000, 65536};
  for (size_t si = 0; si < sizeof(skips) / sizeof(skips[0]); si++) {
    for (size_t ci = 0; ci < sizeof(chunks) / sizeof(chunks[0]); ci++) {
      emit_ctx_t e;
      memset(&e, 0, sizeof(e));
      e.expect = payload;
      e.n = n;
      e.skip = skips[si];
      e.next_off = skips[si];
      e.chunk_size = chunks[ci];
      e.fail_after = -1;
      uint64_t total = 0;
      st = murmur_files_stream_plain_chunks(o, "s", skips[si], chunks[ci],
                                            test_emit, &e, NULL, &total,
                                            &detail, &sqlrc);
      CHECK_ST(st, MURMUR_FILES_OK, detail, "stream");
      free(detail);
      detail = NULL;
      CHECK(total == (uint64_t)n, "stream total");
      uint64_t want_calls =
          (n > skips[si]) ? (n - skips[si] + chunks[ci] - 1) / chunks[ci] : 0;
      CHECK((uint64_t)e.calls == want_calls, "stream calls");
    }
  }

  /* Emit abort propagates the emitter's status. */
  emit_ctx_t e;
  memset(&e, 0, sizeof(e));
  e.expect = payload;
  e.n = n;
  e.chunk_size = 1000;
  e.fail_after = 2;
  st = murmur_files_stream_plain_chunks(o, "s", 0, 1000, test_emit, &e, NULL,
                                        NULL, &detail, &sqlrc);
  CHECK(detail && strcmp(detail, "boom") == 0, "emit detail");
  CHECK_ST(st, MURMUR_FILES_IO, detail, "emit abort");

  st = murmur_files_stream_plain_chunks(o, "s", 0, 0, test_emit, &e, NULL,
                                        NULL, &detail, &sqlrc);
  CHECK_ST(st, MURMUR_FILES_INVALID, detail, "zero chunk");
  free(detail);
  detail = NULL;
  st = murmur_files_stream_plain_chunks(o, "nope", 0, 100, test_emit, &e,
                                        NULL, NULL, &detail, &sqlrc);
  CHECK_ST(st, MURMUR_FILES_UNAVAILABLE, detail, "missing stream");
  free(detail);

  free(payload);
  murmur_files_close(o);
  sqlite3_close(db);
  free(dir);
}

/* ---------- suite 6: corruption ---------- */

static uint8_t *slurp(const char *path, size_t *n_out) {
  FILE *f = fopen(path, "rb");
  if (!f) {
    return NULL;
  }
  fseek(f, 0, SEEK_END);
  long n = ftell(f);
  fseek(f, 0, SEEK_SET);
  uint8_t *b = malloc((size_t)n);
  if (fread(b, 1, (size_t)n, f) != (size_t)n) {
    fclose(f);
    free(b);
    return NULL;
  }
  fclose(f);
  *n_out = (size_t)n;
  return b;
}

static void suite_corrupt(void) {
  suites++;
  uint8_t key[32];
  memset(key, 0x77, 32);
  sqlite3 *db = open_db();
  char *dir = make_tmpdir();
  murmur_node_t self = test_self();
  murmur_files_t *o = open_store(dir, key, 3, db, &self);
  size_t n = 70000;
  uint8_t *payload = malloc(n);
  fill_payload(payload, n, 9);
  mem_reader_t r;
  memset(&r, 0, sizeof(r));
  r.p = payload;
  r.n = n;
  char *detail = NULL;
  int sqlrc = 0;
  murmur_files_meta_t meta;
  memset(&meta, 0, sizeof(meta));
  murmur_files_status_t st =
      murmur_files_upload_one(o, "c", mem_read, &r, &meta, &detail, &sqlrc);
  CHECK_ST(st, MURMUR_FILES_OK, detail, "upload");
  free(detail);
  detail = NULL;
  char *obj = find_object(dir);
  CHECK(obj != NULL, "object");
  size_t on = 0;
  uint8_t *orig = slurp(obj, &on);
  CHECK(orig != NULL && on > 100, "slurp");

  /* Each case: mutate a copy, expect AUTH (or UNAVAILABLE for
   * missing). */
  struct {
    const char *name;
    size_t off;
    size_t extra; /* appended bytes */
    size_t trunc; /* truncate to */
  } cases[] = {
      {"magic", 0, 0, 0},
      {"generation", 15, 0, 0},
      {"salt", 20, 0, 0},
      {"chunk-len", 41, 0, 0},
      {"ciphertext", 60, 0, 0},
      {"trailing", 0, 1, 0},
      {"truncated", 0, 0, 50},
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    char staged[1024];
    snprintf(staged, sizeof(staged), "%s/mut-%zu", dir, i);
    FILE *f = fopen(staged, "wb");
    size_t wn = on;
    if (cases[i].trunc) {
      wn = cases[i].trunc;
    }
    uint8_t *mut = malloc(on + cases[i].extra);
    memcpy(mut, orig, on);
    if (cases[i].extra) {
      mut[on] = 0xAA;
      wn = on + cases[i].extra;
    } else if (!cases[i].trunc) {
      mut[cases[i].off] ^= 0xFF;
    }
    fwrite(mut, 1, wn, f);
    fclose(f);
    free(mut);
    st = murmur_files_verify(o, staged, &meta, NULL, NULL, &detail, &sqlrc);
    if (st != MURMUR_FILES_AUTH) {
      printf("FAIL corrupt %s: want auth got %s (%s)\n", cases[i].name,
             murmur_files_status_str(st), detail ? detail : "-");
      failures++;
    }
    free(detail);
    detail = NULL;
    unlink(staged);
  }
  /* Wrong metadata digest. */
  murmur_files_meta_t wrong = meta;
  wrong.digest[0] ^= 1;
  st = murmur_files_verify(o, obj, &wrong, NULL, NULL, &detail, &sqlrc);
  CHECK_ST(st, MURMUR_FILES_AUTH, detail, "wrong digest");
  free(detail);
  detail = NULL;
  /* Missing path. */
  st = murmur_files_verify(o, "/tmp/murmur-files-nope", &meta, NULL, NULL,
                           &detail, &sqlrc);
  CHECK_ST(st, MURMUR_FILES_UNAVAILABLE, detail, "missing verify");
  free(detail);

  free(orig);
  free(obj);
  free(payload);
  murmur_files_meta_free(&meta);
  murmur_files_close(o);
  sqlite3_close(db);
  free(dir);
}

/* ---------- suite 7: list and delete ---------- */

static void suite_list_delete(void) {
  suites++;
  uint8_t key[32];
  memset(key, 0x88, 32);
  sqlite3 *db = open_db();
  char *dir = make_tmpdir();
  murmur_node_t self = test_self();
  murmur_files_t *o = open_store(dir, key, 0, db, &self);
  char *detail = NULL;
  int sqlrc = 0;
  const char *names[] = {"charlie", "alpha", "bravo"};
  for (size_t i = 0; i < 3; i++) {
    uint8_t p[10 + i];
    fill_payload(p, sizeof(p), (unsigned)i);
    mem_reader_t r;
    memset(&r, 0, sizeof(r));
    r.p = p;
    r.n = sizeof(p);
    murmur_files_meta_t m;
    memset(&m, 0, sizeof(m));
    murmur_files_status_t st = murmur_files_upload_one(
        o, names[i], mem_read, &r, &m, &detail, &sqlrc);
    CHECK_ST(st, MURMUR_FILES_OK, detail, "upload");
    free(detail);
    detail = NULL;
    murmur_files_meta_free(&m);
  }
  murmur_files_meta_t *ms = NULL;
  size_t nms = 0;
  murmur_files_status_t st =
      murmur_files_list(o, &ms, &nms, &detail, &sqlrc);
  CHECK_ST(st, MURMUR_FILES_OK, detail, "list");
  free(detail);
  detail = NULL;
  CHECK(nms == 3, "list count");
  if (nms == 3) {
    CHECK(strcmp(ms[0].name, "alpha") == 0, "list sorted 0");
    CHECK(strcmp(ms[1].name, "bravo") == 0, "list sorted 1");
    CHECK(strcmp(ms[2].name, "charlie") == 0, "list sorted 2");
  }
  murmur_files_meta_list_free(ms, nms);

  /* Bounded: tiny budget trips, generous passes. */
  st = murmur_files_list_bounded(o, 10, &ms, &nms, &detail, &sqlrc);
  CHECK_ST(st, MURMUR_FILES_OVERLOADED, detail, "bounded trip");
  free(detail);
  detail = NULL;
  st = murmur_files_list_bounded(o, 1u << 20, &ms, &nms, &detail, &sqlrc);
  CHECK_ST(st, MURMUR_FILES_OK, detail, "bounded pass");
  free(detail);
  detail = NULL;
  CHECK(nms == 3, "bounded count");
  murmur_files_meta_list_free(ms, nms);

  st = murmur_files_delete(o, "bravo", &detail, &sqlrc);
  CHECK_ST(st, MURMUR_FILES_OK, detail, "delete");
  free(detail);
  detail = NULL;
  st = murmur_files_list(o, &ms, &nms, &detail, &sqlrc);
  CHECK_ST(st, MURMUR_FILES_OK, detail, "list after delete");
  free(detail);
  detail = NULL;
  CHECK(nms == 2, "list count after delete");
  murmur_files_meta_list_free(ms, nms);
  murmur_files_meta_t m;
  memset(&m, 0, sizeof(m));
  int found = 0;
  st = murmur_files_metadata(o, "bravo", &m, &found, &detail, &sqlrc);
  CHECK_ST(st, MURMUR_FILES_OK, detail, "tombstone read");
  free(detail);
  detail = NULL;
  CHECK(found && m.deleted, "tombstone flag");
  murmur_files_meta_free(&m);
  int avail = 1;
  st = murmur_files_available(o, "bravo", &avail, &detail, &sqlrc);
  CHECK_ST(st, MURMUR_FILES_OK, detail, "avail tombstone");
  free(detail);
  detail = NULL;
  CHECK(!avail, "tombstone unavailable");
  mem_writer_t w;
  memset(&w, 0, sizeof(w));
  st = murmur_files_read(o, "bravo", mem_write, &w, NULL, &detail, &sqlrc);
  CHECK_ST(st, MURMUR_FILES_UNAVAILABLE, detail, "read tombstone");
  free(detail);
  free(w.p);
  st = murmur_files_delete(o, "missing", &detail, &sqlrc);
  CHECK_ST(st, MURMUR_FILES_OK, detail, "delete missing");
  free(detail);

  murmur_files_close(o);
  sqlite3_close(db);
  free(dir);
}

/* ---------- suite 8: availability ---------- */

static void suite_availability(void) {
  suites++;
  uint8_t key[32];
  memset(key, 0x99, 32);
  sqlite3 *db = open_db();
  char *dir = make_tmpdir();
  murmur_node_t self = test_self();
  murmur_files_t *o = open_store(dir, key, 0, db, &self);
  uint8_t p[32];
  fill_payload(p, sizeof(p), 3);
  mem_reader_t r;
  memset(&r, 0, sizeof(r));
  r.p = p;
  r.n = sizeof(p);
  char *detail = NULL;
  int sqlrc = 0;
  murmur_files_meta_t meta;
  memset(&meta, 0, sizeof(meta));
  murmur_files_status_t st =
      murmur_files_upload_one(o, "a", mem_read, &r, &meta, &detail, &sqlrc);
  CHECK_ST(st, MURMUR_FILES_OK, detail, "upload");
  free(detail);
  detail = NULL;

  murmur_file_avail_t av;
  st = murmur_files_availability(o, "a", &av, &detail, &sqlrc);
  CHECK_ST(st, MURMUR_FILES_OK, detail, "avail local");
  free(detail);
  detail = NULL;
  CHECK(av.kind == MURMUR_FILE_LOCAL, "local kind");
  murmur_file_avail_free(&av);

  /* Drop the object: unknown peers -> unavailable. */
  char *obj = find_object(dir);
  unlink(obj);
  free(obj);
  st = murmur_files_availability(o, "a", &av, &detail, &sqlrc);
  CHECK_ST(st, MURMUR_FILES_OK, detail, "avail gone");
  free(detail);
  detail = NULL;
  CHECK(av.kind == MURMUR_FILE_UNAVAILABLE, "gone kind");
  murmur_file_avail_free(&av);

  murmur_node_t peer;
  memset(peer.b, 0x01, 16);
  st = murmur_files_record_peer(o, meta.digest, meta.generation, &peer, 1,
                                &detail, &sqlrc);
  CHECK_ST(st, MURMUR_FILES_OK, detail, "record peer");
  free(detail);
  detail = NULL;
  murmur_node_t peer2;
  memset(peer2.b, 0x02, 16);
  st = murmur_files_record_peer(o, meta.digest, meta.generation, &peer2, 1,
                                &detail, &sqlrc);
  CHECK_ST(st, MURMUR_FILES_OK, detail, "record peer2");
  free(detail);
  detail = NULL;
  st = murmur_files_availability(o, "a", &av, &detail, &sqlrc);
  CHECK_ST(st, MURMUR_FILES_OK, detail, "avail remote");
  free(detail);
  detail = NULL;
  CHECK(av.kind == MURMUR_FILE_REMOTE, "remote kind");
  CHECK(av.n_remote == 2, "remote count");
  if (av.n_remote == 2) {
    CHECK(memcmp(av.remote[0].b, peer.b, 16) == 0, "remote sorted 0");
    CHECK(memcmp(av.remote[1].b, peer2.b, 16) == 0, "remote sorted 1");
  }
  murmur_file_avail_free(&av);

  st = murmur_files_record_peer(o, meta.digest, meta.generation, &peer, 0,
                                &detail, &sqlrc);
  CHECK_ST(st, MURMUR_FILES_OK, detail, "unrecord");
  free(detail);
  detail = NULL;
  st = murmur_files_record_peer(o, meta.digest, meta.generation, &peer2, 0,
                                &detail, &sqlrc);
  CHECK_ST(st, MURMUR_FILES_OK, detail, "unrecord2");
  free(detail);
  detail = NULL;
  st = murmur_files_availability(o, "a", &av, &detail, &sqlrc);
  CHECK_ST(st, MURMUR_FILES_OK, detail, "avail after unrecord");
  free(detail);
  detail = NULL;
  CHECK(av.kind == MURMUR_FILE_UNAVAILABLE, "unrecorded kind");
  murmur_file_avail_free(&av);

  st = murmur_files_availability(o, "nope", &av, &detail, &sqlrc);
  CHECK_ST(st, MURMUR_FILES_OK, detail, "avail unknown");
  free(detail);
  CHECK(av.kind == MURMUR_FILE_UNAVAILABLE, "unknown kind");
  murmur_file_avail_free(&av);

  murmur_files_meta_free(&meta);
  murmur_files_close(o);
  sqlite3_close(db);
  free(dir);
}

/* ---------- suite 9: publish fetched ---------- */

static void suite_publish(void) {
  suites++;
  uint8_t key[32];
  memset(key, 0xaa, 32);
  sqlite3 *db = open_db();
  char *dir = make_tmpdir();
  murmur_node_t self = test_self();
  murmur_files_t *o = open_store(dir, key, 0, db, &self);
  uint8_t p[5000];
  fill_payload(p, sizeof(p), 11);
  mem_reader_t r;
  memset(&r, 0, sizeof(r));
  r.p = p;
  r.n = sizeof(p);
  char *detail = NULL;
  int sqlrc = 0;
  murmur_files_meta_t meta;
  memset(&meta, 0, sizeof(meta));
  murmur_files_status_t st =
      murmur_files_upload_one(o, "p", mem_read, &r, &meta, &detail, &sqlrc);
  CHECK_ST(st, MURMUR_FILES_OK, detail, "upload");
  free(detail);
  detail = NULL;
  char *obj = find_object(dir);
  size_t on = 0;
  uint8_t *bytes = slurp(obj, &on);

  /* Stage a copy elsewhere, delete the object, publish the stage. */
  char staged[1024];
  snprintf(staged, sizeof(staged), "%s/staged.spfo", dir);
  FILE *f = fopen(staged, "wb");
  fwrite(bytes, 1, on, f);
  fclose(f);
  unlink(obj);
  int avail = 1;
  st = murmur_files_available(o, "p", &avail, &detail, &sqlrc);
  CHECK_ST(st, MURMUR_FILES_OK, detail, "avail before publish");
  free(detail);
  detail = NULL;
  CHECK(!avail, "object gone");
  st = murmur_files_publish_fetched(o, staged, &meta, &detail, &sqlrc);
  CHECK_ST(st, MURMUR_FILES_OK, detail, "publish");
  free(detail);
  detail = NULL;
  st = murmur_files_available(o, "p", &avail, &detail, &sqlrc);
  CHECK_ST(st, MURMUR_FILES_OK, detail, "avail after publish");
  free(detail);
  detail = NULL;
  CHECK(avail, "published present");

  /* Corrupt staged container is rejected. */
  snprintf(staged, sizeof(staged), "%s/staged2.spfo", dir);
  f = fopen(staged, "wb");
  bytes[50] ^= 1;
  fwrite(bytes, 1, on, f);
  fclose(f);
  st = murmur_files_publish_fetched(o, staged, &meta, &detail, &sqlrc);
  CHECK_ST(st, MURMUR_FILES_AUTH, detail, "publish corrupt");
  free(detail);
  unlink(staged);

  free(bytes);
  free(obj);
  murmur_files_meta_free(&meta);
  murmur_files_close(o);
  sqlite3_close(db);
  free(dir);
}

/* ---------- suite 10: rotation ---------- */

static void suite_rotate(void) {
  suites++;
  uint8_t k0[32], k1[32];
  memset(k0, 0x10, 32);
  memset(k1, 0x11, 32);
  sqlite3 *db = open_db();
  char *dir = make_tmpdir();
  murmur_node_t self = test_self();
  murmur_files_t *o = open_store(dir, k0, 0, db, &self);
  uint8_t p[9000];
  fill_payload(p, sizeof(p), 13);
  mem_reader_t r;
  memset(&r, 0, sizeof(r));
  r.p = p;
  r.n = sizeof(p);
  char *detail = NULL;
  int sqlrc = 0;
  murmur_files_meta_t meta;
  memset(&meta, 0, sizeof(meta));
  murmur_files_status_t st =
      murmur_files_upload_one(o, "rot", mem_read, &r, &meta, &detail, &sqlrc);
  CHECK_ST(st, MURMUR_FILES_OK, detail, "upload gen0");
  free(detail);
  detail = NULL;
  uint8_t digest[32];
  memcpy(digest, meta.digest, 32);
  murmur_files_meta_free(&meta);
  char *obj0 = find_object(dir);
  CHECK(obj0 && strstr(obj0, ".g0.spfo") != NULL, "gen0 object");
  murmur_files_close(o);

  /* Reopen at gen1 without the previous key: refused. */
  murmur_files_config_t c;
  murmur_files_config_default(&c, dir, k1);
  c.generation = 1;
  murmur_files_t *bad = NULL;
  st = murmur_files_open(&c, db, &self, &bad, &detail, &sqlrc);
  CHECK_ST(st, MURMUR_FILES_INVALID, detail, "no prevkey refused");
  free(detail);
  detail = NULL;

  murmur_files_config_default(&c, dir, k1);
  c.generation = 1;
  uint8_t prev[32];
  memcpy(prev, k0, 32);
  c.previous_key = (const uint8_t(*)[32])prev;
  murmur_files_t *o1 = NULL;
  st = murmur_files_open(&c, db, &self, &o1, &detail, &sqlrc);
  CHECK_ST(st, MURMUR_FILES_OK, detail, "open gen1");
  free(detail);
  detail = NULL;

  /* Old object still readable via the previous key. */
  mem_writer_t w;
  memset(&w, 0, sizeof(w));
  st = murmur_files_read(o1, "rot", mem_write, &w, NULL, &detail, &sqlrc);
  CHECK_ST(st, MURMUR_FILES_OK, detail, "read via prevkey");
  free(detail);
  detail = NULL;
  CHECK(w.n == sizeof(p) && memcmp(w.p, p, sizeof(p)) == 0, "prevkey bytes");
  free(w.p);

  murmur_file_keyrot_t ks;
  st = murmur_files_key_rotation_status(o1, &ks, &detail, &sqlrc);
  CHECK_ST(st, MURMUR_FILES_OK, detail, "rotstatus before");
  free(detail);
  detail = NULL;
  CHECK(ks.current_generation == 1, "rot gen");
  CHECK(ks.old_generation_objects == 1, "rot old objects");
  CHECK(!ks.previous_key_unused_locally, "prevkey in use");

  size_t rotated = 0;
  st = murmur_files_rotate_keys(o1, 10, &rotated, &detail, &sqlrc);
  CHECK_ST(st, MURMUR_FILES_OK, detail, "rotate");
  free(detail);
  detail = NULL;
  CHECK(rotated == 1, "rotated count");
  murmur_files_meta_t m;
  memset(&m, 0, sizeof(m));
  int found = 0;
  st = murmur_files_metadata(o1, "rot", &m, &found, &detail, &sqlrc);
  CHECK_ST(st, MURMUR_FILES_OK, detail, "meta after rotate");
  free(detail);
  detail = NULL;
  CHECK(found && m.generation == 1, "meta gen1");
  CHECK(memcmp(m.digest, digest, 32) == 0, "digest stable");
  murmur_files_meta_free(&m);

  /* New object exists; collect reaps the orphaned gen0 object. */
  char *obj1 = find_object(dir);
  CHECK(obj1 == NULL, "two objects before collect");
  free(obj1);
  size_t removed = 0;
  st = murmur_files_collect(o1, 0, &removed, &detail, &sqlrc);
  CHECK_ST(st, MURMUR_FILES_OK, detail, "collect");
  free(detail);
  detail = NULL;
  CHECK(removed == 1, "collect removed old");
  CHECK(!file_present(obj0), "old object gone");
  char *obj = find_object(dir);
  CHECK(obj && strstr(obj, ".g1.spfo") != NULL, "gen1 object");
  free(obj);
  free(obj0);

  st = murmur_files_key_rotation_status(o1, &ks, &detail, &sqlrc);
  CHECK_ST(st, MURMUR_FILES_OK, detail, "rotstatus after");
  free(detail);
  CHECK(ks.previous_key_unused_locally, "prevkey unused");

  /* Second rotate is a no-op. */
  st = murmur_files_rotate_keys(o1, 10, &rotated, &detail, &sqlrc);
  CHECK_ST(st, MURMUR_FILES_OK, detail, "rotate again");
  free(detail);
  CHECK(rotated == 0, "nothing to rotate");

  murmur_files_close(o1);
  sqlite3_close(db);
  free(dir);
}

/* ---------- suite 11: collect and staging ---------- */

static void plant(const char *path, const char *data) {
  FILE *f = fopen(path, "wb");
  fwrite(data, 1, strlen(data), f);
  fclose(f);
}

static void suite_collect(void) {
  suites++;
  uint8_t key[32];
  memset(key, 0xbb, 32);
  sqlite3 *db = open_db();
  char *dir = make_tmpdir();
  murmur_node_t self = test_self();
  murmur_files_t *o = open_store(dir, key, 0, db, &self);
  char *detail = NULL;
  int sqlrc = 0;

  /* Live file (fresh object, kept under a huge grace). */
  uint8_t p[64];
  fill_payload(p, sizeof(p), 1);
  mem_reader_t r;
  memset(&r, 0, sizeof(r));
  r.p = p;
  r.n = sizeof(p);
  murmur_files_meta_t meta;
  memset(&meta, 0, sizeof(meta));
  murmur_files_status_t st =
      murmur_files_upload_one(o, "live", mem_read, &r, &meta, &detail,
                              &sqlrc);
  CHECK_ST(st, MURMUR_FILES_OK, detail, "upload live");
  free(detail);
  detail = NULL;
  murmur_files_meta_free(&meta);
  char *live_obj = find_object(dir);

  /* Orphan object (valid name, unreferenced). */
  char orphan[1024];
  snprintf(orphan, sizeof(orphan), "%s/%064x.g0.spfo", dir, 0xdead);
  /* %064x of an int won't fill 64 chars; build manually. */
  char orphex[65];
  memset(orphex, 'd', 64);
  orphex[64] = 0;
  snprintf(orphan, sizeof(orphan), "%s/%s.g0.spfo", dir, orphex);
  plant(orphan, "junk");

  char up[1024];
  snprintf(up, sizeof(up), "%s/.upload-stale", dir);
  plant(up, "junk");

  char staging[1024];
  snprintf(staging, sizeof(staging), "%s/staging", dir);
  mkdir(staging, 0700);
  char part[1024], lone[1024], keep[1024];
  snprintf(part, sizeof(part), "%s/stale.part", staging);
  snprintf(lone, sizeof(lone), "%s/lone.identity", staging);
  snprintf(keep, sizeof(keep), "%s/keep.part", staging);
  plant(part, "junk");
  plant(lone, "junk");
  plant(keep, "junk");
  murmur_staged_transfer_t *t = murmur_files_protect_staging(o, keep);
  CHECK(t != NULL, "protect");

  size_t removed = 0;
  st = murmur_files_collect(o, 0, &removed, &detail, &sqlrc);
  CHECK_ST(st, MURMUR_FILES_OK, detail, "collect");
  free(detail);
  detail = NULL;
  CHECK(removed == 4, "collect count");
  CHECK(!file_present(orphan), "orphan gone");
  CHECK(!file_present(up), "upload temp gone");
  CHECK(!file_present(part), "stale part gone");
  CHECK(!file_present(lone), "lone sidecar gone");
  CHECK(file_present(keep), "protected kept");
  CHECK(file_present(live_obj), "live kept");
  murmur_files_staged_release(t);
  /* Released protection: reapable now. */
  st = murmur_files_collect(o, 0, &removed, &detail, &sqlrc);
  CHECK_ST(st, MURMUR_FILES_OK, detail, "collect2");
  free(detail);
  CHECK(removed == 1, "released reaped");
  CHECK(!file_present(keep), "released gone");

  /* Huge grace keeps a fresh orphan. */
  plant(orphan, "junk");
  st = murmur_files_collect(o, ~0ull, &removed, &detail, &sqlrc);
  CHECK_ST(st, MURMUR_FILES_OK, detail, "collect grace");
  free(detail);
  CHECK(removed == 0, "grace keeps");
  CHECK(file_present(orphan), "orphan kept");
  CHECK(file_present(live_obj), "live kept2");

  free(live_obj);
  murmur_files_close(o);
  sqlite3_close(db);
  free(dir);
}

/* ---------- suite 12: reconcile and reap ---------- */

static void suite_reconcile(void) {
  suites++;
  uint8_t key[32];
  memset(key, 0xcc, 32);
  sqlite3 *db = open_db();
  char *dir = make_tmpdir();
  murmur_node_t self = test_self();
  char staging[1024];
  snprintf(staging, sizeof(staging), "%s/staging", dir);
  mkdir(dir, 0700);
  mkdir(staging, 0700);
  /* Lone sidecar, part without sidecar: both dropped at open. */
  char lone[1024], part[1024];
  snprintf(lone, sizeof(lone), "%s/lone.identity", staging);
  snprintf(part, sizeof(part), "%s/solo.part", staging);
  plant(lone, "x");
  plant(part, "x");
  /* Resumable pair: kept. */
  char rp[1024], ri[1024];
  snprintf(rp, sizeof(rp), "%s/0011-abcd.g0.part", staging);
  snprintf(ri, sizeof(ri), "%s/0011-abcd.g0.identity", staging);
  plant(rp, "x");
  plant(ri, "x");

  murmur_files_t *o = open_store(dir, key, 0, db, &self);
  CHECK(o != NULL, "open");
  CHECK(!file_present(lone), "lone dropped");
  CHECK(!file_present(part), "solo dropped");
  CHECK(file_present(rp), "pair kept");
  CHECK(file_present(ri), "sidecar kept");

  /* Published pair is reaped by the orphan sweep. */
  uint8_t p[16];
  fill_payload(p, sizeof(p), 5);
  mem_reader_t r;
  memset(&r, 0, sizeof(r));
  r.p = p;
  r.n = sizeof(p);
  char *detail = NULL;
  int sqlrc = 0;
  murmur_files_meta_t meta;
  memset(&meta, 0, sizeof(meta));
  murmur_files_status_t st =
      murmur_files_upload_one(o, "q", mem_read, &r, &meta, &detail, &sqlrc);
  CHECK_ST(st, MURMUR_FILES_OK, detail, "upload");
  free(detail);
  detail = NULL;
  char dhex[65];
  for (int i = 0; i < 32; i++) {
    sprintf(dhex + 2 * i, "%02x", meta.digest[i]);
  }
  char pp[2048], pi[2048];
  snprintf(pp, sizeof(pp), "%s/00112233445566778899aabbccddeeff-%s.g%llu.part",
           staging, dhex, (unsigned long long)meta.generation);
  snprintf(pi, sizeof(pi), "%s/00112233445566778899aabbccddeeff-%s.g%llu.identity",
           staging, dhex, (unsigned long long)meta.generation);
  plant(pp, "x");
  plant(pi, "x");
  murmur_files_meta_free(&meta);
  st = murmur_files_reap_staging_orphans(o, &detail);
  CHECK_ST(st, MURMUR_FILES_OK, detail, "reap");
  free(detail);
  CHECK(!file_present(pp), "published part reaped");
  CHECK(!file_present(pi), "published sidecar reaped");
  CHECK(file_present(rp), "resumable kept");

  /* Protected published pair survives the reap. */
  plant(pp, "x");
  plant(pi, "x");
  murmur_staged_transfer_t *t = murmur_files_protect_staging(o, pp);
  st = murmur_files_reap_staging_orphans(o, &detail);
  CHECK_ST(st, MURMUR_FILES_OK, detail, "reap protected");
  free(detail);
  CHECK(file_present(pp), "protected part kept");
  CHECK(file_present(pi), "protected sidecar kept");
  murmur_files_staged_release(t);

  murmur_files_close(o);
  sqlite3_close(db);
  free(dir);
}

/* ---------- suite 13: multipart upload ---------- */

static void suite_multipart(void) {
  suites++;
  uint8_t key[32];
  memset(key, 0xdd, 32);
  sqlite3 *db = open_db();
  char *dir = make_tmpdir();
  murmur_node_t self = test_self();
  murmur_files_t *o = open_store(dir, key, 0, db, &self);
  char *detail = NULL;
  int sqlrc = 0;
  size_t n = 70000;
  uint8_t *payload = malloc(n);
  fill_payload(payload, n, 21);

  murmur_file_upload_t *u = NULL;
  murmur_files_status_t st =
      murmur_files_begin_upload(o, "mp", &u, &detail, &sqlrc);
  CHECK_ST(st, MURMUR_FILES_OK, detail, "begin");
  free(detail);
  detail = NULL;
  /* Odd-sized appends. */
  size_t off = 0;
  while (off < n) {
    size_t take = (off * 7919 % 5000) + 1;
    if (take > n - off) {
      take = n - off;
    }
    st = murmur_files_upload_append(u, payload + off, take, &detail);
    if (st != MURMUR_FILES_OK) {
      break;
    }
    off += take;
  }
  CHECK_ST(st, MURMUR_FILES_OK, detail, "append");
  free(detail);
  detail = NULL;
  murmur_files_meta_t meta;
  memset(&meta, 0, sizeof(meta));
  st = murmur_files_finish_upload(o, u, &meta, &detail, &sqlrc);
  CHECK_ST(st, MURMUR_FILES_OK, detail, "finish");
  free(detail);
  detail = NULL;
  CHECK(meta.bytes == (uint64_t)n, "mp bytes");
  uint8_t digest[32];
  murmur_sha256(payload, n, digest);
  CHECK(memcmp(meta.digest, digest, 32) == 0, "mp digest");
  murmur_files_meta_free(&meta);
  mem_writer_t w;
  memset(&w, 0, sizeof(w));
  st = murmur_files_read(o, "mp", mem_write, &w, NULL, &detail, &sqlrc);
  CHECK_ST(st, MURMUR_FILES_OK, detail, "read mp");
  free(detail);
  detail = NULL;
  CHECK(w.n == n && memcmp(w.p, payload, n) == 0, "mp exact");
  free(w.p);

  /* Abort removes the temp. */
  st = murmur_files_begin_upload(o, "abortme", &u, &detail, &sqlrc);
  CHECK_ST(st, MURMUR_FILES_OK, detail, "begin abort");
  free(detail);
  detail = NULL;
  st = murmur_files_upload_append(u, payload, 100, &detail);
  CHECK_ST(st, MURMUR_FILES_OK, detail, "append abort");
  free(detail);
  murmur_files_upload_abort(u);
  int found = 0;
  murmur_files_meta_t m;
  memset(&m, 0, sizeof(m));
  st = murmur_files_metadata(o, "abortme", &m, &found, &detail, &sqlrc);
  CHECK_ST(st, MURMUR_FILES_OK, detail, "aborted meta");
  free(detail);
  CHECK(!found, "aborted absent");
  DIR *d = opendir(dir);
  struct dirent *e;
  int temps = 0;
  while ((e = readdir(d)) != NULL) {
    if (strncmp(e->d_name, ".upload-", 8) == 0) {
      temps++;
    }
  }
  closedir(d);
  CHECK(temps == 0, "no upload temps");

  /* Cross-store finish rejected. */
  char *dir2 = make_tmpdir();
  murmur_files_t *o2 = open_store(dir2, key, 0, db, &self);
  st = murmur_files_begin_upload(o, "cross", &u, &detail, &sqlrc);
  CHECK_ST(st, MURMUR_FILES_OK, detail, "begin cross");
  free(detail);
  detail = NULL;
  st = murmur_files_finish_upload(o2, u, &meta, &detail, &sqlrc);
  CHECK_ST(st, MURMUR_FILES_INVALID, detail, "cross rejected");
  free(detail);
  murmur_files_upload_abort(u);
  murmur_files_close(o2);
  free(dir2);

  free(payload);
  murmur_files_close(o);
  sqlite3_close(db);
  free(dir);
}

/* ---------- suite 14: fetch error latch ---------- */

static void suite_fetcherr(void) {
  suites++;
  uint8_t key[32];
  memset(key, 0xee, 32);
  sqlite3 *db = open_db();
  char *dir = make_tmpdir();
  murmur_node_t self = test_self();
  murmur_files_t *o = open_store(dir, key, 0, db, &self);
  CHECK(murmur_files_last_fetch_error(o) == NULL, "no error initially");
  murmur_files_fetch_error(o, "peer reset");
  char *e = murmur_files_last_fetch_error(o);
  CHECK(e && strcmp(e, "peer reset") == 0, "latch");
  free(e);
  murmur_files_fetch_error(o, "second");
  e = murmur_files_last_fetch_error(o);
  CHECK(e && strcmp(e, "second") == 0, "latch overwrite");
  free(e);
  murmur_files_close(o);
  sqlite3_close(db);
  free(dir);
}

int main(void) {
  suite_crypto();
  suite_roundtrip();
  suite_limits();
  suite_download();
  suite_stream();
  suite_corrupt();
  suite_list_delete();
  suite_availability();
  suite_publish();
  suite_rotate();
  suite_collect();
  suite_reconcile();
  suite_multipart();
  suite_fetcherr();
  if (failures) {
    printf("FILES-FAIL %d\n", failures);
    return 1;
  }
  printf("FILES-OK %d\n", suites);
  return 0;
}
