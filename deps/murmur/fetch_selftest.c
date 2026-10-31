/* fetch_selftest - native file fetch service suites (FETCH-OK).
 * Usage: ./build/fetchtest [testdata-dir] [base-port]
 */
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "fetch.h"
#include "member.h"
#include "files.h"
#include "kv.h"
#include "mbedtls/pem.h"
#include "sha256.h"
#include "sqlite3.h"
#include "sqlite_murmur_crsqlite.h"
#include "sync.h"

static int failures = 0;
static int suites = 0;

#define CHECK(cond, msg)                                  \
  do {                                                    \
    if (!(cond)) {                                        \
      printf("FAIL %s:%d: %s\n", __func__, __LINE__, msg); \
      failures++;                                         \
    }                                                     \
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

static void sleep_ms(long ms) {
  struct timespec ts;
  ts.tv_sec = ms / 1000;
  ts.tv_nsec = (ms % 1000) * 1000 * 1000;
  nanosleep(&ts, NULL);
}

static void fill(uint8_t *p, size_t n, unsigned seed) {
  unsigned x = 0x12345678u + seed;
  for (size_t i = 0; i < n; i++) {
    x = x * 1103515245u + 12345u;
    p[i] = (uint8_t)(x >> 16);
  }
}

/* ---------- PEM loading ---------- */

static uint8_t *slurp(const char *path, size_t *n_out) {
  FILE *f = fopen(path, "rb");
  if (!f) {
    return NULL;
  }
  fseek(f, 0, SEEK_END);
  long n = ftell(f);
  fseek(f, 0, SEEK_SET);
  uint8_t *b = malloc((size_t)n + 1);
  if (!b || fread(b, 1, (size_t)n, f) != (size_t)n) {
    fclose(f);
    free(b);
    return NULL;
  }
  fclose(f);
  b[n] = 0;
  *n_out = (size_t)n;
  return b;
}

static int load_certs(const char *path, uint8_t ***ders, size_t **lens,
                      size_t *n) {
  *ders = NULL;
  *lens = NULL;
  *n = 0;
  size_t raw_len = 0;
  uint8_t *raw = slurp(path, &raw_len);
  if (!raw) {
    return -1;
  }
  uint8_t **ds = NULL;
  size_t *ls = NULL, nd = 0, cap = 0;
  size_t off = 0;
  int rc = 0;
  while (off < raw_len) {
    mbedtls_pem_context pc;
    mbedtls_pem_init(&pc);
    size_t used = 0;
    if (mbedtls_pem_read_buffer(&pc, "-----BEGIN CERTIFICATE-----",
                                "-----END CERTIFICATE-----", raw + off, NULL,
                                0, &used) != 0) {
      mbedtls_pem_free(&pc);
      break;
    }
    size_t blen = 0;
    const uint8_t *der = mbedtls_pem_get_buffer(&pc, &blen);
    if (nd >= cap) {
      size_t ncap = cap ? cap * 2 : 4;
      uint8_t **nders = realloc(ds, ncap * sizeof(*nders));
      size_t *nlens = realloc(ls, ncap * sizeof(*nlens));
      if (!nders || !nlens) {
        free(nders);
        free(nlens);
        mbedtls_pem_free(&pc);
        rc = -1;
        break;
      }
      ds = nders;
      ls = nlens;
      cap = ncap;
    }
    ds[nd] = malloc(blen);
    if (!ds[nd]) {
      mbedtls_pem_free(&pc);
      rc = -1;
      break;
    }
    memcpy(ds[nd], der, blen);
    ls[nd] = blen;
    nd++;
    off += used;
    mbedtls_pem_free(&pc);
  }
  free(raw);
  if (rc != 0 || nd == 0) {
    for (size_t i = 0; i < nd; i++) {
      free(ds[i]);
    }
    free(ds);
    free(ls);
    return -1;
  }
  *ders = ds;
  *lens = ls;
  *n = nd;
  return 0;
}

static void free_certs(uint8_t **ders, size_t *lens, size_t n) {
  for (size_t i = 0; i < n; i++) {
    free(ders[i]);
  }
  free(ders);
  free(lens);
}

/* ---------- node harness ---------- */

typedef struct {
  sqlite3 *db;
  murmur_files_t *objects;
  murmur_fetch_t *fetch;
  murmur_node_t self;
  char *dir;
  char ip[64];
  uint16_t port;
  uint8_t **chain;
  size_t *chain_lens;
  size_t chain_n;
  uint8_t *key;
  size_t key_len;
  uint8_t **ca;
  size_t *ca_lens;
  size_t ca_n;
} fnode_t;

static murmur_node_t node_id(uint8_t b) {
  murmur_node_t n;
  memset(n.b, b, 16);
  return n;
}

static char *make_tmpdir(void) {
  char *t = strdup("/tmp/murmur-fetch-XXXXXX");
  if (!t || !mkdtemp(t)) {
    free(t);
    return NULL;
  }
  return t;
}

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

static int node_boot(fnode_t *n, const char *td, const char *cert,
                     const char *key, uint8_t id_byte,
                     const murmur_node_t *database, int port,
                     int concurrent, uint64_t max_staging) {
  memset(n, 0, sizeof(*n));
  n->self = node_id(id_byte);
  n->db = open_db();
  n->dir = make_tmpdir();
  if (!n->db || !n->dir) {
    return 0;
  }
  uint8_t fkey[32];
  memset(fkey, 0x2a, 32);
  murmur_files_config_t fc;
  murmur_files_config_default(&fc, n->dir, fkey);
  char *detail = NULL;
  int sqlrc = 0;
  if (murmur_files_open(&fc, n->db, &n->self, &n->objects, &detail, &sqlrc) !=
      MURMUR_FILES_OK) {
    printf("FAIL files open: %s\n", detail ? detail : "-");
    failures++;
    free(detail);
    return 0;
  }
  free(detail);
  char path[1024];
  snprintf(path, sizeof(path), "%s/%s", td, cert);
  if (load_certs(path, &n->chain, &n->chain_lens, &n->chain_n) != 0) {
    printf("FAIL chain %s\n", path);
    failures++;
    return 0;
  }
  snprintf(path, sizeof(path), "%s/%s", td, key);
  n->key = slurp(path, &n->key_len);
  if (!n->key) {
    printf("FAIL key %s\n", path);
    failures++;
    return 0;
  }
  snprintf(path, sizeof(path), "%s/ca.pem", td);
  if (load_certs(path, &n->ca, &n->ca_lens, &n->ca_n) != 0) {
    printf("FAIL ca %s\n", path);
    failures++;
    return 0;
  }
  murmur_fetch_config_t c;
  memset(&c, 0, sizeof(c));
  c.bind_ip = "127.0.0.1";
  c.bind_port = (uint16_t)port;
  c.chain_der = (const uint8_t **)n->chain;
  c.chain_lens = n->chain_lens;
  c.chain_n = n->chain_n;
  c.key_pem = n->key;
  c.key_len = n->key_len;
  c.ca_der = (const uint8_t **)n->ca;
  c.ca_lens = n->ca_lens;
  c.ca_n = n->ca_n;
  c.self = n->self;
  c.concurrent_fetches = concurrent;
  c.max_staging_bytes = max_staging;
  detail = NULL;
  if (murmur_fetch_start(&c, n->objects, database, &n->fetch, &detail) !=
      MURMUR_FILES_OK) {
    printf("FAIL fetch start: %s\n", detail ? detail : "-");
    failures++;
    free(detail);
    return 0;
  }
  free(detail);
  if (murmur_fetch_local_addr(n->fetch, n->ip, sizeof(n->ip), &n->port) != 0) {
    printf("FAIL local addr\n");
    failures++;
    return 0;
  }
  return 1;
}

static void node_down(fnode_t *n) {
  if (n->fetch) {
    murmur_fetch_stop(n->fetch);
  }
  if (n->objects) {
    murmur_files_close(n->objects);
  }
  if (n->db) {
    sqlite3_close(n->db);
  }
  free_certs(n->chain, n->chain_lens, n->chain_n);
  free(n->key);
  free_certs(n->ca, n->ca_lens, n->ca_n);
  free(n->dir);
}

typedef struct {
  const uint8_t *p;
  size_t n;
  size_t off;
} reader_t;

static int mem_read(void *ctx, uint8_t *buf, size_t cap, size_t *n_out,
                    int *eof_out) {
  reader_t *r = ctx;
  size_t take = r->n - r->off;
  if (take > cap) {
    take = cap;
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
} writer_t;

static int mem_write(void *ctx, const uint8_t *buf, size_t n) {
  writer_t *w = ctx;
  if (w->n + n > w->cap) {
    size_t ncap = w->cap ? w->cap * 2 : 4096;
    while (ncap < w->n + n) {
      ncap *= 2;
    }
    uint8_t *np = realloc(w->p, ncap);
    if (!np) {
      return -1;
    }
    w->p = np;
    w->cap = ncap;
  }
  memcpy(w->p + w->n, buf, n);
  w->n += n;
  return 0;
}

static int upload(fnode_t *n, const char *name, const uint8_t *p, size_t len,
                  murmur_files_meta_t *meta) {
  reader_t r;
  memset(&r, 0, sizeof(r));
  r.p = p;
  r.n = len;
  char *detail = NULL;
  int sqlrc = 0;
  murmur_files_status_t st = murmur_files_upload_one(
      n->objects, name, mem_read, &r, meta, &detail, &sqlrc);
  if (st != MURMUR_FILES_OK) {
    printf("FAIL upload %s: %s (%s)\n", name, murmur_files_status_str(st),
           detail ? detail : "-");
    failures++;
    free(detail);
    return 0;
  }
  free(detail);
  return 1;
}

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
      found = malloc(strlen(dir) + 1 + n + 1);
      sprintf(found, "%s/%s", dir, e->d_name);
      break;
    }
  }
  closedir(d);
  return found;
}

static int wait_available(fnode_t *n, const char *name, int secs) {
  for (int i = 0; i < secs * 10; i++) {
    int avail = 0;
    char *detail = NULL;
    int sqlrc = 0;
    if (murmur_files_available(n->objects, name, &avail, &detail, &sqlrc) ==
        MURMUR_FILES_OK) {
      free(detail);
      if (avail) {
        return 1;
      }
    } else {
      free(detail);
    }
    sleep_ms(100);
  }
  return 0;
}

static char *wait_fetch_error(fnode_t *n, int secs) {
  for (int i = 0; i < secs * 10; i++) {
    char *e = murmur_files_last_fetch_error(n->objects);
    if (e) {
      return e;
    }
    sleep_ms(100);
  }
  return NULL;
}

/* ---------- suite 1: resume offsets ---------- */

static void suite_resume(void) {
  suites++;
  char *dir = make_tmpdir();
  char part[1024], ident[1024];
  snprintf(part, sizeof(part), "%s/x.g0.part", dir);
  snprintf(ident, sizeof(ident), "%s/x.g0.identity", dir);
  char *detail = NULL;
  uint64_t off = 99;
  murmur_files_status_t st =
      murmur_fetch_resume_offset(part, &off, &detail);
  CHECK_ST(st, MURMUR_FILES_OK, detail, "missing part");
  CHECK(off == 0, "missing offset");

  FILE *f = fopen(part, "wb");
  fclose(f);
  st = murmur_fetch_resume_offset(part, &off, &detail);
  CHECK_ST(st, MURMUR_FILES_OK, detail, "empty part");
  CHECK(off == 0, "empty offset");

  f = fopen(part, "wb");
  uint8_t junk[100];
  memset(junk, 7, sizeof(junk));
  fwrite(junk, 1, sizeof(junk), f);
  fclose(f);
  /* No sidecar: discarded. */
  st = murmur_fetch_resume_offset(part, &off, &detail);
  CHECK_ST(st, MURMUR_FILES_OK, detail, "no sidecar");
  CHECK(off == 0, "no-sidecar offset");
  CHECK(access(part, F_OK) != 0, "part discarded");

  f = fopen(part, "wb");
  fwrite(junk, 1, sizeof(junk), f);
  fclose(f);
  f = fopen(ident, "wb");
  fwrite(junk, 1, 10, f);
  fclose(f);
  st = murmur_fetch_resume_offset(part, &off, &detail);
  CHECK_ST(st, MURMUR_FILES_OK, detail, "short sidecar");
  CHECK(off == 0, "short-sidecar offset");
  CHECK(access(part, F_OK) != 0, "short-sidecar discarded");

  f = fopen(part, "wb");
  fwrite(junk, 1, sizeof(junk), f);
  fclose(f);
  f = fopen(ident, "wb");
  fwrite(junk, 1, 32, f);
  fclose(f);
  st = murmur_fetch_resume_offset(part, &off, &detail);
  CHECK_ST(st, MURMUR_FILES_OK, detail, "resumable");
  CHECK(off == 100, "resume offset");
  free(dir);
}

/* ---------- suite 2: live loopback fetch ---------- */

static const char *g_td;
static int g_base;

static void suite_live(void) {
  suites++;
  murmur_node_t db = node_id(0xc0);
  fnode_t a, b;
  if (!node_boot(&a, g_td, "node-a.pem", "node-a-key.pem", 0xa0, &db,
                 g_base, 2, 1u << 30) ||
      !node_boot(&b, g_td, "node-b.pem", "node-b-key.pem", 0xb0, &db,
                 g_base + 1, 2, 1u << 30)) {
    node_down(&a);
    node_down(&b);
    return;
  }
  size_t n = 150000;
  uint8_t *payload = malloc(n);
  fill(payload, n, 31);
  murmur_files_meta_t ma, mb;
  memset(&ma, 0, sizeof(ma));
  memset(&mb, 0, sizeof(mb));
  CHECK(upload(&a, "f", payload, n, &ma), "upload A");
  CHECK(upload(&b, "f", payload, n, &mb), "upload B");
  CHECK(memcmp(ma.digest, mb.digest, 32) == 0, "same digest");
  char *bobj = find_object(b.dir);
  CHECK(bobj != NULL, "B object");
  unlink(bobj);
  free(bobj);

  murmur_fetch_source_t src;
  src.node = a.self;
  {
    char ap[96];
    snprintf(ap, sizeof(ap), "%s:%u", a.ip, a.port);
    CHECK(murmur_addr_parse(&src.addr, ap) == 0, "parse addr");
  }
  char *detail = NULL;
  int sqlrc = 0;
  murmur_files_status_t st =
      murmur_fetch_missing(b.fetch, &src, 1, &detail, &sqlrc);
  CHECK_ST(st, MURMUR_FILES_OK, detail, "fetch missing");
  CHECK(wait_available(&b, "f", 30), "B fetched");
  writer_t w;
  memset(&w, 0, sizeof(w));
  st = murmur_files_read(b.objects, "f", mem_write, &w, NULL, &detail,
                         &sqlrc);
  CHECK_ST(st, MURMUR_FILES_OK, detail, "read fetched");
  CHECK(w.n == n && memcmp(w.p, payload, n) == 0, "fetched bytes exact");
  free(w.p);

  /* No residue in staging. */
  char staging[1024];
  snprintf(staging, sizeof(staging), "%s/staging", b.dir);
  DIR *d = opendir(staging);
  int leftovers = 0;
  if (d) {
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
      if (strcmp(e->d_name, ".") && strcmp(e->d_name, "..")) {
        leftovers++;
      }
    }
    closedir(d);
  }
  CHECK(leftovers == 0, "staging clean");

  /* Second round is a no-op (already available). */
  st = murmur_fetch_missing(b.fetch, &src, 1, &detail, &sqlrc);
  CHECK_ST(st, MURMUR_FILES_OK, detail, "fetch again");

  murmur_files_meta_free(&ma);
  murmur_files_meta_free(&mb);
  free(payload);
  node_down(&a);
  node_down(&b);
}

/* ---------- suite 3: resume ---------- */

static void suite_resume_fetch(void) {
  suites++;
  murmur_node_t db = node_id(0xc0);
  fnode_t a, b;
  if (!node_boot(&a, g_td, "node-a.pem", "node-a-key.pem", 0xa0, &db,
                 g_base + 10, 2, 1u << 30) ||
      !node_boot(&b, g_td, "node-b.pem", "node-b-key.pem", 0xb0, &db,
                 g_base + 11, 2, 1u << 30)) {
    node_down(&a);
    node_down(&b);
    return;
  }
  size_t n = 200000;
  uint8_t *payload = malloc(n);
  fill(payload, n, 33);
  murmur_files_meta_t ma, mb;
  memset(&ma, 0, sizeof(ma));
  memset(&mb, 0, sizeof(mb));
  CHECK(upload(&a, "g", payload, n, &ma), "upload A");
  CHECK(upload(&b, "g", payload, n, &mb), "upload B");
  char *bobj = find_object(b.dir);
  unlink(bobj);
  free(bobj);

  /* Stage the first 50000 container bytes + correct identity. */
  char *aobj = find_object(a.dir);
  size_t on = 0;
  uint8_t *obytes = slurp(aobj, &on);
  CHECK(obytes && on > 60000, "slurp A");
  char staging[1024];
  snprintf(staging, sizeof(staging), "%s/staging", b.dir);
  mkdir(staging, 0700);
  char ahex[33], dhex[65];
  for (int i = 0; i < 16; i++) {
    sprintf(ahex + 2 * i, "%02x", a.self.b[i]);
  }
  for (int i = 0; i < 32; i++) {
    sprintf(dhex + 2 * i, "%02x", mb.digest[i]);
  }
  char part[2048], ident[2048];
  snprintf(part, sizeof(part), "%s/%s-%s.g%llu.part", staging, ahex, dhex,
           (unsigned long long)mb.generation);
  snprintf(ident, sizeof(ident), "%s/%s-%s.g%llu.identity", staging, ahex,
           dhex, (unsigned long long)mb.generation);
  FILE *f = fopen(part, "wb");
  fwrite(obytes, 1, 50000, f);
  fclose(f);
  uint8_t idsum[32];
  murmur_sha256(obytes, 40, idsum);
  f = fopen(ident, "wb");
  fwrite(idsum, 1, 32, f);
  fclose(f);
  free(obytes);
  free(aobj);

  murmur_fetch_source_t src;
  src.node = a.self;
  {
    char ap[96];
    snprintf(ap, sizeof(ap), "%s:%u", a.ip, a.port);
    CHECK(murmur_addr_parse(&src.addr, ap) == 0, "parse addr");
  }
  char *detail = NULL;
  int sqlrc = 0;
  murmur_files_status_t st =
      murmur_fetch_missing(b.fetch, &src, 1, &detail, &sqlrc);
  CHECK_ST(st, MURMUR_FILES_OK, detail, "fetch resume");
  CHECK(wait_available(&b, "g", 30), "B resumed");
  writer_t w;
  memset(&w, 0, sizeof(w));
  st = murmur_files_read(b.objects, "g", mem_write, &w, NULL, &detail,
                         &sqlrc);
  CHECK_ST(st, MURMUR_FILES_OK, detail, "read resumed");
  CHECK(w.n == n && memcmp(w.p, payload, n) == 0, "resumed bytes exact");
  free(w.p);

  murmur_files_meta_free(&ma);
  murmur_files_meta_free(&mb);
  free(payload);
  node_down(&a);
  node_down(&b);
}

/* ---------- suite 4: source missing ---------- */

static void suite_missing(void) {
  suites++;
  murmur_node_t db = node_id(0xc0);
  fnode_t a, b;
  if (!node_boot(&a, g_td, "node-a.pem", "node-a-key.pem", 0xa0, &db,
                 g_base + 20, 2, 1u << 30) ||
      !node_boot(&b, g_td, "node-b.pem", "node-b-key.pem", 0xb0, &db,
                 g_base + 21, 2, 1u << 30)) {
    node_down(&a);
    node_down(&b);
    return;
  }
  /* B knows "m", nobody holds the object. */
  uint8_t payload[1000];
  fill(payload, sizeof(payload), 35);
  murmur_files_meta_t mb;
  memset(&mb, 0, sizeof(mb));
  CHECK(upload(&b, "m", payload, sizeof(payload), &mb), "upload B");
  char *bobj = find_object(b.dir);
  unlink(bobj);
  free(bobj);

  murmur_fetch_source_t src;
  src.node = a.self;
  {
    char ap[96];
    snprintf(ap, sizeof(ap), "%s:%u", a.ip, a.port);
    CHECK(murmur_addr_parse(&src.addr, ap) == 0, "parse addr");
  }
  char *detail = NULL;
  int sqlrc = 0;
  murmur_files_status_t st =
      murmur_fetch_missing(b.fetch, &src, 1, &detail, &sqlrc);
  CHECK_ST(st, MURMUR_FILES_OK, detail, "fetch missing");
  char *err = wait_fetch_error(&b, 15);
  CHECK(err && strstr(err, "file source has no object") != NULL,
        "missing latched");
  free(err);
  int avail = 1;
  st = murmur_files_available(b.objects, "m", &avail, &detail, &sqlrc);
  CHECK_ST(st, MURMUR_FILES_OK, detail, "still missing");
  CHECK(!avail, "still unavailable");

  murmur_files_meta_free(&mb);
  node_down(&a);
  node_down(&b);
}

/* ---------- suite 5: database mismatch ---------- */

static void suite_wrongdb(void) {
  suites++;
  murmur_node_t dba = node_id(0xc0);
  murmur_node_t dbb = node_id(0xc1);
  fnode_t a, b;
  if (!node_boot(&a, g_td, "node-a.pem", "node-a-key.pem", 0xa0, &dba,
                 g_base + 30, 2, 1u << 30) ||
      !node_boot(&b, g_td, "node-b.pem", "node-b-key.pem", 0xb0, &dbb,
                 g_base + 31, 2, 1u << 30)) {
    node_down(&a);
    node_down(&b);
    return;
  }
  uint8_t payload[5000];
  fill(payload, sizeof(payload), 37);
  murmur_files_meta_t ma, mb;
  memset(&ma, 0, sizeof(ma));
  memset(&mb, 0, sizeof(mb));
  CHECK(upload(&a, "w", payload, sizeof(payload), &ma), "upload A");
  CHECK(upload(&b, "w", payload, sizeof(payload), &mb), "upload B");
  char *bobj = find_object(b.dir);
  unlink(bobj);
  free(bobj);

  murmur_fetch_source_t src;
  src.node = a.self;
  {
    char ap[96];
    snprintf(ap, sizeof(ap), "%s:%u", a.ip, a.port);
    CHECK(murmur_addr_parse(&src.addr, ap) == 0, "parse addr");
  }
  char *detail = NULL;
  int sqlrc = 0;
  murmur_files_status_t st =
      murmur_fetch_missing(b.fetch, &src, 1, &detail, &sqlrc);
  CHECK_ST(st, MURMUR_FILES_OK, detail, "fetch wrongdb");
  /* Server rejects: A latches the auth error, B latches a transfer
   * failure. Both prove the identity gate fired. */
  char *erra = wait_fetch_error(&a, 15);
  CHECK(erra && strstr(erra, "file database identity") != NULL,
        "server gate latched");
  free(erra);
  char *errb = wait_fetch_error(&b, 15);
  CHECK(errb != NULL, "client failure latched");
  free(errb);

  murmur_files_meta_free(&ma);
  murmur_files_meta_free(&mb);
  node_down(&a);
  node_down(&b);
}

/* ---------- suite 6: overload + validation ---------- */

static void suite_limits(void) {
  suites++;
  murmur_node_t db = node_id(0xc0);
  fnode_t a, b;
  if (!node_boot(&a, g_td, "node-a.pem", "node-a-key.pem", 0xa0, &db,
                 g_base + 40, 2, 1u << 30) ||
      !node_boot(&b, g_td, "node-b.pem", "node-b-key.pem", 0xb0, &db,
                 g_base + 41, 2, 64u << 10)) {
    node_down(&a);
    node_down(&b);
    return;
  }
  size_t n = 150000;
  uint8_t *payload = malloc(n);
  fill(payload, n, 39);
  murmur_files_meta_t ma, mb;
  memset(&ma, 0, sizeof(ma));
  memset(&mb, 0, sizeof(mb));
  CHECK(upload(&a, "big", payload, n, &ma), "upload A");
  CHECK(upload(&b, "big", payload, n, &mb), "upload B");
  char *bobj = find_object(b.dir);
  unlink(bobj);
  free(bobj);

  /* Container ~150KiB > 64KiB staging: skipped synchronously. */
  murmur_fetch_source_t src;
  src.node = a.self;
  {
    char ap[96];
    snprintf(ap, sizeof(ap), "%s:%u", a.ip, a.port);
    CHECK(murmur_addr_parse(&src.addr, ap) == 0, "parse addr");
  }
  char *detail = NULL;
  int sqlrc = 0;
  murmur_files_status_t st =
      murmur_fetch_missing(b.fetch, &src, 1, &detail, &sqlrc);
  CHECK_ST(st, MURMUR_FILES_OK, detail, "fetch oversize");
  char *err = murmur_files_last_fetch_error(b.objects);
  CHECK(err && strstr(err, "overloaded") != NULL, "overload latched");
  free(err);

  /* Start validation. */
  murmur_fetch_config_t c;
  memset(&c, 0, sizeof(c));
  murmur_fetch_t *bad = NULL;
  st = murmur_fetch_start(&c, b.objects, &db, &bad, &detail);
  CHECK_ST(st, MURMUR_FILES_INVALID, detail, "empty config");
  const char *cidrs[] = {"not-a-cidr"};
  c.concurrent_fetches = 1;
  c.max_staging_bytes = 1u << 20;
  c.allow_cidrs = cidrs;
  c.n_cidrs = 1;
  st = murmur_fetch_start(&c, b.objects, &db, &bad, &detail);
  CHECK_ST(st, MURMUR_FILES_INVALID, detail, "bad cidr");

  murmur_files_meta_free(&ma);
  murmur_files_meta_free(&mb);
  free(payload);
  node_down(&a);
  node_down(&b);
}

int main(int argc, char **argv) {
  g_td = argc > 1 ? argv[1] : "deps/murmur/testdata";
  g_base = argc > 2 ? atoi(argv[2]) : 24500;
  suite_resume();
  suite_live();
  suite_resume_fetch();
  suite_missing();
  suite_wrongdb();
  suite_limits();
  if (failures) {
    printf("FETCH-FAIL %d\n", failures);
    return 1;
  }
  printf("FETCH-OK %d\n", suites);
  return 0;
}
