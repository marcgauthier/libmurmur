/* murmur files - native FileObjects store. See files.h. */
#include "files.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "aesgcm.h"
#include "hkdf.h"
#include "kv.h"
extern int nvFlushDb(const char *);
#include "postcard.h"
#include "schema.h"
#include "sha256.h"
#include "sqlite3.h"

#define FILES_AVAIL_PREFIX "08/files/availability/"
#define FILES_MAGIC "SPFO0001"
#define FILES_MAGIC_LEN 8
#define FILES_HEADER_LEN 40
#define FILES_CHUNK (64u << 10)
#define FILES_DOWNLOAD_LIMIT (1u << 20)
#define FILES_AVAIL_WINDOW_MS (7ull * 86400ull * 1000ull)

const char *murmur_files_status_str(murmur_files_status_t st) {
  switch (st) {
    case MURMUR_FILES_OK:
      return "ok";
    case MURMUR_FILES_INVALID:
      return "invalid";
    case MURMUR_FILES_AUTH:
      return "auth";
    case MURMUR_FILES_IO:
      return "io";
    case MURMUR_FILES_UNAVAILABLE:
      return "unavailable";
    case MURMUR_FILES_OVERLOADED:
      return "overloaded";
    case MURMUR_FILES_SQLITE:
      return "sqlite";
    case MURMUR_FILES_PROTOCOL:
      return "protocol";
  }
  return "unknown";
}

static void set_detail(char **out, const char *fmt, ...) {
  if (!out) {
    return;
  }
  *out = NULL;
  char buf[512];
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(buf, sizeof(buf), fmt, ap);
  va_end(ap);
  *out = strdup(buf);
}

static murmur_files_status_t io_fail(char **detail_out) {
  set_detail(detail_out, "%s", strerror(errno));
  return MURMUR_FILES_IO;
}

static murmur_files_status_t kv_fail(murmur_sync_status_t st, char **detail_out,
                                     int *sqlrc, int rc) {
  if (sqlrc) {
    *sqlrc = rc;
  }
  if (st == MURMUR_SYNC_INVALID) {
    set_detail(detail_out, "store");
    return MURMUR_FILES_INVALID;
  }
  if (st == MURMUR_SYNC_OVERLOADED) {
    set_detail(detail_out, "store");
    return MURMUR_FILES_OVERLOADED;
  }
  set_detail(detail_out, "store");
  return MURMUR_FILES_SQLITE;
}

void murmur_files_meta_free(murmur_files_meta_t *m) {
  if (!m) {
    return;
  }
  free(m->name);
  memset(m, 0, sizeof(*m));
}

void murmur_files_meta_list_free(murmur_files_meta_t *ms, size_t n) {
  if (!ms) {
    return;
  }
  for (size_t i = 0; i < n; i++) {
    free(ms[i].name);
  }
  free(ms);
}

void murmur_files_config_default(murmur_files_config_t *c,
                                 const char *directory,
                                 const uint8_t key[32]) {
  memset(c, 0, sizeof(*c));
  c->directory = directory;
  memcpy(c->key, key, 32);
  c->max_file_bytes = 4ull << 30;
  c->max_staging_bytes = 1ull << 30;
  c->concurrent_fetches = 2;
  c->fetch_interval_ms = 30000;
}

/* ---------- small helpers ---------- */

static void hex_encode(const uint8_t *b, size_t n, char *out) {
  static const char *digits = "0123456789abcdef";
  for (size_t i = 0; i < n; i++) {
    out[2 * i] = digits[b[i] >> 4];
    out[2 * i + 1] = digits[b[i] & 15];
  }
  out[2 * n] = 0;
}

static int hex_val(char c, uint8_t *out) {
  if (c >= '0' && c <= '9') {
    *out = (uint8_t)(c - '0');
    return 1;
  }
  if (c >= 'a' && c <= 'f') {
    *out = (uint8_t)(c - 'a' + 10);
    return 1;
  }
  return 0;
}

/* Lowercase-only 32-char node decode. */
static int decode_hex_node(const char *s, size_t n, murmur_node_t *out) {
  if (n != 32) {
    return 0;
  }
  for (int j = 0; j < 16; j++) {
    uint8_t hi, lo;
    if (!hex_val(s[2 * j], &hi) || !hex_val(s[2 * j + 1], &lo)) {
      return 0;
    }
    out->b[j] = (uint8_t)(hi << 4 | lo);
  }
  return 1;
}

static uint64_t sat_sub(uint64_t a, uint64_t b) {
  return a >= b ? a - b : 0;
}

static uint64_t div_ceil(uint64_t a, uint64_t b) {
  uint64_t q = a / b;
  if (a % b != 0) {
    q++;
  }
  return q;
}

static uint64_t files_now_ms(void) {
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  if (ts.tv_sec < 0) {
    return 0;
  }
  return (uint64_t)ts.tv_sec * 1000ull +
         (uint64_t)ts.tv_nsec / 1000000ull;
}

static uint64_t modified_ms(const struct stat *st) {
#if defined(__APPLE__)
  return (uint64_t)st->st_mtimespec.tv_sec * 1000ull +
         (uint64_t)st->st_mtimespec.tv_nsec / 1000000ull;
#else
  if (st->st_mtime < 0) {
    return 0;
  }
  return (uint64_t)st->st_mtime * 1000ull +
         (uint64_t)st->st_mtim.tv_nsec / 1000000ull;
#endif
}

static void put_u32be(uint8_t b[4], uint32_t v) {
  b[0] = (uint8_t)(v >> 24);
  b[1] = (uint8_t)(v >> 16);
  b[2] = (uint8_t)(v >> 8);
  b[3] = (uint8_t)v;
}

static void put_u64be(uint8_t b[8], uint64_t v) {
  for (int i = 0; i < 8; i++) {
    b[i] = (uint8_t)(v >> (56 - 8 * i));
  }
}

static uint32_t get_u32be(const uint8_t b[4]) {
  return ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) |
         ((uint32_t)b[2] << 8) | (uint32_t)b[3];
}

static uint64_t get_u64be(const uint8_t b[8]) {
  uint64_t v = 0;
  for (int i = 0; i < 8; i++) {
    v = (v << 8) | b[i];
  }
  return v;
}

/* Per-object key: HKDF-SHA256(file key, salt,
 * "murmur/sqlite-file-object/v1"). */
static int object_key(const uint8_t key[32], const uint8_t salt[16],
                      uint8_t out[32]) {
  static const char info[] = "murmur/sqlite-file-object/v1";
  return murmur_hkdf(key, 32, salt, 16, (const uint8_t *)info,
                     sizeof(info) - 1, out, 32);
}

static void file_nonce(const uint8_t prefix[8], uint32_t index,
                       uint8_t out[12]) {
  memcpy(out, prefix, 8);
  put_u32be(out + 8, index);
}

static murmur_files_status_t check_file_name(const char *name,
                                             char **detail_out) {
  /* An embedded NUL is unrepresentable in C strings; strlen
   * truncates there, which the backend then treats as the name. */
  if (!name || name[0] == 0 || strlen(name) > 4096) {
    set_detail(detail_out, "file name");
    return MURMUR_FILES_INVALID;
  }
  return MURMUR_FILES_OK;
}

/* File metadata lives in the replicated murmur_file_meta CRR table
 * (name TEXT PRIMARY KEY, meta BLOB): the mesh ships it like any
 * other row, which is what makes multi-node files work. The meta
 * blob stays the Go postcard FileMetadata encoding byte for byte.
 * Availability sightings stay in node-local kv (7-day window). */

/* availabilityPrefix: "08/files/availability/" + hex + "/" + dec + "/". */
static char *avail_prefix(const uint8_t digest[32], uint64_t generation) {
  char hex[65];
  hex_encode(digest, 32, hex);
  char *key = malloc(sizeof(FILES_AVAIL_PREFIX) + 64 + 1 + 20 + 1);
  if (!key) {
    return NULL;
  }
  sprintf(key, "%s%s/%llu/", FILES_AVAIL_PREFIX, hex,
          (unsigned long long)generation);
  return key;
}

/* Staging identity sidecar: strip the extension, add ".identity". */
static char *staging_identity_path(const char *path) {
  const char *slash = strrchr(path, '/');
  const char *dot = strrchr(slash ? slash : path, '.');
  size_t stem = dot ? (size_t)(dot - path) : strlen(path);
  const char *suffix = ".identity";
  char *out = malloc(stem + strlen(suffix) + 1);
  if (!out) {
    return NULL;
  }
  memcpy(out, path, stem);
  strcpy(out + stem, suffix);
  return out;
}

/* Parses "<64hex>.g<dec>.spfo" (wrapping decimal, like Go). */
static int parse_object_name(const char *name, uint8_t digest[32],
                             uint64_t *generation) {
  size_t n = strlen(name);
  const char *suffix = ".spfo";
  if (n <= 5 || strcmp(name + n - 5, suffix) != 0) {
    return 0;
  }
  size_t stem = n - 5;
  /* Last ".g". */
  size_t at = stem;
  int found = 0;
  for (size_t i = 0; i + 1 < stem; i++) {
    if (name[i] == '.' && name[i + 1] == 'g') {
      at = i;
      found = 1;
    }
  }
  if (!found || name[at + 2] == 0) {
    return 0;
  }
  uint64_t gen = 0;
  int digits = 0;
  for (size_t i = at + 2; i < stem; i++) {
    char c = name[i];
    if (c < '0' || c > '9') {
      return 0;
    }
    gen = gen * 10 + (uint64_t)(c - '0');
    digits++;
  }
  if (digits == 0 || at != 64) {
    return 0;
  }
  for (int j = 0; j < 32; j++) {
    uint8_t hi, lo;
    if (!hex_val(name[2 * j], &hi) || !hex_val(name[2 * j + 1], &lo)) {
      return 0;
    }
    digest[j] = (uint8_t)(hi << 4 | lo);
  }
  *generation = gen;
  return 1;
}

/* Parses a staging stem "<sourcehex>-<64hex>.g<dec>" (no suffix). */
static int parse_staging_stem(const char *stem, uint8_t digest[32],
                              uint64_t *generation) {
  const char *dash = strchr(stem, '-');
  if (!dash) {
    return 0;
  }
  const char *rest = dash + 1;
  size_t n = strlen(rest);
  size_t at = n;
  int found = 0;
  for (size_t i = 0; i + 1 < n; i++) {
    if (rest[i] == '.' && rest[i + 1] == 'g') {
      at = i;
      found = 1;
    }
  }
  if (!found || rest[at + 2] == 0) {
    return 0;
  }
  uint64_t gen = 0;
  int digits = 0;
  for (size_t i = at + 2; i < n; i++) {
    char c = rest[i];
    if (c < '0' || c > '9') {
      return 0;
    }
    gen = gen * 10 + (uint64_t)(c - '0');
    digits++;
  }
  if (digits == 0 || at != 64) {
    return 0;
  }
  for (int j = 0; j < 32; j++) {
    uint8_t hi, lo;
    if (!hex_val(rest[2 * j], &hi) || !hex_val(rest[2 * j + 1], &lo)) {
      return 0;
    }
    digest[j] = (uint8_t)(hi << 4 | lo);
  }
  *generation = gen;
  return 1;
}

static int parse_staging_name(const char *name, uint8_t digest[32],
                              uint64_t *generation) {
  size_t n = strlen(name);
  if (n <= 5 || strcmp(name + n - 5, ".part") != 0) {
    return 0;
  }
  char *stem = malloc(n - 5 + 1);
  if (!stem) {
    return 0;
  }
  memcpy(stem, name, n - 5);
  stem[n - 5] = 0;
  int ok = parse_staging_stem(stem, digest, generation);
  free(stem);
  return ok;
}

static int has_suffix(const char *s, const char *suffix) {
  size_t n = strlen(s), m = strlen(suffix);
  return n >= m && strcmp(s + n - m, suffix) == 0;
}

static int has_prefix(const char *s, const char *prefix) {
  return strncmp(s, prefix, strlen(prefix)) == 0;
}

/* ---------- filesystem helpers ---------- */

static int mkdir_all(const char *path, mode_t mode) {
  char *tmp = strdup(path);
  if (!tmp) {
    return -1;
  }
  size_t n = strlen(tmp);
  while (n > 0 && tmp[n - 1] == '/') {
    tmp[--n] = 0;
  }
  for (char *p = tmp + 1; *p; p++) {
    if (*p == '/') {
      *p = 0;
      if (mkdir(tmp, mode) != 0 && errno != EEXIST) {
        free(tmp);
        return -1;
      }
      *p = '/';
    }
  }
  if (mkdir(tmp, mode) != 0 && errno != EEXIST) {
    free(tmp);
    return -1;
  }
  free(tmp);
  return 0;
}

static int sync_directory(const char *path) {
#ifdef _WIN32
  (void)path;
  return 0;
#else
  int fd = open(path, O_RDONLY | O_DIRECTORY);
  if (fd < 0) {
    return -1;
  }
  int rc = fsync(fd);
  int err = errno;
  close(fd);
  errno = err;
  return rc;
#endif
}

static ssize_t read_exact(int fd, uint8_t *buf, size_t n) {
  size_t got = 0;
  while (got < n) {
    ssize_t r = read(fd, buf + got, n - got);
    if (r < 0) {
      if (errno == EINTR) {
        continue;
      }
      return -1;
    }
    if (r == 0) {
      break;
    }
    got += (size_t)r;
  }
  return (ssize_t)got;
}

static int write_all(int fd, const uint8_t *buf, size_t n) {
  size_t done = 0;
  while (done < n) {
    ssize_t r = write(fd, buf + done, n - done);
    if (r < 0) {
      if (errno == EINTR) {
        continue;
      }
      return -1;
    }
    done += (size_t)r;
  }
  return 0;
}

/* O_WRONLY|O_CREAT|O_EXCL, 0600. */
static int private_file(const char *path) {
  return open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
}

/* ---------- store ---------- */

struct murmur_files_t {
  char *dir;
  uint8_t key[32];
  uint8_t prev[32];
  int has_prev;
  uint64_t generation;
  uint64_t max_file;
  uint64_t max_staging;
  sqlite3 *db;
  murmur_node_t self;
  pthread_mutex_t gate;
  pthread_mutex_t staged_mu;
  char **staged;
  size_t n_staged;
  size_t cap_staged;
  pthread_mutex_t usage_mu;
  uint64_t staging_used;
  pthread_mutex_t err_mu;
  char *last_err;
};

struct murmur_staging_reservation_t {
  murmur_files_t *o;
  uint64_t bytes;
  int released;
};

struct murmur_staged_transfer_t {
  murmur_files_t *o;
  char **paths;
  size_t n;
  int released;
};

/* Object path: dir + "/" + hex + ".g" + dec + ".spfo". Caller frees. */
static char *object_path(murmur_files_t *o, const uint8_t digest[32],
                         uint64_t generation) {
  char hex[65];
  hex_encode(digest, 32, hex);
  size_t n = strlen(o->dir) + 1 + 64 + 2 + 20 + 5 + 1;
  char *out = malloc(n);
  if (!out) {
    return NULL;
  }
  snprintf(out, n, "%s/%s.g%llu.spfo", o->dir, hex,
           (unsigned long long)generation);
  return out;
}

static char *join_path(const char *dir, const char *name) {
  size_t n = strlen(dir) + 1 + strlen(name) + 1;
  char *out = malloc(n);
  if (!out) {
    return NULL;
  }
  snprintf(out, n, "%s/%s", dir, name);
  return out;
}

static int staged_contains(murmur_files_t *o, const char *path) {
  pthread_mutex_lock(&o->staged_mu);
  int found = 0;
  for (size_t i = 0; i < o->n_staged; i++) {
    if (strcmp(o->staged[i], path) == 0) {
      found = 1;
      break;
    }
  }
  pthread_mutex_unlock(&o->staged_mu);
  return found;
}

static int staged_add(murmur_files_t *o, const char *path) {
  pthread_mutex_lock(&o->staged_mu);
  for (size_t i = 0; i < o->n_staged; i++) {
    if (strcmp(o->staged[i], path) == 0) {
      pthread_mutex_unlock(&o->staged_mu);
      return 0;
    }
  }
  if (o->n_staged == o->cap_staged) {
    size_t cap = o->cap_staged ? o->cap_staged * 2 : 16;
    char **next = realloc(o->staged, cap * sizeof(*next));
    if (!next) {
      pthread_mutex_unlock(&o->staged_mu);
      return -1;
    }
    o->staged = next;
    o->cap_staged = cap;
  }
  o->staged[o->n_staged] = strdup(path);
  if (!o->staged[o->n_staged]) {
    pthread_mutex_unlock(&o->staged_mu);
    return -1;
  }
  o->n_staged++;
  pthread_mutex_unlock(&o->staged_mu);
  return 0;
}

static void staged_remove(murmur_files_t *o, const char *path) {
  pthread_mutex_lock(&o->staged_mu);
  for (size_t i = 0; i < o->n_staged; i++) {
    if (strcmp(o->staged[i], path) == 0) {
      free(o->staged[i]);
      o->staged[i] = o->staged[--o->n_staged];
      break;
    }
  }
  pthread_mutex_unlock(&o->staged_mu);
}

/* ---------- metadata encode/decode ---------- */

static murmur_files_status_t meta_from_wire(const uint8_t *raw, size_t raw_len,
                                            murmur_files_meta_t *out,
                                            char **detail_out) {
  murmur_file_meta_t w;
  if (murmur_file_meta_decode(raw, raw_len, &w) != MURMUR_PC_OK) {
    set_detail(detail_out, "file metadata");
    return MURMUR_FILES_PROTOCOL;
  }
  memset(out, 0, sizeof(*out));
  out->name = malloc(w.name_len + 1);
  if (!out->name) {
    set_detail(detail_out, "file metadata");
    return MURMUR_FILES_IO;
  }
  memcpy(out->name, w.name, w.name_len);
  out->name[w.name_len] = 0;
  memcpy(out->digest, w.digest, 32);
  out->bytes = w.bytes;
  out->generation = w.generation;
  out->millis = w.millis;
  out->node = w.node;
  out->deleted = w.deleted;
  return MURMUR_FILES_OK;
}

static int meta_to_wire(const murmur_files_meta_t *m, uint8_t **out,
                        size_t *out_len) {
  murmur_file_meta_t w;
  memset(&w, 0, sizeof(w));
  w.name = (const uint8_t *)m->name;
  w.name_len = strlen(m->name);
  memcpy(w.digest, m->digest, 32);
  w.bytes = m->bytes;
  w.generation = m->generation;
  w.millis = m->millis;
  w.node = m->node;
  w.deleted = m->deleted;
  murmur_pc_enc_t e;
  murmur_pc_enc_init(&e);
  murmur_file_meta_encode(&e, &w);
  *out = e.b;
  *out_len = e.len;
  return 0;
}

static murmur_files_status_t sql_fail(int rc, char **detail_out,
                                      int *sqlrc) {
  if (sqlrc) {
    *sqlrc = rc;
  }
  set_detail(detail_out, "store");
  return MURMUR_FILES_SQLITE;
}

/* Upserts one metadata blob into the replicated table
 * (tombstones included; the row is never SQL-deleted). */
static murmur_files_status_t meta_put_inner(murmur_files_t *o,
                                      const murmur_files_meta_t *m,
                                      char **detail_out, int *sqlrc) {
  uint8_t *wire = NULL;
  size_t wire_len = 0;
  if (meta_to_wire(m, &wire, &wire_len) != 0) {
    return io_fail(detail_out);
  }
  sqlite3_stmt *st = NULL;
  int rc = sqlite3_prepare_v2(
      o->db,
      "INSERT INTO murmur_file_meta(name,meta) VALUES(?1,?2) "
      "ON CONFLICT(name) DO UPDATE SET meta=excluded.meta",
      -1, &st, NULL);
  if (rc != SQLITE_OK) {
    free(wire);
    return sql_fail(rc, detail_out, sqlrc);
  }
  sqlite3_bind_text(st, 1, m->name, -1, SQLITE_TRANSIENT);
  sqlite3_bind_blob(st, 2, wire, (int)wire_len, SQLITE_TRANSIENT);
  rc = sqlite3_step(st);
  sqlite3_finalize(st);
  free(wire);
  if (rc != SQLITE_DONE) {
    return sql_fail(rc, detail_out, sqlrc);
  }
  if (sqlrc) {
    *sqlrc = SQLITE_OK;
  }
  return MURMUR_FILES_OK;
}
static murmur_files_status_t meta_put(murmur_files_t *o,const murmur_files_meta_t *m,char **detail_out,int *sqlrc) {
  murmur_db_writer_lock();
  murmur_files_status_t fs=meta_put_inner(o,m,detail_out,sqlrc);
  murmur_db_writer_unlock();
  return fs;
}


/* Reads one metadata blob; *found false when absent. */
static murmur_files_status_t meta_get_inner(murmur_files_t *o, const char *name,
                                      murmur_files_meta_t *out, int *found,
                                      char **detail_out, int *sqlrc) {
  *found = 0;
  memset(out, 0, sizeof(*out));
  sqlite3_stmt *st = NULL;
  int rc = sqlite3_prepare_v2(
      o->db, "SELECT meta FROM murmur_file_meta WHERE name=?1", -1, &st,
      NULL);
  if (rc != SQLITE_OK) {
    return sql_fail(rc, detail_out, sqlrc);
  }
  sqlite3_bind_text(st, 1, name, -1, SQLITE_TRANSIENT);
  rc = sqlite3_step(st);
  if (rc == SQLITE_ROW) {
    const uint8_t *blob = sqlite3_column_blob(st, 0);
    size_t n = (size_t)sqlite3_column_bytes(st, 0);
    murmur_files_status_t fs = meta_from_wire(blob, n, out, detail_out);
    sqlite3_finalize(st);
    if (fs != MURMUR_FILES_OK) {
      return fs;
    }
    *found = 1;
    if (sqlrc) {
      *sqlrc = SQLITE_OK;
    }
    return MURMUR_FILES_OK;
  }
  sqlite3_finalize(st);
  if (rc != SQLITE_DONE) {
    return sql_fail(rc, detail_out, sqlrc);
  }
  if (sqlrc) {
    *sqlrc = SQLITE_OK;
  }
  return MURMUR_FILES_OK;
}
static murmur_files_status_t meta_get(murmur_files_t *o,const char *name,murmur_files_meta_t *out,int *found,char **detail_out,int *sqlrc) {
  murmur_db_writer_lock();
  murmur_files_status_t fs=meta_get_inner(o,name,out,found,detail_out,sqlrc);
  murmur_db_writer_unlock();
  return fs;
}


/* All metadata rows in name order. */
static murmur_files_status_t meta_scan_all_inner(murmur_files_t *o,
                                           murmur_files_meta_t **out, size_t *n,
                                           char **detail_out, int *sqlrc) {
  *out = NULL;
  *n = 0;
  sqlite3_stmt *st = NULL;
  int rc = sqlite3_prepare_v2(
      o->db, "SELECT meta FROM murmur_file_meta ORDER BY name", -1, &st,
      NULL);
  if (rc != SQLITE_OK) {
    return sql_fail(rc, detail_out, sqlrc);
  }
  murmur_files_meta_t *ms = NULL;
  size_t count = 0, cap = 0;
  murmur_files_status_t fs = MURMUR_FILES_OK;
  for (;;) {
    rc = sqlite3_step(st);
    if (rc == SQLITE_DONE) {
      break;
    }
    if (rc != SQLITE_ROW) {
      fs = sql_fail(rc, detail_out, sqlrc);
      break;
    }
    if (count == cap) {
      size_t ncap = cap ? cap * 2 : 16;
      murmur_files_meta_t *next = realloc(ms, ncap * sizeof(*next));
      if (!next) {
        set_detail(detail_out, "file list");
        fs = MURMUR_FILES_IO;
        break;
      }
      ms = next;
      cap = ncap;
    }
    memset(&ms[count], 0, sizeof(ms[count]));
    fs = meta_from_wire(sqlite3_column_blob(st, 0),
                        (size_t)sqlite3_column_bytes(st, 0), &ms[count],
                        detail_out);
    if (fs != MURMUR_FILES_OK) {
      break;
    }
    count++;
  }
  sqlite3_finalize(st);
  if (fs != MURMUR_FILES_OK) {
    murmur_files_meta_list_free(ms, count);
    return fs;
  }
  *out = ms;
  *n = count;
  if (sqlrc) {
    *sqlrc = SQLITE_OK;
  }
  return MURMUR_FILES_OK;
}
static murmur_files_status_t meta_scan_all(murmur_files_t *o,murmur_files_meta_t **out,size_t *n,char **detail_out,int *sqlrc) {
  murmur_db_writer_lock();
  murmur_files_status_t fs=meta_scan_all_inner(o,out,n,detail_out,sqlrc);
  murmur_db_writer_unlock();
  return fs;
}


/* Durable single-record kv write (availability sightings). */
static murmur_files_status_t files_write_record(murmur_files_t *o,
                                                const uint8_t *key,
                                                size_t key_len,
                                                const uint8_t *val,
                                                size_t val_len, int is_delete,
                                                char **detail_out, int *sqlrc) {
  murmur_kv_record_t r;
  memset(&r, 0, sizeof(r));
  r.key = (uint8_t *)key;
  r.key_len = key_len;
  r.value = (uint8_t *)val;
  r.value_len = val_len;
  r.is_delete = is_delete;
  int rc = 0;
  murmur_sync_status_t st = murmur_kv_commit(o->db, &r, 1, &rc);
  if (st != MURMUR_SYNC_OK) {
    return kv_fail(st, detail_out, sqlrc, rc);
  }
  if (sqlrc) {
    *sqlrc = rc;
  }
  return MURMUR_FILES_OK;
}

static murmur_files_status_t files_get_inner(murmur_files_t *o, const uint8_t *key,
                                       size_t key_len, uint8_t **val,
                                       size_t *val_len, int *found,
                                       char **detail_out, int *sqlrc) {
  int rc = 0;
  murmur_sync_status_t st =
      murmur_kv_get(o->db, key, key_len, val, val_len, found, &rc);
  if (st != MURMUR_SYNC_OK) {
    return kv_fail(st, detail_out, sqlrc, rc);
  }
  if (sqlrc) {
    *sqlrc = rc;
  }
  return MURMUR_FILES_OK;
}
static murmur_files_status_t files_get(murmur_files_t *o,const uint8_t *key,size_t key_len,uint8_t **val,size_t *val_len,int *found,char **detail_out,int *sqlrc) {
  murmur_db_writer_lock();
  murmur_files_status_t fs=files_get_inner(o,key,key_len,val,val_len,found,detail_out,sqlrc);
  murmur_db_writer_unlock();
  return fs;
}


/* ---------- open / close ---------- */

/* Directory listing of non-directory names. Caller frees. */
static char **dir_names(const char *dir, size_t *n_out) {
  *n_out = 0;
  DIR *d = opendir(dir);
  if (!d) {
    return NULL;
  }
  char **names = NULL;
  size_t n = 0, cap = 0;
  struct dirent *e;
  while ((e = readdir(d)) != NULL) {
    if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0) {
      continue;
    }
    char *full = join_path(dir, e->d_name);
    if (!full) {
      continue;
    }
    struct stat st;
    int ok = stat(full, &st) == 0 && !S_ISDIR(st.st_mode);
    free(full);
    if (!ok) {
      continue;
    }
    if (n == cap) {
      size_t ncap = cap ? cap * 2 : 32;
      char **next = realloc(names, ncap * sizeof(*next));
      if (!next) {
        break;
      }
      names = next;
      cap = ncap;
    }
    names[n] = strdup(e->d_name);
    if (!names[n]) {
      break;
    }
    n++;
  }
  closedir(d);
  *n_out = n;
  if (!names) {
    /* Empty directory: return a non-NULL empty list so callers can
     * keep reading NULL as failure (opendir error or ENOMEM, both
     * with errno set). A NULL success here used to surface stale
     * errno (EEXIST from mkdir_all) as "File exists" on reopen. */
    names = malloc(sizeof(*names));
    if (!names) {
      return NULL;
    }
  }
  return names;
}

static void names_free(char **names, size_t n) {
  if (!names) {
    return;
  }
  for (size_t i = 0; i < n; i++) {
    free(names[i]);
  }
  free(names);
}

static int names_has(char **names, size_t n, const char *want) {
  for (size_t i = 0; i < n; i++) {
    if (strcmp(names[i], want) == 0) {
      return 1;
    }
  }
  return 0;
}

/* reconcileStaging at open: drop sidecars without a partial,
 * partials without a sidecar, and partials whose object is
 * already published. */
static murmur_files_status_t reconcile_staging(murmur_files_t *o,
                                               char **detail_out) {
  char *dir = join_path(o->dir, "staging");
  if (!dir) {
    return io_fail(detail_out);
  }
  size_t n = 0;
  char **names = dir_names(dir, &n);
  if (!names) {
    if (errno == ENOENT) {
      free(dir);
      return MURMUR_FILES_OK;
    }
    free(dir);
    return io_fail(detail_out);
  }
  murmur_files_status_t st = MURMUR_FILES_OK;
  for (size_t i = 0; i < n && st == MURMUR_FILES_OK; i++) {
    char *full = join_path(dir, names[i]);
    if (!full) {
      st = io_fail(detail_out);
      break;
    }
    if (has_suffix(names[i], ".identity")) {
      size_t stem = strlen(names[i]) - (sizeof(".identity") - 1);
      char *part = malloc(stem + sizeof(".part"));
      if (!part) {
        free(full);
        st = io_fail(detail_out);
        break;
      }
      memcpy(part, names[i], stem);
      strcpy(part + stem, ".part");
      if (!names_has(names, n, part)) {
        if (unlink(full) != 0 && errno != ENOENT) {
          st = io_fail(detail_out);
        }
      }
      free(part);
    } else if (has_suffix(names[i], ".part")) {
      size_t stem = strlen(names[i]) - (sizeof(".part") - 1);
      char *sidecar = malloc(stem + sizeof(".identity"));
      if (!sidecar) {
        free(full);
        st = io_fail(detail_out);
        break;
      }
      memcpy(sidecar, names[i], stem);
      strcpy(sidecar + stem, ".identity");
      if (!names_has(names, n, sidecar)) {
        if (unlink(full) != 0 && errno != ENOENT) {
          st = io_fail(detail_out);
        }
      } else {
        uint8_t digest[32];
        uint64_t gen = 0;
        if (parse_staging_name(names[i], digest, &gen)) {
          char *obj = object_path(o, digest, gen);
          struct stat ost;
          int published =
              obj && stat(obj, &ost) == 0 && !S_ISDIR(ost.st_mode);
          free(obj);
          if (published) {
            if (unlink(full) != 0 && errno != ENOENT) {
              st = io_fail(detail_out);
            } else {
              char *sp = join_path(dir, sidecar);
              if (!sp || (unlink(sp) != 0 && errno != ENOENT)) {
                st = io_fail(detail_out);
              }
              free(sp);
            }
          }
        }
      }
      free(sidecar);
    }
    free(full);
  }
  names_free(names, n);
  free(dir);
  return st;
}

murmur_files_status_t murmur_files_open(const murmur_files_config_t *config,
                                        sqlite3 *db, const murmur_node_t *self,
                                        murmur_files_t **out, char **detail_out,
                                        int *sqlrc) {
  *out = NULL;
  if (!config || !config->directory || !db || !self) {
    set_detail(detail_out, "file limits");
    return MURMUR_FILES_INVALID;
  }
  if (config->max_file_bytes == 0 ||
      config->max_staging_bytes < FILES_CHUNK ||
      config->concurrent_fetches == 0 || config->fetch_interval_ms == 0) {
    set_detail(detail_out, "file limits");
    return MURMUR_FILES_INVALID;
  }
  murmur_files_t *o = calloc(1, sizeof(*o));
  if (!o) {
    return io_fail(detail_out);
  }
  o->dir = strdup(config->directory);
  if (!o->dir) {
    free(o);
    return io_fail(detail_out);
  }
  memcpy(o->key, config->key, 32);
  if (config->previous_key) {
    memcpy(o->prev, config->previous_key, 32);
    o->has_prev = 1;
  }
  o->generation = config->generation;
  o->max_file = config->max_file_bytes;
  o->max_staging = config->max_staging_bytes;
  o->db = db;
  o->self = *self;
  pthread_mutex_init(&o->gate, NULL);
  pthread_mutex_init(&o->staged_mu, NULL);
  pthread_mutex_init(&o->usage_mu, NULL);
  pthread_mutex_init(&o->err_mu, NULL);

  /* The metadata table replicates: ensure it, make it a CRR,
   * then refuse old-generation metadata without its key. */
  int rc = 0;
  if (murmur_sync_ensure_schema(db, &rc) != MURMUR_SYNC_OK) {
    murmur_files_close(o);
    if (sqlrc) {
      *sqlrc = rc;
    }
    set_detail(detail_out, "store");
    return MURMUR_FILES_SQLITE;
  }
  static const uint8_t meta_table[] = "murmur_file_meta";
  murmur_sync_status_t st = murmur_schema_make_crr(
      db, meta_table, sizeof(meta_table) - 1, &rc);
  if (st != MURMUR_SYNC_OK) {
    murmur_files_close(o);
    if (sqlrc) {
      *sqlrc = rc;
    }
    set_detail(detail_out, "store");
    return MURMUR_FILES_SQLITE;
  }
  murmur_files_meta_t *existing = NULL;
  size_t n_existing = 0;
  murmur_files_status_t fs =
      meta_scan_all(o, &existing, &n_existing, detail_out, sqlrc);
  if (fs == MURMUR_FILES_OK) {
    for (size_t i = 0; i < n_existing && fs == MURMUR_FILES_OK; i++) {
      if (!existing[i].deleted && existing[i].generation < o->generation) {
        if (!o->has_prev) {
          set_detail(detail_out,
                     "previous file key is required while "
                     "old-generation metadata exists");
          fs = MURMUR_FILES_INVALID;
        } else if (existing[i].generation + 1 != o->generation) {
          set_detail(detail_out,
                     "file keys must rotate one generation at a time");
          fs = MURMUR_FILES_INVALID;
        }
      }
    }
  }
  murmur_files_meta_list_free(existing, n_existing);
  if (fs != MURMUR_FILES_OK) {
    murmur_files_close(o);
    return fs;
  }

  if (mkdir_all(o->dir, 0700) != 0) {
    fs = io_fail(detail_out);
    murmur_files_close(o);
    return fs;
  }
  fs = reconcile_staging(o, detail_out);
  if (fs != MURMUR_FILES_OK) {
    murmur_files_close(o);
    return fs;
  }
  *out = o;
  if (sqlrc) {
    *sqlrc = 0;
  }
  return MURMUR_FILES_OK;
}

const char *murmur_files_directory(const murmur_files_t *o) {
  return o ? o->dir : NULL;
}

char *murmur_files_object_path(murmur_files_t *o, const uint8_t digest[32],
                               uint64_t generation) {
  return o ? object_path(o, digest, generation) : NULL;
}

void murmur_files_close(murmur_files_t *o) {
  if (!o) {
    return;
  }
  for (size_t i = 0; i < o->n_staged; i++) {
    free(o->staged[i]);
  }
  free(o->staged);
  free(o->dir);
  free(o->last_err);
  pthread_mutex_destroy(&o->gate);
  pthread_mutex_destroy(&o->staged_mu);
  pthread_mutex_destroy(&o->usage_mu);
  pthread_mutex_destroy(&o->err_mu);
  memset(o->key, 0, sizeof(o->key));
  memset(o->prev, 0, sizeof(o->prev));
  free(o);
}

/* ---------- staging protection / reservations ---------- */

murmur_staged_transfer_t *murmur_files_protect_staging(murmur_files_t *o,
                                                       const char *path) {
  murmur_staged_transfer_t *t = calloc(1, sizeof(*t));
  if (!t) {
    return NULL;
  }
  t->o = o;
  char *sidecar = staging_identity_path(path);
  t->paths = calloc(2, sizeof(*t->paths));
  if (!sidecar || !t->paths) {
    free(sidecar);
    free(t->paths);
    free(t);
    return NULL;
  }
  t->paths[0] = strdup(path);
  t->paths[1] = sidecar;
  if (!t->paths[0]) {
    free(t->paths[1]);
    free(t->paths);
    free(t);
    return NULL;
  }
  t->n = 2;
  pthread_mutex_lock(&o->gate);
  staged_add(o, t->paths[0]);
  staged_add(o, t->paths[1]);
  pthread_mutex_unlock(&o->gate);
  return t;
}

void murmur_files_staged_release(murmur_staged_transfer_t *s) {
  if (!s || s->released) {
    return;
  }
  s->released = 1;
  for (size_t i = 0; i < s->n; i++) {
    staged_remove(s->o, s->paths[i]);
    free(s->paths[i]);
  }
  free(s->paths);
  free(s);
}

murmur_files_status_t murmur_files_reserve_staging(
    murmur_files_t *o, uint64_t n, murmur_staging_reservation_t **out) {
  *out = NULL;
  murmur_staging_reservation_t *r = calloc(1, sizeof(*r));
  if (!r) {
    return MURMUR_FILES_IO;
  }
  r->o = o;
  pthread_mutex_lock(&o->usage_mu);
  if (n > sat_sub(o->max_staging, o->staging_used)) {
    pthread_mutex_unlock(&o->usage_mu);
    free(r);
    return MURMUR_FILES_OVERLOADED;
  }
  o->staging_used += n;
  pthread_mutex_unlock(&o->usage_mu);
  r->bytes = n;
  *out = r;
  return MURMUR_FILES_OK;
}

void murmur_files_staging_release(murmur_staging_reservation_t *r) {
  if (!r || r->released) {
    return;
  }
  r->released = 1;
  murmur_files_t *o = r->o;
  pthread_mutex_lock(&o->usage_mu);
  if (o->staging_used < r->bytes) {
    o->staging_used = 0;
  } else {
    o->staging_used -= r->bytes;
  }
  pthread_mutex_unlock(&o->usage_mu);
  free(r);
}

void murmur_files_fetch_error(murmur_files_t *o, const char *msg) {
  char *cp = msg ? strdup(msg) : NULL;
  pthread_mutex_lock(&o->err_mu);
  free(o->last_err);
  o->last_err = cp;
  pthread_mutex_unlock(&o->err_mu);
}

char *murmur_files_last_fetch_error(murmur_files_t *o) {
  pthread_mutex_lock(&o->err_mu);
  char *cp = o->last_err ? strdup(o->last_err) : NULL;
  pthread_mutex_unlock(&o->err_mu);
  return cp;
}

/* ---------- upload ---------- */

struct murmur_file_upload_t {
  char *name;
  char *path;
  int fd;
  uint8_t derived[32];
  uint8_t header[FILES_HEADER_LEN];
  uint8_t prefix[8];
  murmur_sha256_t hash;
  uint64_t total;
  uint32_t index;
  uint64_t generation;
  uint64_t max;
  uint8_t *pending;
  size_t pending_len;
  murmur_staging_reservation_t *reserve;
  uint64_t staging_max;
  murmur_files_t *o;
  int dead; /* fd closed / cleaned up */
};

static void upload_cleanup(murmur_file_upload_t *u) {
  if (!u || u->dead) {
    return;
  }
  u->dead = 1;
  if (u->fd >= 0) {
    close(u->fd);
    u->fd = -1;
  }
  if (u->path) {
    unlink(u->path);
    staged_remove(u->o, u->path);
  }
  if (u->pending) {
    memset(u->pending, 0, FILES_CHUNK);
  }
  murmur_files_staging_release(u->reserve);
  u->reserve = NULL;
}

/* Gate held. */
static murmur_files_status_t upload_new(murmur_files_t *o, const char *name,
                                        murmur_file_upload_t **out,
                                        char **detail_out) {
  *out = NULL;
  murmur_files_status_t fs = check_file_name(name, detail_out);
  if (fs != MURMUR_FILES_OK) {
    return fs;
  }
  murmur_staging_reservation_t *res = NULL;
  fs = murmur_files_reserve_staging(o, 128, &res);
  if (fs != MURMUR_FILES_OK) {
    return fs;
  }
  murmur_file_upload_t *u = calloc(1, sizeof(*u));
  if (!u) {
    murmur_files_staging_release(res);
    return io_fail(detail_out);
  }
  u->fd = -1;
  u->o = o;
  u->reserve = res;
  u->name = strdup(name);
  u->pending = malloc(FILES_CHUNK);
  uint8_t id[16];
  if (!u->name || !u->pending || murmur_rand_bytes(id, 16) != 0) {
    free(u->name);
    free(u->pending);
    free(u);
    murmur_files_staging_release(res);
    return io_fail(detail_out);
  }
  char hex[33];
  hex_encode(id, 16, hex);
  size_t pn = strlen(o->dir) + sizeof("/.upload-") + 32;
  u->path = malloc(pn);
  if (!u->path) {
    free(u->name);
    free(u->pending);
    free(u);
    murmur_files_staging_release(res);
    return io_fail(detail_out);
  }
  snprintf(u->path, pn, "%s/.upload-%s", o->dir, hex);
  u->fd = private_file(u->path);
  if (u->fd < 0) {
    fs = io_fail(detail_out);
    free(u->name);
    free(u->pending);
    free(u->path);
    free(u);
    murmur_files_staging_release(res);
    return fs;
  }
  uint8_t salt[16];
  if (murmur_rand_bytes(salt, 16) != 0 ||
      object_key(o->key, salt, u->derived) != 0 ||
      murmur_rand_bytes(u->prefix, 8) != 0) {
    close(u->fd);
    unlink(u->path);
    free(u->name);
    free(u->pending);
    free(u->path);
    free(u);
    murmur_files_staging_release(res);
    return io_fail(detail_out);
  }
  memcpy(u->header, FILES_MAGIC, FILES_MAGIC_LEN);
  put_u64be(u->header + 8, o->generation);
  memcpy(u->header + 16, salt, 16);
  memcpy(u->header + 32, u->prefix, 8);
  if (write_all(u->fd, u->header, FILES_HEADER_LEN) != 0) {
    fs = io_fail(detail_out);
    close(u->fd);
    unlink(u->path);
    free(u->name);
    free(u->pending);
    free(u->path);
    free(u);
    murmur_files_staging_release(res);
    return fs;
  }
  murmur_sha256_init(&u->hash);
  u->generation = o->generation;
  u->max = o->max_file;
  u->staging_max = o->max_staging;
  staged_add(o, u->path);
  *out = u;
  return MURMUR_FILES_OK;
}

murmur_files_status_t murmur_files_begin_upload(murmur_files_t *o,
                                                const char *name,
                                                murmur_file_upload_t **out,
                                                char **detail_out, int *sqlrc) {
  (void)sqlrc;
  pthread_mutex_lock(&o->gate);
  murmur_files_status_t fs = upload_new(o, name, out, detail_out);
  pthread_mutex_unlock(&o->gate);
  return fs;
}

static murmur_files_status_t upload_flush(murmur_file_upload_t *u,
                                          char **detail_out) {
  if (u->pending_len == 0) {
    return MURMUR_FILES_OK;
  }
  uint8_t aad[FILES_HEADER_LEN + 4];
  memcpy(aad, u->header, FILES_HEADER_LEN);
  put_u32be(aad + FILES_HEADER_LEN, u->index);
  uint8_t nonce[12];
  file_nonce(u->prefix, u->index, nonce);
  size_t sealed_len = u->pending_len + 16;
  uint8_t *sealed = malloc(sealed_len);
  if (!sealed) {
    return io_fail(detail_out);
  }
  int rc = murmur_aes256gcm_seal(u->derived, nonce, u->pending, u->pending_len,
                                 aad, sizeof(aad), sealed);
  if (rc != 0) {
    free(sealed);
    return io_fail(detail_out);
  }
  uint8_t nb[4];
  put_u32be(nb, (uint32_t)sealed_len);
  if (write_all(u->fd, nb, 4) != 0 || write_all(u->fd, sealed, sealed_len)) {
    free(sealed);
    return io_fail(detail_out);
  }
  free(sealed);
  if (u->index == 0xFFFFFFFFu) {
    return MURMUR_FILES_OVERLOADED;
  }
  u->index++;
  memset(u->pending, 0, u->pending_len);
  u->pending_len = 0;
  return MURMUR_FILES_OK;
}

murmur_files_status_t murmur_files_upload_append(murmur_file_upload_t *u,
                                                 const uint8_t *p, size_t n,
                                                 char **detail_out) {
  if (u->dead) {
    set_detail(detail_out, "upload aborted");
    return MURMUR_FILES_IO;
  }
  uint64_t total = u->total + (uint64_t)n;
  if (total < u->total) {
    return MURMUR_FILES_OVERLOADED;
  }
  if (total > u->max) {
    return MURMUR_FILES_OVERLOADED;
  }
  uint64_t reserve =
      (uint64_t)n +
      (div_ceil(total, FILES_CHUNK) - div_ceil(u->total, FILES_CHUNK)) * 20;
  murmur_files_t *o = u->o;
  pthread_mutex_lock(&o->usage_mu);
  if (reserve > sat_sub(u->staging_max, o->staging_used)) {
    pthread_mutex_unlock(&o->usage_mu);
    return MURMUR_FILES_OVERLOADED;
  }
  o->staging_used += reserve;
  pthread_mutex_unlock(&o->usage_mu);
  u->reserve->bytes += reserve;
  murmur_sha256_update(&u->hash, p, n);
  u->total = total;
  while (n > 0) {
    size_t take = FILES_CHUNK - u->pending_len;
    if (take > n) {
      take = n;
    }
    memcpy(u->pending + u->pending_len, p, take);
    u->pending_len += take;
    p += take;
    n -= take;
    if (u->pending_len == FILES_CHUNK) {
      murmur_files_status_t fs = upload_flush(u, detail_out);
      if (fs != MURMUR_FILES_OK) {
        return fs;
      }
    }
  }
  return MURMUR_FILES_OK;
}

/* Gate held. Consumes the upload either way. */
static murmur_files_status_t upload_finish(murmur_files_t *o,
                                           murmur_file_upload_t *u,
                                           murmur_files_meta_t *meta_out,
                                           char **detail_out, int *sqlrc,
 murmur_files_commit_fn commit,void *commit_ctx) {
  murmur_files_status_t fs = upload_flush(u, detail_out);
  uint8_t digest[32];
  uint8_t *terminal = NULL;
  size_t terminal_len = 0;
  uint8_t *sealed = NULL;
  char *objpath = NULL;
  if (fs == MURMUR_FILES_OK) {
    murmur_sha256_final(&u->hash, digest);
  }
  if (fs == MURMUR_FILES_OK) {
    murmur_pc_enc_t e;
    murmur_pc_enc_init(&e);
    murmur_pc_u64(&e, u->total);
    murmur_pc_raw(&e, digest, 32);
    terminal = e.b;
    terminal_len = e.len;
    uint8_t aad[FILES_HEADER_LEN + 4 + 5];
    memcpy(aad, u->header, FILES_HEADER_LEN);
    put_u32be(aad + FILES_HEADER_LEN, u->index);
    memcpy(aad + FILES_HEADER_LEN + 4, "final", 5);
    uint8_t nonce[12];
    file_nonce(u->prefix, u->index, nonce);
    sealed = malloc(terminal_len + 16);
    if (!sealed ||
        murmur_aes256gcm_seal(u->derived, nonce, terminal, terminal_len, aad,
                              sizeof(aad), sealed) != 0) {
      fs = io_fail(detail_out);
    }
  }
  if (fs == MURMUR_FILES_OK) {
    uint8_t mark[4], nb[4];
    put_u32be(mark, 0xFFFFFFFFu);
    put_u32be(nb, (uint32_t)(terminal_len + 16));
    if (write_all(u->fd, mark, 4) != 0 ||
        write_all(u->fd, nb, 4) != 0 ||
        write_all(u->fd, sealed, terminal_len + 16) != 0 ||
        fsync(u->fd) != 0) {
      fs = io_fail(detail_out);
    }
  }
  if (sealed) {
    memset(sealed, 0, terminal_len + 16);
    free(sealed);
  }
  free(terminal);
  if (fs == MURMUR_FILES_OK) {
    close(u->fd);
    u->fd = -1;
    objpath = object_path(o, digest, u->generation);
    if (!objpath) {
      fs = io_fail(detail_out);
    }
  }
  if (fs == MURMUR_FILES_OK) {
    struct stat st;
    if (stat(objpath, &st) == 0) {
      unlink(u->path);
    } else {
      if (rename(u->path, objpath) != 0) {
        fs = io_fail(detail_out);
      } else if (sync_directory(o->dir) != 0) {
        fs = io_fail(detail_out);
      }
    }
  }
  if (fs == MURMUR_FILES_OK) {
    murmur_files_meta_t meta;
    memset(&meta, 0, sizeof(meta));
    meta.name = u->name;
    memcpy(meta.digest, digest, 32);
    meta.bytes = u->total;
    meta.generation = u->generation;
    meta.millis = files_now_ms();
    meta.node = o->self;
    murmur_db_writer_lock();
    int rc=SQLITE_OK;
    int began=0;
    if(commit) {
      rc=sqlite3_get_autocommit(o->db) ? sqlite3_exec(o->db,"BEGIN IMMEDIATE",NULL,NULL,NULL) : SQLITE_MISUSE;
      began=rc==SQLITE_OK;
      if(rc==SQLITE_OK) rc=commit(o->db,&meta,commit_ctx);
    }
    fs=rc==SQLITE_OK ? meta_put(o,&meta,detail_out,sqlrc) : sql_fail(rc,detail_out,sqlrc);
    if(began) {
      if(fs==MURMUR_FILES_OK) {
        rc=sqlite3_exec(o->db,"COMMIT",NULL,NULL,NULL);
        if(rc!=SQLITE_OK) fs=sql_fail(rc,detail_out,sqlrc);
      }
      if(!sqlite3_get_autocommit(o->db)) sqlite3_exec(o->db,"ROLLBACK",NULL,NULL,NULL);
      if(fs==MURMUR_FILES_OK) {
        const char *path=sqlite3_db_filename(o->db,"main");
        if(path && *path && nvFlushDb(path)) fs=sql_fail(SQLITE_IOERR_FSYNC,detail_out,sqlrc);
      }
    }
    murmur_db_writer_unlock();
    if (fs == MURMUR_FILES_OK && meta_out) {
      memset(meta_out, 0, sizeof(*meta_out));
      meta_out->name = strdup(u->name);
      if (!meta_out->name) {
        fs = io_fail(detail_out);
      } else {
        memcpy(meta_out->digest, digest, 32);
        meta_out->bytes = u->total;
        meta_out->generation = u->generation;
        meta_out->millis = meta.millis;
        meta_out->node = o->self;
      }
    }
  }
  free(objpath);
  upload_cleanup(u);
  /* upload_cleanup unlinks u->path; after a rename that path is
   * gone and unlink fails silently, matching Go's os.Remove. */
  free(u->name);
  free(u->pending);
  free(u->path);
  memset(u->derived, 0, sizeof(u->derived));
  free(u);
  return fs;
}

murmur_files_status_t murmur_files_finish_upload(
    murmur_files_t *o, murmur_file_upload_t *u, murmur_files_meta_t *meta_out,
    char **detail_out, int *sqlrc) {
  if (!u || u->o != o) {
    set_detail(detail_out, "upload belongs to another object store");
    return MURMUR_FILES_INVALID;
  }
  pthread_mutex_lock(&o->gate);
  murmur_files_status_t fs = upload_finish(o, u, meta_out, detail_out, sqlrc, NULL, NULL);
  pthread_mutex_unlock(&o->gate);
  return fs;
}

murmur_files_status_t murmur_files_finish_upload_atomic(
    murmur_files_t *o,murmur_file_upload_t *u,murmur_files_commit_fn commit,void *ctx,
    murmur_files_meta_t *meta_out,char **detail_out,int *sqlrc) {
  if(!o || !u || u->o!=o || !commit) return MURMUR_FILES_INVALID;
  pthread_mutex_lock(&o->gate);
  murmur_files_status_t fs=upload_finish(o,u,meta_out,detail_out,sqlrc,commit,ctx);
  pthread_mutex_unlock(&o->gate);
  return fs;
}

void murmur_files_upload_abort(murmur_file_upload_t *u) {
  if (!u) {
    return;
  }
  upload_cleanup(u);
  free(u->name);
  free(u->pending);
  free(u->path);
  memset(u->derived, 0, sizeof(u->derived));
  free(u);
}

/* Gate held. */
static murmur_files_status_t upload_inner(murmur_files_t *o, const char *name,
                                          murmur_files_read_fn read, void *ctx,
                                          murmur_files_meta_t *meta_out,
                                          char **detail_out, int *sqlrc) {
  murmur_file_upload_t *u = NULL;
  murmur_files_status_t fs = upload_new(o, name, &u, detail_out);
  if (fs != MURMUR_FILES_OK) {
    return fs;
  }
  uint8_t *buf = malloc(FILES_CHUNK);
  if (!buf) {
    murmur_files_upload_abort(u);
    return io_fail(detail_out);
  }
  for (;;) {
    size_t n = 0;
    int eof = 0;
    if (read(ctx, buf, FILES_CHUNK, &n, &eof) != 0) {
      murmur_files_upload_abort(u);
      free(buf);
      return io_fail(detail_out);
    }
    if (n > 0) {
      fs = murmur_files_upload_append(u, buf, n, detail_out);
      if (fs != MURMUR_FILES_OK) {
        murmur_files_upload_abort(u);
        free(buf);
        return fs;
      }
    }
    if (eof) {
      break;
    }
    if (n == 0) {
      /* No progress and no EOF: avoid a spin; treat as EOF. */
      break;
    }
  }
  free(buf);
  return upload_finish(o, u, meta_out, detail_out, sqlrc, NULL, NULL);
}

murmur_files_status_t murmur_files_upload_one(
    murmur_files_t *o, const char *name, murmur_files_read_fn read, void *ctx,
    murmur_files_meta_t *meta_out, char **detail_out, int *sqlrc) {
  pthread_mutex_lock(&o->gate);
  murmur_files_status_t fs =
      upload_inner(o, name, read, ctx, meta_out, detail_out, sqlrc);
  pthread_mutex_unlock(&o->gate);
  return fs;
}

/* ---------- verify ---------- */

/* Authenticates one open container, streaming plaintext to output
 * (nullable). Matches verifyInput exactly, including the trailing
 * byte check and the total guards. */
static murmur_files_status_t verify_fd(murmur_files_t *o, int fd,
                                       const murmur_files_meta_t *meta,
                                       murmur_files_write_fn output, void *ctx,
                                       char **detail_out) {
  uint8_t header[FILES_HEADER_LEN];
  ssize_t r = read_exact(fd, header, sizeof(header));
  if (r < 0) {
    return io_fail(detail_out);
  }
  if (r != (ssize_t)sizeof(header)) {
    set_detail(detail_out, "object header");
    return MURMUR_FILES_AUTH;
  }
  if (memcmp(header, FILES_MAGIC, FILES_MAGIC_LEN) != 0) {
    set_detail(detail_out, "object header");
    return MURMUR_FILES_AUTH;
  }
  uint64_t generation = get_u64be(header + 8);
  const uint8_t *key = NULL;
  if (generation == o->generation) {
    key = o->key;
  } else if (generation + 1 == o->generation && o->has_prev) {
    key = o->prev;
  } else if (generation + 1 == o->generation) {
    set_detail(detail_out, "object key unavailable");
    return MURMUR_FILES_AUTH;
  } else {
    set_detail(detail_out, "object key generation");
    return MURMUR_FILES_AUTH;
  }
  uint8_t derived[32];
  if (object_key(key, header + 16, derived) != 0) {
    return io_fail(detail_out);
  }
  uint8_t prefix[8];
  memcpy(prefix, header + 32, 8);
  murmur_sha256_t hash;
  murmur_sha256_init(&hash);
  uint64_t total = 0;
  uint32_t index = 0;
  murmur_files_status_t fs = MURMUR_FILES_OK;
  for (;;) {
    uint8_t nb[4];
    r = read_exact(fd, nb, 4);
    if (r < 0) {
      fs = io_fail(detail_out);
      break;
    }
    if (r != 4) {
      set_detail(detail_out, "object chunk length");
      fs = MURMUR_FILES_AUTH;
      break;
    }
    uint32_t size = get_u32be(nb);
    int final = (size == 0xFFFFFFFFu);
    if (final) {
      r = read_exact(fd, nb, 4);
      if (r < 0) {
        fs = io_fail(detail_out);
        break;
      }
      if (r != 4) {
        set_detail(detail_out, "object chunk length");
        fs = MURMUR_FILES_AUTH;
        break;
      }
      size = get_u32be(nb);
    }
    if (size > FILES_CHUNK + 16 || size < 16) {
      set_detail(detail_out, "object chunk length");
      fs = MURMUR_FILES_AUTH;
      break;
    }
    uint8_t *enc = malloc(size);
    if (!enc) {
      fs = io_fail(detail_out);
      break;
    }
    r = read_exact(fd, enc, size);
    if (r < 0) {
      free(enc);
      fs = io_fail(detail_out);
      break;
    }
    if (r != (ssize_t)size) {
      free(enc);
      set_detail(detail_out, "object chunk length");
      fs = MURMUR_FILES_AUTH;
      break;
    }
    uint8_t aad[FILES_HEADER_LEN + 4 + 5];
    memcpy(aad, header, FILES_HEADER_LEN);
    put_u32be(aad + FILES_HEADER_LEN, index);
    size_t aad_len = FILES_HEADER_LEN + 4;
    if (final) {
      memcpy(aad + FILES_HEADER_LEN + 4, "final", 5);
      aad_len += 5;
    }
    uint8_t nonce[12];
    file_nonce(prefix, index, nonce);
    size_t plain_len = size - 16;
    uint8_t *plain = plain_len ? malloc(plain_len) : NULL;
    if (plain_len && !plain) {
      free(enc);
      fs = io_fail(detail_out);
      break;
    }
    int rc =
        murmur_aes256gcm_open(derived, nonce, enc, size, aad, aad_len, plain);
    memset(enc, 0, size);
    free(enc);
    if (rc != 0) {
      free(plain);
      set_detail(detail_out, "object authentication");
      fs = MURMUR_FILES_AUTH;
      break;
    }
    if (final) {
      murmur_pc_dec_t d;
      murmur_pc_dec_init(&d, plain, plain_len);
      uint64_t length = murmur_pc_g_u64(&d);
      const uint8_t *dg = murmur_pc_g_raw(&d, 32);
      murmur_pc_status_t derr = murmur_pc_end(&d);
      if (derr != MURMUR_PC_OK || d.err != MURMUR_PC_OK || !dg) {
        free(plain);
        set_detail(detail_out, "object terminal");
        fs = MURMUR_FILES_PROTOCOL;
        break;
      }
      uint8_t sum[32];
      murmur_sha256_final(&hash, sum);
      uint8_t one[1];
      ssize_t trailing = read(fd, one, 1);
      int bad = (length != total || length != meta->bytes ||
                 memcmp(dg, meta->digest, 32) != 0 ||
                 memcmp(sum, dg, 32) != 0 || trailing != 0);
      memset(sum, 0, sizeof(sum));
      free(plain);
      if (trailing < 0) {
        fs = io_fail(detail_out);
        break;
      }
      if (bad) {
        set_detail(detail_out, "object length or digest");
        fs = MURMUR_FILES_AUTH;
        break;
      }
      memset(derived, 0, sizeof(derived));
      return MURMUR_FILES_OK;
    }
    if (total + (uint64_t)plain_len < total) {
      free(plain);
      fs = MURMUR_FILES_OVERLOADED;
      break;
    }
    total += (uint64_t)plain_len;
    if (total > meta->bytes || total > o->max_file) {
      free(plain);
      fs = MURMUR_FILES_OVERLOADED;
      break;
    }
    murmur_sha256_update(&hash, plain, plain_len);
    if (output && output(ctx, plain, plain_len) != 0) {
      free(plain);
      fs = io_fail(detail_out);
      break;
    }
    free(plain);
    if (index == 0xFFFFFFFFu) {
      fs = MURMUR_FILES_OVERLOADED;
      break;
    }
    index++;
  }
  memset(derived, 0, sizeof(derived));
  return fs;
}

murmur_files_status_t murmur_files_verify(murmur_files_t *o, const char *path,
                                           const murmur_files_meta_t *meta,
                                           murmur_files_write_fn output,
                                           void *ctx, char **detail_out,
                                           int *sqlrc) {
  (void)sqlrc;
  int fd = open(path, O_RDONLY);
  if (fd < 0) {
    set_detail(detail_out, "file payload unavailable");
    return MURMUR_FILES_UNAVAILABLE;
  }
  murmur_files_status_t fs = verify_fd(o, fd, meta, output, ctx, detail_out);
  close(fd);
  return fs;
}

/* ---------- download ---------- */

struct murmur_file_download_t {
  murmur_files_meta_t meta;
  int fd;
  uint8_t derived[32];
  uint8_t header[FILES_HEADER_LEN];
  uint8_t prefix[8];
  uint32_t index;
  uint64_t offset;
  uint8_t *pending;
  size_t pending_len;
  size_t pending_pos;
  char *pin;
  murmur_files_t *o;
  int closed;
};

const murmur_files_meta_t *murmur_files_download_metadata(const murmur_file_download_t *d) {
  return d ? &d->meta : NULL;
}
sqlite3 *murmur_files_database(const murmur_files_t *o) {return o ? o->db : NULL;}
uint64_t murmur_files_download_bytes(const murmur_file_download_t *d) {
  return d->meta.bytes;
}

murmur_files_status_t murmur_files_download(murmur_files_t *o,
                                             const char *name,
                                             murmur_file_download_t **out,
                                             char **detail_out, int *sqlrc) {
  *out = NULL;
  pthread_mutex_lock(&o->gate);
  murmur_files_status_t fs;
  murmur_files_meta_t meta;
  memset(&meta, 0, sizeof(meta));
  int found = 0;
  char *objpath = NULL;
  murmur_file_download_t *d = NULL;
  fs = murmur_files_metadata(o, name, &meta, &found, detail_out, sqlrc);
  if (fs != MURMUR_FILES_OK) {
    goto done;
  }
  if (!found || meta.deleted) {
    set_detail(detail_out, "file metadata missing");
    fs = MURMUR_FILES_UNAVAILABLE;
    goto done;
  }
  objpath = object_path(o, meta.digest, meta.generation);
  if (!objpath) {
    fs = io_fail(detail_out);
    goto done;
  }
  int fd = open(objpath, O_RDONLY);
  if (fd < 0) {
    set_detail(detail_out,
               "file payload unavailable; retry after background fetching");
    fs = MURMUR_FILES_UNAVAILABLE;
    goto done;
  }
  fs = verify_fd(o, fd, &meta, NULL, NULL, detail_out);
  if (fs != MURMUR_FILES_OK) {
    close(fd);
    goto done;
  }
  if (lseek(fd, 0, SEEK_SET) != 0) {
    close(fd);
    fs = io_fail(detail_out);
    goto done;
  }
  uint8_t header[FILES_HEADER_LEN];
  if (read_exact(fd, header, sizeof(header)) !=
      (ssize_t)sizeof(header)) {
    close(fd);
    fs = io_fail(detail_out);
    goto done;
  }
  /* Key selection follows the metadata generation here (unlike
   * verify, which follows the container header). */
  const uint8_t *key = NULL;
  if (meta.generation == o->generation) {
    key = o->key;
  } else if (o->has_prev) {
    key = o->prev;
  } else {
    close(fd);
    set_detail(detail_out, "object key unavailable");
    fs = MURMUR_FILES_AUTH;
    goto done;
  }
  d = calloc(1, sizeof(*d));
  if (!d) {
    close(fd);
    fs = io_fail(detail_out);
    goto done;
  }
  d->fd = -1;
  if (object_key(key, header + 16, d->derived) != 0) {
    close(fd);
    free(d);
    d = NULL;
    fs = io_fail(detail_out);
    goto done;
  }
  uint8_t id[16];
  if (murmur_rand_bytes(id, 16) != 0) {
    close(fd);
    free(d);
    d = NULL;
    fs = io_fail(detail_out);
    goto done;
  }
  char hex[33];
  hex_encode(id, 16, hex);
  size_t pn = strlen(o->dir) + sizeof("/.download-") + 32;
  d->pin = malloc(pn);
  if (!d->pin) {
    close(fd);
    free(d);
    d = NULL;
    fs = io_fail(detail_out);
    goto done;
  }
  snprintf(d->pin, pn, "%s/.download-%s", o->dir, hex);
  if (link(objpath, d->pin) != 0) {
    close(fd);
    free(d->pin);
    free(d);
    d = NULL;
    fs = io_fail(detail_out);
    goto done;
  }
  d->fd = fd;
  d->meta = meta;
  memset(&meta, 0, sizeof(meta));
  memcpy(d->header, header, sizeof(header));
  memcpy(d->prefix, header + 32, 8);
  d->o = o;
  staged_add(o, d->pin);
  *out = d;
  fs = MURMUR_FILES_OK;
done:
  pthread_mutex_unlock(&o->gate);
  murmur_files_meta_free(&meta);
  free(objpath);
  return fs;
}

murmur_files_status_t murmur_files_download_next(
    murmur_file_download_t *d, size_t limit, uint64_t *start_out,
    uint8_t *out_buf, size_t *n_out, int *done_out, char **detail_out) {
  *n_out = 0;
  *done_out = 0;
  if (d->closed) {
    set_detail(detail_out, "download closed");
    return MURMUR_FILES_IO;
  }
  if (limit == 0 || limit > FILES_DOWNLOAD_LIMIT) {
    set_detail(detail_out, "file chunk limit");
    return MURMUR_FILES_INVALID;
  }
  uint64_t start = d->offset;
  size_t out = 0;
  while (out < limit && d->offset < d->meta.bytes) {
    if (d->pending_pos == d->pending_len) {
      uint8_t nb[4];
      if (read_exact(d->fd, nb, 4) != 4) {
        return io_fail(detail_out);
      }
      uint32_t n = get_u32be(nb);
      if (n < 16 || n > FILES_CHUNK + 16) {
        set_detail(detail_out, "object chunk length");
        return MURMUR_FILES_AUTH;
      }
      uint8_t *enc = malloc(n);
      if (!enc) {
        return io_fail(detail_out);
      }
      ssize_t r = read_exact(d->fd, enc, n);
      if (r != (ssize_t)n) {
        free(enc);
        return io_fail(detail_out);
      }
      uint8_t aad[FILES_HEADER_LEN + 4];
      memcpy(aad, d->header, FILES_HEADER_LEN);
      put_u32be(aad + FILES_HEADER_LEN, d->index);
      uint8_t nonce[12];
      file_nonce(d->prefix, d->index, nonce);
      size_t plain_len = n - 16;
      uint8_t *plain = plain_len ? malloc(plain_len) : NULL;
      if (plain_len && !plain) {
        free(enc);
        return io_fail(detail_out);
      }
      int rc = murmur_aes256gcm_open(d->derived, nonce, enc, n, aad,
                                     sizeof(aad), plain);
      memset(enc, 0, n);
      free(enc);
      if (rc != 0) {
        free(plain);
        set_detail(detail_out, "object authentication");
        return MURMUR_FILES_AUTH;
      }
      if (d->pending) {
        memset(d->pending, 0, d->pending_len);
        free(d->pending);
      }
      d->pending = plain;
      d->pending_len = plain_len;
      d->pending_pos = 0;
      d->index++;
    }
    size_t take = limit - out;
    if (take > d->pending_len - d->pending_pos) {
      take = d->pending_len - d->pending_pos;
    }
    memcpy(out_buf + out, d->pending + d->pending_pos, take);
    d->pending_pos += take;
    d->offset += (uint64_t)take;
    out += take;
    if (d->pending_pos == d->pending_len) {
      memset(d->pending, 0, d->pending_len);
      free(d->pending);
      d->pending = NULL;
      d->pending_len = 0;
      d->pending_pos = 0;
    }
  }
  *start_out = start;
  *n_out = out;
  *done_out = (d->offset == d->meta.bytes);
  return MURMUR_FILES_OK;
}

void murmur_files_download_close(murmur_file_download_t *d) {
  if (!d || d->closed) {
    return;
  }
  d->closed = 1;
  if (d->fd >= 0) {
    close(d->fd);
  }
  if (d->pin) {
    unlink(d->pin);
    staged_remove(d->o, d->pin);
    free(d->pin);
  }
  if (d->pending) {
    memset(d->pending, 0, d->pending_len);
    free(d->pending);
  }
  murmur_files_meta_free(&d->meta);
  memset(d->derived, 0, sizeof(d->derived));
  free(d);
}

/* ---------- metadata verbs ---------- */

murmur_files_status_t murmur_files_metadata(murmur_files_t *o,
                                             const char *name,
                                             murmur_files_meta_t *meta_out,
                                             int *found, char **detail_out,
                                             int *sqlrc) {
  *found = 0;
  memset(meta_out, 0, sizeof(*meta_out));
  murmur_files_status_t fs = check_file_name(name, detail_out);
  if (fs != MURMUR_FILES_OK) {
    return fs;
  }
  return meta_get(o, name, meta_out, found, detail_out, sqlrc);
}

murmur_files_status_t murmur_files_list(murmur_files_t *o,
                                        murmur_files_meta_t **out, size_t *n,
                                        char **detail_out, int *sqlrc) {
  *out = NULL;
  *n = 0;
  murmur_files_meta_t *all = NULL;
  size_t nall = 0;
  murmur_files_status_t fs =
      meta_scan_all(o, &all, &nall, detail_out, sqlrc);
  if (fs != MURMUR_FILES_OK) {
    return fs;
  }
  /* Already in name order; drop tombstones in place. */
  size_t count = 0;
  for (size_t i = 0; i < nall; i++) {
    if (all[i].deleted) {
      murmur_files_meta_free(&all[i]);
      continue;
    }
    if (count != i) {
      all[count] = all[i];
      memset(&all[i], 0, sizeof(all[i]));
    }
    count++;
  }
  *out = all;
  *n = count;
  return MURMUR_FILES_OK;
}

static murmur_files_status_t murmur_files_list_bounded_inner(murmur_files_t *o,
                                                size_t max_bytes,
                                                murmur_files_meta_t **out,
                                                size_t *n, char **detail_out,
                                                int *sqlrc) {
  *out = NULL;
  *n = 0;
  murmur_files_meta_t *ms = NULL;
  size_t count = 0, cap = 0;
  size_t used = 0;
  char *after = NULL;
  murmur_files_status_t fs = MURMUR_FILES_OK;
  /* Name-ordered pages of 256, mirroring KeysPage's bounded
   * cursor traversal. */
  for (;;) {
    sqlite3_stmt *st = NULL;
    int rc = sqlite3_prepare_v2(
        o->db,
        after ? "SELECT name,meta FROM murmur_file_meta WHERE name>?1 "
                "ORDER BY name LIMIT 256"
              : "SELECT name,meta FROM murmur_file_meta ORDER BY name "
                "LIMIT 256",
        -1, &st, NULL);
    if (rc != SQLITE_OK) {
      fs = sql_fail(rc, detail_out, sqlrc);
      break;
    }
    if (after) {
      sqlite3_bind_text(st, 1, after, -1, SQLITE_TRANSIENT);
    }
    size_t npage = 0;
    char *last = NULL;
    for (;;) {
      rc = sqlite3_step(st);
      if (rc == SQLITE_DONE) {
        break;
      }
      if (rc != SQLITE_ROW) {
        fs = sql_fail(rc, detail_out, sqlrc);
        break;
      }
      const uint8_t *blob = sqlite3_column_blob(st, 1);
      size_t blen = (size_t)sqlite3_column_bytes(st, 1);
      murmur_files_meta_t meta;
      memset(&meta, 0, sizeof(meta));
      fs = meta_from_wire(blob, blen, &meta, detail_out);
      if (fs != MURMUR_FILES_OK) {
        break;
      }
      free(last);
      last = strdup((const char *)sqlite3_column_text(st, 0));
      npage++;
      if (!meta.deleted) {
        size_t add = strlen(meta.name) + 256;
        if (used + add < used) {
          murmur_files_meta_free(&meta);
          fs = MURMUR_FILES_OVERLOADED;
          break;
        }
        used += add;
        if (used > max_bytes) {
          murmur_files_meta_free(&meta);
          fs = MURMUR_FILES_OVERLOADED;
          break;
        }
        if (count == cap) {
          size_t ncap = cap ? cap * 2 : 16;
          murmur_files_meta_t *next = realloc(ms, ncap * sizeof(*next));
          if (!next) {
            murmur_files_meta_free(&meta);
            set_detail(detail_out, "file list");
            fs = MURMUR_FILES_IO;
            break;
          }
          ms = next;
          cap = ncap;
        }
        ms[count++] = meta;
      } else {
        murmur_files_meta_free(&meta);
      }
    }
    sqlite3_finalize(st);
    if (fs != MURMUR_FILES_OK) {
      free(last);
      break;
    }
    free(after);
    after = last;
    if (npage < 256) {
      break;
    }
  }
  free(after);
  if (fs != MURMUR_FILES_OK) {
    murmur_files_meta_list_free(ms, count);
    return fs;
  }
  /* Pages arrive in name order; no re-sort needed. */
  *out = ms;
  *n = count;
  if (sqlrc) {
    *sqlrc = SQLITE_OK;
  }
  return MURMUR_FILES_OK;
}
murmur_files_status_t murmur_files_list_bounded(murmur_files_t *o,size_t max_bytes,murmur_files_meta_t **out,size_t *n,char **detail_out,int *sqlrc) {
  murmur_db_writer_lock();
  murmur_files_status_t fs=murmur_files_list_bounded_inner(o,max_bytes,out,n,detail_out,sqlrc);
  murmur_db_writer_unlock();
  return fs;
}


murmur_files_status_t murmur_files_available(murmur_files_t *o,
                                             const char *name, int *avail,
                                             char **detail_out, int *sqlrc) {
  *avail = 0;
  murmur_files_meta_t meta;
  memset(&meta, 0, sizeof(meta));
  int found = 0;
  murmur_files_status_t fs =
      murmur_files_metadata(o, name, &meta, &found, detail_out, sqlrc);
  if (fs != MURMUR_FILES_OK) {
    return fs;
  }
  if (!found || meta.deleted) {
    return MURMUR_FILES_OK;
  }
  char *path = object_path(o, meta.digest, meta.generation);
  murmur_files_meta_free(&meta);
  if (!path) {
    return io_fail(detail_out);
  }
  struct stat st;
  *avail = (stat(path, &st) == 0 && !S_ISDIR(st.st_mode));
  free(path);
  return MURMUR_FILES_OK;
}

static int node_cmp(const void *a, const void *b) {
  return memcmp(a, b, 16);
}

murmur_files_status_t murmur_files_availability(murmur_files_t *o,
                                                const char *name,
                                                murmur_file_avail_t *avail_out,
                                                char **detail_out, int *sqlrc) {
  memset(avail_out, 0, sizeof(*avail_out));
  avail_out->kind = MURMUR_FILE_UNAVAILABLE;
  murmur_files_meta_t meta;
  memset(&meta, 0, sizeof(meta));
  int found = 0;
  murmur_files_status_t fs =
      murmur_files_metadata(o, name, &meta, &found, detail_out, sqlrc);
  if (fs != MURMUR_FILES_OK) {
    return fs;
  }
  if (!found || meta.deleted) {
    return MURMUR_FILES_OK;
  }
  char *path = object_path(o, meta.digest, meta.generation);
  if (!path) {
    murmur_files_meta_free(&meta);
    return io_fail(detail_out);
  }
  struct stat st;
  int local = (stat(path, &st) == 0 && !S_ISDIR(st.st_mode));
  free(path);
  if (local) {
    avail_out->kind = MURMUR_FILE_LOCAL;
    murmur_files_meta_free(&meta);
    return MURMUR_FILES_OK;
  }
  char *prefix = avail_prefix(meta.digest, meta.generation);
  murmur_files_meta_free(&meta);
  if (!prefix) {
    return io_fail(detail_out);
  }
  uint64_t cutoff = sat_sub(files_now_ms(), FILES_AVAIL_WINDOW_MS);
  uint8_t **keys = NULL;
  size_t *key_lens = NULL;
  size_t nkeys = 0;
  int rc = 0;
  murmur_sync_status_t kst =
      murmur_kv_keys(o->db, (const uint8_t *)prefix, strlen(prefix), &keys,
                     &key_lens, &nkeys, &rc);
  if (kst != MURMUR_SYNC_OK) {
    free(prefix);
    return kv_fail(kst, detail_out, sqlrc, rc);
  }
  murmur_node_t *peers = NULL;
  size_t npeers = 0, cap = 0;
  fs = MURMUR_FILES_OK;
  for (size_t i = 0; i < nkeys && fs == MURMUR_FILES_OK; i++) {
    uint8_t *raw = NULL;
    size_t raw_len = 0;
    int got = 0;
    fs = files_get(o, keys[i], key_lens[i], &raw, &raw_len, &got, detail_out,
                   sqlrc);
    if (fs != MURMUR_FILES_OK) {
      break;
    }
    if (!got || !raw) {
      free(raw);
      continue;
    }
    murmur_pc_dec_t d;
    murmur_pc_dec_init(&d, raw, raw_len);
    uint64_t seen = murmur_pc_g_u64(&d);
    murmur_pc_status_t derr = murmur_pc_end(&d);
    int dec_ok = (derr == MURMUR_PC_OK && d.err == MURMUR_PC_OK);
    free(raw);
    if (!dec_ok) {
      set_detail(detail_out, "file availability");
      fs = MURMUR_FILES_PROTOCOL;
      break;
    }
    if (seen >= cutoff) {
      /* Last path segment is the lowercase node hex. */
      const uint8_t *key = keys[i];
      size_t kl = key_lens[i];
      size_t start = kl;
      while (start > 0 && key[start - 1] != '/') {
        start--;
      }
      murmur_node_t node;
      if (decode_hex_node((const char *)key + start, kl - start, &node)) {
        if (npeers == cap) {
          size_t ncap = cap ? cap * 2 : 8;
          murmur_node_t *next = realloc(peers, ncap * sizeof(*next));
          if (!next) {
            set_detail(detail_out, "file availability");
            fs = MURMUR_FILES_IO;
            break;
          }
          peers = next;
          cap = ncap;
        }
        peers[npeers++] = node;
      }
    }
  }
  murmur_kv_keys_free(keys, key_lens, nkeys);
  free(prefix);
  if (fs != MURMUR_FILES_OK) {
    free(peers);
    return fs;
  }
  qsort(peers, npeers, sizeof(*peers), node_cmp);
  size_t unique = 0;
  for (size_t i = 0; i < npeers; i++) {
    if (i == 0 || memcmp(&peers[i], &peers[i - 1], 16) != 0) {
      peers[unique++] = peers[i];
    }
  }
  if (unique == 0) {
    free(peers);
    return MURMUR_FILES_OK;
  }
  avail_out->kind = MURMUR_FILE_REMOTE;
  avail_out->remote = peers;
  avail_out->n_remote = unique;
  return MURMUR_FILES_OK;
}

murmur_files_status_t murmur_files_record_peer(
    murmur_files_t *o, const uint8_t digest[32], uint64_t generation,
    const murmur_node_t *node, int available, char **detail_out, int *sqlrc) {
  char *prefix = avail_prefix(digest, generation);
  if (!prefix) {
    return io_fail(detail_out);
  }
  char hex[33];
  hex_encode(node->b, 16, hex);
  size_t n = strlen(prefix) + 32 + 1;
  char *key = malloc(n);
  if (!key) {
    free(prefix);
    return io_fail(detail_out);
  }
  snprintf(key, n, "%s%s", prefix, hex);
  free(prefix);
  murmur_files_status_t fs;
  if (available) {
    murmur_pc_enc_t e;
    murmur_pc_enc_init(&e);
    murmur_pc_u64(&e, files_now_ms());
    fs = files_write_record(o, (const uint8_t *)key, strlen(key), e.b, e.len,
                            0, detail_out, sqlrc);
    murmur_pc_enc_finish(&e);
  } else {
    fs = files_write_record(o, (const uint8_t *)key, strlen(key), NULL, 0, 1,
                            detail_out, sqlrc);
  }
  free(key);
  return fs;
}

murmur_files_status_t murmur_files_delete(murmur_files_t *o, const char *name,
                                           char **detail_out, int *sqlrc) {
  pthread_mutex_lock(&o->gate);
  murmur_files_meta_t meta;
  memset(&meta, 0, sizeof(meta));
  int found = 0;
  murmur_files_status_t fs =
      murmur_files_metadata(o, name, &meta, &found, detail_out, sqlrc);
  if (fs == MURMUR_FILES_OK && found) {
    meta.deleted = 1;
    meta.millis = files_now_ms();
    meta.node = o->self;
    fs = meta_put(o, &meta, detail_out, sqlrc);
  }
  murmur_files_meta_free(&meta);
  pthread_mutex_unlock(&o->gate);
  return fs;
}

murmur_files_status_t murmur_files_read(murmur_files_t *o, const char *name,
                                        murmur_files_write_fn output, void *ctx,
                                        murmur_files_meta_t *meta_out,
                                        char **detail_out, int *sqlrc) {
  murmur_files_meta_t meta;
  memset(&meta, 0, sizeof(meta));
  int found = 0;
  murmur_files_status_t fs =
      murmur_files_metadata(o, name, &meta, &found, detail_out, sqlrc);
  if (fs != MURMUR_FILES_OK) {
    return fs;
  }
  if (!found || meta.deleted) {
    set_detail(detail_out, "file metadata missing");
    return MURMUR_FILES_UNAVAILABLE;
  }
  char *path = object_path(o, meta.digest, meta.generation);
  if (!path) {
    murmur_files_meta_free(&meta);
    return io_fail(detail_out);
  }
  fs = murmur_files_verify(o, path, &meta, output, ctx, detail_out, sqlrc);
  free(path);
  if (fs == MURMUR_FILES_OK && meta_out) {
    *meta_out = meta;
    memset(&meta, 0, sizeof(meta));
  }
  murmur_files_meta_free(&meta);
  return fs;
}

/* ---------- stream plain chunks ---------- */

typedef struct {
  uint64_t skip;
  uint64_t position;
  uint64_t total;
  size_t chunk_size;
  uint8_t *buffer;
  size_t buffer_len;
  murmur_files_emit_fn emit;
  void *emit_ctx;
  murmur_files_status_t emit_status;
  char *emit_detail;
  int emit_failed;
} chunk_sink_t;

static int chunk_sink_write(void *ctx, const uint8_t *buf, size_t n) {
  chunk_sink_t *w = ctx;
  size_t original = n;
  w->total += (uint64_t)n;
  uint64_t discard = w->skip;
  if (discard > (uint64_t)n) {
    discard = (uint64_t)n;
  }
  w->skip -= discard;
  buf += discard;
  n -= (size_t)discard;
  while (n > 0) {
    size_t take = w->chunk_size - w->buffer_len;
    if (take > n) {
      take = n;
    }
    memcpy(w->buffer + w->buffer_len, buf, take);
    w->buffer_len += take;
    buf += take;
    n -= take;
    if (w->buffer_len == w->chunk_size) {
      char *detail = NULL;
      murmur_files_status_t st =
          w->emit(w->emit_ctx, w->position, w->buffer, w->buffer_len, &detail);
      if (st != MURMUR_FILES_OK) {
        w->emit_status = st;
        w->emit_detail = detail;
        w->emit_failed = 1;
        return -1;
      }
      free(detail);
      w->position += (uint64_t)w->buffer_len;
      w->buffer_len = 0;
    }
  }
  (void)original;
  return 0;
}

murmur_files_status_t murmur_files_stream_plain_chunks(
    murmur_files_t *o, const char *name, uint64_t skip, size_t chunk_size,
    murmur_files_emit_fn emit, void *ctx, murmur_files_meta_t *meta_out,
    uint64_t *total_out, char **detail_out, int *sqlrc) {
  if (chunk_size == 0) {
    set_detail(detail_out, "zero file chunk size");
    return MURMUR_FILES_INVALID;
  }
  murmur_files_meta_t meta;
  memset(&meta, 0, sizeof(meta));
  int found = 0;
  murmur_files_status_t fs =
      murmur_files_metadata(o, name, &meta, &found, detail_out, sqlrc);
  if (fs != MURMUR_FILES_OK) {
    return fs;
  }
  if (!found || meta.deleted) {
    set_detail(detail_out, "file metadata missing");
    return MURMUR_FILES_UNAVAILABLE;
  }
  char *path = object_path(o, meta.digest, meta.generation);
  if (!path) {
    murmur_files_meta_free(&meta);
    return io_fail(detail_out);
  }
  chunk_sink_t sink;
  memset(&sink, 0, sizeof(sink));
  sink.skip = skip;
  sink.position = skip;
  sink.chunk_size = chunk_size;
  sink.emit = emit;
  sink.emit_ctx = ctx;
  sink.buffer = malloc(chunk_size);
  if (!sink.buffer) {
    free(path);
    murmur_files_meta_free(&meta);
    return io_fail(detail_out);
  }
  fs = murmur_files_verify(o, path, &meta, chunk_sink_write, &sink, detail_out,
                           sqlrc);
  free(path);
  if (sink.emit_failed) {
    free(sink.buffer);
    free(*detail_out);
    *detail_out = sink.emit_detail;
    murmur_files_meta_free(&meta);
    return sink.emit_status;
  }
  if (fs != MURMUR_FILES_OK) {
    free(sink.buffer);
    murmur_files_meta_free(&meta);
    return fs;
  }
  if (sink.buffer_len > 0) {
    char *detail = NULL;
    fs = emit(ctx, sink.position, sink.buffer, sink.buffer_len, &detail);
    if (fs != MURMUR_FILES_OK) {
      free(sink.buffer);
      free(*detail_out);
      *detail_out = detail;
      murmur_files_meta_free(&meta);
      return fs;
    }
    free(detail);
    sink.position += (uint64_t)sink.buffer_len;
  }
  uint64_t total = sink.total;
  free(sink.buffer);
  if (meta_out) {
    *meta_out = meta;
    memset(&meta, 0, sizeof(meta));
  }
  if (total_out) {
    *total_out = total;
  }
  murmur_files_meta_free(&meta);
  return MURMUR_FILES_OK;
}

/* ---------- publish / rotate / collect ---------- */

murmur_files_status_t murmur_files_publish_fetched(
    murmur_files_t *o, const char *staged, const murmur_files_meta_t *meta,
    char **detail_out, int *sqlrc) {
  (void)sqlrc;
  pthread_mutex_lock(&o->gate);
  murmur_files_status_t fs =
      murmur_files_verify(o, staged, meta, NULL, NULL, detail_out, sqlrc);
  if (fs == MURMUR_FILES_OK) {
    char *path = object_path(o, meta->digest, meta->generation);
    if (!path) {
      fs = io_fail(detail_out);
    } else {
      struct stat st;
      if (stat(path, &st) != 0) {
        if (rename(staged, path) != 0) {
          fs = io_fail(detail_out);
        } else if (sync_directory(o->dir) != 0) {
          fs = io_fail(detail_out);
        }
      }
      free(path);
    }
  }
  pthread_mutex_unlock(&o->gate);
  return fs;
}

/* Reader over an open fd for rotate's re-upload. */
typedef struct {
  int fd;
} fd_reader_t;

static int fd_read(void *ctx, uint8_t *buf, size_t cap, size_t *n_out,
                   int *eof_out) {
  fd_reader_t *r = ctx;
  ssize_t n = read(r->fd, buf, cap);
  if (n < 0) {
    return -1;
  }
  *n_out = (size_t)n;
  *eof_out = (n == 0);
  return 0;
}

/* Writer to an open fd for rotate's plaintext staging. */
static int fd_write(void *ctx, const uint8_t *buf, size_t n) {
  int fd = *(int *)ctx;
  return write_all(fd, buf, n);
}

murmur_files_status_t murmur_files_rotate_keys(murmur_files_t *o, size_t limit,
                                                size_t *rotated,
                                                char **detail_out, int *sqlrc) {
  *rotated = 0;
  murmur_files_meta_t *listed = NULL;
  size_t nlisted = 0;
  murmur_files_status_t fs =
      murmur_files_list(o, &listed, &nlisted, detail_out, sqlrc);
  if (fs != MURMUR_FILES_OK) {
    return fs;
  }
  size_t done = 0;
  for (size_t i = 0; i < nlisted && done < limit; i++) {
    if (listed[i].generation == o->generation) {
      continue;
    }
    char *obj = object_path(o, listed[i].digest, listed[i].generation);
    struct stat st;
    int present = obj && stat(obj, &st) == 0 && !S_ISDIR(st.st_mode);
    free(obj);
    if (!present) {
      continue;
    }
    pthread_mutex_lock(&o->gate);
    murmur_files_meta_t current;
    memset(&current, 0, sizeof(current));
    int found = 0;
    fs = murmur_files_metadata(o, listed[i].name, &current, &found, detail_out,
                               sqlrc);
    if (fs != MURMUR_FILES_OK || !found || current.deleted ||
        memcmp(current.digest, listed[i].digest, 32) != 0 ||
        current.generation == o->generation) {
      pthread_mutex_unlock(&o->gate);
      murmur_files_meta_free(&current);
      if (fs != MURMUR_FILES_OK) {
        break;
      }
      fs = MURMUR_FILES_OK;
      continue;
    }
    uint8_t id[16];
    char *raw = NULL;
    char *curpath = NULL;
    int pfd = -1;
    int ofd = -1;
    murmur_files_status_t verr = MURMUR_FILES_OK;
    if (murmur_rand_bytes(id, 16) != 0) {
      verr = io_fail(detail_out);
    }
    if (verr == MURMUR_FILES_OK) {
      char hex[33];
      hex_encode(id, 16, hex);
      size_t rn = strlen(o->dir) + sizeof("/.rotate-") + 32;
      raw = malloc(rn);
      curpath = object_path(o, current.digest, current.generation);
      if (!raw || !curpath) {
        verr = io_fail(detail_out);
      } else {
        snprintf(raw, rn, "%s/.rotate-%s", o->dir, hex);
      }
    }
    if (verr == MURMUR_FILES_OK) {
      pfd = private_file(raw);
      if (pfd < 0) {
        verr = io_fail(detail_out);
      }
    }
    if (verr == MURMUR_FILES_OK) {
      int cfd = open(curpath, O_RDONLY);
      if (cfd < 0) {
        set_detail(detail_out, "file payload unavailable");
        verr = MURMUR_FILES_UNAVAILABLE;
      } else {
        verr = verify_fd(o, cfd, &current, fd_write, &pfd, detail_out);
        close(cfd);
      }
      if (verr == MURMUR_FILES_OK && fsync(pfd) != 0) {
        verr = io_fail(detail_out);
      }
    }
    if (pfd >= 0) {
      close(pfd);
      pfd = -1;
    }
    if (verr == MURMUR_FILES_OK) {
      ofd = open(raw, O_RDONLY);
      if (ofd < 0) {
        verr = io_fail(detail_out);
      }
    }
    if (verr == MURMUR_FILES_OK) {
      fd_reader_t fr;
      fr.fd = ofd;
      murmur_files_meta_t meta;
      memset(&meta, 0, sizeof(meta));
      verr = upload_inner(o, current.name, fd_read, &fr, &meta, detail_out,
                          sqlrc);
      murmur_files_meta_free(&meta);
    }
    if (ofd >= 0) {
      close(ofd);
    }
    if (raw) {
      unlink(raw);
    }
    free(raw);
    free(curpath);
    murmur_files_meta_free(&current);
    pthread_mutex_unlock(&o->gate);
    if (verr != MURMUR_FILES_OK) {
      fs = verr;
      break;
    }
    done++;
  }
  murmur_files_meta_list_free(listed, nlisted);
  *rotated = done;
  return fs;
}

murmur_files_status_t murmur_files_key_rotation_status(
    murmur_files_t *o, murmur_file_keyrot_t *out, char **detail_out,
    int *sqlrc) {
  memset(out, 0, sizeof(*out));
  out->current_generation = o->generation;
  murmur_files_meta_t *listed = NULL;
  size_t nlisted = 0;
  murmur_files_status_t fs =
      murmur_files_list(o, &listed, &nlisted, detail_out, sqlrc);
  if (fs != MURMUR_FILES_OK) {
    return fs;
  }
  for (size_t i = 0; i < nlisted; i++) {
    if (listed[i].generation != o->generation) {
      char *obj = object_path(o, listed[i].digest, listed[i].generation);
      struct stat st;
      if (!obj || stat(obj, &st) != 0 || S_ISDIR(st.st_mode)) {
        out->old_generation_metadata_missing_locally++;
      }
      free(obj);
    }
  }
  murmur_files_meta_list_free(listed, nlisted);
  DIR *d = opendir(o->dir);
  if (!d) {
    return io_fail(detail_out);
  }
  struct dirent *e;
  while ((e = readdir(d)) != NULL) {
    if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0) {
      continue;
    }
    char *full = join_path(o->dir, e->d_name);
    if (!full) {
      closedir(d);
      return io_fail(detail_out);
    }
    struct stat st;
    if (stat(full, &st) != 0) {
      free(full);
      continue;
    }
    if (strcmp(e->d_name, "staging") == 0 && S_ISDIR(st.st_mode)) {
      DIR *sd = opendir(full);
      if (!sd) {
        free(full);
        closedir(d);
        return io_fail(detail_out);
      }
      struct dirent *se;
      while ((se = readdir(sd)) != NULL) {
        if (strcmp(se->d_name, ".") == 0 || strcmp(se->d_name, "..") == 0) {
          continue;
        }
        char *sp = join_path(full, se->d_name);
        struct stat sst;
        int isfile = sp && stat(sp, &sst) == 0 && !S_ISDIR(sst.st_mode);
        free(sp);
        if (isfile) {
          out->staged_transfers++;
        }
      }
      closedir(sd);
      free(full);
      continue;
    }
    uint8_t digest[32];
    uint64_t gen = 0;
    if (parse_object_name(e->d_name, digest, &gen) && gen != o->generation) {
      out->old_generation_objects++;
    }
    free(full);
  }
  closedir(d);
  out->previous_key_unused_locally =
      (out->old_generation_objects == 0 &&
       out->old_generation_metadata_missing_locally == 0 &&
       out->staged_transfers == 0);
  return MURMUR_FILES_OK;
}

typedef struct {
  uint8_t digest[32];
  uint64_t generation;
} live_key_t;

murmur_files_status_t murmur_files_collect(murmur_files_t *o,
                                            uint64_t grace_ms, size_t *removed,
                                            char **detail_out, int *sqlrc) {
  *removed = 0;
  pthread_mutex_lock(&o->gate);
  uint64_t cutoff = sat_sub(files_now_ms(), grace_ms);
  murmur_files_meta_t *all = NULL;
  size_t nall = 0;
  murmur_files_status_t fs =
      meta_scan_all(o, &all, &nall, detail_out, sqlrc);
  if (fs != MURMUR_FILES_OK) {
    pthread_mutex_unlock(&o->gate);
    return fs;
  }
  live_key_t *live = NULL;
  size_t nlive = 0, livecap = 0;
  for (size_t i = 0; i < nall && fs == MURMUR_FILES_OK; i++) {
    if (!all[i].deleted) {
      if (nlive == livecap) {
        size_t ncap = livecap ? livecap * 2 : 32;
        live_key_t *next = realloc(live, ncap * sizeof(*next));
        if (!next) {
          set_detail(detail_out, "file collect");
          fs = MURMUR_FILES_IO;
          break;
        }
        live = next;
        livecap = ncap;
      }
      memcpy(live[nlive].digest, all[i].digest, 32);
      live[nlive].generation = all[i].generation;
      nlive++;
    }
  }
  murmur_files_meta_list_free(all, nall);
  size_t nremoved = 0;
  DIR *d = NULL;
  if (fs == MURMUR_FILES_OK) {
    d = opendir(o->dir);
    if (!d) {
      fs = io_fail(detail_out);
    }
  }
  struct dirent *dent;
  while (fs == MURMUR_FILES_OK && (dent = readdir(d)) != NULL) {
    if (strcmp(dent->d_name, ".") == 0 || strcmp(dent->d_name, "..") == 0) {
      continue;
    }
    char *full = join_path(o->dir, dent->d_name);
    if (!full) {
      fs = io_fail(detail_out);
      break;
    }
    struct stat st;
    if (stat(full, &st) != 0) {
      free(full);
      continue;
    }
    if (strcmp(dent->d_name, "staging") == 0 && S_ISDIR(st.st_mode)) {
      DIR *sd = opendir(full);
      if (!sd) {
        free(full);
        fs = io_fail(detail_out);
        break;
      }
      struct dirent *se;
      while (fs == MURMUR_FILES_OK && (se = readdir(sd)) != NULL) {
        if (strcmp(se->d_name, ".") == 0 || strcmp(se->d_name, "..") == 0) {
          continue;
        }
        char *sp = join_path(full, se->d_name);
        if (!sp) {
          fs = io_fail(detail_out);
          break;
        }
        if (staged_contains(o, sp)) {
          free(sp);
          continue;
        }
        struct stat sst;
        if (stat(sp, &sst) != 0) {
          free(sp);
          continue;
        }
        if (modified_ms(&sst) <= cutoff && !S_ISDIR(sst.st_mode)) {
          if (unlink(sp) != 0 && errno != ENOENT) {
            free(sp);
            fs = io_fail(detail_out);
            break;
          }
          nremoved++;
        }
        free(sp);
      }
      closedir(sd);
      free(full);
      continue;
    }
    if (modified_ms(&st) > cutoff) {
      free(full);
      continue;
    }
    if (staged_contains(o, full)) {
      free(full);
      continue;
    }
    if (has_prefix(dent->d_name, ".upload-") ||
        has_prefix(dent->d_name, ".rotate-") ||
        has_prefix(dent->d_name, ".download-")) {
      if (!S_ISDIR(st.st_mode)) {
        if (unlink(full) != 0 && errno != ENOENT) {
          free(full);
          fs = io_fail(detail_out);
          break;
        }
        nremoved++;
      }
      free(full);
      continue;
    }
    uint8_t digest[32];
    uint64_t gen = 0;
    if (parse_object_name(dent->d_name, digest, &gen)) {
      int is_live = 0;
      for (size_t i = 0; i < nlive; i++) {
        if (live[i].generation == gen &&
            memcmp(live[i].digest, digest, 32) == 0) {
          is_live = 1;
          break;
        }
      }
      if (!is_live) {
        if (unlink(full) != 0 && errno != ENOENT) {
          free(full);
          fs = io_fail(detail_out);
          break;
        }
        nremoved++;
      }
    }
    free(full);
  }
  if (d) {
    closedir(d);
  }
  free(live);
  if (fs == MURMUR_FILES_OK && nremoved > 0) {
    if (sync_directory(o->dir) != 0) {
      fs = io_fail(detail_out);
    }
  }
  pthread_mutex_unlock(&o->gate);
  *removed = nremoved;
  return fs;
}

murmur_files_status_t murmur_files_reap_staging_orphans(murmur_files_t *o,
                                                         char **detail_out) {
  char *dir = join_path(o->dir, "staging");
  if (!dir) {
    return io_fail(detail_out);
  }
  size_t n = 0;
  char **names = dir_names(dir, &n);
  if (!names) {
    if (errno == ENOENT) {
      free(dir);
      return MURMUR_FILES_OK;
    }
    free(dir);
    return io_fail(detail_out);
  }
  murmur_files_status_t fs = MURMUR_FILES_OK;
  for (size_t i = 0; i < n && fs == MURMUR_FILES_OK; i++) {
    char *full = join_path(dir, names[i]);
    if (!full) {
      fs = io_fail(detail_out);
      break;
    }
    if (has_suffix(names[i], ".identity")) {
      size_t stem = strlen(names[i]) - (sizeof(".identity") - 1);
      char *part = malloc(stem + sizeof(".part"));
      if (!part) {
        free(full);
        fs = io_fail(detail_out);
        break;
      }
      memcpy(part, names[i], stem);
      strcpy(part + stem, ".part");
      int keep = names_has(names, n, part) || staged_contains(o, full);
      free(part);
      if (!keep && unlink(full) != 0 && errno != ENOENT) {
        fs = io_fail(detail_out);
      }
    } else if (has_suffix(names[i], ".part")) {
      size_t stem = strlen(names[i]) - (sizeof(".part") - 1);
      char *sidecar = malloc(stem + sizeof(".identity"));
      if (!sidecar) {
        free(full);
        fs = io_fail(detail_out);
        break;
      }
      memcpy(sidecar, names[i], stem);
      strcpy(sidecar + stem, ".identity");
      int keep = staged_contains(o, full);
      int published = 0;
      if (!keep) {
        uint8_t digest[32];
        uint64_t gen = 0;
        char *stemstr = malloc(stem + 1);
        if (stemstr) {
          memcpy(stemstr, names[i], stem);
          stemstr[stem] = 0;
          if (parse_staging_stem(stemstr, digest, &gen)) {
            char *obj = object_path(o, digest, gen);
            struct stat ost;
            published =
                obj && stat(obj, &ost) == 0 && !S_ISDIR(ost.st_mode);
            free(obj);
          }
          free(stemstr);
        }
        keep = !published;
      }
      if (!keep) {
        if (unlink(full) != 0 && errno != ENOENT) {
          fs = io_fail(detail_out);
        } else {
          char *sp = join_path(dir, sidecar);
          if (sp && names_has(names, n, sidecar) &&
              !staged_contains(o, sp)) {
            if (unlink(sp) != 0 && errno != ENOENT) {
              fs = io_fail(detail_out);
            }
          }
          free(sp);
        }
      }
      free(sidecar);
    }
    free(full);
  }
  names_free(names, n);
  free(dir);
  return fs;
}
