/* murmur driver - see driver.h. */
#include "driver.h"

#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "config.h"
#include "member.h"
#include "mbedtls/pem.h"
#include "retain.h"
#include "schema.h"
#include "serve.h"
#include "transport.h"

#define DRIVER_DIAL_TIMEOUT_MS 2000
#define DRIVER_FIRST_STREAM_TIMEOUT_MS 10000
#define DRIVER_POLL_MS 200
#define DRIVER_SCHED_MS 500
#define DRIVER_SYNC_MS 5000
#define DRIVER_TICK_MS 1000
#define DRIVER_RETENTION_TICKS 60

static void set_sqlrc(int *sqlrc, int rc) {
  if (sqlrc) {
    *sqlrc = rc;
  }
}

static void set_detail(char **out, const char *s) {
  if (!out) {
    return;
  }
  *out = s ? strdup(s) : NULL;
}

static void sleep_ms(long ms) {
  struct timespec ts;
  ts.tv_sec = ms / 1000;
  ts.tv_nsec = (ms % 1000) * 1000 * 1000;
  nanosleep(&ts, NULL);
}

void murmur_driver_init(murmur_driver_t *d, murmur_engine_t *e) {
  memset(d, 0, sizeof(*d));
  pthread_mutex_init(&d->mu, NULL);
  pthread_cond_init(&d->detach_cond, NULL);
  d->eng = e;
}

void murmur_driver_destroy(murmur_driver_t *d) {
  if (d->sess) {
    for (size_t i = 0; i < d->n_sess; i++) {
      free(d->sess[i]);
    }
    free(d->sess);
  }
  free((void *)d->files_cfg.directory);
  free((void *)d->files_cfg.fetch_bind_ip);
  free((void *)d->files_cfg.previous_key);
  if (d->search) {
    murmur_search_close(d->search);
  }
  pthread_cond_destroy(&d->detach_cond);
  pthread_mutex_destroy(&d->mu);
  memset(d, 0, sizeof(*d));
}

/* ---- files ---- */

murmur_files_t *murmur_driver_files(murmur_driver_t *d) {
  pthread_mutex_lock(&d->mu);
  murmur_files_t *f = d->files;
  pthread_mutex_unlock(&d->mu);
  return f;
}

murmur_sync_status_t murmur_driver_files_open(
    murmur_driver_t *d, const murmur_driver_files_config_t *c,
    char **detail_out, int *sqlrc) {
  set_detail(detail_out, NULL);
  set_sqlrc(sqlrc, SQLITE_OK);
  if (!c || !c->directory || !c->directory[0] || c->fetch_port == 0) {
    set_detail(detail_out, "file store needs a directory and fetch port");
    return MURMUR_SYNC_INVALID;
  }
  pthread_mutex_lock(&d->mu);
  if (d->running) {
    pthread_mutex_unlock(&d->mu);
    set_detail(detail_out, "replication already running");
    return MURMUR_SYNC_OVERLOADED;
  }
  free((void *)d->files_cfg.directory);
  free((void *)d->files_cfg.fetch_bind_ip);
  free((void *)d->files_cfg.previous_key);
  memset(&d->files_cfg, 0, sizeof(d->files_cfg));
  d->files_cfg.directory = strdup(c->directory);
  d->files_cfg.fetch_bind_ip =
      c->fetch_bind_ip ? strdup(c->fetch_bind_ip) : NULL;
  if (!d->files_cfg.directory ||
      (c->fetch_bind_ip && !d->files_cfg.fetch_bind_ip)) {
    free((void *)d->files_cfg.directory);
    free((void *)d->files_cfg.fetch_bind_ip);
    memset(&d->files_cfg, 0, sizeof(d->files_cfg));
    pthread_mutex_unlock(&d->mu);
    set_detail(detail_out, "file config copy failed");
    return MURMUR_SYNC_OVERLOADED;
  }
  if (c->previous_key) {
    uint8_t *prev = malloc(32);
    if (!prev) {
      free((void *)d->files_cfg.directory);
      free((void *)d->files_cfg.fetch_bind_ip);
      memset(&d->files_cfg, 0, sizeof(d->files_cfg));
      pthread_mutex_unlock(&d->mu);
      set_detail(detail_out, "file config copy failed");
      return MURMUR_SYNC_OVERLOADED;
    }
    memcpy(prev, c->previous_key, 32);
    d->files_cfg.previous_key = (const uint8_t(*)[32])prev;
  }
  memcpy(d->files_cfg.key, c->key, 32);
  d->files_cfg.generation = c->generation;
  d->files_cfg.max_file_bytes =
      c->max_file_bytes ? c->max_file_bytes : (4ull << 30);
  d->files_cfg.max_staging_bytes =
      c->max_staging_bytes ? c->max_staging_bytes : (1ull << 30);
  d->files_cfg.concurrent_fetches =
      c->concurrent_fetches > 0 ? c->concurrent_fetches : 2;
  d->files_cfg.fetch_interval_ms =
      c->fetch_interval_ms ? c->fetch_interval_ms : 30000;
  d->files_cfg.fetch_port = c->fetch_port;
  d->files_on = 1;
  pthread_mutex_unlock(&d->mu);
  return MURMUR_SYNC_OK;
}

/* ---- search ---- */

murmur_search_manager_t *murmur_driver_search(murmur_driver_t *d) {
  pthread_mutex_lock(&d->mu);
  murmur_search_manager_t *m = d->search;
  pthread_mutex_unlock(&d->mu);
  return m;
}

murmur_sync_status_t murmur_driver_search_open(
    murmur_driver_t *d, const murmur_driver_search_config_t *c,
    char **detail_out, int *sqlrc) {
  set_detail(detail_out, NULL);
  set_sqlrc(sqlrc, SQLITE_OK);
  if (!c || (c->n_defs && !c->defs)) {
    set_detail(detail_out, "search needs index definitions");
    return MURMUR_SYNC_INVALID;
  }
  pthread_mutex_lock(&d->mu);
  if (d->running) {
    pthread_mutex_unlock(&d->mu);
    set_detail(detail_out, "replication already running");
    return MURMUR_SYNC_OVERLOADED;
  }
  size_t queue = c->queue_bytes ? c->queue_bytes : (8u << 20);
  size_t batch = c->batch_rows ? c->batch_rows : 256;
  char *sdetail = NULL;
  murmur_search_manager_t *m = NULL;
  murmur_search_status_t ss =
      murmur_search_open(c->defs, c->n_defs, queue, batch, &m, &sdetail);
  if (ss != MURMUR_SEARCH_OK) {
    pthread_mutex_unlock(&d->mu);
    set_detail(detail_out, sdetail ? sdetail : "search open failed");
    free(sdetail);
    return MURMUR_SYNC_INVALID;
  }
  free(sdetail);
  if (d->search) {
    murmur_search_close(d->search);
  }
  d->search = m;
  d->search_interval_ms = c->interval_ms ? c->interval_ms : 100;
  d->search_on = 1;
  d->search_tick_n = 0;
  pthread_mutex_unlock(&d->mu);
  return MURMUR_SYNC_OK;
}

murmur_sync_status_t murmur_driver_search_sync(murmur_driver_t *d,
                                               int allow_missing,
                                               char **detail_out, int *sqlrc) {
  set_detail(detail_out, NULL);
  set_sqlrc(sqlrc, SQLITE_OK);
  pthread_mutex_lock(&d->mu);
  murmur_search_manager_t *m = d->search;
  sqlite3 *db = d->eng ? d->eng->db : NULL;
  pthread_mutex_unlock(&d->mu);
  if (!m || !db) {
    set_detail(detail_out, "search is not open");
    return MURMUR_SYNC_INVALID;
  }
  char *sdetail = NULL;
  int ssqlrc = 0;
  murmur_search_status_t ss =
      murmur_search_sync_schema(m, db, allow_missing, &sdetail, &ssqlrc);
  if (ss != MURMUR_SEARCH_OK) {
    set_detail(detail_out, sdetail ? sdetail : "search sync failed");
    free(sdetail);
    set_sqlrc(sqlrc, ssqlrc);
    return ss == MURMUR_SEARCH_INVALID || ss == MURMUR_SEARCH_MISMATCH
               ? MURMUR_SYNC_INVALID
               : MURMUR_SYNC_SQLITE;
  }
  free(sdetail);
  return MURMUR_SYNC_OK;
}

/* One search tick: a bounded maintenance turn. Errors latch inside
 * the manager (per-index err + guard) and are also recorded. */
static void search_tick(murmur_driver_t *d) {
  pthread_mutex_lock(&d->mu);
  murmur_search_manager_t *m = d->search;
  sqlite3 *db = d->eng ? d->eng->db : NULL;
  pthread_mutex_unlock(&d->mu);
  if (!m || !db) {
    return;
  }
  char *detail = NULL;
  int sqlrc = 0;
  murmur_search_status_t ss =
      murmur_search_tick(m, db, NULL, NULL, &detail, &sqlrc);
  if (ss != MURMUR_SEARCH_OK) {
    murmur_engine_record(d->eng, detail ? detail : "search tick");
  }
  free(detail);
}

/* One file tick: fetch locally-missing objects from mesh peers,
 * rotate old-generation objects, garbage-collect. Mirrors Go's
 * fileTick (fetchMissing + RotateKeys(4) + Collect(7d)). Runs on
 * the tick thread; fetch/objects outlive it via stop ordering. */
static void file_tick(murmur_driver_t *d) {
  murmur_fetch_source_t sources[64];
  size_t n = murmur_engine_fetch_sources(d->eng,
                                         d->files_cfg.fetch_port, sources, 64);
  char *detail = NULL;
  int sqlrc = 0;
  murmur_files_status_t fs =
      murmur_fetch_missing(d->fetch, sources, n, &detail, &sqlrc);
  if (fs != MURMUR_FILES_OK) {
    murmur_engine_record(d->eng, detail ? detail : "file tick");
  }
  free(detail);
  detail = NULL;
  size_t rotated = 0;
  fs = murmur_files_rotate_keys(d->files, 4, &rotated, &detail, &sqlrc);
  if (fs != MURMUR_FILES_OK) {
    murmur_engine_record(d->eng, detail ? detail : "file rotate");
  }
  free(detail);
  detail = NULL;
  size_t removed = 0;
  fs = murmur_files_collect(d->files, 7ull * 86400ull * 1000ull, &removed,
                            &detail, &sqlrc);
  if (fs != MURMUR_FILES_OK) {
    murmur_engine_record(d->eng, detail ? detail : "file collect");
  }
  free(detail);
}

int murmur_driver_running(murmur_driver_t *d) {
  pthread_mutex_lock(&d->mu);
  int r = d->running;
  pthread_mutex_unlock(&d->mu);
  return r;
}

murmur_sync_status_t murmur_driver_retention_collect(murmur_driver_t *d,
                                                     uint64_t *moved,
                                                     uint64_t *pruned,
                                                     int *sqlrc) {
  if (!d || !d->eng) {
    if (sqlrc) {
      *sqlrc = 21; /* SQLITE_MISUSE */
    }
    return MURMUR_SYNC_INVALID;
  }
  return murmur_engine_retention_pass(d->eng, moved, pruned, sqlrc);
}

/* ---- session registry ---- */

static murmur_driver_sess_t *reg_find(murmur_driver_t *d,
                                      const murmur_node_t *peer) {
  for (size_t i = 0; i < d->n_sess; i++) {
    if (!d->sess[i]->dead && murmur_node_eq(&d->sess[i]->peer, peer)) {
      return d->sess[i];
    }
  }
  return NULL;
}

/* Registers a connected session. Entries are individually boxed so
 * engine-held pointers survive registry growth. */
static murmur_driver_sess_t *reg_add(murmur_driver_t *d,
                                     const murmur_node_t *peer,
                                     murmur_session_t *qs) {
  murmur_driver_sess_t *s =
      (murmur_driver_sess_t *)malloc(sizeof(*s));
  if (!s) {
    return NULL;
  }
  memset(s, 0, sizeof(*s));
  s->peer = *peer;
  s->qs = qs;
  s->drv = d;
  pthread_mutex_lock(&d->mu);
  if (d->n_sess >= d->cap_sess) {
    size_t ncap = d->cap_sess ? d->cap_sess * 2 : 8;
    murmur_driver_sess_t **nv =
        (murmur_driver_sess_t **)realloc(d->sess, ncap * sizeof(*nv));
    if (!nv) {
      pthread_mutex_unlock(&d->mu);
      free(s);
      return NULL;
    }
    d->sess = nv;
    d->cap_sess = ncap;
  }
  s->gen = ++d->gen_next;
  d->sess[d->n_sess++] = s;
  pthread_mutex_unlock(&d->mu);
  return s;
}

/* Idempotent kill: marks dead, drops QUIC state, removes the
 * engine session (whose close hook re-enters here safely). */
static void sess_kill(murmur_driver_sess_t *s) {
  murmur_driver_t *d = s->drv;
  murmur_session_t *qs = NULL;
  pthread_mutex_lock(&d->mu);
  if (!s->dead) {
    s->dead = 1;
    qs = s->qs;
    s->qs = NULL;
  }
  pthread_mutex_unlock(&d->mu);
  if (qs) {
    murmur_session_close(qs);
    murmur_session_release(qs);
    murmur_engine_remove_conn(d->eng, &s->peer);
  }
}

/* ---- QUIC adapters ---- */

typedef struct {
  murmur_driver_sess_t *s;
  murmur_stream_t *st;
  char err[128];
} stream_ctx_t;

static int stream_write(void *ctx, const uint8_t *b, size_t n) {
  stream_ctx_t *c = (stream_ctx_t *)ctx;
  if (murmur_stream_write(c->st, b, n) != 0) {
    snprintf(c->err, sizeof(c->err), "stream write failed");
    return 1;
  }
  return 0;
}

/* Per-read silence budget: transfers stream continuously, so 30 s without
 * a byte means the peer stalled mid-frame (never hang a sync/fetch worker
 * forever; callers already reopen and resume). Overridable in ms via
 * MURMUR_STREAM_READ_MS for mechanism tests. */
#define DRIVER_STREAM_READ_MS 30000

static int stream_read_ms(void) {
  static int v = -1;
  if (v < 0) {
    v = DRIVER_STREAM_READ_MS;
    const char *e = getenv("MURMUR_STREAM_READ_MS");
    if (e && atoi(e) > 0) {
      v = atoi(e);
    }
  }
  return v;
}

static int stream_read_full(void *ctx, uint8_t *b, size_t n) {
  stream_ctx_t *c = (stream_ctx_t *)ctx;
  size_t got = 0;
  while (got < n) {
    size_t m = 0;
    int rc = murmur_stream_read_timeout(c->st, b + got, n - got, &m,
                                          stream_read_ms());
    if (rc == -MURMUR_QUIC_TIMEOUT) {
      snprintf(c->err, sizeof(c->err), "stream read timeout");
      return 1;
    }
    if (rc != 0) {
      snprintf(c->err, sizeof(c->err), "stream read failed");
      return 1;
    }
    if (m == 0) {
      snprintf(c->err, sizeof(c->err), "eof");
      return 1;
    }
    got += m;
  }
  return 0;
}

static int stream_close(void *ctx) {
  stream_ctx_t *c = (stream_ctx_t *)ctx;
  murmur_stream_close(c->st);
  murmur_stream_release(c->st);
  free(c);
  return 0;
}

static const char *stream_error(void *ctx) {
  stream_ctx_t *c = (stream_ctx_t *)ctx;
  return c->err[0] ? c->err : NULL;
}

static int sess_open_stream(void *ctx, murmur_stream_io_t *out) {
  murmur_driver_sess_t *s = (murmur_driver_sess_t *)ctx;
  murmur_driver_t *d = s->drv;
  pthread_mutex_lock(&d->mu);
  int dead = s->dead || !d->running;
  murmur_session_t *qs =
      !dead ? murmur_session_acquire(s->qs) : NULL;
  pthread_mutex_unlock(&d->mu);
  if (dead || !qs) {
    murmur_session_release(qs);
    return 1;
  }
  murmur_stream_t *st = NULL;
  int orc = murmur_session_open_stream(qs, &st);
  murmur_session_release(qs);
  if (orc != 0) {
    pthread_mutex_lock(&d->mu);
    if (d->quic) {
      murmur_last_error(d->quic, s->err, sizeof(s->err));
    }
    pthread_mutex_unlock(&d->mu);
    sess_kill(s);
    return 1;
  }
  stream_ctx_t *c = (stream_ctx_t *)malloc(sizeof(*c));
  if (!c) {
    murmur_stream_close(st);
    murmur_stream_release(st);
    return 1;
  }
  memset(c, 0, sizeof(*c));
  c->s = s;
  c->st = st;
  out->write = stream_write;
  out->read_full = stream_read_full;
  out->close = stream_close;
  out->error_text = stream_error;
  out->ctx = c;
  return 0;
}

static int sess_send_datagram(void *ctx, const uint8_t *b, size_t n) {
  murmur_driver_sess_t *s = (murmur_driver_sess_t *)ctx;
  murmur_driver_t *d = s->drv;
  pthread_mutex_lock(&d->mu);
  int dead = s->dead || !d->running;
  murmur_session_t *qs =
      !dead ? murmur_session_acquire(s->qs) : NULL;
  pthread_mutex_unlock(&d->mu);
  if (dead || !qs) {
    murmur_session_release(qs);
    return 1;
  }
  int rc = murmur_session_send_datagram(qs, b, n);
  murmur_session_release(qs);
  return rc != 0;
}

static int sess_close(void *ctx) {
  sess_kill((murmur_driver_sess_t *)ctx);
  return 0;
}

static const char *sess_error(void *ctx) {
  murmur_driver_sess_t *s = (murmur_driver_sess_t *)ctx;
  return s->err[0] ? s->err : NULL;
}

static void sess_iface(murmur_driver_sess_t *s, murmur_session_if_t *out) {
  memset(out, 0, sizeof(*out));
  out->open_stream = sess_open_stream;
  out->send_datagram = sess_send_datagram;
  out->close = sess_close;
  out->error_text = sess_error;
  out->ctx = s;
}

/* Closes a used stream io (handlers never close). */
static void io_close(murmur_stream_io_t *io) {
  if (io && io->close) {
    io->close(io->ctx);
  }
}

/* ---- endpoint bring-up ---- */

static int read_file(const char *path, uint8_t **out, size_t *len) {
  *out = NULL;
  *len = 0;
  FILE *f = fopen(path, "rb");
  if (!f) {
    return -1;
  }
  size_t cap = 4096, n = 0;
  uint8_t *b = (uint8_t *)malloc(cap + 1);
  if (!b) {
    fclose(f);
    return -1;
  }
  size_t r = 0;
  while ((r = fread(b + n, 1, cap - n, f)) > 0) {
    n += r;
    if (n == cap) {
      cap *= 2;
      uint8_t *nb = (uint8_t *)realloc(b, cap + 1);
      if (!nb) {
        free(b);
        fclose(f);
        return -1;
      }
      b = nb;
    }
  }
  fclose(f);
  b[n] = '\0';
  *out = b;
  *len = n;
  return 0;
}

/* All CERTIFICATE blocks in a PEM file as DER. */
static int load_pem_certs(const char *path, uint8_t ***ders, size_t **lens,
                          size_t *n) {
  *ders = NULL;
  *lens = NULL;
  *n = 0;
  uint8_t *raw = NULL;
  size_t raw_len = 0;
  if (read_file(path, &raw, &raw_len) != 0) {
    return -1;
  }
  uint8_t **ds = NULL;
  size_t *ls = NULL, nd = 0, cap = 0;
  size_t off = 0;
  int rc = -1;
  while (off < raw_len) {
    mbedtls_pem_context pc;
    mbedtls_pem_init(&pc);
    size_t used = 0;
    if (mbedtls_pem_read_buffer(
            &pc, "-----BEGIN CERTIFICATE-----",
            "-----END CERTIFICATE-----", raw + off, NULL, 0, &used) != 0) {
      mbedtls_pem_free(&pc);
      break;
    }
    size_t blen = 0;
    const uint8_t *der =
        mbedtls_pem_get_buffer(&pc, &blen);
    if (nd >= cap) {
      size_t ncap = cap ? cap * 2 : 4;
      uint8_t **nders =
          (uint8_t **)realloc(ds, ncap * sizeof(*nders));
      size_t *nlens = (size_t *)realloc(ls, ncap * sizeof(*nlens));
      if (!nders || !nlens) {
        free(nders);
        free(nlens);
        mbedtls_pem_free(&pc);
        goto out;
      }
      ds = nders;
      ls = nlens;
      cap = ncap;
    }
    ds[nd] = (uint8_t *)malloc(blen ? blen : 1);
    if (!ds[nd]) {
      mbedtls_pem_free(&pc);
      goto out;
    }
    if (blen > 0) {
      memcpy(ds[nd], der, blen);
    }
    ls[nd] = blen;
    nd++;
    mbedtls_pem_free(&pc);
    if (used == 0) {
      break;
    }
    off += used;
  }
  if (nd == 0) {
    goto out;
  }
  *ders = ds;
  *lens = ls;
  *n = nd;
  ds = NULL;
  ls = NULL;
  nd = 0;
  rc = 0;
out:
  for (size_t i = 0; i < nd; i++) {
    free(ds[i]);
  }
  free(ds);
  free(ls);
  free(raw);
  return rc;
}

static void free_ders(uint8_t **ders, size_t *lens, size_t n) {
  if (!ders) {
    return;
  }
  for (size_t i = 0; i < n; i++) {
    free(ders[i]);
  }
  free(ders);
  free(lens);
}

/* A JSON string-array setting via JSON1. */
static int load_json_strings(sqlite3 *db, const char *name, char ***out,
                             size_t *n, int *sqlrc) {
  *out = NULL;
  *n = 0;
  char *raw = NULL;
  if (murmur_cfg_setting(db, name, &raw, sqlrc) != MURMUR_SYNC_OK) {
    return -1;
  }
  sqlite3_stmt *st = NULL;
  int rc = sqlite3_prepare_v2(
      db, "SELECT value FROM json_each(?) WHERE type='text'", -1, &st, NULL);
  if (rc != SQLITE_OK) {
    free(raw);
    set_sqlrc(sqlrc, rc);
    return -1;
  }
  sqlite3_bind_text(st, 1, raw, -1, SQLITE_TRANSIENT);
  char **vs = NULL;
  size_t nv = 0, cap = 0;
  int ok = 1;
  while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
    const uint8_t *t = sqlite3_column_text(st, 0);
    if (nv >= cap) {
      size_t ncap = cap ? cap * 2 : 8;
      char **nnv = (char **)realloc(vs, ncap * sizeof(*nnv));
      if (!nnv) {
        ok = 0;
        break;
      }
      vs = nnv;
      cap = ncap;
    }
    vs[nv] = strdup((const char *)(t ? t : (const uint8_t *)""));
    if (!vs[nv]) {
      ok = 0;
      break;
    }
    nv++;
  }
  if (rc != SQLITE_DONE) {
    ok = 0;
  }
  sqlite3_finalize(st);
  free(raw);
  if (!ok) {
    for (size_t i = 0; i < nv; i++) {
      free(vs[i]);
    }
    free(vs);
    return -1;
  }
  *out = vs;
  *n = nv;
  set_sqlrc(sqlrc, SQLITE_OK);
  return 0;
}

/* Splits "ip:port" / "[v6]:port" for dial/bind. */
static int split_addr(const char *s, char *ip, size_t ip_cap,
                      uint16_t *port) {
  *port = 0;
  if (!s || !s[0]) {
    return -1;
  }
  const char *host = s, *colon = strrchr(s, ':');
  char hb[128];
  if (s[0] == '[') {
    const char *end = strchr(s, ']');
    if (!end || end[1] != ':' || (size_t)(end - s - 1) >= sizeof(hb)) {
      return -1;
    }
    memcpy(hb, s + 1, (size_t)(end - s - 1));
    hb[end - s - 1] = '\0';
    host = hb;
    colon = end + 1;
  } else if (!colon || strchr(s, ':') != colon) {
    return -1;
  }
  uint64_t p = 0;
  if (murmur_cfg_atoi(colon + 1, &p) != 0 || p == 0 || p > 65535) {
    return -1;
  }
  if (s[0] != '[') {
    size_t hl = (size_t)(colon - s);
    if (hl == 0 || hl >= sizeof(hb)) {
      return -1;
    }
    memcpy(hb, s, hl);
    hb[hl] = '\0';
    host = hb;
  }
  if (strlen(host) + 1 > ip_cap) {
    return -1;
  }
  strcpy(ip, host);
  *port = (uint16_t)p;
  return 0;
}

typedef struct {
  char *bind;
  char *cert_file;
  char *key_file;
  char *ca_file;
  murmur_node_t *allowed;
  size_t n_allowed;
  char **cidrs;
  size_t n_cidrs;
  uint32_t sessions;
} quic_settings_t;

static void quic_settings_free(quic_settings_t *q) {
  free(q->bind);
  free(q->cert_file);
  free(q->key_file);
  free(q->ca_file);
  free(q->allowed);
  if (q->cidrs) {
    for (size_t i = 0; i < q->n_cidrs; i++) {
      free(q->cidrs[i]);
    }
    free(q->cidrs);
  }
  memset(q, 0, sizeof(*q));
}

/* loadQuicParams: bind/cert/key/ca/allowed_peers/allowed_networks/
 * sessions from settings. */
static murmur_sync_status_t load_quic_settings(sqlite3 *db, quic_settings_t *q,
                                               char **detail_out, int *sqlrc) {
  memset(q, 0, sizeof(*q));
  murmur_sync_status_t st;
  st = murmur_cfg_setting(db, "bind", &q->bind, sqlrc);
  if (st != MURMUR_SYNC_OK) {
    goto fail;
  }
  if (!q->bind[0]) {
    free(q->bind);
    q->bind = strdup("0.0.0.0:7443");
  }
  st = murmur_cfg_setting(db, "certificate", &q->cert_file, sqlrc);
  if (st != MURMUR_SYNC_OK) {
    goto fail;
  }
  st = murmur_cfg_setting(db, "private_key", &q->key_file, sqlrc);
  if (st != MURMUR_SYNC_OK) {
    goto fail;
  }
  st = murmur_cfg_setting(db, "ca", &q->ca_file, sqlrc);
  if (st != MURMUR_SYNC_OK) {
    goto fail;
  }
  char **peers = NULL;
  size_t n_peers = 0;
  if (load_json_strings(db, "allowed_peers", &peers, &n_peers, sqlrc) != 0) {
    set_detail(detail_out, "invalid allowed_peers");
    set_sqlrc(sqlrc, SQLITE_OK);
    st = MURMUR_SYNC_INVALID;
    goto fail;
  }
  if (n_peers > 0) {
    q->allowed =
        (murmur_node_t *)malloc(n_peers * sizeof(*q->allowed));
    if (!q->allowed) {
      for (size_t i = 0; i < n_peers; i++) {
        free(peers[i]);
      }
      free(peers);
      set_sqlrc(sqlrc, SQLITE_OK);
      return MURMUR_SYNC_OVERLOADED;
    }
    for (size_t i = 0; i < n_peers; i++) {
      int prc = 0;
      if (murmur_engine_node_parse(peers[i], &q->allowed[i], &prc) !=
          MURMUR_SYNC_OK) {
        for (size_t j = 0; j < n_peers; j++) {
          free(peers[j]);
        }
        free(peers);
        set_detail(detail_out, "invalid allowed_peers");
        set_sqlrc(sqlrc, SQLITE_OK);
        st = MURMUR_SYNC_INVALID;
        goto fail;
      }
      free(peers[i]);
    }
    free(peers);
    q->n_allowed = n_peers;
  }
  if (load_json_strings(db, "allowed_networks", &q->cidrs, &q->n_cidrs,
                        sqlrc) != 0) {
    set_detail(detail_out, "invalid allowed_networks");
    set_sqlrc(sqlrc, SQLITE_OK);
    st = MURMUR_SYNC_INVALID;
    goto fail;
  }
  char *sess_raw = NULL;
  st = murmur_cfg_setting(db, "sessions", &sess_raw, sqlrc);
  if (st != MURMUR_SYNC_OK) {
    goto fail;
  }
  uint64_t n = 0;
  if (murmur_cfg_atoi(sess_raw, &n) != 0 || n < 1 || n > 256) {
    free(sess_raw);
    set_detail(detail_out, "invalid sessions");
    set_sqlrc(sqlrc, SQLITE_OK);
    st = MURMUR_SYNC_INVALID;
    goto fail;
  }
  free(sess_raw);
  q->sessions = (uint32_t)n;
  set_sqlrc(sqlrc, SQLITE_OK);
  return MURMUR_SYNC_OK;
fail:
  if (st == MURMUR_SYNC_SQLITE) {
    set_detail(detail_out, sqlite3_errmsg(db));
  }
  quic_settings_free(q);
  return st;
}

/* ---- connection setup ---- */

typedef struct {
  murmur_driver_t *d;
  void *(*fn)(void *);
  void *arg;
} detach_root_t;

static void *detach_root(void *v) {
  detach_root_t *r = (detach_root_t *)v;
  void *out = r->fn(r->arg);
  pthread_mutex_lock(&r->d->mu);
  r->d->detached--;
  pthread_cond_broadcast(&r->d->detach_cond);
  pthread_mutex_unlock(&r->d->mu);
  free(r);
  return out;
}

static int spawn_detached(murmur_driver_t *d, void *(*fn)(void *),
                          void *arg) {
  detach_root_t *r = (detach_root_t *)malloc(sizeof(*r));
  if (!r) {
    return -1;
  }
  r->d = d;
  r->fn = fn;
  r->arg = arg;
  pthread_mutex_lock(&d->mu);
  d->detached++;
  pthread_mutex_unlock(&d->mu);
  pthread_t t;
  pthread_attr_t at;
  pthread_attr_init(&at);
  pthread_attr_setdetachstate(&at, PTHREAD_CREATE_DETACHED);
  int rc = pthread_create(&t, &at, detach_root, r);
  pthread_attr_destroy(&at);
  if (rc != 0) {
    free(r);
    pthread_mutex_lock(&d->mu);
    d->detached--;
    pthread_mutex_unlock(&d->mu);
    return rc;
  }
  return 0;
}

static void *stream_pump(void *v);
static void *dgram_pump(void *v);

static int sync_dbg_on(void) {
  static int v = -1;
  if (v < 0) {
    v = getenv("MURMUR_DEBUG_SYNC") != NULL;
  }
  return v;
}

#define SYNC_DBG(...)                                    \
  do {                                                   \
    if (sync_dbg_on()) {                                 \
      fprintf(stderr, "murmur-sync: ");                  \
      fprintf(stderr, __VA_ARGS__);                      \
      fprintf(stderr, "\n");                             \
    }                                                    \
  } while (0)

/* Registers a handshaked session and spawns its pumps. */
static void register_and_serve(murmur_driver_t *d, murmur_session_t *qs,
                               const murmur_node_t *peer) {
  pthread_mutex_lock(&d->mu);
  int dup = reg_find(d, peer) != NULL;
  int running = d->running;
  pthread_mutex_unlock(&d->mu);
  if (dup || !running) {
    murmur_session_close(qs);
    murmur_session_release(qs);
    return;
  }
  murmur_driver_sess_t *s = reg_add(d, peer, qs);
  if (!s) {
    murmur_session_close(qs);
    murmur_session_release(qs);
    return;
  }
  murmur_session_if_t si;
  sess_iface(s, &si);
  murmur_engine_add_conn(d->eng, peer, &si, NULL);
  if (spawn_detached(d, stream_pump, s) != 0 ||
      spawn_detached(d, dgram_pump, s) != 0) {
    sess_kill(s);
  }
}

static void *stream_pump(void *v) {
  murmur_driver_sess_t *s = (murmur_driver_sess_t *)v;
  murmur_driver_t *d = s->drv;
  for (;;) {
    pthread_mutex_lock(&d->mu);
    int dead = s->dead || !d->running;
    murmur_session_t *qs =
        !dead ? murmur_session_acquire(s->qs) : NULL;
    pthread_mutex_unlock(&d->mu);
    if (dead || !qs) {
      murmur_session_release(qs);
      return NULL;
    }
    murmur_stream_t *st = NULL;
    int rc = murmur_session_accept_stream(qs, &st, DRIVER_POLL_MS);
    murmur_session_release(qs);
    if (rc == -MURMUR_QUIC_TIMEOUT) {
      continue;
    }
    if (rc != 0) {
      sess_kill(s);
      return NULL;
    }
    stream_ctx_t *c = (stream_ctx_t *)malloc(sizeof(*c));
    if (!c) {
      murmur_stream_close(st);
      murmur_stream_release(st);
      continue;
    }
    memset(c, 0, sizeof(*c));
    c->s = s;
    c->st = st;
    murmur_stream_io_t io;
    io.write = stream_write;
    io.read_full = stream_read_full;
    io.close = stream_close;
    io.error_text = stream_error;
    io.ctx = c;
    SYNC_DBG("serve begin");
    murmur_sync_status_t sst =
        murmur_serve_stream(d->eng, &s->peer, &io, NULL, NULL);
    SYNC_DBG("serve end st=%d", (int)sst);
    io_close(&io);
  }
}

static void *dgram_pump(void *v) {
  murmur_driver_sess_t *s = (murmur_driver_sess_t *)v;
  murmur_driver_t *d = s->drv;
  uint8_t buf[2048];
  for (;;) {
    pthread_mutex_lock(&d->mu);
    int dead = s->dead || !d->running;
    murmur_session_t *qs =
        !dead ? murmur_session_acquire(s->qs) : NULL;
    pthread_mutex_unlock(&d->mu);
    if (dead || !qs) {
      murmur_session_release(qs);
      return NULL;
    }
    size_t len = 0;
    int rc =
        murmur_session_recv_datagram(qs, buf, sizeof(buf), &len,
                                     DRIVER_POLL_MS);
    murmur_session_release(qs);
    if (rc == -MURMUR_QUIC_TIMEOUT) {
      continue;
    }
    if (rc != 0) {
      sess_kill(s);
      return NULL;
    }
    murmur_engine_handle_packet(d->eng, &s->peer, buf, len,
                                murmur_engine_wall_ms(), NULL);
  }
}

/* One handshake over an open io; records failures for Status. */
static int run_handshake(murmur_driver_t *d, const murmur_node_t *peer,
                         murmur_stream_io_t *io, int outgoing) {
  uint64_t inc = 0;
  murmur_addr_t addr;
  memset(&addr, 0, sizeof(addr));
  char *detail = NULL;
  murmur_sync_status_t st = murmur_serve_handshake(
      d->eng, peer, io, outgoing, &inc, &addr, &detail, NULL);
  if (st != MURMUR_SYNC_OK && detail) {
    murmur_engine_record(d->eng, detail);
  }
  free(detail);
  (void)inc;
  (void)addr;
  return st == MURMUR_SYNC_OK ? 0 : 1;
}

static int peer_is_self(murmur_driver_t *d, const murmur_node_t *peer) {
  pthread_mutex_lock(&d->eng->mu);
  murmur_node_t self = d->eng->node;
  pthread_mutex_unlock(&d->eng->mu);
  return murmur_node_eq(peer, &self);
}

static void *accept_thread(void *v) {
  murmur_driver_t *d = (murmur_driver_t *)v;
  for (;;) {
    pthread_mutex_lock(&d->mu);
    int running = d->running;
    murmur_quic_t *q = d->quic;
    pthread_mutex_unlock(&d->mu);
    if (!running || !q) {
      return NULL;
    }
    murmur_session_t *qs = NULL;
    int rc = murmur_quic_accept(q, &qs, DRIVER_POLL_MS);
    if (rc == -MURMUR_QUIC_TIMEOUT) {
      continue;
    }
    if (rc != 0) {
      sleep_ms(100);
      continue;
    }
    murmur_node_t peer;
    memset(&peer, 0, sizeof(peer));
    if (murmur_session_peer(qs, &peer) != 0 || peer_is_self(d, &peer)) {
      murmur_session_close(qs);
      murmur_session_release(qs);
      continue;
    }
    pthread_mutex_lock(&d->mu);
    int dup = reg_find(d, &peer) != NULL;
    pthread_mutex_unlock(&d->mu);
    if (dup) {
      murmur_session_close(qs);
      murmur_session_release(qs);
      continue;
    }
    murmur_stream_t *st = NULL;
    rc = murmur_session_accept_stream(qs, &st,
                                      DRIVER_FIRST_STREAM_TIMEOUT_MS);
    if (rc != 0) {
      murmur_session_close(qs);
      murmur_session_release(qs);
      continue;
    }
    stream_ctx_t *c = (stream_ctx_t *)malloc(sizeof(*c));
    if (!c) {
      murmur_stream_close(st);
      murmur_stream_release(st);
      murmur_session_close(qs);
      murmur_session_release(qs);
      continue;
    }
    memset(c, 0, sizeof(*c));
    c->st = st;
    murmur_stream_io_t io;
    io.write = stream_write;
    io.read_full = stream_read_full;
    io.close = stream_close;
    io.error_text = stream_error;
    io.ctx = c;
    rc = run_handshake(d, &peer, &io, 0);
    io_close(&io);
    if (rc != 0) {
      murmur_session_close(qs);
      murmur_session_release(qs);
      continue;
    }
    register_and_serve(d, qs, &peer);
  }
}

/* ---- dialing ---- */

typedef struct {
  murmur_driver_t *d;
  char addr[72];
} dial_arg_t;

static void dial_begin(murmur_driver_t *d, const char *addr) {
  pthread_mutex_lock(&d->mu);
  if (d->n_dialing < 16) {
    strncpy(d->dialing[d->n_dialing], addr, 71);
    d->dialing[d->n_dialing][71] = '\0';
    d->n_dialing++;
  }
  pthread_mutex_unlock(&d->mu);
}

/* Ends a dial attempt with a 5s cooldown against hot redial. */
static void dial_end(murmur_driver_t *d, const char *addr) {
  pthread_mutex_lock(&d->mu);
  for (size_t i = 0; i < d->n_dialing; i++) {
    if (strcmp(d->dialing[i], addr) == 0) {
      d->dialing[i][0] = '\0';
      if (i + 1 < d->n_dialing) {
        memmove(d->dialing[i], d->dialing[i + 1],
                (d->n_dialing - i - 1) * 72);
      }
      d->n_dialing--;
      break;
    }
  }
  uint64_t until = murmur_engine_wall_ms() + 5000;
  size_t slot = 0;
  for (; slot < d->n_cool; slot++) {
    if (strcmp(d->dial_cool[slot], addr) == 0) {
      break;
    }
  }
  if (slot == d->n_cool) {
    if (d->n_cool < 16) {
      slot = d->n_cool++;
    } else {
      slot = 0;
    }
    strncpy(d->dial_cool[slot], addr, 71);
    d->dial_cool[slot][71] = '\0';
  }
  d->dial_cool_until[slot] = until;
  pthread_mutex_unlock(&d->mu);
}

static int dial_suppressed(murmur_driver_t *d, const char *addr) {
  uint64_t now = murmur_engine_wall_ms();
  pthread_mutex_lock(&d->mu);
  for (size_t i = 0; i < d->n_dialing; i++) {
    if (strcmp(d->dialing[i], addr) == 0) {
      pthread_mutex_unlock(&d->mu);
      return 1;
    }
  }
  for (size_t i = 0; i < d->n_cool; i++) {
    if (strcmp(d->dial_cool[i], addr) == 0 &&
        d->dial_cool_until[i] > now) {
      pthread_mutex_unlock(&d->mu);
      return 1;
    }
  }
  pthread_mutex_unlock(&d->mu);
  return 0;
}

static void *dial_thread(void *v) {
  dial_arg_t *a = (dial_arg_t *)v;
  murmur_driver_t *d = a->d;
  char ip[128];
  uint16_t port = 0;
  if (split_addr(a->addr, ip, sizeof(ip), &port) != 0) {
    dial_end(d, a->addr);
    free(a);
    return NULL;
  }
  pthread_mutex_lock(&d->mu);
  murmur_quic_t *q = d->quic;
  int running = d->running;
  pthread_mutex_unlock(&d->mu);
  murmur_session_t *qs = NULL;
  if (!running || !q ||
      murmur_quic_dial(q, ip, port, NULL, &qs,
                       DRIVER_DIAL_TIMEOUT_MS) != 0) {
    dial_end(d, a->addr);
    free(a);
    return NULL;
  }
  murmur_node_t peer;
  memset(&peer, 0, sizeof(peer));
  if (murmur_session_peer(qs, &peer) != 0 || peer_is_self(d, &peer)) {
    murmur_session_close(qs);
    murmur_session_release(qs);
    dial_end(d, a->addr);
    free(a);
    return NULL;
  }
  pthread_mutex_lock(&d->mu);
  int dup = reg_find(d, &peer) != NULL;
  pthread_mutex_unlock(&d->mu);
  if (dup) {
    murmur_session_close(qs);
    murmur_session_release(qs);
    dial_end(d, a->addr);
    free(a);
    return NULL;
  }
  murmur_stream_t *st = NULL;
  if (murmur_session_open_stream(qs, &st) != 0) {
    murmur_session_close(qs);
    murmur_session_release(qs);
    dial_end(d, a->addr);
    free(a);
    return NULL;
  }
  stream_ctx_t *c = (stream_ctx_t *)malloc(sizeof(*c));
  if (!c) {
    murmur_stream_close(st);
    murmur_stream_release(st);
    murmur_session_close(qs);
    murmur_session_release(qs);
    dial_end(d, a->addr);
    free(a);
    return NULL;
  }
  memset(c, 0, sizeof(*c));
  c->st = st;
  murmur_stream_io_t io;
  io.write = stream_write;
  io.read_full = stream_read_full;
  io.close = stream_close;
  io.error_text = stream_error;
  io.ctx = c;
  int rc = run_handshake(d, &peer, &io, 1);
  io_close(&io);
  dial_end(d, a->addr);
  free(a);
  if (rc != 0) {
    murmur_session_close(qs);
    murmur_session_release(qs);
    return NULL;
  }
  register_and_serve(d, qs, &peer);
  return NULL;
}

/* ---- sync workers ---- */

static int accept_remote(murmur_driver_t *d) {
  pthread_mutex_lock(&d->eng->mu);
  sqlite3 *db = d->eng->db;
  pthread_mutex_unlock(&d->eng->mu);
  murmur_schema_params_t p;
  memset(&p, 0, sizeof(p));
  if (murmur_schema_params_from(db, &p, NULL) != MURMUR_SYNC_OK) {
    return 0;
  }
  return p.accept_remote != 0;
}

/* isSchemaMismatch: Protocol + "schema mismatch" in the message. */
static int is_schema_mismatch(murmur_sync_status_t st, const char *detail) {
  return st == MURMUR_SYNC_PROTOCOL && detail &&
         strstr(detail, "schema mismatch") != NULL;
}

/* isCursorPruned: Protocol + "cursor pruned" in the message: our pull
 * cursor is below the donor's GC watermark, so per-tx catch-up can
 * never succeed and a snapshot is required. */
static int is_cursor_pruned(murmur_sync_status_t st, const char *detail) {
  return st == MURMUR_SYNC_PROTOCOL && detail &&
         strstr(detail, "cursor pruned") != NULL;
}

/* Reference parity (engine_sync.go missingHistory): a pruned pull
 * cursor triggers a trust-gated snapshot request. The in-flight
 * refusal inside request_snapshot plus the 5s sweep cadence pace
 * retries; failures surface via snapshot_status and the next sweep
 * retries. Untrusted donors stay on per-tx pull (which keeps
 * failing closed until an operator provisions trust). */
static void maybe_request_snapshot(murmur_driver_t *d,
                                   const murmur_node_t *peer) {
  pthread_mutex_lock(&d->eng->mu);
  sqlite3 *db = d->eng->db;
  pthread_mutex_unlock(&d->eng->mu);
  murmur_snap_params_t sp;
  memset(&sp, 0, sizeof(sp));
  if (murmur_snap_params_from(db, &sp, NULL) != MURMUR_SYNC_OK) {
    return;
  }
  int trusted = 0;
  for (size_t i = 0; i < sp.n_trusted; i++) {
    if (murmur_node_eq(&sp.trusted[i], peer)) {
      trusted = 1;
      break;
    }
  }
  murmur_snap_params_free(&sp);
  if (!trusted) {
    return;
  }
  int sqlrc = 0;
  murmur_serve_request_snapshot(d->eng, peer, &sqlrc);
}

typedef struct {
  murmur_driver_t *d;
  murmur_node_t peer;
  uint64_t gen;
} sync_arg_t;

static int sync_alive(murmur_driver_t *d, sync_arg_t *a,
                      murmur_driver_sess_t **sp) {
  pthread_mutex_lock(&d->mu);
  int alive = d->running;
  murmur_driver_sess_t *found = NULL;
  if (alive) {
    for (size_t i = 0; i < d->n_sess; i++) {
      if (d->sess[i]->gen == a->gen && !d->sess[i]->dead) {
        found = d->sess[i];
        break;
      }
    }
    alive = found && murmur_engine_get_conn(d->eng, &a->peer, NULL);
  }
  pthread_mutex_unlock(&d->mu);
  if (sp) {
    *sp = found;
  }
  return alive;
}

static void *sync_thread(void *v) {
  sync_arg_t *a = (sync_arg_t *)v;
  murmur_driver_t *d = a->d;
  char peer8[9];
  static const char *hexd = "0123456789abcdef";
  for (int i = 0; i < 4; i++) {
    peer8[2 * i] = hexd[a->peer.b[i] >> 4];
    peer8[2 * i + 1] = hexd[a->peer.b[i] & 15];
  }
  peer8[8] = '\0';
  SYNC_DBG("peer=%s gen=%llu thread start", peer8,
           (unsigned long long)a->gen);
  for (;;) {
    murmur_driver_sess_t *s = NULL;
    if (!sync_alive(d, a, &s)) {
      SYNC_DBG("gen=%llu not alive; thread exit",
               (unsigned long long)a->gen);
      break;
    }
    murmur_session_if_t sess;
    if (!murmur_engine_get_conn(d->eng, &a->peer, &sess)) {
      SYNC_DBG("gen=%llu no conn; thread exit",
               (unsigned long long)a->gen);
      break;
    }
    int adopted = 0;
    int accept = accept_remote(d);
    for (;;) {
      /* One request per stream: the donor serves exactly one pull
       * request per accepted stream, so each round opens fresh.
       * Reusing the stream reads EOF ("truncated frame header"). */
      if (!sync_alive(d, a, &s)) {
        break;
      }
      murmur_stream_io_t io;
      memset(&io, 0, sizeof(io));
      if (sess.open_stream(sess.ctx, &io) != 0) {
        SYNC_DBG("gen=%llu open_stream failed; killing sess",
                 (unsigned long long)a->gen);
        sess_kill(s);
        break;
      }
      int more = 0;
      char *detail = NULL;
      murmur_sync_status_t st = murmur_serve_pull_once(
          d->eng, &a->peer, &io, &more, &detail, NULL);
      io_close(&io);
      SYNC_DBG("peer=%s gen=%llu pull_once st=%d more=%d detail=%s",
               peer8, (unsigned long long)a->gen, (int)st, more,
               detail ? detail : "-");
      if (st == MURMUR_SYNC_OK) {
        free(detail);
        if (!more) {
          break;
        }
        continue;
      }
      int retry = !adopted && accept &&
                  is_schema_mismatch(st, detail);
      int pruned = is_cursor_pruned(st, detail);
      free(detail);
      if (pruned) {
        SYNC_DBG("gen=%llu cursor pruned; requesting snapshot",
                 (unsigned long long)a->gen);
        maybe_request_snapshot(d, &a->peer);
      }
      if (!retry) {
        SYNC_DBG("gen=%llu pull error st=%d; closing stream",
                 (unsigned long long)a->gen, (int)st);
        break;
      }
      adopted = 1;
      if (murmur_serve_adopt_from_peer(d->eng, &a->peer, &sess, NULL,
                                       NULL) != MURMUR_SYNC_OK) {
        break;
      }
    }
    if (!sync_alive(d, a, NULL)) {
      break;
    }
    murmur_serve_push_schema(d->eng, &a->peer, &sess);
    /* Idle until the next sweep, a kick, or death. */
    int kicked = 0;
    for (int i = 0; i < DRIVER_SYNC_MS / 100; i++) {
      if (!sync_alive(d, a, NULL)) {
        break;
      }
      if (murmur_engine_take_sync(d->eng)) {
        kicked = 1;
        break;
      }
      sleep_ms(100);
    }
    if (!sync_alive(d, a, NULL)) {
      break;
    }
    (void)kicked;
  }
  pthread_mutex_lock(&d->mu);
  for (size_t i = 0; i < d->n_sess; i++) {
    if (d->sess[i]->gen == a->gen) {
      d->sess[i]->syncing = 0;
    }
  }
  pthread_mutex_unlock(&d->mu);
  free(a);
  return NULL;
}

/* ---- scheduler and ticks ---- */

static void *sched_thread(void *v) {
  murmur_driver_t *d = (murmur_driver_t *)v;
  char seeds[32 * MURMUR_SEED_STRLEN];
  murmur_fetch_source_t sources[128];
  murmur_node_t peers[128];
  for (;;) {
    pthread_mutex_lock(&d->mu);
    int running = d->running;
    uint16_t port = d->local_port;
    pthread_mutex_unlock(&d->mu);
    if (!running) {
      return NULL;
    }
    size_t n_seeds = murmur_engine_seeds(d->eng, seeds, 32);
    for (size_t i = 0; i < n_seeds; i++) {
      const char *addr = seeds + i * MURMUR_SEED_STRLEN;
      if (!addr[0] || dial_suppressed(d, addr)) {
        continue;
      }
      dial_arg_t *a = (dial_arg_t *)malloc(sizeof(*a));
      if (!a) {
        continue;
      }
      a->d = d;
      strncpy(a->addr, addr, sizeof(a->addr) - 1);
      a->addr[sizeof(a->addr) - 1] = '\0';
      dial_begin(d, a->addr);
      if (spawn_detached(d, dial_thread, a) != 0) {
        dial_end(d, a->addr);
        free(a);
      }
    }
    size_t n_src =
        murmur_engine_fetch_sources(d->eng, port, sources, 128);
    for (size_t i = 0; i < n_src; i++) {
      if (peer_is_self(d, &sources[i].node)) {
        continue;
      }
      pthread_mutex_lock(&d->mu);
      int known = reg_find(d, &sources[i].node) != NULL;
      pthread_mutex_unlock(&d->mu);
      if (known) {
        continue;
      }
      char addr[72];
      murmur_addr_format(&sources[i].addr, addr, sizeof(addr));
      if (dial_suppressed(d, addr)) {
        continue;
      }
      dial_arg_t *a = (dial_arg_t *)malloc(sizeof(*a));
      if (!a) {
        continue;
      }
      a->d = d;
      strncpy(a->addr, addr, sizeof(a->addr) - 1);
      a->addr[sizeof(a->addr) - 1] = '\0';
      dial_begin(d, a->addr);
      if (spawn_detached(d, dial_thread, a) != 0) {
        dial_end(d, a->addr);
        free(a);
      }
    }
    size_t n_peers = murmur_engine_conn_peers(d->eng, peers, 128);
    for (size_t i = 0; i < n_peers; i++) {
      pthread_mutex_lock(&d->mu);
      murmur_driver_sess_t *s = reg_find(d, &peers[i]);
      if (s && !s->syncing) {
        s->syncing = 1;
        sync_arg_t *a = (sync_arg_t *)malloc(sizeof(*a));
        if (a) {
          a->d = d;
          a->peer = peers[i];
          a->gen = s->gen;
          pthread_mutex_unlock(&d->mu);
          if (spawn_detached(d, sync_thread, a) != 0) {
            pthread_mutex_lock(&d->mu);
            s->syncing = 0;
            pthread_mutex_unlock(&d->mu);
            free(a);
          }
          continue;
        }
      }
      pthread_mutex_unlock(&d->mu);
    }
    sleep_ms(DRIVER_SCHED_MS);
  }
}

static void *tick_thread(void *v) {
  murmur_driver_t *d = (murmur_driver_t *)v;
  int n = 0;
  for (;;) {
    pthread_mutex_lock(&d->mu);
    int running = d->running;
    pthread_mutex_unlock(&d->mu);
    if (!running) {
      return NULL;
    }
    murmur_engine_gossip(d->eng);
    murmur_engine_probe(d->eng, murmur_engine_wall_ms());
    if (++n >= DRIVER_RETENTION_TICKS) {
      n = 0;
      murmur_engine_retention_pass(d->eng, NULL, NULL, NULL);
    }
    if (d->files_on && d->fetch) {
      uint64_t interval = d->files_cfg.fetch_interval_ms;
      uint64_t every =
          (interval + DRIVER_TICK_MS - 1) / DRIVER_TICK_MS;
      if (every < 1) {
        every = 1;
      }
      if (++d->file_tick >= every) {
        d->file_tick = 0;
        file_tick(d);
      }
    }
    if (d->search_on && d->search) {
      uint64_t interval = d->search_interval_ms;
      uint64_t every =
          (interval + DRIVER_TICK_MS - 1) / DRIVER_TICK_MS;
      if (every < 1) {
        every = 1;
      }
      if (++d->search_tick_n >= every) {
        d->search_tick_n = 0;
        search_tick(d);
      }
    }
    sleep_ms(DRIVER_TICK_MS);
  }
}

/* ---- lifecycle ---- */

murmur_sync_status_t murmur_driver_start(murmur_driver_t *d,
                                         char **detail_out, int *sqlrc) {
  set_detail(detail_out, NULL);
  pthread_mutex_lock(&d->mu);
  if (d->running) {
    pthread_mutex_unlock(&d->mu);
    set_detail(detail_out, "replication already running");
    set_sqlrc(sqlrc, SQLITE_OK);
    return MURMUR_SYNC_OVERLOADED;
  }
  pthread_mutex_unlock(&d->mu);
  pthread_mutex_lock(&d->eng->mu);
  sqlite3 *db = d->eng->db;
  pthread_mutex_unlock(&d->eng->mu);
  quic_settings_t qs;
  murmur_sync_status_t st =
      load_quic_settings(db, &qs, detail_out, sqlrc);
  if (st != MURMUR_SYNC_OK) {
    return st;
  }
  char bind_ip[128];
  uint16_t bind_port = 0;
  if (split_addr(qs.bind, bind_ip, sizeof(bind_ip), &bind_port) != 0) {
    quic_settings_free(&qs);
    set_detail(detail_out, "invalid bind");
    set_sqlrc(sqlrc, SQLITE_OK);
    return MURMUR_SYNC_INVALID;
  }
  if (!qs.cert_file[0] || !qs.key_file[0] || !qs.ca_file[0]) {
    quic_settings_free(&qs);
    set_detail(detail_out, "replication TLS is not configured");
    set_sqlrc(sqlrc, SQLITE_OK);
    return MURMUR_SYNC_INVALID;
  }
  murmur_engine_set_transport(d->eng, qs.bind);
  st = murmur_engine_start(d->eng, detail_out, sqlrc);
  if (st != MURMUR_SYNC_OK) {
    quic_settings_free(&qs);
    return st;
  }
  pthread_mutex_lock(&d->eng->mu);
  murmur_node_t self = d->eng->node;
  murmur_node_t group = d->eng->group;
  pthread_mutex_unlock(&d->eng->mu);
  if (d->files_on && !d->files) {
    murmur_files_config_t fc;
    murmur_files_config_default(&fc, d->files_cfg.directory, d->files_cfg.key);
    fc.previous_key = d->files_cfg.previous_key;
    fc.generation = d->files_cfg.generation;
    fc.max_file_bytes = d->files_cfg.max_file_bytes;
    fc.max_staging_bytes = d->files_cfg.max_staging_bytes;
    fc.fetch_interval_ms = d->files_cfg.fetch_interval_ms;
    fc.concurrent_fetches = d->files_cfg.concurrent_fetches;
    char *fdetail = NULL;
    int fsqlrc = 0;
    murmur_files_status_t fws = murmur_files_open(&fc, db, &self, &d->files,
                                                  &fdetail, &fsqlrc);
    if (fws != MURMUR_FILES_OK) {
      set_detail(detail_out, fdetail ? fdetail : "file store open failed");
      free(fdetail);
      set_sqlrc(sqlrc, fsqlrc);
      st = fws == MURMUR_FILES_INVALID ? MURMUR_SYNC_INVALID
                                       : MURMUR_SYNC_SQLITE;
      quic_settings_free(&qs);
      murmur_driver_stop(d, NULL);
      return st;
    }
    free(fdetail);
  }
  if (d->search_on && d->search) {
    char *sdetail = NULL;
    int ssqlrc = 0;
    murmur_search_status_t sss =
        murmur_search_register(db, d->search, &sdetail, &ssqlrc);
    if (sss == MURMUR_SEARCH_OK) {
      free(sdetail);
      sdetail = NULL;
      sss = murmur_search_sync_schema(d->search, db, 1, &sdetail, &ssqlrc);
    }
    if (sss != MURMUR_SEARCH_OK) {
      set_detail(detail_out, sdetail ? sdetail : "search start failed");
      free(sdetail);
      set_sqlrc(sqlrc, ssqlrc);
      st = MURMUR_SYNC_INVALID;
      quic_settings_free(&qs);
      murmur_driver_stop(d, NULL);
      return st;
    }
    free(sdetail);
    murmur_search_attach(d->search, db);
  }
  uint8_t **chain = NULL, **ca = NULL;
  size_t *chain_lens = NULL, *ca_lens = NULL;
  size_t n_chain = 0, n_ca = 0;
  uint8_t *key = NULL;
  size_t key_len = 0;
  murmur_quic_t *q = NULL;
  if (load_pem_certs(qs.cert_file, &chain, &chain_lens, &n_chain) != 0 ||
      read_file(qs.key_file, &key, &key_len) != 0 ||
      load_pem_certs(qs.ca_file, &ca, &ca_lens, &n_ca) != 0) {
    set_detail(detail_out, "replication TLS files unreadable");
    set_sqlrc(sqlrc, SQLITE_OK);
    st = MURMUR_SYNC_INVALID;
    goto unwind_engine;
  }
  const char **cidrs = NULL;
  if (qs.n_cidrs > 0) {
    cidrs = (const char **)malloc(qs.n_cidrs * sizeof(*cidrs));
    if (!cidrs) {
      set_sqlrc(sqlrc, SQLITE_OK);
      st = MURMUR_SYNC_OVERLOADED;
      goto unwind_tls;
    }
    for (size_t i = 0; i < qs.n_cidrs; i++) {
      cidrs[i] = qs.cidrs[i];
    }
  }
  int rc = murmur_quic_create(
      &q, bind_ip, bind_port, (const uint8_t **)chain, chain_lens, n_chain,
      key, key_len, (const uint8_t **)ca, ca_lens, n_ca, &self,
      qs.allowed, qs.n_allowed, cidrs, qs.n_cidrs, qs.sessions,
      qs.sessions);
  free(cidrs);
  if (rc != 0) {
    set_detail(detail_out, NULL);
    set_sqlrc(sqlrc, SQLITE_OK);
    st = rc == -MURMUR_QUIC_AUTH ? MURMUR_SYNC_AUTH : MURMUR_SYNC_INVALID;
    goto unwind_tls;
  }
  if (d->files_on && !d->fetch) {
    murmur_fetch_config_t fc;
    memset(&fc, 0, sizeof(fc));
    fc.bind_ip = d->files_cfg.fetch_bind_ip;
    fc.bind_port = d->files_cfg.fetch_port;
    fc.chain_der = (const uint8_t **)chain;
    fc.chain_lens = chain_lens;
    fc.chain_n = n_chain;
    fc.key_pem = key;
    fc.key_len = key_len;
    fc.ca_der = (const uint8_t **)ca;
    fc.ca_lens = ca_lens;
    fc.ca_n = n_ca;
    fc.self = self;
    fc.allowed = qs.allowed;
    fc.n_allowed = qs.n_allowed;
    fc.allow_cidrs = (const char **)qs.cidrs;
    fc.n_cidrs = qs.n_cidrs;
    fc.concurrent_fetches = d->files_cfg.concurrent_fetches;
    fc.max_staging_bytes = d->files_cfg.max_staging_bytes;
    fc.max_conns = qs.sessions;
    char *fdetail = NULL;
    murmur_files_status_t fws = murmur_fetch_start(&fc, d->files, &group,
                                                   &d->fetch, &fdetail);
    if (fws != MURMUR_FILES_OK) {
      set_detail(detail_out, fdetail ? fdetail : "file service start failed");
      free(fdetail);
      set_sqlrc(sqlrc, SQLITE_OK);
      st = MURMUR_SYNC_INVALID;
      goto unwind_tls;
    }
    free(fdetail);
  }
  free_ders(chain, chain_lens, n_chain);
  free_ders(ca, ca_lens, n_ca);
  free(key);
  chain = NULL;
  ca = NULL;
  key = NULL;
  char actual[128];
  if (murmur_quic_local_addr(q, actual, sizeof(actual)) == 0) {
    murmur_engine_set_transport(d->eng, actual);
  }
  pthread_mutex_lock(&d->mu);
  d->quic = q;
  d->local_port = bind_port;
  d->sessions = qs.sessions;
  d->running = 1;
  pthread_mutex_unlock(&d->mu);
  quic_settings_free(&qs);
  if (pthread_create(&d->accept_th, NULL, accept_thread, d) != 0 ||
      pthread_create(&d->sched_th, NULL, sched_thread, d) != 0 ||
      pthread_create(&d->tick_th, NULL, tick_thread, d) != 0) {
    murmur_driver_stop(d, NULL);
    set_detail(detail_out, "replication threads failed to start");
    set_sqlrc(sqlrc, SQLITE_OK);
    return MURMUR_SYNC_OVERLOADED;
  }
  set_sqlrc(sqlrc, SQLITE_OK);
  return MURMUR_SYNC_OK;

unwind_tls:
  free_ders(chain, chain_lens, n_chain);
  free_ders(ca, ca_lens, n_ca);
  free(key);
unwind_engine:
  quic_settings_free(&qs);
  murmur_driver_stop(d, NULL);
  return st;
}

murmur_sync_status_t murmur_driver_stop(murmur_driver_t *d, int *sqlrc) {
  pthread_mutex_lock(&d->mu);
  int was = d->running;
  d->running = 0;
  murmur_quic_t *q = d->quic;
  d->quic = NULL;
  pthread_mutex_unlock(&d->mu);
  /* Close first: unblocks every pump, syncer, and accept. */
  if (q) {
    murmur_quic_close(q);
  }
  if (was) {
    pthread_join(d->accept_th, NULL);
    pthread_join(d->sched_th, NULL);
    pthread_join(d->tick_th, NULL);
  }
  /* Tick is down: no file_tick/search_tick in flight. Stop the
   * fetch service (drains transfer workers), close the store, and
   * detach the search hook (the manager stays staged). */
  pthread_mutex_lock(&d->mu);
  murmur_fetch_t *fetch = d->fetch;
  d->fetch = NULL;
  murmur_files_t *files = d->files;
  d->files = NULL;
  d->file_tick = 0;
  murmur_search_manager_t *search = d->search;
  sqlite3 *sdb = d->eng ? d->eng->db : NULL;
  d->search_tick_n = 0;
  pthread_mutex_unlock(&d->mu);
  if (search && sdb) {
    murmur_search_detach(search, sdb);
  }
  if (fetch) {
    murmur_fetch_stop(fetch);
  }
  if (files) {
    murmur_files_close(files);
  }
  pthread_mutex_lock(&d->mu);
  while (d->detached > 0) {
    pthread_cond_wait(&d->detach_cond, &d->mu);
  }
  pthread_mutex_unlock(&d->mu);
  if (q) {
    murmur_quic_free(q);
  }
  /* All driver threads are down. Serve workers (vet/snapshot)
   * still hold session copies, so wait them out before dropping
   * sessions (bounded: endpoint close fails their IO; a mid-apply
   * snapshot poll caps the stall at 60s). */
  murmur_engine_worker_wait(d->eng);
  pthread_mutex_lock(&d->mu);
  size_t n = d->n_sess;
  murmur_driver_sess_t **all = d->sess;
  d->sess = NULL;
  d->n_sess = d->cap_sess = 0;
  d->n_dialing = 0;
  d->n_cool = 0;
  pthread_mutex_unlock(&d->mu);
  for (size_t i = 0; i < n; i++) {
    murmur_driver_sess_t *s = all[i];
    murmur_session_t *qs = NULL;
    pthread_mutex_lock(&d->mu);
    if (!s->dead) {
      s->dead = 1;
      qs = s->qs;
      s->qs = NULL;
    }
    pthread_mutex_unlock(&d->mu);
    if (qs) {
      murmur_session_close(qs);
      murmur_session_release(qs);
    }
    murmur_engine_remove_conn(d->eng, &s->peer);
    free(s);
  }
  free(all);
  return murmur_engine_stop(d->eng, sqlrc);
}
