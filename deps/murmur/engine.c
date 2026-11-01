/* murmur engine - see engine.h. */
#include "engine.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "config.h"
#include "framing.h"
#include "kv.h"
#include "retain.h"
#include "retainpass.h"
#include "schema.h"
#include "serve.h"
#include "sqlite3.h"
#include "../crsqlite/include/sqlite_murmur_crsqlite.h"
#include "txretain.h"
#include "txsnap.h"

#define SEED_SLOT 72

static int seed_has(const murmur_engine_t *e, const char *canon);
static int seed_put(murmur_engine_t *e, const char *canon);

static void set_sqlrc(int *sqlrc, int rc) {
  if (sqlrc) {
    *sqlrc = rc;
  }
}

static murmur_sync_status_t sqlite_fail(int *sqlrc, int rc) {
  set_sqlrc(sqlrc, rc);
  return MURMUR_SYNC_SQLITE;
}

static murmur_sync_status_t ok_rc(int *sqlrc) {
  set_sqlrc(sqlrc, SQLITE_OK);
  return MURMUR_SYNC_OK;
}

static murmur_sync_status_t invalid_fail(int *sqlrc) {
  set_sqlrc(sqlrc, SQLITE_OK);
  return MURMUR_SYNC_INVALID;
}

static murmur_sync_status_t busy_fail(int *sqlrc) {
  set_sqlrc(sqlrc, SQLITE_OK);
  return MURMUR_SYNC_OVERLOADED;
}

uint64_t murmur_engine_wall_ms(void) {
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  return (uint64_t)ts.tv_sec * 1000 + (uint64_t)(ts.tv_nsec / 1000000);
}

static uint64_t mono_ms(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * 1000 + (uint64_t)(ts.tv_nsec / 1000000);
}

void murmur_engine_init(murmur_engine_t *e, sqlite3 *db) {
  memset(e, 0, sizeof(*e));
  pthread_mutex_init(&e->mu, NULL);
  pthread_mutex_init(&e->mship_mu, NULL);
  pthread_cond_init(&e->sync_cond, NULL);
  pthread_cond_init(&e->serving_cond, NULL);
  pthread_cond_init(&e->receiving_cond, NULL);
  pthread_cond_init(&e->worker_cond, NULL);
  e->db = db;
}

void murmur_engine_destroy(murmur_engine_t *e) {
  free(e->bind_addr);
  murmur_mship_free(e->mship);
  free(e->last_err_kind);
  free(e->last_err_msg);
  free(e->last_error_text);
  free(e->snapshot_status);
  free(e->vetted);
  free(e->schema_sent);
  free(e->conns);
  free(e->seeds);
  pthread_mutex_destroy(&e->mu);
  pthread_mutex_destroy(&e->mship_mu);
  pthread_cond_destroy(&e->sync_cond);
  pthread_cond_destroy(&e->serving_cond);
  pthread_cond_destroy(&e->receiving_cond);
  pthread_cond_destroy(&e->worker_cond);
  memset(e, 0, sizeof(*e));
}

void murmur_engine_set_transport(murmur_engine_t *e, const char *local_addr) {
  pthread_mutex_lock(&e->mu);
  free(e->bind_addr);
  e->bind_addr = NULL;
  e->has_transport = local_addr != NULL;
  if (local_addr) {
    e->bind_addr = strdup(local_addr);
  }
  pthread_mutex_unlock(&e->mu);
}

int murmur_engine_running(murmur_engine_t *e) {
  pthread_mutex_lock(&e->mu);
  int r = e->running;
  pthread_mutex_unlock(&e->mu);
  return r;
}

void murmur_engine_worker_add(murmur_engine_t *e) {
  pthread_mutex_lock(&e->mu);
  e->workers++;
  pthread_mutex_unlock(&e->mu);
}

void murmur_engine_worker_release(murmur_engine_t *e) {
  pthread_mutex_lock(&e->mu);
  e->workers--;
  pthread_cond_broadcast(&e->worker_cond);
  pthread_mutex_unlock(&e->mu);
}

void murmur_engine_worker_wait(murmur_engine_t *e) {
  pthread_mutex_lock(&e->mu);
  while (e->workers > 0) {
    pthread_cond_wait(&e->worker_cond, &e->mu);
  }
  pthread_mutex_unlock(&e->mu);
}

void murmur_engine_fail(murmur_engine_t *e, int32_t code, const char *kind,
                        const char *message) {
  pthread_mutex_lock(&e->mu);
  free(e->last_err_kind);
  free(e->last_err_msg);
  e->has_last_err = 1;
  e->last_err_code = code;
  e->last_err_kind = strdup(kind ? kind : "Storage");
  e->last_err_msg = strdup(message ? message : "");
  pthread_mutex_unlock(&e->mu);
}

void murmur_engine_record(murmur_engine_t *e, const char *text) {
  pthread_mutex_lock(&e->mu);
  free(e->last_error_text);
  e->last_error_text = text ? strdup(text) : NULL;
  pthread_mutex_unlock(&e->mu);
}

/* ---- node strings ---- */

/* 32 lowercase hex digits plus NUL. */
void murmur_engine_node_format(const murmur_node_t *id, char out[33]) {
  static const char *d = "0123456789abcdef";
  for (int i = 0; i < 16; i++) {
    out[2 * i] = d[id->b[i] >> 4];
    out[2 * i + 1] = d[id->b[i] & 15];
  }
  out[32] = '\0';
}

/* ParseID: dashes ignored, 16 hex bytes, nonzero (INVALID). */
murmur_sync_status_t murmur_engine_node_parse(const char *s, murmur_node_t *id,
                                              int *sqlrc) {
  murmur_node_t out;
  memset(out.b, 0, sizeof(out.b));
  size_t n = 0;
  for (const char *p = s ? s : ""; *p; p++) {
    int v;
    if (*p == '-') {
      continue;
    } else if (*p >= '0' && *p <= '9') {
      v = *p - '0';
    } else if (*p >= 'a' && *p <= 'f') {
      v = *p - 'a' + 10;
    } else if (*p >= 'A' && *p <= 'F') {
      v = *p - 'A' + 10;
    } else {
      return invalid_fail(sqlrc);
    }
    if (n >= 32) {
      return invalid_fail(sqlrc);
    }
    if ((n & 1) == 0) {
      out.b[n / 2] = (uint8_t)(v << 4);
    } else {
      out.b[n / 2] = (uint8_t)(out.b[n / 2] | v);
    }
    n++;
  }
  if (n != 32) {
    return invalid_fail(sqlrc);
  }
  static const murmur_node_t zero;
  if (murmur_node_eq(&out, &zero)) {
    return invalid_fail(sqlrc);
  }
  if (id) {
    *id = out;
  }
  return ok_rc(sqlrc);
}

/* ---- JSON (Go encoding/json: sorted keys, HTML escaping) ---- */

typedef struct {
  char *p;
  size_t n, cap;
  int ok;
} jbuf_t;

static void jinit(jbuf_t *b) {
  memset(b, 0, sizeof(*b));
  b->ok = 1;
}

static void jneed(jbuf_t *b, size_t more) {
  if (!b->ok) {
    return;
  }
  if (b->n + more + 1 > b->cap) {
    size_t ncap = b->cap ? b->cap * 2 : 256;
    while (ncap < b->n + more + 1) {
      ncap *= 2;
    }
    char *np = (char *)realloc(b->p, ncap);
    if (!np) {
      b->ok = 0;
      return;
    }
    b->p = np;
    b->cap = ncap;
  }
}

static void jraw(jbuf_t *b, const char *s, size_t len) {
  jneed(b, len);
  if (!b->ok) {
    return;
  }
  memcpy(b->p + b->n, s, len);
  b->n += len;
}

static void jstr(jbuf_t *b, const char *s) {
  static const char *hex = "0123456789abcdef";
  jneed(b, 2);
  if (!b->ok) {
    return;
  }
  b->p[b->n++] = '"';
  for (const uint8_t *p = (const uint8_t *)(s ? s : ""); *p; p++) {
    uint8_t c = *p;
    if (c == '"' || c == '\\') {
      jneed(b, 2);
      if (!b->ok) {
        return;
      }
      b->p[b->n++] = '\\';
      b->p[b->n++] = (char)c;
    } else if (c == '\n') {
      jraw(b, "\\n", 2);
    } else if (c == '\r') {
      jraw(b, "\\r", 2);
    } else if (c == '\t') {
      jraw(b, "\\t", 2);
    } else if (c < 0x20) {
      char e[6] = {'\\', 'u', '0', '0', hex[c >> 4], hex[c & 15]};
      jraw(b, e, 6);
    } else if (c == '<') {
      jraw(b, "\\u003c", 6);
    } else if (c == '>') {
      jraw(b, "\\u003e", 6);
    } else if (c == '&') {
      jraw(b, "\\u0026", 6);
    } else if (c == 0xE2 && p[1] == 0x80 && (p[2] == 0xA8 || p[2] == 0xA9)) {
      /* U+2028/29 */
      char e[6] = {'\\', 'u', '2', '0', '2', (char)('8' + (p[2] & 1))};
      jraw(b, e, 6);
      p += 2;
    } else {
      jneed(b, 1);
      if (!b->ok) {
        return;
      }
      b->p[b->n++] = (char)c;
    }
    if (!b->ok) {
      return;
    }
  }
  jneed(b, 1);
  if (b->ok) {
    b->p[b->n++] = '"';
  }
}

static void ju64(jbuf_t *b, uint64_t v) {
  char tmp[21];
  size_t n = 0;
  if (v == 0) {
    tmp[n++] = '0';
  } else {
    char rev[20];
    size_t rn = 0;
    while (v > 0) {
      rev[rn++] = (char)('0' + v % 10);
      v /= 10;
    }
    while (rn > 0) {
      tmp[n++] = rev[--rn];
    }
  }
  jraw(b, tmp, n);
}

static void ji64(jbuf_t *b, int64_t v) {
  if (v < 0) {
    jraw(b, "-", 1);
    /* careful with INT64_MIN */
    uint64_t u = (uint64_t)(-(v + 1)) + 1;
    ju64(b, u);
  } else {
    ju64(b, (uint64_t)v);
  }
}

static void jkey(jbuf_t *b, int *first, const char *k) {
  jraw(b, *first ? "{" : ",", 1);
  *first = 0;
  jstr(b, k);
  jraw(b, ":", 1);
}

static char *jfinish(jbuf_t *b, const char *fallback) {
  if (!b->ok) {
    free(b->p);
    return strdup(fallback);
  }
  jneed(b, 1);
  if (!b->ok) {
    free(b->p);
    return strdup(fallback);
  }
  b->p[b->n] = '\0';
  return b->p;
}

char *murmur_engine_status(murmur_engine_t *e) {
  pthread_mutex_lock(&e->mu);
  int running = e->running;
  char node[33], site[33], group[33];
  murmur_engine_node_format(&e->node, node);
  murmur_engine_node_format(&e->site, site);
  murmur_engine_node_format(&e->group, group);
  char *bind = e->bind_addr ? strdup(e->bind_addr) : NULL;
  size_t conns = e->n_conns;
  uint64_t applied = e->applied, sent = e->sent;
  char *snap = e->snapshot_status ? strdup(e->snapshot_status) : NULL;
  uint64_t adoptions = e->schema_adoptions;
  uint64_t vok = e->vet_ok, vno = e->vet_no, vfail = e->vet_fail;
  uint64_t sok = e->serve_ok, srej = e->serve_reject, serr = e->serve_error;
  uint64_t m_recv = e->recv_batches, m_snap = e->snapshots;
  uint64_t m_gossip = e->gossip_rounds;
  uint64_t m_psent = e->probes_sent, m_pfail = e->probes_failed;
  uint64_t m_ae = e->anti_entropy, m_push = e->schema_pushes;
  uint64_t m_runs = e->retention_runs;
  uint64_t m_abytes = e->apply_bytes, m_anos = e->apply_nanos;
  uint64_t serving_use = e->serving_in_use;
  uint64_t receiving_max = e->receiving_max, receiving_use = e->receiving_in_use;
  sqlite3 *db = e->db;
  char *le = e->last_error_text ? strdup(e->last_error_text) : NULL;
  int has_err = e->has_last_err;
  int32_t code = e->last_err_code;
  char *kind = e->last_err_kind ? strdup(e->last_err_kind) : NULL;
  char *msg = e->last_err_msg ? strdup(e->last_err_msg) : NULL;
  pthread_mutex_unlock(&e->mu);
  size_t members = 0;
  pthread_mutex_lock(&e->mship_mu);
  if (e->mship && murmur_mship_view(e->mship)) {
    members = murmur_view_size(murmur_mship_view(e->mship));
  }
  pthread_mutex_unlock(&e->mship_mu);
  /* staged gauge + durable collected counter (db reads need no lock). */
  uint64_t staged = 0, rcollected = 0;
  if (running && db) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM murmur_stage", -1, &st,
                           NULL) == SQLITE_OK &&
        sqlite3_step(st) == SQLITE_ROW) {
      staged = (uint64_t)sqlite3_column_int64(st, 0);
    }
    sqlite3_finalize(st);
    int sqlrc = 0;
    murmur_tx_retention_status_t rst;
    memset(&rst, 0, sizeof(rst));
    if (murmur_tx_status(db, &rst, &sqlrc) == MURMUR_SYNC_OK) {
      rcollected = rst.collected_transactions;
    }
    murmur_tx_retention_status_free(&rst);
  }
  jbuf_t b;
  jinit(&b);
  int first = 1;
  if (running) {
    jkey(&b, &first, "applied_batches");
    ju64(&b, applied);
    jkey(&b, &first, "bind");
    if (bind) {
      jstr(&b, bind);
    } else {
      jraw(&b, "null", 4);
    }
    jkey(&b, &first, "connected_peers");
    ju64(&b, (uint64_t)conns);
    jkey(&b, &first, "group_id");
    jstr(&b, group);
    jkey(&b, &first, "last_error");
    if (le) {
      jstr(&b, le);
    } else {
      jraw(&b, "null", 4);
    }
    if (has_err) {
      jkey(&b, &first, "last_error_code");
      ji64(&b, code);
      jkey(&b, &first, "last_error_kind");
      jstr(&b, kind ? kind : "");
      jkey(&b, &first, "last_error_message");
      jstr(&b, msg ? msg : "");
    }
    jkey(&b, &first, "members");
    ju64(&b, (uint64_t)members);
    /* OVERWATCH ReplicationMetrics with reference names. Units are
     * batches (pushed/received/applied), bytes, and nanos; the pull
     * model has no need phase, so no chunk_need_* counters exist. */
    jkey(&b, &first, "metrics");
    {
      int f2 = 1;
      jkey(&b, &f2, "pushed_transactions");
      ju64(&b, sent);
      jkey(&b, &f2, "received_transactions");
      ju64(&b, m_recv);
      jkey(&b, &f2, "applied_transactions");
      ju64(&b, applied);
      jkey(&b, &f2, "staged_transactions");
      ju64(&b, staged);
      jkey(&b, &f2, "snapshots_applied");
      ju64(&b, m_snap);
      jkey(&b, &f2, "gossip_rounds");
      ju64(&b, m_gossip);
      jkey(&b, &f2, "probes_sent");
      ju64(&b, m_psent);
      jkey(&b, &f2, "probes_failed");
      ju64(&b, m_pfail);
      jkey(&b, &f2, "anti_entropy_runs");
      ju64(&b, m_ae);
      jkey(&b, &f2, "schema_pushes");
      ju64(&b, m_push);
      jkey(&b, &f2, "schema_adoptions");
      ju64(&b, adoptions);
      jkey(&b, &f2, "retention_runs");
      ju64(&b, m_runs);
      jkey(&b, &f2, "retention_pruned");
      ju64(&b, rcollected);
      jkey(&b, &f2, "queue_available_bytes");
      ju64(&b, receiving_max > receiving_use ? receiving_max - receiving_use
                                             : 0);
      jkey(&b, &f2, "apply_batches");
      ju64(&b, applied);
      jkey(&b, &f2, "apply_bytes");
      ju64(&b, m_abytes);
      jkey(&b, &f2, "apply_nanos");
      ju64(&b, m_anos);
      jraw(&b, "}", 1);
    }
    jkey(&b, &first, "node_id");
    jstr(&b, node);
    /* No send backlog exists in the pull model; the instantaneous
     * serve hold is the closest pending-send figure. */
    jkey(&b, &first, "pending_bytes");
    ju64(&b, serving_use);
    jkey(&b, &first, "running");
    jraw(&b, "true", 4);
    jkey(&b, &first, "schema_adoptions");
    ju64(&b, adoptions);
    jkey(&b, &first, "sent_batches");
    ju64(&b, sent);
    jkey(&b, &first, "serve_error");
    ju64(&b, serr);
    jkey(&b, &first, "serve_ok");
    ju64(&b, sok);
    jkey(&b, &first, "serve_reject");
    ju64(&b, srej);
    jkey(&b, &first, "site_id");
    jstr(&b, site);
    jkey(&b, &first, "snapshot");
    if (snap) {
      jstr(&b, snap);
    } else {
      jraw(&b, "null", 4);
    }
    jkey(&b, &first, "vet_fail");
    ju64(&b, vfail);
    jkey(&b, &first, "vet_no");
    ju64(&b, vno);
    jkey(&b, &first, "vet_ok");
    ju64(&b, vok);
  } else {
    jkey(&b, &first, "running");
    jraw(&b, "false", 5);
    if (has_err) {
      jkey(&b, &first, "last_error_code");
      ji64(&b, code);
      jkey(&b, &first, "last_error_kind");
      jstr(&b, kind ? kind : "");
      jkey(&b, &first, "last_error_message");
      jstr(&b, msg ? msg : "");
    }
  }
  jraw(&b, "}", 1);
  free(bind);
  free(snap);
  free(le);
  free(kind);
  free(msg);
  return jfinish(&b, "{\"running\":false}");
}

/* writer_* scheduler triple; 0 on any failure (whole block nulls). */
static int health_triple(sqlite3 *db, uint64_t *local, uint64_t *debt,
                         uint64_t *reserve) {
  const char *names[3] = {"writer_local_share", "writer_max_debt_ms",
                          "writer_maintenance_reserve_every"};
  uint64_t *slots[3] = {local, debt, reserve};
  for (int i = 0; i < 3; i++) {
    char *raw = NULL;
    int sqlrc = 0;
    if (murmur_cfg_setting(db, names[i], &raw, &sqlrc) != MURMUR_SYNC_OK) {
      return 0;
    }
    uint64_t v = 0;
    int bad = murmur_cfg_atoi(raw, &v) != 0;
    free(raw);
    if (bad) {
      return 0;
    }
    *slots[i] = v;
  }
  return *local >= 1 && *local <= 99;
}

static void jconfig(jbuf_t *b, uint64_t local, uint64_t debt,
                    uint64_t reserve) {
  int first = 1;
  jkey(b, &first, "local_share");
  ju64(b, local);
  jkey(b, &first, "maintenance_reserve_every");
  ju64(b, reserve);
  jkey(b, &first, "max_debt_ms");
  ju64(b, debt);
  jkey(b, &first, "remote_share");
  ju64(b, 100 - local);
  jraw(b, "}", 1);
}

char *murmur_engine_health(murmur_engine_t *e) {
  pthread_mutex_lock(&e->mu);
  int running = e->running;
  uint64_t applied = e->applied, sent = e->sent;
  size_t peers = e->n_conns;
  char *engine_err =
      strdup(e->last_error_text ? e->last_error_text : "");
  uint64_t serving = e->serving_in_use, receiving = e->receiving_in_use;
  int has_err = e->has_last_err;
  int32_t code = e->last_err_code;
  char *kind = e->last_err_kind ? strdup(e->last_err_kind) : NULL;
  char *msg = e->last_err_msg ? strdup(e->last_err_msg) : NULL;
  sqlite3 *db = e->db;
  pthread_mutex_unlock(&e->mu);
  /* pending config + stage bytes + cursor, all-or-nothing */
  int have_pending = 0;
  uint64_t plocal = 0, pdebt = 0, preserve = 0;
  int64_t stage = 0;
  int have_cursor = 0;
  int64_t cursor = 0;
  if (health_triple(db, &plocal, &pdebt, &preserve)) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, "SELECT SUM(LENGTH(data)) FROM murmur_stage",
                           -1, &st, NULL) == SQLITE_OK) {
      int rc = sqlite3_step(st);
      if (rc == SQLITE_ROW) {
        if (sqlite3_column_type(st, 0) != SQLITE_NULL) {
          stage = sqlite3_column_int64(st, 0);
        }
        int sqlrc = 0;
        int64_t v = 0;
        if (murmur_sync_db_version(db, &v, &sqlrc) == MURMUR_SYNC_OK) {
          cursor = v;
          have_cursor = 1;
        }
        have_pending = 1;
      }
      sqlite3_finalize(st);
    }
  }
  uint64_t elocal = 90, edebt = 1000, ereserve = 100;
  if (health_triple(db, &elocal, &edebt, &ereserve)) {
    /* effective from settings */
  } else {
    elocal = 90;
    edebt = 1000;
    ereserve = 100;
  }
  /* retention block */
  int have_retention = 0;
  size_t rpeers = 0, rretired = 0;
  uint64_t rcollected = 0, rlast = 0;
  if (running) {
    int sqlrc = 0;
    murmur_tx_retention_status_t st;
    memset(&st, 0, sizeof(st));
    if (murmur_tx_status(db, &st, &sqlrc) == MURMUR_SYNC_OK) {
      rpeers = st.n_peers;
      for (size_t i = 0; i < st.n_peers; i++) {
        rretired += st.peers[i].retired ? 1 : 0;
      }
      rcollected = st.collected_transactions;
      rlast = st.last_collection_millis;
      have_retention = 1;
    }
    murmur_tx_retention_status_free(&st);
  }
  jbuf_t b;
  jinit(&b);
  int first = 1;
  jkey(&b, &first, "budgets");
  {
    int f2 = 1;
    jkey(&b, &f2, "receiving_in_use_bytes");
    ju64(&b, receiving);
    jkey(&b, &f2, "serving_in_use_bytes");
    ju64(&b, serving);
    jkey(&b, &f2, "stage_bytes");
    if (have_pending) {
      ji64(&b, stage);
    } else {
      jraw(&b, "null", 4);
    }
    jkey(&b, &f2, "worker_payload_bytes");
    jraw(&b, "null", 4);
    jraw(&b, "}", 1);
  }
  jkey(&b, &first, "replication");
  {
    int f2 = 1;
    jkey(&b, &f2, "applied_batches");
    ju64(&b, applied);
    jkey(&b, &f2, "connected_peers");
    ju64(&b, (uint64_t)peers);
    jkey(&b, &f2, "last_error");
    jstr(&b, engine_err ? engine_err : "");
    if (has_err) {
      jkey(&b, &f2, "last_error_code");
      ji64(&b, code);
      jkey(&b, &f2, "last_error_kind");
      jstr(&b, kind ? kind : "");
      jkey(&b, &f2, "last_error_message");
      jstr(&b, msg ? msg : "");
    }
    jkey(&b, &f2, "running");
    jraw(&b, running ? "true" : "false", running ? 4 : 5);
    jkey(&b, &f2, "sent_batches");
    ju64(&b, sent);
    jraw(&b, "}", 1);
  }
  jkey(&b, &first, "retention");
  if (have_retention) {
    int f2 = 1;
    jkey(&b, &f2, "collected_transactions");
    ju64(&b, rcollected);
    jkey(&b, &f2, "last_collection_millis");
    ju64(&b, rlast);
    jkey(&b, &f2, "peers");
    ju64(&b, (uint64_t)rpeers);
    jkey(&b, &f2, "retired");
    ju64(&b, (uint64_t)rretired);
    jraw(&b, "}", 1);
  } else {
    jraw(&b, "null", 4);
  }
  jkey(&b, &first, "scheduler");
  {
    int f2 = 1;
    jkey(&b, &f2, "effective_config");
    jconfig(&b, elocal, edebt, ereserve);
    jkey(&b, &f2, "local_admission_enforced");
    jraw(&b, "false", 5);
    jkey(&b, &f2, "pending_config");
    if (have_pending) {
      jconfig(&b, plocal, pdebt, preserve);
    } else {
      jraw(&b, "null", 4);
    }
    jkey(&b, &f2, "scope");
    jstr(&b, "remote_and_maintenance");
    jkey(&b, &f2, "stats");
    jraw(&b, "null", 4);
    jraw(&b, "}", 1);
  }
  jkey(&b, &first, "storage");
  {
    int f2 = 1;
    jkey(&b, &f2, "committed_cursor");
    if (have_pending && have_cursor) {
      ji64(&b, cursor);
    } else {
      jraw(&b, "null", 4);
    }
    jkey(&b, &f2, "counters");
    jraw(&b, "null", 4);
    jkey(&b, &f2, "durable_cursor");
    jraw(&b, "null", 4);
    jraw(&b, "}", 1);
  }
  jkey(&b, &first, "version");
  ju64(&b, 1);
  jraw(&b, "}", 1);
  free(engine_err);
  free(kind);
  free(msg);
  return jfinish(&b, "{\"version\":1}");
}

char *murmur_engine_progress(murmur_engine_t *e) {
  pthread_mutex_lock(&e->mu);
  int running = e->running;
  sqlite3 *db = e->db;
  murmur_node_t node = e->node;
  pthread_mutex_unlock(&e->mu);
  if (!running) {
    return strdup("[]");
  }
  int sqlrc = 0;
  murmur_tx_progress_t *heads = NULL;
  size_t n_heads = 0;
  if (murmur_backend_progress(db, &node, &heads, &n_heads, &sqlrc) !=
      MURMUR_SYNC_OK) {
    return strdup("[]");
  }
  jbuf_t b;
  jinit(&b);
  jraw(&b, "[", 1);
  for (size_t i = 0; i < n_heads; i++) {
    char origin[33];
    murmur_engine_node_format(&heads[i].origin, origin);
    if (i > 0) {
      jraw(&b, ",", 1);
    }
    int first = 1;
    jkey(&b, &first, "applied");
    ju64(&b, heads[i].applied);
    jkey(&b, &first, "observed");
    ju64(&b, heads[i].observed);
    jkey(&b, &first, "origin");
    jstr(&b, origin);
    jkey(&b, &first, "retained_from");
    ju64(&b, heads[i].retained_from);
    jkey(&b, &first, "retained_through");
    ju64(&b, heads[i].retained_through);
    jraw(&b, "}", 1);
  }
  jraw(&b, "]", 1);
  murmur_tx_progress_free(heads, n_heads);
  return jfinish(&b, "[]");
}

static const char *state_str(murmur_state_t s) {
  switch (s) {
    case MURMUR_ALIVE:
      return "alive";
    case MURMUR_SUSPECT:
      return "suspect";
    case MURMUR_DEAD:
      return "dead";
    case MURMUR_LEFT:
      return "left";
    default:
      return "unknown";
  }
}

/* Go hand-concatenates Peers() with no JSON escaping; replicate. A
 * zero address renders Go's "invalid AddrPort". */
/* Per-peer replication diagnostics (OVERWATCH PeerDiagnostics
 * subset with honest pull-model sources). */
typedef struct {
  int has_seen;
  uint64_t last_seen_ago;
  uint64_t sent_watermark;
  uint64_t lag_txns;
  uint64_t origins_behind;
  int schema_agreed;
} peer_diag_t;

static void jem_emit(jbuf_t *b, int *first, const murmur_member_t *m,
                     int connected, const peer_diag_t *diag) {
  char id[33], addr[64];
  murmur_engine_node_format(&m->node, id);
  static const murmur_addr_t zero;
  if (memcmp(&m->addr, &zero, sizeof(zero)) == 0) {
    strcpy(addr, "invalid AddrPort");
  } else {
    murmur_addr_format(&m->addr, addr, sizeof(addr));
  }
  jraw(b, *first ? "[" : ",", 1);
  *first = 0;
  jraw(b, "{\"node_id\":\"", 12);
  jraw(b, id, 32);
  jraw(b, "\",\"address\":\"", 13);
  jraw(b, addr, strlen(addr));
  jraw(b, "\",\"state\":\"", 11);
  const char *st = state_str(m->state);
  jraw(b, st, strlen(st));
  jraw(b, "\",\"member_state\":\"", 18);
  jraw(b, st, strlen(st));
  jraw(b, "\",\"connected\":", 14);
  jraw(b, connected ? "true" : "false", connected ? 4 : 5);
  jraw(b, ",\"incarnation\":", 15);
  ju64(b, m->incarnation);
  jraw(b, ",\"schema_agreed\":", 17);
  jraw(b, diag->schema_agreed ? "true" : "false", diag->schema_agreed ? 4 : 5);
  /* Pull-only stack: no peer ever enters push mode. */
  jraw(b, ",\"push_mode\":false", 18);
  jraw(b, ",\"last_seen_millis_ago\":", 24);
  if (diag->has_seen) {
    ju64(b, diag->last_seen_ago);
  } else {
    jraw(b, "null", 4);
  }
  jraw(b, ",\"sent_watermark\":", 18);
  ju64(b, diag->sent_watermark);
  jraw(b, ",\"lag_txns\":", 12);
  ju64(b, diag->lag_txns);
  jraw(b, ",\"origins_behind\":", 18);
  ju64(b, diag->origins_behind);
  jraw(b, "}", 1);
}

/* Schema agreement for one peer (reference parity: schemaAcked !=
 * nil). schema_sent[] records peers that acked our manifest push,
 * so an entry means mutual agreement on the pushed schema. The
 * vetted cache is the reverse direction (our verdict on their
 * manifest) and only populates on pull-vet. */
static int peer_schema_agreed(const murmur_schema_sent_t *sent, size_t n_sent,
                              const murmur_node_t *peer) {
  for (size_t i = n_sent; i > 0; i--) {
    if (murmur_node_eq(&sent[i - 1].peer, peer)) {
      return 1;
    }
  }
  return 0;
}

/* Lag math over our applied heads vs the peer's acked boundary. */
static void peer_lag(const murmur_tx_progress_t *heads, size_t n_heads,
                     const murmur_tx_peer_t *record, int have_record,
                     uint64_t *sent_wm, uint64_t *lag, uint64_t *behind) {
  uint64_t wm = 0, lg = 0, bh = 0;
  if (have_record) {
    for (size_t i = 0; i < record->n_acks; i++) {
      if (record->acks[i].seq > wm) {
        wm = record->acks[i].seq;
      }
    }
    for (size_t i = 0; i < n_heads; i++) {
      uint64_t ack = 0;
      for (size_t k = 0; k < record->n_acks; k++) {
        if (murmur_node_eq(&record->acks[k].origin, &heads[i].origin)) {
          ack = record->acks[k].seq;
          break;
        }
      }
      if (heads[i].applied > ack) {
        lg += heads[i].applied - ack;
        bh++;
      }
    }
  }
  *sent_wm = wm;
  *lag = lg;
  *behind = bh;
}

/* Fills one row's diagnostics from the schema-ack records, peer
 * ack records, and our applied heads. */
static void peer_diag_fill(peer_diag_t *diag, sqlite3 *db,
                           const murmur_schema_sent_t *sent, size_t n_sent,
                           const murmur_tx_progress_t *heads, size_t n_heads,
                           const murmur_node_t *peer, uint64_t now_ms) {
  memset(diag, 0, sizeof(*diag));
  diag->schema_agreed = peer_schema_agreed(sent, n_sent, peer);
  if (!db) {
    return;
  }
  murmur_tx_peer_t record;
  memset(&record, 0, sizeof(record));
  int found = 0, sqlrc = 0;
  if (murmur_tx_peer(db, peer, &record, &found, &sqlrc) == MURMUR_SYNC_OK &&
      found) {
    diag->has_seen = 1;
    diag->last_seen_ago = now_ms > record.last_seen_millis
                              ? now_ms - record.last_seen_millis
                              : 0;
    peer_lag(heads, n_heads, &record, 1, &diag->sent_watermark,
             &diag->lag_txns, &diag->origins_behind);
  }
  murmur_tx_peer_free(&record);
}

char *murmur_engine_peers(murmur_engine_t *e) {
  pthread_mutex_lock(&e->mship_mu);
  murmur_view_t *view = e->mship ? murmur_mship_view(e->mship) : NULL;
  size_t n = view ? murmur_view_size(view) : 0;
  murmur_member_t *members = NULL;
  const murmur_member_t *local = NULL;
  murmur_node_t *conns = NULL;
  if (view) {
    members = (murmur_member_t *)malloc(n ? n * sizeof(*members) : 1);
    if (members) {
      murmur_view_members(view, members, n);
    }
    local = murmur_view_local(view);
  }
  murmur_member_t local_copy;
  int have_local = local != NULL;
  if (have_local) {
    local_copy = *local;
  }
  pthread_mutex_unlock(&e->mship_mu);
  pthread_mutex_lock(&e->mu);
  if (e->n_conns > 0) {
    conns = (murmur_node_t *)malloc(e->n_conns * sizeof(*conns));
    if (conns) {
      for (size_t i = 0; i < e->n_conns; i++) {
        conns[i] = e->conns[i].peer;
      }
    }
  }
  size_t n_conns = e->n_conns;
  murmur_schema_sent_t *sent = NULL;
  size_t n_sent = e->n_schema_sent;
  if (n_sent > 0) {
    sent = (murmur_schema_sent_t *)malloc(n_sent * sizeof(*sent));
    if (sent) {
      memcpy(sent, e->schema_sent, n_sent * sizeof(*sent));
    } else {
      n_sent = 0;
    }
  }
  sqlite3 *db = e->db;
  pthread_mutex_unlock(&e->mu);
  murmur_tx_progress_t *heads = NULL;
  size_t n_heads = 0;
  if (db) {
    int sqlrc = 0;
    if (murmur_tx_progress(db, &heads, &n_heads, &sqlrc) != MURMUR_SYNC_OK) {
      heads = NULL;
      n_heads = 0;
    }
  }
  uint64_t now_ms = murmur_tx_now_millis();
  jbuf_t b;
  jinit(&b);
  int first = 1;
  if (members && have_local) {
    for (size_t i = 0; i < n + 1; i++) {
      const murmur_member_t *m = i == 0 ? &local_copy : &members[i - 1];
      int connected = 0;
      if (conns) {
        for (size_t k = 0; k < n_conns && !connected; k++) {
          connected = murmur_node_eq(&conns[k], &m->node);
        }
      }
      peer_diag_t diag;
      peer_diag_fill(&diag, db, sent, n_sent, heads, n_heads, &m->node,
                     now_ms);
      jem_emit(&b, &first, m, connected, &diag);
    }
    /* Union with the transport conn table (reference parity: SHOW
     * PEERS iterates conns, not the gossip view). A freshly dialed
     * peer is connected before SWIM learns it; without this row the
     * peer count reads 0 until the first gossip round. */
    if (conns) {
      for (size_t k = 0; k < n_conns; k++) {
        int known = murmur_node_eq(&conns[k], &local_copy.node);
        for (size_t i = 0; i < n && !known; i++) {
          known = murmur_node_eq(&conns[k], &members[i].node);
        }
        if (known) {
          continue;
        }
        murmur_member_t synth;
        memset(&synth, 0, sizeof(synth));
        synth.node = conns[k];
        synth.state = (murmur_state_t)99; /* renders "unknown" */
        peer_diag_t diag;
        peer_diag_fill(&diag, db, sent, n_sent, heads, n_heads, &conns[k],
                       now_ms);
        jem_emit(&b, &first, &synth, 1, &diag);
      }
    }
  }
  if (first) {
    jraw(&b, "[", 1);
  }
  jraw(&b, "]", 1);
  free(members);
  free(conns);
  free(sent);
  if (heads) {
    murmur_tx_progress_free(heads, n_heads);
  }
  return jfinish(&b, "[]");
}

/* ---- identity ---- */

static murmur_sync_status_t claim_site(sqlite3 *db, murmur_node_t *site,
                                       int *sqlrc) {
  murmur_node_t id;
  murmur_sync_status_t s = murmur_sync_site_id(db, &id, sqlrc);
  if (s != MURMUR_SYNC_OK) {
    return s;
  }
  sqlite3_stmt *st = NULL;
  int rc = sqlite3_prepare_v2(db, "SELECT site FROM murmur_identity WHERE id=1",
                              -1, &st, NULL);
  if (rc != SQLITE_OK) {
    return sqlite_fail(sqlrc, rc);
  }
  rc = sqlite3_step(st);
  if (rc != SQLITE_ROW && rc != SQLITE_DONE) {
    sqlite3_finalize(st);
    return sqlite_fail(sqlrc, rc);
  }
  if (rc == SQLITE_ROW && sqlite3_column_type(st, 0) != SQLITE_NULL) {
    const uint8_t *old = (const uint8_t *)sqlite3_column_blob(st, 0);
    int len = sqlite3_column_bytes(st, 0);
    if (len != 16 || memcmp(old, id.b, 16) != 0) {
      sqlite3_finalize(st);
      set_sqlrc(sqlrc, SQLITE_OK);
      return MURMUR_SYNC_AUTH;
    }
  }
  sqlite3_finalize(st);
  st = NULL;
  rc = sqlite3_prepare_v2(db, "UPDATE murmur_identity SET site=?1 WHERE id=1",
                          -1, &st, NULL);
  if (rc != SQLITE_OK) {
    return sqlite_fail(sqlrc, rc);
  }
  sqlite3_bind_blob(st, 1, id.b, 16, SQLITE_TRANSIENT);
  rc = sqlite3_step(st);
  sqlite3_finalize(st);
  if (rc != SQLITE_DONE) {
    return sqlite_fail(sqlrc, rc);
  }
  if (site) {
    *site = id;
  }
  return ok_rc(sqlrc);
}

static murmur_sync_status_t claim_node(sqlite3 *db, murmur_node_t *node,
                                       int *sqlrc) {
  murmur_node_t id;
  memset(&id, 0, sizeof(id));
  sqlite3_stmt *st = NULL;
  int rc = sqlite3_prepare_v2(db, "SELECT node FROM murmur_identity WHERE id=1",
                              -1, &st, NULL);
  if (rc != SQLITE_OK) {
    return sqlite_fail(sqlrc, rc);
  }
  rc = sqlite3_step(st);
  if (rc != SQLITE_ROW && rc != SQLITE_DONE) {
    sqlite3_finalize(st);
    return sqlite_fail(sqlrc, rc);
  }
  if (rc == SQLITE_ROW && sqlite3_column_type(st, 0) != SQLITE_NULL) {
    const uint8_t *raw = (const uint8_t *)sqlite3_column_blob(st, 0);
    int len = sqlite3_column_bytes(st, 0);
    if (len != 16) {
      sqlite3_finalize(st);
      return invalid_fail(sqlrc);
    }
    memcpy(id.b, raw, 16);
    sqlite3_finalize(st);
    if (node) {
      *node = id;
    }
    return ok_rc(sqlrc);
  }
  sqlite3_finalize(st);
  for (int i = 0; i < 2; i++) {
    uint64_t w = 0;
    if (murmur_word_crypto(NULL, &w) != 0) {
      return sqlite_fail(sqlrc, SQLITE_IOERR);
    }
    memcpy(id.b + 8 * i, &w, 8);
  }
  static const murmur_node_t zero;
  if (murmur_node_eq(&id, &zero)) {
    id.b[0] = 1;
  }
  rc = sqlite3_prepare_v2(db, "UPDATE murmur_identity SET node=?1 WHERE id=1",
                          -1, &st, NULL);
  if (rc != SQLITE_OK) {
    return sqlite_fail(sqlrc, rc);
  }
  sqlite3_bind_blob(st, 1, id.b, 16, SQLITE_TRANSIENT);
  rc = sqlite3_step(st);
  sqlite3_finalize(st);
  if (rc != SQLITE_DONE) {
    return sqlite_fail(sqlrc, rc);
  }
  if (node) {
    *node = id;
  }
  return ok_rc(sqlrc);
}

static murmur_sync_status_t bump_incarnation(sqlite3 *db, uint64_t *out,
                                             char **detail_out, int *sqlrc) {
  sqlite3_stmt *st = NULL;
  int rc = sqlite3_prepare_v2(db,
                              "UPDATE murmur_identity "
                              "SET incarnation=incarnation+1 WHERE id=1 "
                              "RETURNING incarnation",
                              -1, &st, NULL);
  if (rc != SQLITE_OK) {
    return sqlite_fail(sqlrc, rc);
  }
  rc = sqlite3_step(st);
  if (rc != SQLITE_ROW && rc != SQLITE_DONE) {
    sqlite3_finalize(st);
    return sqlite_fail(sqlrc, rc);
  }
  if (rc == SQLITE_DONE) {
    sqlite3_finalize(st);
    if (detail_out) {
      *detail_out = strdup("identity row missing");
    }
    return invalid_fail(sqlrc);
  }
  int64_t v = sqlite3_column_int64(st, 0);
  sqlite3_finalize(st);
  if (v < 0) {
    if (detail_out) {
      *detail_out = strdup("identity incarnation");
    }
    return invalid_fail(sqlrc);
  }
  if (out) {
    *out = (uint64_t)v;
  }
  return ok_rc(sqlrc);
}

static murmur_sync_status_t parse_advertise(sqlite3 *db, murmur_addr_t *out,
                                            int *sqlrc) {
  memset(out, 0, sizeof(*out));
  char *raw = NULL;
  murmur_sync_status_t s = murmur_cfg_setting(db, "advertise", &raw, sqlrc);
  if (s != MURMUR_SYNC_OK) {
    return s;
  }
  if (raw[0] == '\0') {
    free(raw);
    return ok_rc(sqlrc);
  }
  int rc = murmur_addr_parse(out, raw);
  free(raw);
  if (rc != 0) {
    memset(out, 0, sizeof(*out));
    return invalid_fail(sqlrc);
  }
  return ok_rc(sqlrc);
}

/* ---- bootstrap JSON: ["addr",...]; malformed reads empty ---- */

static void skip_ws(const char **p) {
  while (**p == ' ' || **p == '\t' || **p == '\n' || **p == '\r') {
    (*p)++;
  }
}

/* Parses one JSON string; *end lands past the closing quote. */
static char *parse_jstr(const char *p, const char **end) {
  if (*p != '"') {
    return NULL;
  }
  p++;
  size_t cap = 32, n = 0;
  char *o = (char *)malloc(cap);
  if (!o) {
    return NULL;
  }
  for (;;) {
    uint8_t c = (uint8_t)*p;
    if (c == '\0') {
      free(o);
      return NULL;
    }
    if (c == '"') {
      p++;
      break;
    }
    char buf[4];
    size_t bl = 0;
    if (c == '\\') {
      p++;
      switch (*p) {
        case '"':
        case '\\':
        case '/':
          buf[0] = *p;
          bl = 1;
          p++;
          break;
        case 'b':
          buf[0] = '\b';
          bl = 1;
          p++;
          break;
        case 'f':
          buf[0] = '\f';
          bl = 1;
          p++;
          break;
        case 'n':
          buf[0] = '\n';
          bl = 1;
          p++;
          break;
        case 'r':
          buf[0] = '\r';
          bl = 1;
          p++;
          break;
        case 't':
          buf[0] = '\t';
          bl = 1;
          p++;
          break;
        case 'u': {
          /* \uXXXX with surrogate pairs, re-encoded UTF-8 */
          unsigned v = 0;
          for (int i = 0; i < 4; i++) {
            char h = p[1 + i];
            v <<= 4;
            if (h >= '0' && h <= '9') {
              v |= (unsigned)(h - '0');
            } else if (h >= 'a' && h <= 'f') {
              v |= (unsigned)(h - 'a' + 10);
            } else if (h >= 'A' && h <= 'F') {
              v |= (unsigned)(h - 'A' + 10);
            } else {
              free(o);
              return NULL;
            }
          }
          p += 5;
          if (v >= 0xD800 && v <= 0xDBFF && p[0] == '\\' && p[1] == 'u') {
            unsigned lo = 0;
            for (int i = 0; i < 4; i++) {
              char h = p[2 + i];
              lo <<= 4;
              if (h >= '0' && h <= '9') {
                lo |= (unsigned)(h - '0');
              } else if (h >= 'a' && h <= 'f') {
                lo |= (unsigned)(h - 'a' + 10);
              } else if (h >= 'A' && h <= 'F') {
                lo |= (unsigned)(h - 'A' + 10);
              } else {
                free(o);
                return NULL;
              }
            }
            if (lo < 0xDC00 || lo > 0xDFFF) {
              free(o);
              return NULL;
            }
            p += 6;
            v = 0x10000 + ((v - 0xD800) << 10) + (lo - 0xDC00);
          } else if (v >= 0xDC00 && v <= 0xDFFF) {
            free(o);
            return NULL;
          }
          if (v < 0x80) {
            buf[0] = (char)v;
            bl = 1;
          } else if (v < 0x800) {
            buf[0] = (char)(0xC0 | (v >> 6));
            buf[1] = (char)(0x80 | (v & 63));
            bl = 2;
          } else if (v < 0x10000) {
            buf[0] = (char)(0xE0 | (v >> 12));
            buf[1] = (char)(0x80 | ((v >> 6) & 63));
            buf[2] = (char)(0x80 | (v & 63));
            bl = 3;
          } else {
            buf[0] = (char)(0xF0 | (v >> 18));
            buf[1] = (char)(0x80 | ((v >> 12) & 63));
            buf[2] = (char)(0x80 | ((v >> 6) & 63));
            buf[3] = (char)(0x80 | (v & 63));
            bl = 4;
          }
          break;
        }
        default:
          free(o);
          return NULL;
      }
    } else if (c < 0x20) {
      free(o);
      return NULL;
    } else {
      buf[0] = (char)c;
      bl = 1;
      p++;
    }
    if (n + bl + 1 > cap) {
      cap *= 2;
      char *no = (char *)realloc(o, cap);
      if (!no) {
        free(o);
        return NULL;
      }
      o = no;
    }
    memcpy(o + n, buf, bl);
    n += bl;
  }
  o[n] = '\0';
  *end = p;
  return o;
}

static char **decode_bootstrap(const char *raw, size_t *n_out) {
  *n_out = 0;
  const char *p = raw;
  skip_ws(&p);
  if (*p != '[') {
    return NULL;
  }
  p++;
  char **v = NULL;
  size_t n = 0, cap = 0;
  skip_ws(&p);
  if (*p == ']') {
    *n_out = 0;
    return (char **)malloc(1);
  }
  for (;;) {
    const char *end = NULL;
    char *s = parse_jstr(p, &end);
    if (!s) {
      goto fail;
    }
    if (n >= cap) {
      size_t ncap = cap ? cap * 2 : 4;
      char **nv = (char **)realloc(v, ncap * sizeof(*nv));
      if (!nv) {
        free(s);
        goto fail;
      }
      v = nv;
      cap = ncap;
    }
    v[n++] = s;
    p = end;
    skip_ws(&p);
    if (*p == ',') {
      p++;
      skip_ws(&p);
      continue;
    }
    if (*p == ']') {
      p++;
      break;
    }
    goto fail;
  }
  skip_ws(&p);
  if (*p != '\0') {
    goto fail;
  }
  *n_out = n;
  return v;
fail:
  for (size_t i = 0; i < n; i++) {
    free(v[i]);
  }
  free(v);
  *n_out = 0;
  return NULL;
}

/* ---- mship io ---- */

static int engine_send(void *ctx, const murmur_node_t *peer,
                       const murmur_pkt_t *pkt) {
  murmur_engine_t *e = (murmur_engine_t *)ctx;
  uint8_t buf[MURMUR_MAX_DATAGRAM_BYTES + 64];
  size_t len = murmur_pkt_encode(pkt, buf, sizeof(buf));
  if (len == 0 || len > MURMUR_MAX_DATAGRAM_BYTES) {
    return -1;
  }
  pthread_mutex_lock(&e->mu);
  murmur_session_if_t sess;
  int found = 0;
  for (size_t i = 0; i < e->n_conns && !found; i++) {
    if (murmur_node_eq(&e->conns[i].peer, peer)) {
      sess = e->conns[i].sess;
      found = 1;
    }
  }
  pthread_mutex_unlock(&e->mu);
  if (!found) {
    return -1;
  }
  return sess.send_datagram(sess.ctx, buf, len);
}

static int engine_persist(void *ctx, uint64_t incarnation) {
  murmur_engine_t *e = (murmur_engine_t *)ctx;
  pthread_mutex_lock(&e->mu);
  sqlite3 *db = e->db;
  pthread_mutex_unlock(&e->mu);
  sqlite3_stmt *st = NULL;
  int rc = sqlite3_prepare_v2(db,
                              "UPDATE murmur_identity "
                              "SET incarnation=max(incarnation,?1) WHERE id=1",
                              -1, &st, NULL);
  if (rc != SQLITE_OK) {
    return -1;
  }
  sqlite3_bind_int64(st, 1, (int64_t)incarnation);
  rc = sqlite3_step(st);
  sqlite3_finalize(st);
  return rc == SQLITE_DONE ? 0 : -1;
}

static void engine_notify(void *ctx) {
  murmur_engine_kick_sync((murmur_engine_t *)ctx);
}

static void engine_close_conn(void *ctx, const murmur_node_t *peer) {
  murmur_engine_t *e = (murmur_engine_t *)ctx;
  pthread_mutex_lock(&e->mu);
  murmur_session_if_t sess;
  int found = 0;
  for (size_t i = 0; i < e->n_conns; i++) {
    if (murmur_node_eq(&e->conns[i].peer, peer)) {
      sess = e->conns[i].sess;
      e->conns[i] = e->conns[e->n_conns - 1];
      e->n_conns--;
      found = 1;
      break;
    }
  }
  pthread_mutex_unlock(&e->mu);
  if (found && sess.close) {
    sess.close(sess.ctx);
  }
}

/* ---- lifecycle ---- */

/* Start records nothing (Go verbs record via failTo); statuses
 * carry the failure and the caller composes the message. */
murmur_sync_status_t murmur_engine_start(murmur_engine_t *e, char **detail_out,
                                         int *sqlrc) {
  if (detail_out) {
    *detail_out = NULL;
  }
  pthread_mutex_lock(&e->mu);
  if (e->running) {
    pthread_mutex_unlock(&e->mu);
    if (detail_out) {
      *detail_out = strdup("replication already running");
    }
    return busy_fail(sqlrc);
  }
  if (!e->has_transport) {
    pthread_mutex_unlock(&e->mu);
    if (detail_out) {
      *detail_out = strdup("no transport configured");
    }
    return invalid_fail(sqlrc);
  }
  sqlite3 *db = e->db;
  pthread_mutex_unlock(&e->mu);
  /* Signed stores must never fall back to this legacy unsigned runtime. */
  sqlite3_stmt *profile = NULL;
  int profile_rc = sqlite3_prepare_v2(db,
      "SELECT 1 FROM sqlite_schema WHERE type='table' AND name='murmur_origin_config'", -1, &profile, NULL);
  if (profile_rc != SQLITE_OK) return sqlite_fail(sqlrc, profile_rc);
  profile_rc = sqlite3_step(profile);
  sqlite3_finalize(profile);
  if (profile_rc == SQLITE_ROW) {
    profile = NULL;
    profile_rc = sqlite3_prepare_v2(db, "SELECT 1 FROM murmur_origin_config LIMIT 1", -1, &profile, NULL);
    if (profile_rc != SQLITE_OK) return sqlite_fail(sqlrc, profile_rc);
    profile_rc = sqlite3_step(profile);
    sqlite3_finalize(profile);
    if (profile_rc == SQLITE_ROW) {
      if (detail_out) *detail_out = strdup("signed store requires managed replication runtime");
      set_sqlrc(sqlrc, SQLITE_AUTH);
      return MURMUR_SYNC_AUTH;
    }
  }
  if (profile_rc != SQLITE_DONE) return sqlite_fail(sqlrc, profile_rc);
  murmur_sync_status_t s = murmur_sync_ensure_schema(db, sqlrc);
  if (s != MURMUR_SYNC_OK) {
    return s;
  }
  char *err = NULL;
  /* cr-sqlite extension init is idempotent per connection */
  if (sqlite3_crsqlite_init(db, &err, NULL) != SQLITE_OK) {
    if (detail_out) {
      *detail_out = strdup(err ? err : "crsqlite init failed");
    }
    sqlite3_free(err);
    return sqlite_fail(sqlrc, SQLITE_ERROR);
  }
  /* File metadata replicates through the mesh, so the table must be a
   * CRR on every node (crsql_ingest_blob rejects rows for non-CRR
   * tables with "unknown table", which would stall sync from
   * files-enabled peers). Conversion is idempotent; files-disabled
   * nodes simply carry the rows without fetching objects. */
  static const uint8_t file_meta[] = "murmur_file_meta";
  s = murmur_schema_make_crr(db, file_meta, sizeof(file_meta) - 1, sqlrc);
  if (s != MURMUR_SYNC_OK) {
    if (detail_out) {
      *detail_out = strdup("murmur_file_meta make_crr failed");
    }
    return s;
  }
  char *group_raw = NULL;
  s = murmur_cfg_setting(db, "group_id", &group_raw, sqlrc);
  if (s != MURMUR_SYNC_OK) {
    return s;
  }
  if (group_raw[0] == '\0') {
    free(group_raw);
    if (detail_out) {
      *detail_out = strdup("murmur_group_id is not set");
    }
    return invalid_fail(sqlrc);
  }
  murmur_node_t gid;
  s = murmur_engine_node_parse(group_raw, &gid, sqlrc);
  if (s != MURMUR_SYNC_OK) {
    if (detail_out) {
      size_t n = strlen(group_raw);
      char *m = (char *)malloc(n + 32);
      if (m) {
        snprintf(m, n + 32, "invalid node id \"%s\"", group_raw);
      }
      *detail_out = m;
    }
    free(group_raw);
    return s;
  }
  free(group_raw);
  murmur_node_t site, node;
  s = claim_site(db, &site, sqlrc);
  if (s != MURMUR_SYNC_OK) {
    if (detail_out && s == MURMUR_SYNC_AUTH) {
      *detail_out = strdup("site identity changed");
    }
    return s;
  }
  s = claim_node(db, &node, sqlrc);
  if (s != MURMUR_SYNC_OK) {
    if (detail_out && s == MURMUR_SYNC_INVALID) {
      *detail_out = strdup("stored node id");
    }
    return s;
  }
  uint64_t incarnation = 0;
  s = bump_incarnation(db, &incarnation, detail_out, sqlrc);
  if (s != MURMUR_SYNC_OK) {
    return s;
  }
  murmur_serve_params_t params;
  char *pdetail = NULL;
  s = murmur_serve_params(db, &params, detail_out ? &pdetail : NULL, sqlrc);
  if (s != MURMUR_SYNC_OK) {
    if (detail_out) {
      *detail_out = pdetail;
    } else {
      free(pdetail);
    }
    return s;
  }
  murmur_addr_t advertise;
  s = parse_advertise(db, &advertise, sqlrc);
  if (s != MURMUR_SYNC_OK) {
    if (detail_out && s == MURMUR_SYNC_INVALID) {
      *detail_out = strdup("invalid advertise");
    }
    return s;
  }
  murmur_member_t local;
  local.node = node;
  local.addr = advertise;
  local.incarnation = incarnation;
  local.state = MURMUR_ALIVE;
  murmur_mship_t *mship = murmur_mship_new(&gid, &node, &local);
  if (!mship) {
    return sqlite_fail(sqlrc, SQLITE_NOMEM);
  }
  murmur_mship_set_io(mship, engine_send, e, engine_persist, e, engine_notify,
                      e, engine_close_conn, e);
  if (params.sessions < 1) {
    params.sessions = 1;
  }
  murmur_mship_set_fanout(mship, (int)params.gossip_fanout);
  pthread_mutex_lock(&e->mship_mu);
  murmur_mship_free(e->mship);
  e->mship = mship;
  pthread_mutex_unlock(&e->mship_mu);
  pthread_mutex_lock(&e->mu);
  e->group = gid;
  e->node = node;
  e->site = site;
  e->incarnation = incarnation;
  e->advertise = advertise;
  e->serve_cap = (size_t)params.sessions;
  e->serve_in_use = 0;
  e->serving_max = (uint64_t)params.queue_bytes;
  e->serving_in_use = 0;
  e->receiving_max = (uint64_t)params.queue_bytes;
  e->receiving_in_use = 0;
  e->gossip_fanout = (int)params.gossip_fanout;
  e->persisted_incarnation = incarnation;
  e->running = 1;
  e->started_wall_ms = murmur_engine_wall_ms();
  pthread_mutex_unlock(&e->mu);
  /* seed the dial set: buffered adds replay first, then the
   * persisted bootstrap list (malformed entries never fail Start) */
  pthread_mutex_lock(&e->mu);
  size_t nbuf = e->n_seeds;
  char *bufcpy = NULL;
  if (nbuf > 0) {
    bufcpy = (char *)malloc(nbuf * SEED_SLOT);
    if (bufcpy) {
      memcpy(bufcpy, e->seeds, nbuf * SEED_SLOT);
    } else {
      nbuf = 0;
    }
  }
  pthread_mutex_unlock(&e->mu);
  pthread_mutex_lock(&e->mship_mu);
  for (size_t i = 0; i < nbuf; i++) {
    murmur_mship_add_seed_raw(mship, bufcpy + i * SEED_SLOT);
  }
  pthread_mutex_unlock(&e->mship_mu);
  free(bufcpy);
  char *boot = NULL;
  int dsql = 0;
  if (murmur_cfg_setting(db, "bootstrap", &boot, &dsql) == MURMUR_SYNC_OK &&
      boot && boot[0] != '\0') {
    size_t n = 0;
    char **seeds = decode_bootstrap(boot, &n);
    if (seeds) {
      pthread_mutex_lock(&e->mship_mu);
      pthread_mutex_lock(&e->mu);
      for (size_t i = 0; i < n; i++) {
        murmur_mship_add_seed_raw(mship, seeds[i]);
        seed_put(e, seeds[i]);
        free(seeds[i]);
      }
      pthread_mutex_unlock(&e->mu);
      pthread_mutex_unlock(&e->mship_mu);
      free(seeds);
    }
    free(boot);
  }
  set_sqlrc(sqlrc, SQLITE_OK);
  return MURMUR_SYNC_OK;
}

/* Stopped-stop is OVERLOADED: errClosed collapses onto the transient
 * bucket (no CLOSED status in the one enum). */
murmur_sync_status_t murmur_engine_stop(murmur_engine_t *e, int *sqlrc) {
  pthread_mutex_lock(&e->mu);
  if (!e->running) {
    pthread_mutex_unlock(&e->mu);
    return busy_fail(sqlrc);
  }
  e->running = 0;
  size_t n = e->n_conns;
  murmur_engine_conn_t *conns = e->conns;
  e->conns = NULL;
  e->n_conns = 0;
  e->cap_conns = 0;
  pthread_mutex_unlock(&e->mu);
  for (size_t i = 0; i < n; i++) {
    if (conns[i].sess.close) {
      conns[i].sess.close(conns[i].sess.ctx);
    }
  }
  free(conns);
  /* the driver owns the transport handle and closes it */
  return ok_rc(sqlrc);
}

/* ---- sessions ---- */

murmur_sync_status_t murmur_engine_add_conn(murmur_engine_t *e,
                                            const murmur_node_t *peer,
                                            const murmur_session_if_t *sess,
                                            int *sqlrc) {
  pthread_mutex_lock(&e->mu);
  for (size_t i = 0; i < e->n_conns; i++) {
    if (murmur_node_eq(&e->conns[i].peer, peer)) {
      e->conns[i].sess = *sess;
      pthread_mutex_unlock(&e->mu);
      pthread_mutex_lock(&e->mship_mu);
      if (e->mship) {
        murmur_mship_add_conn(e->mship, peer);
      }
      pthread_mutex_unlock(&e->mship_mu);
      return ok_rc(sqlrc);
    }
  }
  if (e->n_conns >= e->cap_conns) {
    size_t ncap = e->cap_conns ? e->cap_conns * 2 : 8;
    murmur_engine_conn_t *nv = (murmur_engine_conn_t *)realloc(
        e->conns, ncap * sizeof(*nv));
    if (!nv) {
      pthread_mutex_unlock(&e->mu);
      return sqlite_fail(sqlrc, SQLITE_NOMEM);
    }
    e->conns = nv;
    e->cap_conns = ncap;
  }
  e->conns[e->n_conns].peer = *peer;
  e->conns[e->n_conns].sess = *sess;
  e->n_conns++;
  pthread_mutex_unlock(&e->mu);
  pthread_mutex_lock(&e->mship_mu);
  if (e->mship) {
    murmur_mship_add_conn(e->mship, peer);
  }
  pthread_mutex_unlock(&e->mship_mu);
  return ok_rc(sqlrc);
}

void murmur_engine_remove_conn(murmur_engine_t *e, const murmur_node_t *peer) {
  engine_close_conn(e, peer);
}

int murmur_engine_get_conn(murmur_engine_t *e, const murmur_node_t *peer,
                           murmur_session_if_t *out) {
  pthread_mutex_lock(&e->mu);
  int found = 0;
  for (size_t i = 0; i < e->n_conns && !found; i++) {
    if (murmur_node_eq(&e->conns[i].peer, peer)) {
      if (out) {
        *out = e->conns[i].sess;
      }
      found = 1;
    }
  }
  pthread_mutex_unlock(&e->mu);
  return found;
}

/* ---- sync flag ---- */

void murmur_engine_kick_sync(murmur_engine_t *e) {
  pthread_mutex_lock(&e->mu);
  e->sync_pending = 1;
  pthread_cond_broadcast(&e->sync_cond);
  pthread_mutex_unlock(&e->mu);
}

int murmur_engine_take_sync(murmur_engine_t *e) {
  pthread_mutex_lock(&e->mu);
  int v = e->sync_pending;
  e->sync_pending = 0;
  pthread_mutex_unlock(&e->mu);
  return v;
}

/* ---- membership ---- */

void murmur_engine_gossip(murmur_engine_t *e) {
  pthread_mutex_lock(&e->mship_mu);
  int round = e->mship != NULL;
  if (e->mship) {
    murmur_mship_gossip(e->mship, murmur_word_crypto, NULL);
  }
  pthread_mutex_unlock(&e->mship_mu);
  if (round) {
    pthread_mutex_lock(&e->mu);
    e->gossip_rounds++;
    pthread_mutex_unlock(&e->mu);
  }
}

void murmur_engine_probe(murmur_engine_t *e, uint64_t now_ms) {
  size_t sent = 0, lost = 0;
  pthread_mutex_lock(&e->mship_mu);
  if (e->mship) {
    murmur_mship_probe(e->mship, now_ms, murmur_word_crypto, NULL, &sent,
                       &lost);
  }
  pthread_mutex_unlock(&e->mship_mu);
  if (sent > 0 || lost > 0) {
    pthread_mutex_lock(&e->mu);
    e->probes_sent += (uint64_t)sent;
    e->probes_failed += (uint64_t)lost;
    pthread_mutex_unlock(&e->mu);
  }
}

static murmur_sync_status_t mship_map(murmur_mship_status_t st, int *sqlrc) {
  set_sqlrc(sqlrc, SQLITE_OK);
  switch (st) {
    case MURMUR_OK:
      return MURMUR_SYNC_OK;
    case MURMUR_MSHIP_AUTH:
      return MURMUR_SYNC_AUTH;
    case MURMUR_MSHIP_PROTOCOL:
      return MURMUR_SYNC_PROTOCOL;
    case MURMUR_MSHIP_OVERLOADED:
      return MURMUR_SYNC_OVERLOADED;
    case MURMUR_MSHIP_INVALID:
    default:
      return MURMUR_SYNC_INVALID;
  }
}

murmur_sync_status_t murmur_engine_handle_packet(murmur_engine_t *e,
                                                 const murmur_node_t *peer,
                                                 const uint8_t *datagram,
                                                 size_t len, uint64_t now_ms,
                                                 int *sqlrc) {
  if (len > MURMUR_MAX_DATAGRAM_BYTES) {
    set_sqlrc(sqlrc, SQLITE_OK);
    return MURMUR_SYNC_PROTOCOL;
  }
  murmur_member_t *members = (murmur_member_t *)malloc(
      MURMUR_MAX_VIEW_MEMBERS * sizeof(*members));
  if (!members) {
    return sqlite_fail(sqlrc, SQLITE_NOMEM);
  }
  murmur_pkt_t pkt;
  murmur_mship_status_t ds =
      murmur_pkt_decode(datagram, len, &pkt, members, MURMUR_MAX_VIEW_MEMBERS);
  if (ds != MURMUR_OK) {
    free(members);
    return mship_map(ds, sqlrc);
  }
  pthread_mutex_lock(&e->mship_mu);
  murmur_mship_status_t s = MURMUR_OK;
  if (e->mship) {
    s = murmur_mship_on_packet(e->mship, peer, &pkt, now_ms);
  }
  const murmur_member_t *local =
      e->mship ? murmur_view_local(murmur_mship_view(e->mship)) : NULL;
  uint64_t incarnation = local ? local->incarnation : 0;
  pthread_mutex_unlock(&e->mship_mu);
  free(members);
  if (s != MURMUR_OK) {
    return mship_map(s, sqlrc);
  }
  /* a refuted incarnation persists ahead (the write itself ran in
   * the mship persist callback); sync the engine copies */
  pthread_mutex_lock(&e->mu);
  if (incarnation > e->persisted_incarnation) {
    e->persisted_incarnation = incarnation;
    e->incarnation = incarnation;
  }
  pthread_mutex_unlock(&e->mu);
  return ok_rc(sqlrc);
}

static int seed_has(const murmur_engine_t *e, const char *canon) {
  for (size_t i = 0; i < e->n_seeds; i++) {
    if (strcmp(e->seeds + i * SEED_SLOT, canon) == 0) {
      return 1;
    }
  }
  return 0;
}

static int seed_put(murmur_engine_t *e, const char *canon) {
  if (seed_has(e, canon)) {
    return 0;
  }
  if (e->n_seeds >= e->cap_seeds) {
    size_t ncap = e->cap_seeds ? e->cap_seeds * 2 : 8;
    char *nv = (char *)realloc(e->seeds, ncap * SEED_SLOT);
    if (!nv) {
      return -1;
    }
    e->seeds = nv;
    e->cap_seeds = ncap;
  }
  strncpy(e->seeds + e->n_seeds * SEED_SLOT, canon, SEED_SLOT - 1);
  e->seeds[e->n_seeds * SEED_SLOT + SEED_SLOT - 1] = '\0';
  e->n_seeds++;
  return 0;
}

murmur_sync_status_t murmur_engine_add_seed(murmur_engine_t *e, const char *addr,
                                            int *sqlrc) {
  murmur_addr_t ap;
  char canon[SEED_SLOT];
  if (!addr || murmur_addr_parse(&ap, addr) != 0) {
    return invalid_fail(sqlrc);
  }
  murmur_addr_format(&ap, canon, sizeof(canon));
  pthread_mutex_lock(&e->mu);
  if (e->n_seeds >= MURMUR_MAX_VIEW_MEMBERS && !seed_has(e, canon)) {
    pthread_mutex_unlock(&e->mu);
    return busy_fail(sqlrc);
  }
  int rc = seed_put(e, canon);
  pthread_mutex_unlock(&e->mu);
  if (rc != 0) {
    return sqlite_fail(sqlrc, SQLITE_NOMEM);
  }
  pthread_mutex_lock(&e->mship_mu);
  if (e->mship) {
    murmur_mship_add_seed(e->mship, canon);
  }
  pthread_mutex_unlock(&e->mship_mu);
  murmur_engine_kick_sync(e);
  return ok_rc(sqlrc);
}

void murmur_engine_remove_node(murmur_engine_t *e, const murmur_node_t *node) {
  /* drop the member's seed from the buffer first (mship drops its own) */
  char canon[SEED_SLOT];
  int have_seed = 0;
  pthread_mutex_lock(&e->mship_mu);
  if (e->mship) {
    const murmur_member_t *m = murmur_view_lookup(
        murmur_mship_view(e->mship), node);
    if (m) {
      murmur_addr_format(&m->addr, canon, sizeof(canon));
      have_seed = 1;
    }
  }
  pthread_mutex_unlock(&e->mship_mu);
  if (have_seed) {
    pthread_mutex_lock(&e->mu);
    for (size_t i = 0; i < e->n_seeds; i++) {
      if (strcmp(e->seeds + i * SEED_SLOT, canon) == 0) {
        memmove(e->seeds + i * SEED_SLOT,
                e->seeds + (e->n_seeds - 1) * SEED_SLOT, SEED_SLOT);
        e->n_seeds--;
        break;
      }
    }
    pthread_mutex_unlock(&e->mu);
  }
  /* session close flows through the mship close callback */
  pthread_mutex_lock(&e->mship_mu);
  if (e->mship) {
    murmur_mship_remove_node(e->mship, node);
  }
  pthread_mutex_unlock(&e->mship_mu);
}

size_t murmur_engine_fetch_sources(murmur_engine_t *e, uint16_t port,
                                   murmur_fetch_source_t *out, size_t cap) {
  pthread_mutex_lock(&e->mship_mu);
  size_t n = e->mship ? murmur_mship_fetch_sources(e->mship, port, out, cap)
                      : 0;
  pthread_mutex_unlock(&e->mship_mu);
  return n;
}

size_t murmur_engine_seeds(murmur_engine_t *e, char *out, size_t cap) {
  if (!out || cap == 0) {
    return 0;
  }
  pthread_mutex_lock(&e->mship_mu);
  size_t n = e->mship ? murmur_mship_seeds(e->mship, out, cap) : 0;
  pthread_mutex_unlock(&e->mship_mu);
  pthread_mutex_lock(&e->mu);
  for (size_t i = 0; i < e->n_seeds && n < cap; i++) {
    const char *s = e->seeds + i * SEED_SLOT;
    size_t j = 0;
    for (; j < n; j++) {
      if (strcmp(out + j * MURMUR_SEED_STRLEN, s) == 0) {
        break;
      }
    }
    if (j == n) {
      memset(out + n * MURMUR_SEED_STRLEN, 0, MURMUR_SEED_STRLEN);
      strncpy(out + n * MURMUR_SEED_STRLEN, s, MURMUR_SEED_STRLEN - 1);
      n++;
    }
  }
  pthread_mutex_unlock(&e->mu);
  return n;
}

size_t murmur_engine_conn_peers(murmur_engine_t *e, murmur_node_t *out,
                                size_t cap) {
  if (!out || cap == 0) {
    return 0;
  }
  pthread_mutex_lock(&e->mu);
  size_t n = e->n_conns < cap ? e->n_conns : cap;
  for (size_t i = 0; i < n; i++) {
    out[i] = e->conns[i].peer;
  }
  pthread_mutex_unlock(&e->mu);
  return n;
}

/* ---- retention ---- */

murmur_sync_status_t murmur_engine_retention_pass(murmur_engine_t *e,
                                                  uint64_t *moved,
                                                  uint64_t *pruned,
                                                  int *sqlrc) {
  if (moved) {
    *moved = 0;
  }
  if (pruned) {
    *pruned = 0;
  }
  pthread_mutex_lock(&e->mu);
  e->retention_runs++;
  size_t n_online = e->n_conns;
  murmur_node_t *online = NULL;
  if (n_online > 0) {
    online = (murmur_node_t *)malloc(n_online * sizeof(*online));
    if (online) {
      for (size_t i = 0; i < n_online; i++) {
        online[i] = e->conns[i].peer;
      }
    } else {
      n_online = 0;
    }
  }
  murmur_node_t node = e->node;
  uint64_t boot = e->started_wall_ms;
  sqlite3 *db = e->db;
  pthread_mutex_unlock(&e->mu);
  uint64_t now = murmur_tx_now_millis();
  if (boot == 0) {
    boot = now;
  }
  murmur_retain_params_t params;
  murmur_sync_status_t s = murmur_retain_params_from(db, &params, sqlrc);
  if (s != MURMUR_SYNC_OK) {
    free(online);
    return s;
  }
  uint64_t floors = 0;
  int dsql = 0;
  (void)murmur_collect_floors(db, &node, &params, online, n_online, now,
                              boot, &floors, &dsql);
  (void)murmur_tx_maintain(db, now, &dsql);
  (void)murmur_tx_reap_forgotten_pins(db, now, params.max_offline_ms, online,
                                      n_online, &dsql);
  uint64_t pruned_n = 0;
  char *gc_raw = NULL;
  if (murmur_cfg_setting(db, "retention_gc", &gc_raw, &dsql) ==
          MURMUR_SYNC_OK &&
      gc_raw && strcmp(gc_raw, "1") == 0) {
    uint64_t own_applied = 0;
    int64_t v = 0;
    if (murmur_sync_db_version(db, &v, &dsql) == MURMUR_SYNC_OK && v > 0) {
      own_applied = (uint64_t)v;
    }
    uint64_t floor = 0;
    if (murmur_my_stream_floor(db, &params, online, n_online, &node,
                               own_applied, now, boot, &floor,
                               &dsql) == MURMUR_SYNC_OK) {
      uint64_t deleted = 0;
      if (murmur_gc_tombstones(db, floor, &deleted, &dsql) ==
          MURMUR_SYNC_OK) {
        pruned_n = deleted;
      }
    }
  }
  free(gc_raw);
  free(online);
  int64_t removed = 0;
  (void)murmur_gc_stage(db, &removed, &dsql);
  if (moved) {
    *moved = floors;
  }
  if (pruned) {
    *pruned = pruned_n;
  }
  return ok_rc(sqlrc);
}

/* ---- waits ---- */

static void sleep_ms(uint64_t ms) {
  struct timespec ts;
  ts.tv_sec = (time_t)(ms / 1000);
  ts.tv_nsec = (long)((ms % 1000) * 1000000);
  nanosleep(&ts, NULL);
}

murmur_sync_status_t murmur_engine_wait_applied(murmur_engine_t *e,
                                                const murmur_node_t *origin,
                                                uint64_t seq,
                                                uint64_t timeout_ms, int *ok,
                                                int *sqlrc) {
  uint64_t start = mono_ms();
  for (;;) {
    uint64_t applied = 0;
    pthread_mutex_lock(&e->mu);
    sqlite3 *db = e->db;
    murmur_node_t node = e->node;
    pthread_mutex_unlock(&e->mu);
    murmur_tx_progress_t *ps = NULL;
    size_t n = 0;
    murmur_sync_status_t s =
        murmur_backend_progress(db, &node, &ps, &n, sqlrc);
    if (s != MURMUR_SYNC_OK) {
      return s;
    }
    for (size_t i = 0; i < n; i++) {
      if (murmur_node_eq(&ps[i].origin, origin) &&
          ps[i].applied > applied) {
        applied = ps[i].applied;
      }
    }
    murmur_tx_progress_free(ps, n);
    if (applied >= seq) {
      if (ok) {
        *ok = 1;
      }
      return ok_rc(sqlrc);
    }
    /* Go checks the deadline after a miss, before sleeping */
    if (mono_ms() - start >= timeout_ms) {
      if (ok) {
        *ok = 0;
      }
      return ok_rc(sqlrc);
    }
    sleep_ms(100);
  }
}

murmur_sync_status_t murmur_engine_wait_lag(murmur_engine_t *e, uint64_t bound,
                                            uint64_t timeout_ms, int *ok,
                                            int *sqlrc) {
  uint64_t start = mono_ms();
  for (;;) {
    pthread_mutex_lock(&e->mu);
    sqlite3 *db = e->db;
    murmur_node_t node = e->node;
    pthread_mutex_unlock(&e->mu);
    murmur_tx_progress_t *ps = NULL;
    size_t n = 0;
    murmur_sync_status_t s =
        murmur_backend_progress(db, &node, &ps, &n, sqlrc);
    if (s != MURMUR_SYNC_OK) {
      return s;
    }
    uint64_t lag = 0;
    for (size_t i = 0; i < n; i++) {
      uint64_t gap = 0;
      if (ps[i].observed > ps[i].applied) {
        gap = ps[i].observed - ps[i].applied;
      }
      if (gap > lag) {
        lag = gap;
      }
    }
    murmur_tx_progress_free(ps, n);
    if (lag <= bound) {
      if (ok) {
        *ok = 1;
      }
      return ok_rc(sqlrc);
    }
    if (mono_ms() - start >= timeout_ms) {
      if (ok) {
        *ok = 0;
      }
      return ok_rc(sqlrc);
    }
    sleep_ms(100);
  }
}

/* ---- SQL verbs ---- */

/* Go %q for short error inputs. */
static char *go_quote(const char *s) {
  jbuf_t b;
  jinit(&b);
  jneed(&b, 2);
  if (b.ok) {
    b.p[b.n++] = '"';
  }
  for (const uint8_t *p = (const uint8_t *)(s ? s : ""); *p; p++) {
    uint8_t c = *p;
    static const char *hex = "0123456789abcdef";
    if (c == '"' || c == '\\') {
      jneed(&b, 2);
      if (b.ok) {
        b.p[b.n++] = '\\';
        b.p[b.n++] = (char)c;
      }
    } else if (c == '\n') {
      jraw(&b, "\\n", 2);
    } else if (c == '\r') {
      jraw(&b, "\\r", 2);
    } else if (c == '\t') {
      jraw(&b, "\\t", 2);
    } else if (c == '\a') {
      jraw(&b, "\\a", 2);
    } else if (c == '\b') {
      jraw(&b, "\\b", 2);
    } else if (c == '\f') {
      jraw(&b, "\\f", 2);
    } else if (c == '\v') {
      jraw(&b, "\\v", 2);
    } else if (c < 0x20 || c == 0x7f) {
      char e[4] = {'\\', 'x', hex[c >> 4], hex[c & 15]};
      jraw(&b, e, 4);
    } else {
      jneed(&b, 1);
      if (b.ok) {
        b.p[b.n++] = (char)c;
      }
    }
    if (!b.ok) {
      break;
    }
  }
  jneed(&b, 1);
  if (b.ok) {
    b.p[b.n++] = '"';
  }
  return jfinish(&b, "\"\"");
}

static int32_t status_code(murmur_sync_status_t st, int sqlrc) {
  switch (st) {
    case MURMUR_SYNC_INVALID:
      return MURMUR_CODE_INVALID;
    case MURMUR_SYNC_PROTOCOL:
      return MURMUR_CODE_PROTOCOL;
    case MURMUR_SYNC_AUTH:
      return MURMUR_CODE_AUTH;
    case MURMUR_SYNC_OVERLOADED:
      return MURMUR_CODE_OVERLOADED;
    case MURMUR_SYNC_SQLITE:
      return sqlrc != 0 ? (int32_t)sqlrc : MURMUR_CODE_STORAGE;
    default:
      return MURMUR_CODE_STORAGE;
  }
}

static const char *status_kind(murmur_sync_status_t st) {
  switch (st) {
    case MURMUR_SYNC_INVALID:
      return "Invalid";
    case MURMUR_SYNC_PROTOCOL:
      return "Protocol";
    case MURMUR_SYNC_AUTH:
      return "Auth";
    case MURMUR_SYNC_OVERLOADED:
      return "Overloaded";
    default:
      return "Native";
  }
}

/* failTo: records code/kind/message, fails the statement with the
 * projected extended code plus "Kind: Msg" (bare sqlite text for
 * Native). detail may be NULL. */
static void verb_fail(sqlite3_context *ctx, murmur_engine_t *e,
                      murmur_sync_status_t st, int sqlrc, const char *detail) {
  int32_t code = status_code(st, sqlrc);
  const char *kind = status_kind(st);
  char *message = NULL;
  if (st == MURMUR_SYNC_SQLITE) {
    pthread_mutex_lock(&e->mu);
    const char *em = sqlite3_errmsg(e->db);
    message = strdup(em ? em : "sqlite error");
    pthread_mutex_unlock(&e->mu);
  } else {
    size_t n = strlen(kind) + 2 + (detail ? strlen(detail) : 0) + 1;
    message = (char *)malloc(n);
    if (message) {
      snprintf(message, n, "%s: %s", kind, detail ? detail : "");
    }
  }
  if (!message) {
    message = strdup(kind);
  }
  murmur_engine_fail(e, code, kind, message ? message : kind);
  sqlite3_result_error_code(ctx, code);
  sqlite3_result_error(ctx, message ? message : kind, -1);
  free(message);
}

/* Closed collapses to OVERLOADED with the Unavailable code/kind. */
static void verb_closed(sqlite3_context *ctx, murmur_engine_t *e,
                        const char *detail) {
  size_t n = strlen("Unavailable: ") + strlen(detail) + 1;
  char *message = (char *)malloc(n);
  if (message) {
    snprintf(message, n, "Unavailable: %s", detail);
  }
  murmur_engine_fail(e, MURMUR_CODE_UNAVAILABLE, "Unavailable",
                     message ? message : detail);
  sqlite3_result_error_code(ctx, MURMUR_CODE_UNAVAILABLE);
  sqlite3_result_error(ctx, message ? message : detail, -1);
  free(message);
}

static const char *arg_text(sqlite3_value *v) {
  const uint8_t *t = sqlite3_value_text(v);
  return t ? (const char *)t : "";
}

static void verb_start(sqlite3_context *ctx, int argc, sqlite3_value **argv) {
  (void)argc;
  (void)argv;
  murmur_engine_t *e = (murmur_engine_t *)sqlite3_user_data(ctx);
  pthread_mutex_lock(&e->mu);
  sqlite3 *db = e->db;
  pthread_mutex_unlock(&e->mu);
  if (!sqlite3_get_autocommit(db)) {
    verb_fail(ctx, e, MURMUR_SYNC_INVALID, 0,
              "replication controls require autocommit");
    return;
  }
  if (murmur_engine_running(e)) {
    sqlite3_result_int64(ctx, 0);
    return;
  }
  char *detail = NULL;
  int sqlrc = 0;
  murmur_sync_status_t s = murmur_engine_start(e, &detail, &sqlrc);
  if (s != MURMUR_SYNC_OK) {
    if (s == MURMUR_SYNC_SQLITE && !detail) {
      verb_fail(ctx, e, s, sqlrc, NULL);
    } else {
      verb_fail(ctx, e, s, sqlrc, detail ? detail : "start failed");
    }
    free(detail);
    return;
  }
  sqlite3_result_int64(ctx, 1);
}

static void verb_stop(sqlite3_context *ctx, int argc, sqlite3_value **argv) {
  (void)argc;
  (void)argv;
  murmur_engine_t *e = (murmur_engine_t *)sqlite3_user_data(ctx);
  pthread_mutex_lock(&e->mu);
  sqlite3 *db = e->db;
  pthread_mutex_unlock(&e->mu);
  if (!sqlite3_get_autocommit(db)) {
    verb_fail(ctx, e, MURMUR_SYNC_INVALID, 0,
              "replication controls require autocommit");
    return;
  }
  int was = murmur_engine_running(e);
  if (was) {
    int sqlrc = 0;
    (void)murmur_engine_stop(e, &sqlrc);
  }
  sqlite3_result_int64(ctx, was ? 1 : 0);
}

static void verb_status(sqlite3_context *ctx, int argc, sqlite3_value **argv) {
  (void)argc;
  (void)argv;
  murmur_engine_t *e = (murmur_engine_t *)sqlite3_user_data(ctx);
  char *s = murmur_engine_status(e);
  sqlite3_result_text(ctx, s ? s : "{\"running\":false}", -1, free);
}

static void verb_health(sqlite3_context *ctx, int argc, sqlite3_value **argv) {
  (void)argc;
  (void)argv;
  murmur_engine_t *e = (murmur_engine_t *)sqlite3_user_data(ctx);
  char *s = murmur_engine_health(e);
  sqlite3_result_text(ctx, s ? s : "{\"version\":1}", -1, free);
}

static void verb_progress(sqlite3_context *ctx, int argc,
                          sqlite3_value **argv) {
  (void)argc;
  (void)argv;
  murmur_engine_t *e = (murmur_engine_t *)sqlite3_user_data(ctx);
  char *s = murmur_engine_progress(e);
  sqlite3_result_text(ctx, s ? s : "[]", -1, free);
}

static murmur_sync_status_t persist_bootstrap(sqlite3 *db, const char *addr,
                                              char **detail_out, int *sqlrc) {
  if (detail_out) {
    *detail_out = NULL;
  }
  murmur_addr_t ap;
  char canon[72];
  if (!addr || murmur_addr_parse(&ap, addr) != 0) {
    if (detail_out) {
      *detail_out = strdup("expected IP:port");
    }
    return invalid_fail(sqlrc);
  }
  murmur_addr_format(&ap, canon, sizeof(canon));
  char *raw = NULL;
  murmur_sync_status_t s = murmur_cfg_setting(db, "bootstrap", &raw, sqlrc);
  if (s != MURMUR_SYNC_OK) {
    return s;
  }
  char **seeds = NULL;
  size_t n = 0;
  if (raw[0] != '\0') {
    seeds = decode_bootstrap(raw, &n);
    if (!seeds) {
      free(raw);
      if (detail_out) {
        *detail_out = strdup("corrupt bootstrap");
      }
      return invalid_fail(sqlrc);
    }
  }
  int found = 0;
  for (size_t i = 0; i < n && !found; i++) {
    found = strcmp(seeds[i], canon) == 0;
  }
  if (!found) {
    if (n >= MURMUR_MAX_VIEW_MEMBERS) {
      for (size_t i = 0; i < n; i++) {
        free(seeds[i]);
      }
      free(seeds);
      free(raw);
      if (detail_out) {
        *detail_out = strdup("seed capacity");
      }
      return busy_fail(sqlrc);
    }
    char **nv = (char **)realloc(seeds, (n + 1) * sizeof(*nv));
    if (!nv) {
      for (size_t i = 0; i < n; i++) {
        free(seeds[i]);
      }
      free(seeds);
      free(raw);
      return sqlite_fail(sqlrc, SQLITE_NOMEM);
    }
    seeds = nv;
    seeds[n] = strdup(canon);
    if (!seeds[n]) {
      for (size_t i = 0; i < n; i++) {
        free(seeds[i]);
      }
      free(seeds);
      free(raw);
      return sqlite_fail(sqlrc, SQLITE_NOMEM);
    }
    n++;
  }
  jbuf_t b;
  jinit(&b);
  jraw(&b, "[", 1);
  for (size_t i = 0; i < n; i++) {
    if (i > 0) {
      jraw(&b, ",", 1);
    }
    jstr(&b, seeds[i]);
    free(seeds[i]);
  }
  free(seeds);
  free(raw);
  jraw(&b, "]", 1);
  char *out = jfinish(&b, NULL);
  if (!out) {
    return sqlite_fail(sqlrc, SQLITE_NOMEM);
  }
  s = murmur_cfg_set_setting(db, "bootstrap", (const uint8_t *)out,
                             strlen(out), sqlrc);
  free(out);
  return s;
}

static void verb_add_peer(sqlite3_context *ctx, int argc,
                          sqlite3_value **argv) {
  (void)argc;
  murmur_engine_t *e = (murmur_engine_t *)sqlite3_user_data(ctx);
  pthread_mutex_lock(&e->mu);
  sqlite3 *db = e->db;
  pthread_mutex_unlock(&e->mu);
  if (!sqlite3_get_autocommit(db)) {
    verb_fail(ctx, e, MURMUR_SYNC_INVALID, 0,
              "peer controls require autocommit");
    return;
  }
  const char *addr = arg_text(argv[0]);
  char *detail = NULL;
  int sqlrc = 0;
  murmur_sync_status_t s = persist_bootstrap(db, addr, &detail, &sqlrc);
  if (s != MURMUR_SYNC_OK) {
    verb_fail(ctx, e, s, sqlrc, detail);
    free(detail);
    return;
  }
  s = murmur_engine_add_seed(e, addr, &sqlrc);
  if (s != MURMUR_SYNC_OK) {
    /* INVALID is always the address parse, OVERLOADED the cap */
    verb_fail(ctx, e, s, sqlrc,
              s == MURMUR_SYNC_INVALID ? "expected IP:port"
                                       : "seed capacity");
    return;
  }
  sqlite3_result_int64(ctx, 1);
}

static murmur_sync_status_t persist_excluded(sqlite3 *db,
                                             const murmur_node_t *id,
                                             int *sqlrc) {
  sqlite3_stmt *st = NULL;
  int rc = sqlite3_prepare_v2(
      db, "INSERT OR IGNORE INTO murmur_excluded VALUES(?1)", -1, &st, NULL);
  if (rc != SQLITE_OK) {
    return sqlite_fail(sqlrc, rc);
  }
  sqlite3_bind_blob(st, 1, id->b, 16, SQLITE_TRANSIENT);
  rc = sqlite3_step(st);
  sqlite3_finalize(st);
  if (rc != SQLITE_DONE) {
    return sqlite_fail(sqlrc, rc);
  }
  return ok_rc(sqlrc);
}

static void verb_remove_peer(sqlite3_context *ctx, int argc,
                             sqlite3_value **argv) {
  (void)argc;
  murmur_engine_t *e = (murmur_engine_t *)sqlite3_user_data(ctx);
  pthread_mutex_lock(&e->mu);
  sqlite3 *db = e->db;
  pthread_mutex_unlock(&e->mu);
  if (!sqlite3_get_autocommit(db)) {
    verb_fail(ctx, e, MURMUR_SYNC_INVALID, 0,
              "peer controls require autocommit");
    return;
  }
  const char *text = arg_text(argv[0]);
  murmur_node_t id;
  int sqlrc = 0;
  if (murmur_engine_node_parse(text, &id, &sqlrc) != MURMUR_SYNC_OK) {
    char *q = go_quote(text);
    size_t n = (q ? strlen(q) : 0) + 32;
    char *detail = (char *)malloc(n);
    if (detail) {
      snprintf(detail, n, "invalid node id %s", q ? q : "\"\"");
    }
    verb_fail(ctx, e, MURMUR_SYNC_INVALID, 0, detail);
    free(detail);
    free(q);
    return;
  }
  if (persist_excluded(db, &id, &sqlrc) != MURMUR_SYNC_OK) {
    verb_fail(ctx, e, MURMUR_SYNC_SQLITE, sqlrc, NULL);
    return;
  }
  murmur_engine_remove_node(e, &id);
  sqlite3_result_int64(ctx, 1);
}

static void verb_sync(sqlite3_context *ctx, int argc, sqlite3_value **argv) {
  (void)argc;
  (void)argv;
  murmur_engine_t *e = (murmur_engine_t *)sqlite3_user_data(ctx);
  pthread_mutex_lock(&e->mu);
  sqlite3 *db = e->db;
  pthread_mutex_unlock(&e->mu);
  if (!sqlite3_get_autocommit(db)) {
    verb_fail(ctx, e, MURMUR_SYNC_INVALID, 0,
              "replication controls require autocommit");
    return;
  }
  if (!murmur_engine_running(e)) {
    verb_closed(ctx, e, "replication is stopped");
    return;
  }
  murmur_engine_kick_sync(e);
  sqlite3_result_int64(ctx, 1);
}

static void verb_gc(sqlite3_context *ctx, int argc, sqlite3_value **argv) {
  (void)argc;
  (void)argv;
  murmur_engine_t *e = (murmur_engine_t *)sqlite3_user_data(ctx);
  uint64_t moved = 0, pruned = 0;
  int sqlrc = 0;
  (void)murmur_engine_retention_pass(e, &moved, &pruned, &sqlrc);
  sqlite3_result_int64(ctx, (int64_t)pruned);
}

static void verb_retire_peer(sqlite3_context *ctx, int argc,
                             sqlite3_value **argv) {
  (void)argc;
  murmur_engine_t *e = (murmur_engine_t *)sqlite3_user_data(ctx);
  pthread_mutex_lock(&e->mu);
  sqlite3 *db = e->db;
  pthread_mutex_unlock(&e->mu);
  if (!sqlite3_get_autocommit(db)) {
    verb_fail(ctx, e, MURMUR_SYNC_INVALID, 0,
              "peer controls require autocommit");
    return;
  }
  const char *text = arg_text(argv[0]);
  murmur_node_t id;
  int sqlrc = 0;
  if (murmur_engine_node_parse(text, &id, &sqlrc) != MURMUR_SYNC_OK) {
    char *q = go_quote(text);
    size_t n = (q ? strlen(q) : 0) + 32;
    char *detail = (char *)malloc(n);
    if (detail) {
      snprintf(detail, n, "invalid node id %s", q ? q : "\"\"");
    }
    verb_fail(ctx, e, MURMUR_SYNC_INVALID, 0, detail);
    free(detail);
    free(q);
    return;
  }
  if (persist_excluded(db, &id, &sqlrc) != MURMUR_SYNC_OK) {
    verb_fail(ctx, e, MURMUR_SYNC_SQLITE, sqlrc, NULL);
    return;
  }
  if (murmur_engine_running(e)) {
    murmur_sync_status_t s = murmur_tx_retire(db, &id, &sqlrc);
    if (s != MURMUR_SYNC_OK) {
      /* code+kind pass through; deep messages stay native */
      verb_fail(ctx, e, s, sqlrc, "retire peer");
      return;
    }
  }
  murmur_engine_remove_node(e, &id);
  sqlite3_result_int64(ctx, 1);
}

static void verb_snapshot_request(sqlite3_context *ctx, int argc,
                                  sqlite3_value **argv) {
  (void)argc;
  murmur_engine_t *e = (murmur_engine_t *)sqlite3_user_data(ctx);
  pthread_mutex_lock(&e->mu);
  sqlite3 *db = e->db;
  pthread_mutex_unlock(&e->mu);
  if (!sqlite3_get_autocommit(db)) {
    verb_fail(ctx, e, MURMUR_SYNC_INVALID, 0,
              "peer controls require autocommit");
    return;
  }
  const char *text = arg_text(argv[0]);
  murmur_node_t id;
  int sqlrc = 0;
  if (murmur_engine_node_parse(text, &id, &sqlrc) != MURMUR_SYNC_OK) {
    char *q = go_quote(text);
    size_t n = (q ? strlen(q) : 0) + 32;
    char *detail = (char *)malloc(n);
    if (detail) {
      snprintf(detail, n, "invalid node id %s", q ? q : "\"\"");
    }
    verb_fail(ctx, e, MURMUR_SYNC_INVALID, 0, detail);
    free(detail);
    free(q);
    return;
  }
  if (!murmur_engine_running(e)) {
    verb_closed(ctx, e, "replication is not running");
    return;
  }
  murmur_session_if_t stmp;
  if (!murmur_engine_get_conn(e, &id, &stmp)) {
    verb_closed(ctx, e, "snapshot peer is not connected");
    return;
  }
  murmur_sync_status_t s = murmur_serve_request_snapshot(e, &id, &sqlrc);
  if (s != MURMUR_SYNC_OK) {
    /* RequestSnapshot only fails on an in-flight build */
    verb_fail(ctx, e, s, sqlrc, "snapshot already running");
    return;
  }
  sqlite3_result_int64(ctx, 1);
}

static int wait_timeout_ms(int64_t ms, uint64_t *out) {
  if (ms < 0 || ms > 86400000) {
    return -1;
  }
  *out = (uint64_t)ms;
  return 0;
}

static void verb_wait_applied(sqlite3_context *ctx, int argc,
                              sqlite3_value **argv) {
  (void)argc;
  murmur_engine_t *e = (murmur_engine_t *)sqlite3_user_data(ctx);
  pthread_mutex_lock(&e->mu);
  sqlite3 *db = e->db;
  pthread_mutex_unlock(&e->mu);
  if (!sqlite3_get_autocommit(db)) {
    verb_fail(ctx, e, MURMUR_SYNC_INVALID, 0, "waits require autocommit");
    return;
  }
  const char *text = arg_text(argv[0]);
  murmur_node_t origin;
  int sqlrc = 0;
  if (murmur_engine_node_parse(text, &origin, &sqlrc) != MURMUR_SYNC_OK) {
    char *q = go_quote(text);
    size_t n = (q ? strlen(q) : 0) + 32;
    char *detail = (char *)malloc(n);
    if (detail) {
      snprintf(detail, n, "invalid node id %s", q ? q : "\"\"");
    }
    verb_fail(ctx, e, MURMUR_SYNC_INVALID, 0, detail);
    free(detail);
    free(q);
    return;
  }
  if (sqlite3_value_int64(argv[1]) < 0) {
    verb_fail(ctx, e, MURMUR_SYNC_INVALID, 0, "sequence must be >= 0");
    return;
  }
  uint64_t timeout = 0;
  if (wait_timeout_ms(sqlite3_value_int64(argv[2]), &timeout) != 0) {
    verb_fail(ctx, e, MURMUR_SYNC_INVALID, 0,
              "timeout outside 0..86400000 ms");
    return;
  }
  if (!murmur_engine_running(e)) {
    sqlite3_result_int64(ctx, 0);
    return;
  }
  int ok = 0;
  murmur_sync_status_t s = murmur_engine_wait_applied(
      e, &origin, (uint64_t)sqlite3_value_int64(argv[1]), timeout, &ok,
      &sqlrc);
  if (s != MURMUR_SYNC_OK) {
    verb_fail(ctx, e, s, sqlrc, NULL);
    return;
  }
  sqlite3_result_int64(ctx, ok ? 1 : 0);
}

static void verb_wait_lag(sqlite3_context *ctx, int argc,
                          sqlite3_value **argv) {
  (void)argc;
  murmur_engine_t *e = (murmur_engine_t *)sqlite3_user_data(ctx);
  pthread_mutex_lock(&e->mu);
  sqlite3 *db = e->db;
  pthread_mutex_unlock(&e->mu);
  if (!sqlite3_get_autocommit(db)) {
    verb_fail(ctx, e, MURMUR_SYNC_INVALID, 0, "waits require autocommit");
    return;
  }
  if (sqlite3_value_int64(argv[0]) < 0) {
    verb_fail(ctx, e, MURMUR_SYNC_INVALID, 0, "bound must be >= 0");
    return;
  }
  uint64_t timeout = 0;
  int sqlrc = 0;
  if (wait_timeout_ms(sqlite3_value_int64(argv[1]), &timeout) != 0) {
    verb_fail(ctx, e, MURMUR_SYNC_INVALID, 0,
              "timeout outside 0..86400000 ms");
    return;
  }
  if (!murmur_engine_running(e)) {
    sqlite3_result_int64(ctx, 0);
    return;
  }
  int ok = 0;
  murmur_sync_status_t s = murmur_engine_wait_lag(
      e, (uint64_t)sqlite3_value_int64(argv[0]), timeout, &ok, &sqlrc);
  if (s != MURMUR_SYNC_OK) {
    verb_fail(ctx, e, s, sqlrc, NULL);
    return;
  }
  sqlite3_result_int64(ctx, ok ? 1 : 0);
}

murmur_sync_status_t murmur_engine_register_sql(murmur_engine_t *e,
                                                int *sqlrc) {
  pthread_mutex_lock(&e->mu);
  sqlite3 *db = e->db;
  pthread_mutex_unlock(&e->mu);
  murmur_sync_status_t s = murmur_sync_ensure_schema(db, sqlrc);
  if (s != MURMUR_SYNC_OK) {
    return s;
  }
  static const struct {
    const char *name;
    int nargs;
    void (*fn)(sqlite3_context *, int, sqlite3_value **);
  } funcs[] = {
      {"murmur_start", 0, verb_start},
      {"murmur_stop", 0, verb_stop},
      {"murmur_status", 0, verb_status},
      {"murmur_health", 0, verb_health},
      {"murmur_progress", 0, verb_progress},
      {"murmur_add_peer", 1, verb_add_peer},
      {"murmur_remove_peer", 1, verb_remove_peer},
      {"murmur_sync", 0, verb_sync},
      {"murmur_gc", 0, verb_gc},
      {"murmur_retire_peer", 1, verb_retire_peer},
      {"murmur_snapshot_request", 1, verb_snapshot_request},
      {"murmur_wait_applied", 3, verb_wait_applied},
      {"murmur_wait_lag", 2, verb_wait_lag},
  };
  for (size_t i = 0; i < sizeof(funcs) / sizeof(funcs[0]); i++) {
    int rc = sqlite3_create_function_v2(db, funcs[i].name, funcs[i].nargs,
                                        SQLITE_UTF8, e, funcs[i].fn, NULL,
                                        NULL, NULL);
    if (rc != SQLITE_OK) {
      return sqlite_fail(sqlrc, rc);
    }
  }
  return ok_rc(sqlrc);
}
