/* murmur serve - native stream handlers. See serve.h. */
#include "serve.h"

#include <pthread.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "kv.h"
#include "retain.h"
#include "schema.h"
#include "schemaadopt.h"
#include "sha256.h"
#include "snapbuild.h"
#include "txretain.h"
#include "txsnap.h"

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

static void set_detail_n(char **out, const uint8_t *b, size_t n) {
  if (!out) {
    return;
  }
  *out = NULL;
  char *d = (char *)malloc(n + 1);
  if (!d) {
    return;
  }
  if (n > 0) {
    memcpy(d, b, n);
  }
  d[n] = '\0';
  *out = d;
}

/* SQLITE detail from the handle; other native failures carry no
 * composed text (NULL). */
static void native_detail(sqlite3 *db, murmur_sync_status_t st,
                          char **detail_out) {
  if (st == MURMUR_SYNC_SQLITE) {
    set_detail(detail_out, sqlite3_errmsg(db));
  } else {
    set_detail(detail_out, NULL);
  }
}

static const char *io_error(murmur_stream_io_t *io) {
  const char *t = NULL;
  if (io && io->error_text) {
    t = io->error_text(io->ctx);
  }
  return t ? t : "stream error";
}

static murmur_sync_status_t map_msg_status(murmur_mship_status_t st) {
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

/* Go Error kinds for record/MsgError composition ("Kind: Msg"). */
static const char *kind_str(murmur_sync_status_t st) {
  switch (st) {
  case MURMUR_SYNC_AUTH:
    return "Auth";
  case MURMUR_SYNC_PROTOCOL:
    return "Protocol";
  case MURMUR_SYNC_OVERLOADED:
    return "Overloaded";
  case MURMUR_SYNC_INVALID:
    return "Invalid";
  default:
    return "Storage";
  }
}

void murmur_serve_msg_free(murmur_serve_msg_t *m) {
  if (!m) {
    return;
  }
  free(m->owned);
  memset(m, 0, sizeof(*m));
}

murmur_sync_status_t murmur_serve_write_msg(murmur_stream_io_t *io,
                                            const murmur_msg_t *m,
                                            char **detail_out, int *sqlrc) {
  set_detail(detail_out, NULL);
  uint8_t *buf = (uint8_t *)malloc(MURMUR_FRAME_BYTES);
  if (!buf) {
    set_sqlrc(sqlrc, SQLITE_OK);
    return MURMUR_SYNC_OVERLOADED;
  }
  size_t n = murmur_msg_encode(m, buf, MURMUR_FRAME_BYTES);
  if (n == 0 || n > MURMUR_FRAME_BYTES) {
    free(buf);
    set_detail(detail_out, "frame too large");
    set_sqlrc(sqlrc, SQLITE_OK);
    return MURMUR_SYNC_OVERLOADED;
  }
  uint8_t hdr[4];
  hdr[0] = (uint8_t)(n >> 24);
  hdr[1] = (uint8_t)(n >> 16);
  hdr[2] = (uint8_t)(n >> 8);
  hdr[3] = (uint8_t)n;
  if (io->write(io->ctx, hdr, 4) != 0) {
    set_detail(detail_out, io_error(io));
    free(buf);
    set_sqlrc(sqlrc, SQLITE_OK);
    return MURMUR_SYNC_PROTOCOL;
  }
  if (io->write(io->ctx, buf, n) != 0) {
    set_detail(detail_out, io_error(io));
    free(buf);
    set_sqlrc(sqlrc, SQLITE_OK);
    return MURMUR_SYNC_PROTOCOL;
  }
  free(buf);
  set_sqlrc(sqlrc, SQLITE_OK);
  return MURMUR_SYNC_OK;
}

murmur_sync_status_t murmur_serve_read_msg(murmur_stream_io_t *io,
                                           murmur_serve_msg_t *out,
                                           char **detail_out, int *sqlrc) {
  set_detail(detail_out, NULL);
  memset(out, 0, sizeof(*out));
  uint8_t hdr[4];
  if (io->read_full(io->ctx, hdr, 4) != 0) {
    set_detail(detail_out, "truncated frame header");
    set_sqlrc(sqlrc, SQLITE_OK);
    return MURMUR_SYNC_PROTOCOL;
  }
  uint32_t n = ((uint32_t)hdr[0] << 24) | ((uint32_t)hdr[1] << 16) |
               ((uint32_t)hdr[2] << 8) | hdr[3];
  if (n == 0 || n > MURMUR_FRAME_BYTES) {
    set_detail(detail_out, "invalid frame length");
    set_sqlrc(sqlrc, SQLITE_OK);
    return MURMUR_SYNC_PROTOCOL;
  }
  out->owned = (uint8_t *)malloc(n);
  if (!out->owned) {
    set_sqlrc(sqlrc, SQLITE_OK);
    return MURMUR_SYNC_OVERLOADED;
  }
  if (io->read_full(io->ctx, out->owned, n) != 0) {
    set_detail(detail_out, "truncated frame");
    murmur_serve_msg_free(out);
    set_sqlrc(sqlrc, SQLITE_OK);
    return MURMUR_SYNC_PROTOCOL;
  }
  murmur_sync_status_t st =
      map_msg_status(murmur_msg_decode(out->owned, n, &out->msg));
  if (st != MURMUR_SYNC_OK) {
    set_detail(detail_out, "invalid message");
    murmur_serve_msg_free(out);
    set_sqlrc(sqlrc, SQLITE_OK);
    return st;
  }
  set_sqlrc(sqlrc, SQLITE_OK);
  return MURMUR_SYNC_OK;
}

static int node_equal(const murmur_node_t *a, const murmur_node_t *b) {
  return murmur_node_eq(a, b);
}

/* Excluded peers must never establish a session, in either direction.
 * The murmur_excluded table is the durable source of truth. Query
 * failures fail closed: a peer that cannot be vetted is refused. */
static int peer_excluded(sqlite3 *db, const murmur_node_t *peer, int *sqlrc) {
  sqlite3_stmt *st = NULL;
  if (sqlite3_prepare_v2(db,
                         "SELECT 1 FROM murmur_excluded WHERE node=?1 LIMIT 1",
                         -1, &st, NULL) != SQLITE_OK) {
    set_sqlrc(sqlrc, sqlite3_errcode(db));
    return 1;
  }
  sqlite3_bind_blob(st, 1, peer->b, 16, SQLITE_TRANSIENT);
  int rc = sqlite3_step(st);
  int found = (rc == SQLITE_ROW);
  if (!found && rc != SQLITE_DONE) {
    set_sqlrc(sqlrc, rc);
    sqlite3_finalize(st);
    return 1;
  }
  sqlite3_finalize(st);
  return found;
}

static int key_equal(const murmur_key_t *a, const murmur_key_t *b) {
  if (a->version != b->version || a->seq != b->seq) {
    return 0;
  }
  if (a->table_len != b->table_len || a->pk_len != b->pk_len ||
      a->cid_len != b->cid_len) {
    return 0;
  }
  if (a->table_len > 0 && memcmp(a->table, b->table, a->table_len) != 0) {
    return 0;
  }
  if (a->pk_len > 0 && memcmp(a->pk, b->pk, a->pk_len) != 0) {
    return 0;
  }
  if (a->cid_len > 0 && memcmp(a->cid, b->cid, a->cid_len) != 0) {
    return 0;
  }
  return 1;
}

/* cursorsEqual verbatim (compareKey equality on After). */
static int cursor_equal(const murmur_cursor_t *a, const murmur_cursor_t *b) {
  if (a->from != b->from) {
    return 0;
  }
  if (!a->has_through != !b->has_through) {
    return 0;
  }
  if (a->has_through && a->through != b->through) {
    return 0;
  }
  if (!a->has_after != !b->has_after) {
    return 0;
  }
  if (a->has_after && !key_equal(&a->after, &b->after)) {
    return 0;
  }
  return 1;
}

typedef struct {
  murmur_engine_t *e;
  murmur_node_t peer;
  uint8_t digest[32];
} vet_work_t;

static void *vet_worker(void *v);

/* compatVetted: a cached allow verdict for (peer, digest), else a
 * detached vet round trip with a reject for this pull (the retry
 * converges once the verdict lands). */
static int compat_vetted(murmur_engine_t *e, const murmur_node_t *peer,
                         const uint8_t digest[32]) {
  pthread_mutex_lock(&e->mu);
  for (size_t i = 0; i < e->n_vetted; i++) {
    if (node_equal(&e->vetted[i].peer, peer) &&
        memcmp(e->vetted[i].digest, digest, 32) == 0) {
      int v = e->vetted[i].verdict != 0;
      pthread_mutex_unlock(&e->mu);
      return v;
    }
  }
  pthread_mutex_unlock(&e->mu);
  vet_work_t *w = (vet_work_t *)malloc(sizeof(*w));
  if (!w) {
    return 0;
  }
  w->e = e;
  w->peer = *peer;
  memcpy(w->digest, digest, 32);
  murmur_engine_worker_add(e);
  pthread_t t;
  pthread_attr_t at;
  pthread_attr_init(&at);
  pthread_attr_setdetachstate(&at, PTHREAD_CREATE_DETACHED);
  int rc = pthread_create(&t, &at, vet_worker, w);
  pthread_attr_destroy(&at);
  if (rc != 0) {
    murmur_engine_worker_release(e);
    free(w);
  }
  return 0;
}

static void vet_work(vet_work_t *w) {
  murmur_engine_t *e = w->e;
  murmur_session_if_t sess;
  if (!murmur_engine_get_conn(e, &w->peer, &sess)) {
    pthread_mutex_lock(&e->mu);
    e->vet_fail++;
    pthread_mutex_unlock(&e->mu);
    free(w);
    return;
  }
  int verdict = 0, ok = 0;
  murmur_serve_vet_fetch(e, &w->peer, &sess, &verdict, &ok);
  pthread_mutex_lock(&e->mu);
  if (!ok) {
    e->vet_fail++;
  } else {
    if (verdict) {
      e->vet_ok++;
    } else {
      e->vet_no++;
    }
    size_t i = 0;
    for (; i < e->n_vetted; i++) {
      if (node_equal(&e->vetted[i].peer, &w->peer) &&
          memcmp(e->vetted[i].digest, w->digest, 32) == 0) {
        e->vetted[i].verdict = verdict;
        break;
      }
    }
    if (i == e->n_vetted) {
      if (e->n_vetted >= e->cap_vetted) {
        size_t ncap = e->cap_vetted ? e->cap_vetted * 2 : 8;
        murmur_vetted_ent_t *nv =
            (murmur_vetted_ent_t *)realloc(e->vetted, ncap * sizeof(*nv));
        if (nv) {
          e->vetted = nv;
          e->cap_vetted = ncap;
        }
      }
      if (e->n_vetted < e->cap_vetted) {
        e->vetted[e->n_vetted].peer = w->peer;
        memcpy(e->vetted[e->n_vetted].digest, w->digest, 32);
        e->vetted[e->n_vetted].verdict = verdict;
        e->n_vetted++;
      }
    }
  }
  pthread_mutex_unlock(&e->mu);
  free(w);
}

static void *vet_worker(void *v) {
  vet_work_t *w = (vet_work_t *)v;
  murmur_engine_t *e = w->e;
  vet_work(w);
  murmur_engine_worker_release(e);
  return NULL;
}

/* byteSem acquire/release on the engine gauges (blocking, like Go). */
static void gauge_acquire(murmur_engine_t *e, int serving, uint64_t n) {
  pthread_mutex_lock(&e->mu);
  for (;;) {
    uint64_t max = serving ? e->serving_max : e->receiving_max;
    uint64_t in_use = serving ? e->serving_in_use : e->receiving_in_use;
    if (max >= in_use && max - in_use >= n) {
      break;
    }
    pthread_cond_wait(serving ? &e->serving_cond : &e->receiving_cond, &e->mu);
  }
  if (serving) {
    e->serving_in_use += n;
  } else {
    e->receiving_in_use += n;
  }
  pthread_mutex_unlock(&e->mu);
}

static void gauge_release(murmur_engine_t *e, int serving, uint64_t n) {
  pthread_mutex_lock(&e->mu);
  if (serving) {
    e->serving_in_use -= n;
  } else {
    e->receiving_in_use -= n;
  }
  pthread_cond_broadcast(serving ? &e->serving_cond : &e->receiving_cond);
  pthread_mutex_unlock(&e->mu);
}

murmur_sync_status_t murmur_serve_handshake(
    murmur_engine_t *e, const murmur_node_t *peer, murmur_stream_io_t *io,
    int outgoing, uint64_t *incarnation_out, murmur_addr_t *addr_out,
    char **detail_out, int *sqlrc) {
  set_detail(detail_out, NULL);
  pthread_mutex_lock(&e->mu);
  murmur_node_t group = e->group, node = e->node, site = e->site;
  uint64_t incarnation = e->incarnation;
  murmur_addr_t advertise = e->advertise;
  sqlite3 *db = e->db;
  pthread_mutex_unlock(&e->mu);

  uint8_t schema[32];
  murmur_sync_status_t st = murmur_schema_digest(db, schema, sqlrc);
  if (st != MURMUR_SYNC_OK) {
    native_detail(db, st, detail_out);
    return st;
  }
  murmur_msg_t hello;
  memset(&hello, 0, sizeof(hello));
  hello.tag = MURMUR_MSG_HELLO;
  hello.group = group;
  hello.node = node;
  hello.site = site;
  memcpy(hello.schema, schema, 32);
  hello.incarnation = incarnation;
  hello.addr = advertise;

  murmur_serve_msg_t got;
  memset(&got, 0, sizeof(got));
  if (outgoing) {
    st = murmur_serve_write_msg(io, &hello, detail_out, sqlrc);
    if (st != MURMUR_SYNC_OK) {
      return st;
    }
    st = murmur_serve_read_msg(io, &got, detail_out, sqlrc);
    if (st != MURMUR_SYNC_OK) {
      return st;
    }
  } else {
    st = murmur_serve_read_msg(io, &got, detail_out, sqlrc);
    if (st != MURMUR_SYNC_OK) {
      return st;
    }
    if (got.msg.tag != MURMUR_MSG_HELLO) {
      murmur_serve_msg_free(&got);
      set_detail(detail_out, "expected hello");
      set_sqlrc(sqlrc, SQLITE_OK);
      return MURMUR_SYNC_PROTOCOL;
    }
    if (!node_equal(&got.msg.group, &group) ||
        !node_equal(&got.msg.node, peer) || node_equal(&got.msg.site, &site)) {
      murmur_serve_msg_free(&got);
      set_detail(detail_out, "session group or identity mismatch");
      set_sqlrc(sqlrc, SQLITE_OK);
      return MURMUR_SYNC_AUTH;
    }
    if (peer_excluded(db, peer, sqlrc)) {
      murmur_serve_msg_free(&got);
      set_detail(detail_out, "peer excluded");
      set_sqlrc(sqlrc, SQLITE_AUTH);
      return MURMUR_SYNC_AUTH;
    }
    if (memcmp(got.msg.schema, schema, 32) != 0) {
      /* Go Handshake: schemas are a fast-fail hint only when
       * adoption is off; adopters proceed and converge through
       * manifests. Rejecting unconditionally deadlocks stale
       * rejoiners: adoption needs the session the handshake
       * would refuse to establish. */
      murmur_schema_params_t hp;
      memset(&hp, 0, sizeof(hp));
      st = murmur_schema_params_from(db, &hp, sqlrc);
      if (st != MURMUR_SYNC_OK) {
        murmur_serve_msg_free(&got);
        native_detail(db, st, detail_out);
        return st;
      }
      if (!hp.accept_remote) {
        murmur_serve_msg_free(&got);
        set_detail(detail_out,
                   "CRR schema mismatch; provision matching table definitions");
        set_sqlrc(sqlrc, SQLITE_OK);
        return MURMUR_SYNC_PROTOCOL;
      }
    }
    st = murmur_serve_write_msg(io, &hello, detail_out, sqlrc);
    if (st != MURMUR_SYNC_OK) {
      murmur_serve_msg_free(&got);
      return st;
    }
    *incarnation_out = got.msg.incarnation;
    *addr_out = got.msg.addr;
    murmur_serve_msg_free(&got);
    set_sqlrc(sqlrc, SQLITE_OK);
    return MURMUR_SYNC_OK;
  }
  if (got.msg.tag != MURMUR_MSG_HELLO) {
    murmur_serve_msg_free(&got);
    set_detail(detail_out, "expected hello");
    set_sqlrc(sqlrc, SQLITE_OK);
    return MURMUR_SYNC_PROTOCOL;
  }
  if (!node_equal(&got.msg.group, &group) ||
      !node_equal(&got.msg.node, peer) || node_equal(&got.msg.site, &site)) {
    murmur_serve_msg_free(&got);
    set_detail(detail_out, "session group or identity mismatch");
    set_sqlrc(sqlrc, SQLITE_OK);
    return MURMUR_SYNC_AUTH;
  }
  if (peer_excluded(db, peer, sqlrc)) {
    murmur_serve_msg_free(&got);
    set_detail(detail_out, "peer excluded");
    set_sqlrc(sqlrc, SQLITE_AUTH);
    return MURMUR_SYNC_AUTH;
  }
  if (memcmp(got.msg.schema, schema, 32) != 0) {
    /* See above: fast-fail only when adoption is off. */
    murmur_schema_params_t hp;
    memset(&hp, 0, sizeof(hp));
    st = murmur_schema_params_from(db, &hp, sqlrc);
    if (st != MURMUR_SYNC_OK) {
      murmur_serve_msg_free(&got);
      native_detail(db, st, detail_out);
      return st;
    }
    if (!hp.accept_remote) {
      murmur_serve_msg_free(&got);
      set_detail(detail_out,
                 "CRR schema mismatch; provision matching table definitions");
      set_sqlrc(sqlrc, SQLITE_OK);
      return MURMUR_SYNC_PROTOCOL;
    }
  }
  *incarnation_out = got.msg.incarnation;
  *addr_out = got.msg.addr;
  murmur_serve_msg_free(&got);
  set_sqlrc(sqlrc, SQLITE_OK);
  return MURMUR_SYNC_OK;
}

void murmur_serve_touch_peer(murmur_engine_t *e, const murmur_node_t *peer,
                             const murmur_tx_progress_t *ps, size_t n_ps) {
  pthread_mutex_lock(&e->mu);
  sqlite3 *db = e->db;
  pthread_mutex_unlock(&e->mu);
  murmur_tx_touch(db, peer, ps, n_ps, NULL);
}

murmur_sync_status_t murmur_serve_pull_once(murmur_engine_t *e,
                                            const murmur_node_t *peer,
                                            murmur_stream_io_t *io, int *more,
                                            char **detail_out, int *sqlrc) {
  set_detail(detail_out, NULL);
  if (more) {
    *more = 0;
  }
  pthread_mutex_lock(&e->mu);
  sqlite3 *db = e->db;
  pthread_mutex_unlock(&e->mu);
  murmur_serve_params_t p;
  murmur_sync_status_t st =
      murmur_serve_params(db, &p, detail_out, sqlrc);
  if (st != MURMUR_SYNC_OK) {
    return st;
  }
  pthread_mutex_lock(&e->mu);
  murmur_node_t group = e->group, node = e->node, site = e->site;
  pthread_mutex_unlock(&e->mu);

  murmur_node_t expected;
  int has_expected = 0;
  murmur_stored_cursor_t cursor;
  memset(&cursor, 0, sizeof(cursor));
  st = murmur_sync_progress(db, peer, &expected, &has_expected, &cursor,
                            sqlrc);
  if (st != MURMUR_SYNC_OK) {
    native_detail(db, st, detail_out);
    return st;
  }
  uint8_t schema[32];
  st = murmur_schema_digest(db, schema, sqlrc);
  if (st != MURMUR_SYNC_OK) {
    murmur_sync_cursor_free(&cursor);
    native_detail(db, st, detail_out);
    return st;
  }
  murmur_msg_t req;
  memset(&req, 0, sizeof(req));
  req.tag = MURMUR_MSG_PULL;
  req.group = group;
  req.node = node;
  req.site = site;
  memcpy(req.schema, schema, 32);
  req.has_expected = has_expected;
  req.expected = expected;
  req.cursor = cursor.cursor;
  st = murmur_serve_write_msg(io, &req, detail_out, sqlrc);
  if (st != MURMUR_SYNC_OK) {
    murmur_sync_cursor_free(&cursor);
    return st;
  }
  murmur_serve_msg_t reply;
  memset(&reply, 0, sizeof(reply));
  st = murmur_serve_read_msg(io, &reply, detail_out, sqlrc);
  if (st != MURMUR_SYNC_OK) {
    murmur_sync_cursor_free(&cursor);
    return st;
  }
  switch (reply.msg.tag) {
  case MURMUR_MSG_IDLE:
    murmur_serve_msg_free(&reply);
    murmur_sync_cursor_free(&cursor);
    set_sqlrc(sqlrc, SQLITE_OK);
    return MURMUR_SYNC_OK;
  case MURMUR_MSG_RESET:
    if (node_equal(&reply.msg.site, &site)) {
      murmur_serve_msg_free(&reply);
      murmur_sync_cursor_free(&cursor);
      set_detail(detail_out, "remote cloned local site identity");
      set_sqlrc(sqlrc, SQLITE_OK);
      return MURMUR_SYNC_AUTH;
    }
    st = murmur_sync_reset(db, peer, &reply.msg.site, sqlrc);
    if (st != MURMUR_SYNC_OK) {
      murmur_serve_msg_free(&reply);
      murmur_sync_cursor_free(&cursor);
      native_detail(db, st, detail_out);
      return st;
    }
    murmur_serve_msg_free(&reply);
    murmur_sync_cursor_free(&cursor);
    if (more) {
      *more = 1;
    }
    set_sqlrc(sqlrc, SQLITE_OK);
    return MURMUR_SYNC_OK;
  case MURMUR_MSG_ERROR:
    set_detail_n(detail_out, reply.msg.data, reply.msg.data_len);
    murmur_serve_msg_free(&reply);
    murmur_sync_cursor_free(&cursor);
    set_sqlrc(sqlrc, SQLITE_OK);
    return MURMUR_SYNC_PROTOCOL;
  case MURMUR_MSG_BATCH:
    break;
  default:
    murmur_serve_msg_free(&reply);
    murmur_sync_cursor_free(&cursor);
    set_detail(detail_out, "expected batch header");
    set_sqlrc(sqlrc, SQLITE_OK);
    return MURMUR_SYNC_PROTOCOL;
  }
  /* Batch branch. */
  murmur_cursor_t next = reply.msg.cursor;
  uint64_t bytes = reply.msg.bytes;
  if (!has_expected || !node_equal(&expected, &reply.msg.site) ||
      node_equal(&reply.msg.site, &site) || bytes < MURMUR_EMPTY_CRSB_LEN ||
      (p.max_batch_bytes >= 0 &&
       bytes > (uint64_t)p.max_batch_bytes)) {
    murmur_serve_msg_free(&reply);
    murmur_sync_cursor_free(&cursor);
    set_detail(detail_out, "batch identity or length");
    set_sqlrc(sqlrc, SQLITE_OK);
    return MURMUR_SYNC_PROTOCOL;
  }
  if (next.from < cursor.cursor.from ||
      (next.has_through && next.through < next.from) ||
      (next.has_after &&
       (!next.has_through || next.after.version > next.through))) {
    murmur_serve_msg_free(&reply);
    murmur_sync_cursor_free(&cursor);
    set_detail(detail_out, "batch cursor");
    set_sqlrc(sqlrc, SQLITE_OK);
    return MURMUR_SYNC_PROTOCOL;
  }
  gauge_acquire(e, 0, bytes);
  st = murmur_sync_stage_begin(db, peer, p.staging_timeout_ms, sqlrc);
  if (st != MURMUR_SYNC_OK) {
    gauge_release(e, 0, bytes);
    murmur_serve_msg_free(&reply);
    murmur_sync_cursor_free(&cursor);
    native_detail(db, st, detail_out);
    return st;
  }
  uint64_t received = 0;
  uint32_t index = 0;
  for (;;) {
    murmur_serve_msg_t f;
    memset(&f, 0, sizeof(f));
    st = murmur_serve_read_msg(io, &f, detail_out, sqlrc);
    if (st != MURMUR_SYNC_OK) {
      gauge_release(e, 0, bytes);
      murmur_serve_msg_free(&reply);
      murmur_sync_cursor_free(&cursor);
      return st;
    }
    if (f.msg.tag == MURMUR_MSG_END) {
      murmur_serve_msg_free(&f);
      break;
    }
    if (f.msg.tag != MURMUR_MSG_CHUNK || f.msg.index != index ||
        f.msg.data_len == 0 || f.msg.data_len > MURMUR_CHUNK_BYTES) {
      murmur_serve_msg_free(&f);
      gauge_release(e, 0, bytes);
      murmur_serve_msg_free(&reply);
      murmur_sync_cursor_free(&cursor);
      set_detail(detail_out, "expected sequential batch chunks");
      set_sqlrc(sqlrc, SQLITE_OK);
      return MURMUR_SYNC_PROTOCOL;
    }
    if (received + (uint64_t)f.msg.data_len > bytes) {
      murmur_serve_msg_free(&f);
      gauge_release(e, 0, bytes);
      murmur_serve_msg_free(&reply);
      murmur_sync_cursor_free(&cursor);
      set_detail(detail_out, "excess chunk bytes");
      set_sqlrc(sqlrc, SQLITE_OK);
      return MURMUR_SYNC_PROTOCOL;
    }
    received += (uint64_t)f.msg.data_len;
    st = murmur_sync_stage(db, peer, index, f.msg.data, f.msg.data_len,
                           p.staging_bytes, sqlrc);
    murmur_serve_msg_free(&f);
    if (st != MURMUR_SYNC_OK) {
      gauge_release(e, 0, bytes);
      murmur_serve_msg_free(&reply);
      murmur_sync_cursor_free(&cursor);
      native_detail(db, st, detail_out);
      return st;
    }
    index++;
  }
  if (received != bytes) {
    gauge_release(e, 0, bytes);
    murmur_serve_msg_free(&reply);
    murmur_sync_cursor_free(&cursor);
    set_detail(detail_out, "incomplete batch");
    set_sqlrc(sqlrc, SQLITE_OK);
    return MURMUR_SYNC_PROTOCOL;
  }
  int want_more = next.has_through != 0;
  int changed = !cursor_equal(&next, &cursor.cursor);
  uint8_t digest[32];
  memcpy(digest, reply.msg.digest, 32);
  murmur_node_t batch_site = reply.msg.site;
  /* next.after borrows reply.owned: keep reply alive through apply,
   * which re-encodes the cursor into progress. Freeing first stores
   * heap garbage that later fails cursor decode on every sweep. */
  struct timespec apply_start, apply_end;
  clock_gettime(CLOCK_MONOTONIC, &apply_start);
  st = murmur_sync_apply(db, peer, &batch_site, &cursor.cursor, &next, bytes,
                         digest, sqlrc);
  clock_gettime(CLOCK_MONOTONIC, &apply_end);
  murmur_serve_msg_free(&reply);
  murmur_sync_cursor_free(&cursor);
  if (st != MURMUR_SYNC_OK) {
    gauge_release(e, 0, bytes);
    native_detail(db, st, detail_out);
    return st;
  }
  {
    uint64_t elapsed =
        (uint64_t)(apply_end.tv_sec - apply_start.tv_sec) * 1000000000u +
        (uint64_t)(apply_end.tv_nsec - apply_start.tv_nsec);
    pthread_mutex_lock(&e->mu);
    if (bytes > 0) {
      e->recv_batches++;
    }
    e->apply_bytes += bytes;
    e->apply_nanos += elapsed;
    pthread_mutex_unlock(&e->mu);
  }
  murmur_serve_touch_peer(e, peer, NULL, 0);
  murmur_msg_t ack;
  memset(&ack, 0, sizeof(ack));
  ack.tag = MURMUR_MSG_ACK;
  memcpy(ack.digest, digest, 32);
  st = murmur_serve_write_msg(io, &ack, detail_out, sqlrc);
  gauge_release(e, 0, bytes);
  if (st != MURMUR_SYNC_OK) {
    return st;
  }
  if (changed) {
    pthread_mutex_lock(&e->mu);
    e->applied++;
    pthread_mutex_unlock(&e->mu);
  }
  if (more) {
    *more = want_more;
  }
  set_sqlrc(sqlrc, SQLITE_OK);
  return MURMUR_SYNC_OK;
}

/* Go err.Error(): "Kind: Msg", bare Kind when empty, raw sqlite
 * text for storage failures. */
static char *full_error(murmur_sync_status_t st, const char *detail,
                        sqlite3 *db) {
  if (st == MURMUR_SYNC_SQLITE) {
    const char *t = sqlite3_errmsg(db);
    return strdup(t ? t : "");
  }
  const char *k = kind_str(st);
  if (!detail || !detail[0]) {
    return strdup(k);
  }
  size_t n = strlen(k) + 2 + strlen(detail) + 1;
  char *d = (char *)malloc(n);
  if (!d) {
    return NULL;
  }
  snprintf(d, n, "%s: %s", k, detail);
  return d;
}

/* isMismatch over the composed error text. */
static int is_mismatch(murmur_sync_status_t st, const char *detail,
                       sqlite3 *db) {
  if (st == MURMUR_SYNC_SQLITE) {
    const char *t = sqlite3_errmsg(db);
    return t && strstr(t, "mismatch") != NULL;
  }
  return detail && strstr(detail, "mismatch") != NULL;
}

murmur_sync_status_t murmur_serve_pull(murmur_engine_t *e,
                                       const murmur_node_t *peer,
                                       murmur_stream_io_t *io,
                                       const murmur_msg_t *req,
                                       char **detail_out, int *sqlrc) {
  set_detail(detail_out, NULL);
  pthread_mutex_lock(&e->mu);
  sqlite3 *db = e->db;
  pthread_mutex_unlock(&e->mu);
  murmur_serve_params_t p;
  murmur_sync_status_t st =
      murmur_serve_params(db, &p, detail_out, sqlrc);
  if (st != MURMUR_SYNC_OK) {
    return st;
  }
  pthread_mutex_lock(&e->mu);
  murmur_node_t group = e->group, node = e->node, site = e->site;
  int running = e->running;
  int held = 0;
  if (running) {
    if (e->serve_in_use >= e->serve_cap) {
      pthread_mutex_unlock(&e->mu);
      set_detail(detail_out, "session capacity");
      set_sqlrc(sqlrc, SQLITE_OK);
      return MURMUR_SYNC_OVERLOADED;
    }
    e->serve_in_use++;
    held = 1;
  }
  pthread_mutex_unlock(&e->mu);

  st = MURMUR_SYNC_OK;
  if (!node_equal(&req->group, &group) || !node_equal(&req->node, peer) ||
      node_equal(&req->site, &site)) {
    set_detail(detail_out, "replication group or identity mismatch");
    set_sqlrc(sqlrc, SQLITE_OK);
    st = MURMUR_SYNC_AUTH;
    goto out;
  }
  uint8_t schema[32];
  st = murmur_schema_digest(db, schema, sqlrc);
  if (st != MURMUR_SYNC_OK) {
    native_detail(db, st, detail_out);
    goto out;
  }
  if (memcmp(schema, req->schema, 32) != 0 &&
      !compat_vetted(e, peer, req->schema)) {
    set_detail(detail_out,
               "CRR schema mismatch; provision matching table definitions");
    set_sqlrc(sqlrc, SQLITE_OK);
    st = MURMUR_SYNC_PROTOCOL;
    goto out;
  }
  if (!req->has_expected || !node_equal(&req->expected, &site)) {
    murmur_msg_t reset;
    memset(&reset, 0, sizeof(reset));
    reset.tag = MURMUR_MSG_RESET;
    reset.site = site;
    st = murmur_serve_write_msg(io, &reset, detail_out, sqlrc);
    goto out;
  }
  gauge_acquire(e, 1, (uint64_t)p.max_batch_bytes);
  uint64_t watermark = 0;
  st = murmur_gc_watermark(db, &watermark, sqlrc);
  if (st != MURMUR_SYNC_OK) {
    gauge_release(e, 1, (uint64_t)p.max_batch_bytes);
    native_detail(db, st, detail_out);
    goto out;
  }
  int64_t from = req->cursor.from;
  if (from < 0) {
    from = 0;
  }
  if ((uint64_t)from < watermark) {
    gauge_release(e, 1, (uint64_t)p.max_batch_bytes);
    set_detail(detail_out, "cursor pruned; snapshot required");
    set_sqlrc(sqlrc, SQLITE_OK);
    st = MURMUR_SYNC_PROTOCOL;
    goto out;
  }
  murmur_export_t batch;
  memset(&batch, 0, sizeof(batch));
  st = murmur_sync_export(db, &req->cursor, p.batch_bytes, p.max_batch_bytes,
                          &batch, sqlrc);
  if (st != MURMUR_SYNC_OK) {
    gauge_release(e, 1, (uint64_t)p.max_batch_bytes);
    native_detail(db, st, detail_out);
    goto out;
  }
  if (cursor_equal(&batch.next.cursor, &req->cursor) &&
      batch.blob_len == MURMUR_EMPTY_CRSB_LEN) {
    murmur_sync_export_free(&batch);
    gauge_release(e, 1, (uint64_t)p.max_batch_bytes);
    murmur_msg_t idle;
    memset(&idle, 0, sizeof(idle));
    idle.tag = MURMUR_MSG_IDLE;
    st = murmur_serve_write_msg(io, &idle, detail_out, sqlrc);
    goto out;
  }
  uint8_t digest[32];
  murmur_sha256(batch.blob, batch.blob_len, digest);
  murmur_msg_t bh;
  memset(&bh, 0, sizeof(bh));
  bh.tag = MURMUR_MSG_BATCH;
  bh.site = site;
  bh.cursor = batch.next.cursor;
  bh.bytes = (uint64_t)batch.blob_len;
  memcpy(bh.digest, digest, 32);
  st = murmur_serve_write_msg(io, &bh, detail_out, sqlrc);
  if (st == MURMUR_SYNC_OK) {
    for (size_t i = 0; i < batch.blob_len; i += MURMUR_CHUNK_BYTES) {
      size_t end = i + MURMUR_CHUNK_BYTES;
      if (end > batch.blob_len) {
        end = batch.blob_len;
      }
      murmur_msg_t ch;
      memset(&ch, 0, sizeof(ch));
      ch.tag = MURMUR_MSG_CHUNK;
      ch.index = (uint32_t)(i / MURMUR_CHUNK_BYTES);
      ch.data = batch.blob + i;
      ch.data_len = end - i;
      st = murmur_serve_write_msg(io, &ch, detail_out, sqlrc);
      if (st != MURMUR_SYNC_OK) {
        break;
      }
    }
  }
  if (st == MURMUR_SYNC_OK) {
    murmur_msg_t end;
    memset(&end, 0, sizeof(end));
    end.tag = MURMUR_MSG_END;
    st = murmur_serve_write_msg(io, &end, detail_out, sqlrc);
  }
  /* bh.cursor.after borrows the export arena: encode the sent cursor
   * before freeing the batch (same use-after-free class as the pull
   * client's next cursor). */
  size_t ccap = 256;
  uint8_t *cbuf = NULL;
  size_t clen = 0;
  if (st == MURMUR_SYNC_OK) {
    for (;;) {
      cbuf = (uint8_t *)realloc(cbuf, ccap);
      if (!cbuf) {
        set_sqlrc(sqlrc, SQLITE_OK);
        st = MURMUR_SYNC_OVERLOADED;
        break;
      }
      clen = murmur_cursor_encode(&bh.cursor, cbuf, ccap);
      if (clen > 0 || ccap >= (1u << 20)) {
        break;
      }
      ccap *= 2;
    }
    if (st == MURMUR_SYNC_OK && clen == 0) {
      free(cbuf);
      cbuf = NULL;
      set_sqlrc(sqlrc, SQLITE_OK);
      st = MURMUR_SYNC_OVERLOADED;
    }
  }
  murmur_sync_export_free(&batch);
  gauge_release(e, 1, (uint64_t)p.max_batch_bytes);
  if (st != MURMUR_SYNC_OK) {
    free(cbuf);
    goto out;
  }
  murmur_serve_msg_t areply;
  memset(&areply, 0, sizeof(areply));
  st = murmur_serve_read_msg(io, &areply, detail_out, sqlrc);
  if (st != MURMUR_SYNC_OK) {
    free(cbuf);
    goto out;
  }
  if (areply.msg.tag != MURMUR_MSG_ACK ||
      memcmp(areply.msg.digest, digest, 32) != 0) {
    murmur_serve_msg_free(&areply);
    free(cbuf);
    set_detail(detail_out, "batch acknowledgement mismatch");
    set_sqlrc(sqlrc, SQLITE_OK);
    st = MURMUR_SYNC_PROTOCOL;
    goto out;
  }
  murmur_serve_msg_free(&areply);
  /* The puller applied our data through its request cursor. */
  uint64_t acked = 0;
  if (req->cursor.from > 0) {
    acked = (uint64_t)req->cursor.from;
  }
  sqlite3_stmt *us = NULL;
  int rc = sqlite3_prepare_v3(
      db, "UPDATE murmur_progress SET sent=?1 WHERE node=?2", -1, 0, &us,
      NULL);
  if (rc != SQLITE_OK) {
    free(cbuf);
    set_sqlrc(sqlrc, rc);
    set_detail(detail_out, sqlite3_errmsg(db));
    st = MURMUR_SYNC_SQLITE;
    goto out;
  }
  sqlite3_bind_blob(us, 1, cbuf, (int)clen, SQLITE_TRANSIENT);
  sqlite3_bind_blob(us, 2, peer->b, 16, SQLITE_TRANSIENT);
  rc = sqlite3_step(us);
  sqlite3_finalize(us);
  free(cbuf);
  if (rc != SQLITE_DONE) {
    set_sqlrc(sqlrc, sqlite3_extended_errcode(db));
    set_detail(detail_out, sqlite3_errmsg(db));
    st = MURMUR_SYNC_SQLITE;
    goto out;
  }
  st = murmur_sync_observed_max(db, &node, acked, sqlrc);
  if (st != MURMUR_SYNC_OK) {
    native_detail(db, st, detail_out);
    goto out;
  }
  int64_t through = bh.cursor.from;
  if (bh.cursor.has_through) {
    through = bh.cursor.through;
  }
  uint64_t acked_through = 0;
  if (through > 0) {
    acked_through = (uint64_t)through;
  }
  murmur_tx_progress_t ps;
  memset(&ps, 0, sizeof(ps));
  ps.origin = node;
  ps.applied = acked_through;
  ps.observed = acked_through;
  murmur_serve_touch_peer(e, peer, &ps, 1);
  pthread_mutex_lock(&e->mu);
  e->sent++;
  pthread_mutex_unlock(&e->mu);
  st = MURMUR_SYNC_OK;
  set_sqlrc(sqlrc, SQLITE_OK);

out:
  if (held) {
    pthread_mutex_lock(&e->mu);
    e->serve_in_use--;
    pthread_mutex_unlock(&e->mu);
  }
  return st;
}

murmur_sync_status_t murmur_serve_stream(murmur_engine_t *e,
                                         const murmur_node_t *peer,
                                         murmur_stream_io_t *io,
                                         char **detail_out, int *sqlrc) {
  set_detail(detail_out, NULL);
  pthread_mutex_lock(&e->mu);
  sqlite3 *db = e->db;
  pthread_mutex_unlock(&e->mu);
  murmur_serve_msg_t first;
  memset(&first, 0, sizeof(first));
  char *detail = NULL;
  murmur_sync_status_t st =
      murmur_serve_read_msg(io, &first, &detail, sqlrc);
  if (st != MURMUR_SYNC_OK) {
    char *text = full_error(st, detail, db);
    if (text) {
      murmur_engine_record(e, text);
      murmur_msg_t em;
      memset(&em, 0, sizeof(em));
      em.tag = MURMUR_MSG_ERROR;
      em.data = (const uint8_t *)text;
      em.data_len = strlen(text);
      murmur_serve_write_msg(io, &em, NULL, NULL);
      free(text);
    }
    if (detail_out) {
      *detail_out = detail;
    } else {
      free(detail);
    }
    return st;
  }
  murmur_sync_status_t rst = MURMUR_SYNC_OK;
  char *rdetail = NULL;
  int sql2 = SQLITE_OK;
  int is_pull = first.msg.tag == MURMUR_MSG_PULL;
  if (is_pull) {
    rst = murmur_serve_pull(e, peer, io, &first.msg, &rdetail, &sql2);
    int mismatch = is_mismatch(rst, rdetail, db);
    pthread_mutex_lock(&e->mu);
    if (rst == MURMUR_SYNC_OK) {
      e->serve_ok++;
    } else if (mismatch) {
      e->serve_reject++;
    } else {
      e->serve_error++;
    }
    pthread_mutex_unlock(&e->mu);
  } else if (first.msg.tag == MURMUR_MSG_SNAPSHOT_REQUEST) {
    rst = murmur_serve_snapshot(e, peer, io, &first.msg, &rdetail, &sql2);
  } else if (first.msg.tag == MURMUR_MSG_SCHEMA_REQUEST) {
    rst = murmur_serve_schema_request(e, io, &rdetail, &sql2);
  } else if (first.msg.tag == MURMUR_MSG_SCHEMA_MANIFEST) {
    rst = murmur_serve_receive_schema_push(e, peer, io, first.msg.data,
                                           first.msg.data_len, &rdetail, &sql2);
  } else {
    rdetail = strdup("expected pull, snapshot, or schema request");
    rst = MURMUR_SYNC_PROTOCOL;
    sql2 = SQLITE_OK;
  }
  murmur_serve_msg_free(&first);
  if (rst != MURMUR_SYNC_OK) {
    char *text = full_error(rst, rdetail, db);
    if (text) {
      murmur_engine_record(e, text);
      murmur_msg_t em;
      memset(&em, 0, sizeof(em));
      em.tag = MURMUR_MSG_ERROR;
      em.data = (const uint8_t *)text;
      em.data_len = strlen(text);
      murmur_serve_write_msg(io, &em, NULL, NULL);
      free(text);
    }
  }
  if (detail_out) {
    *detail_out = rdetail;
  } else {
    free(rdetail);
  }
  set_sqlrc(sqlrc, sql2);
  return rst;
}

static const char *sess_error(murmur_session_if_t *sess) {
  const char *t = NULL;
  if (sess && sess->error_text) {
    t = sess->error_text(sess->ctx);
  }
  return t;
}

murmur_sync_status_t murmur_serve_snapshot(murmur_engine_t *e,
                                           const murmur_node_t *peer,
                                           murmur_stream_io_t *io,
                                           const murmur_msg_t *req,
                                           char **detail_out, int *sqlrc) {
  set_detail(detail_out, NULL);
  pthread_mutex_lock(&e->mu);
  sqlite3 *db = e->db;
  pthread_mutex_unlock(&e->mu);
  murmur_serve_params_t p;
  murmur_sync_status_t st =
      murmur_serve_params(db, &p, detail_out, sqlrc);
  if (st != MURMUR_SYNC_OK) {
    return st;
  }
  pthread_mutex_lock(&e->mu);
  murmur_node_t group = e->group, node = e->node, site = e->site;
  int running = e->running;
  int held = 0;
  if (running) {
    if (e->serve_in_use >= e->serve_cap) {
      pthread_mutex_unlock(&e->mu);
      set_detail(detail_out, "session capacity");
      set_sqlrc(sqlrc, SQLITE_OK);
      return MURMUR_SYNC_OVERLOADED;
    }
    e->serve_in_use++;
    held = 1;
  }
  pthread_mutex_unlock(&e->mu);

  st = MURMUR_SYNC_OK;
  murmur_snap_params_t sp;
  memset(&sp, 0, sizeof(sp));
  murmur_tx_manifest_t m;
  memset(&m, 0, sizeof(m));
  uint8_t *enc = NULL;
  int have_params = 0, have_manifest = 0;
  if (!node_equal(&req->group, &group) || !node_equal(&req->node, peer) ||
      node_equal(&req->site, &site)) {
    set_detail(detail_out, "replication group or identity mismatch");
    set_sqlrc(sqlrc, SQLITE_OK);
    st = MURMUR_SYNC_AUTH;
    goto out;
  }
  uint8_t schema[32];
  st = murmur_schema_digest(db, schema, sqlrc);
  if (st != MURMUR_SYNC_OK) {
    native_detail(db, st, detail_out);
    goto out;
  }
  if (memcmp(schema, req->schema, 32) != 0 &&
      !compat_vetted(e, peer, req->schema)) {
    set_detail(detail_out,
               "CRR schema mismatch; provision matching table definitions");
    set_sqlrc(sqlrc, SQLITE_OK);
    st = MURMUR_SYNC_PROTOCOL;
    goto out;
  }
  st = murmur_snap_params_from(db, &sp, sqlrc);
  if (st != MURMUR_SYNC_OK) {
    native_detail(db, st, detail_out);
    goto out;
  }
  have_params = 1;
  st = murmur_snap_build_for(db, &group, &node, &sp, p.batch_bytes,
                             p.max_batch_bytes, peer, murmur_tx_now_millis(),
                             &m, sqlrc);
  if (st != MURMUR_SYNC_OK) {
    native_detail(db, st, detail_out);
    goto out;
  }
  have_manifest = 1;
  size_t enc_len = 0;
  enc = murmur_tx_manifest_encode(&m, &enc_len);
  if (!enc) {
    set_sqlrc(sqlrc, SQLITE_OK);
    st = MURMUR_SYNC_OVERLOADED;
    goto out;
  }
  murmur_msg_t mm;
  memset(&mm, 0, sizeof(mm));
  mm.tag = MURMUR_MSG_SNAPSHOT_MANIFEST;
  mm.data = enc;
  mm.data_len = enc_len;
  st = murmur_serve_write_msg(io, &mm, detail_out, sqlrc);
  if (st != MURMUR_SYNC_OK) {
    goto out;
  }
  for (size_t i = 0; i < m.n_chunks; i++) {
    size_t klen = 0;
    uint8_t *key =
        murmur_tx_chunk_key(MURMUR_TX_OUT, &m.transfer, (uint32_t)i, &klen);
    if (!key) {
      set_sqlrc(sqlrc, SQLITE_OK);
      st = MURMUR_SYNC_OVERLOADED;
      goto out;
    }
    uint8_t *val = NULL;
    size_t vlen = 0;
    int found = 0;
    st = murmur_kv_get(db, key, klen, &val, &vlen, &found, sqlrc);
    free(key);
    if (st != MURMUR_SYNC_OK) {
      native_detail(db, st, detail_out);
      goto out;
    }
    if (!found) {
      set_detail(detail_out, "snapshot chunk expired");
      set_sqlrc(sqlrc, SQLITE_OK);
      st = MURMUR_SYNC_PROTOCOL;
      goto out;
    }
    murmur_msg_t ch;
    memset(&ch, 0, sizeof(ch));
    ch.tag = MURMUR_MSG_CHUNK;
    ch.index = (uint32_t)i;
    ch.data = val;
    ch.data_len = vlen;
    st = murmur_serve_write_msg(io, &ch, detail_out, sqlrc);
    free(val);
    if (st != MURMUR_SYNC_OK) {
      goto out;
    }
  }
  murmur_msg_t end;
  memset(&end, 0, sizeof(end));
  end.tag = MURMUR_MSG_END;
  st = murmur_serve_write_msg(io, &end, detail_out, sqlrc);
  if (st != MURMUR_SYNC_OK) {
    goto out;
  }
  pthread_mutex_lock(&e->mu);
  e->sent++;
  pthread_mutex_unlock(&e->mu);
  st = MURMUR_SYNC_OK;
  set_sqlrc(sqlrc, SQLITE_OK);

out:
  free(enc);
  if (have_manifest) {
    murmur_tx_manifest_free(&m);
  }
  if (have_params) {
    murmur_snap_params_free(&sp);
  }
  if (held) {
    pthread_mutex_lock(&e->mu);
    e->serve_in_use--;
    pthread_mutex_unlock(&e->mu);
  }
  return st;
}

/* Fetch record kind: 0 standard map, 1 Go-Closed (Unavailable),
 * 2 raw transport text (Storage). */
static murmur_sync_status_t fetch_inner(murmur_engine_t *e,
                                        const murmur_node_t *peer,
                                        murmur_session_if_t *sess,
                                        murmur_node_t *transfer_out,
                                        char **detail_out, int *sqlrc,
                                        int *kind) {
  set_detail(detail_out, NULL);
  if (kind) {
    *kind = 0;
  }
  murmur_session_if_t tmp;
  if (!murmur_engine_get_conn(e, peer, &tmp)) {
    if (kind) {
      *kind = 1;
    }
    set_detail(detail_out, "snapshot peer is not connected");
    set_sqlrc(sqlrc, SQLITE_OK);
    return MURMUR_SYNC_OVERLOADED;
  }
  pthread_mutex_lock(&e->mu);
  murmur_node_t group = e->group, node = e->node, site = e->site;
  sqlite3 *db = e->db;
  pthread_mutex_unlock(&e->mu);
  uint8_t schema[32];
  murmur_sync_status_t st = murmur_schema_digest(db, schema, sqlrc);
  if (st != MURMUR_SYNC_OK) {
    native_detail(db, st, detail_out);
    return st;
  }
  murmur_stream_io_t io;
  memset(&io, 0, sizeof(io));
  if (sess->open_stream(sess->ctx, &io) != 0) {
    if (kind) {
      *kind = 2;
    }
    set_detail(detail_out, sess_error(sess));
    set_sqlrc(sqlrc, SQLITE_OK);
    return MURMUR_SYNC_OVERLOADED;
  }
  murmur_msg_t req;
  memset(&req, 0, sizeof(req));
  req.tag = MURMUR_MSG_SNAPSHOT_REQUEST;
  req.group = group;
  req.node = node;
  req.site = site;
  memcpy(req.schema, schema, 32);
  st = murmur_serve_write_msg(&io, &req, detail_out, sqlrc);
  if (st != MURMUR_SYNC_OK) {
    return st;
  }
  murmur_serve_msg_t first;
  memset(&first, 0, sizeof(first));
  st = murmur_serve_read_msg(&io, &first, detail_out, sqlrc);
  if (st != MURMUR_SYNC_OK) {
    return st;
  }
  if (first.msg.tag == MURMUR_MSG_ERROR) {
    set_detail_n(detail_out, first.msg.data, first.msg.data_len);
    murmur_serve_msg_free(&first);
    set_sqlrc(sqlrc, SQLITE_OK);
    return MURMUR_SYNC_PROTOCOL;
  }
  if (first.msg.tag != MURMUR_MSG_SNAPSHOT_MANIFEST) {
    murmur_serve_msg_free(&first);
    set_detail(detail_out, "expected snapshot manifest");
    set_sqlrc(sqlrc, SQLITE_OK);
    return MURMUR_SYNC_PROTOCOL;
  }
  murmur_tx_manifest_t m;
  memset(&m, 0, sizeof(m));
  st = murmur_tx_manifest_decode(first.msg.data, first.msg.data_len, &m,
                                 sqlrc);
  murmur_serve_msg_free(&first);
  if (st != MURMUR_SYNC_OK) {
    native_detail(db, st, detail_out);
    return st;
  }
  murmur_snap_params_t sp;
  memset(&sp, 0, sizeof(sp));
  st = murmur_snap_params_from(db, &sp, sqlrc);
  if (st != MURMUR_SYNC_OK) {
    murmur_tx_manifest_free(&m);
    native_detail(db, st, detail_out);
    return st;
  }
  murmur_node_t transfer = m.transfer;
  st = murmur_snap_accept(db, &group, &node, &sp, peer, &m,
                          murmur_tx_now_millis(), sqlrc);
  if (st != MURMUR_SYNC_OK) {
    murmur_tx_manifest_free(&m);
    murmur_snap_params_free(&sp);
    native_detail(db, st, detail_out);
    return st;
  }
  uint32_t index = 0;
  for (;;) {
    murmur_serve_msg_t f;
    memset(&f, 0, sizeof(f));
    st = murmur_serve_read_msg(&io, &f, detail_out, sqlrc);
    if (st != MURMUR_SYNC_OK) {
      murmur_tx_manifest_free(&m);
      murmur_snap_params_free(&sp);
      return st;
    }
    if (f.msg.tag == MURMUR_MSG_END) {
      murmur_serve_msg_free(&f);
      break;
    }
    if (f.msg.tag == MURMUR_MSG_ERROR) {
      set_detail_n(detail_out, f.msg.data, f.msg.data_len);
      murmur_serve_msg_free(&f);
      murmur_tx_manifest_free(&m);
      murmur_snap_params_free(&sp);
      set_sqlrc(sqlrc, SQLITE_OK);
      return MURMUR_SYNC_PROTOCOL;
    }
    if (f.msg.tag != MURMUR_MSG_CHUNK || f.msg.index != index ||
        f.msg.data_len == 0 || f.msg.data_len > MURMUR_CHUNK_BYTES) {
      murmur_serve_msg_free(&f);
      murmur_tx_manifest_free(&m);
      murmur_snap_params_free(&sp);
      set_detail(detail_out, "expected sequential snapshot chunks");
      set_sqlrc(sqlrc, SQLITE_OK);
      return MURMUR_SYNC_PROTOCOL;
    }
    size_t klen = 0;
    uint8_t *key = murmur_tx_chunk_key(MURMUR_TX_IN, &transfer, index, &klen);
    if (!key) {
      murmur_serve_msg_free(&f);
      murmur_tx_manifest_free(&m);
      murmur_snap_params_free(&sp);
      set_sqlrc(sqlrc, SQLITE_OK);
      return MURMUR_SYNC_OVERLOADED;
    }
    murmur_kv_record_t rec;
    memset(&rec, 0, sizeof(rec));
    rec.key = key;
    rec.key_len = klen;
    rec.value = (uint8_t *)f.msg.data;
    rec.value_len = f.msg.data_len;
    st = murmur_kv_commit(db, &rec, 1, sqlrc);
    free(key);
    murmur_serve_msg_free(&f);
    if (st != MURMUR_SYNC_OK) {
      murmur_tx_manifest_free(&m);
      murmur_snap_params_free(&sp);
      native_detail(db, st, detail_out);
      return st;
    }
    index++;
  }
  for (int round = 0; round < 600; round++) {
    uint64_t now = murmur_tx_now_millis();
    size_t hklen = 0;
    uint8_t *hkey = murmur_tx_header_key(MURMUR_TX_IN, &transfer, &hklen);
    if (!hkey) {
      st = MURMUR_SYNC_OVERLOADED;
      set_sqlrc(sqlrc, SQLITE_OK);
      break;
    }
    uint8_t *hval = NULL;
    size_t hvlen = 0;
    int hfound = 0;
    st = murmur_kv_get(db, hkey, hklen, &hval, &hvlen, &hfound, sqlrc);
    free(hkey);
    if (st != MURMUR_SYNC_OK) {
      native_detail(db, st, detail_out);
      break;
    }
    if (!hfound) {
      *transfer_out = transfer;
      murmur_tx_manifest_free(&m);
      murmur_snap_params_free(&sp);
      set_sqlrc(sqlrc, SQLITE_OK);
      return MURMUR_SYNC_OK;
    }
    murmur_tx_incoming_t inc;
    memset(&inc, 0, sizeof(inc));
    st = murmur_tx_incoming_decode(hval, hvlen, &inc, sqlrc);
    free(hval);
    if (st != MURMUR_SYNC_OK) {
      native_detail(db, st, detail_out);
      break;
    }
    uint32_t *missing = NULL;
    size_t n_missing = 0;
    st = murmur_tx_missing(db, &inc, &missing, &n_missing, sqlrc);
    murmur_tx_incoming_free(&inc);
    if (st != MURMUR_SYNC_OK) {
      free(missing);
      native_detail(db, st, detail_out);
      break;
    }
    if (n_missing > 0) {
      free(missing);
      murmur_tx_manifest_free(&m);
      murmur_snap_params_free(&sp);
      set_detail(detail_out, "snapshot donor short-sent chunks");
      set_sqlrc(sqlrc, SQLITE_OK);
      return MURMUR_SYNC_PROTOCOL;
    }
    free(missing);
    int done = 0;
    st = murmur_snap_finish(db, &group, &node, &sp, peer, &transfer, now,
                            &done, sqlrc);
    if (st != MURMUR_SYNC_OK) {
      native_detail(db, st, detail_out);
      break;
    }
    if (done) {
      murmur_serve_touch_peer(e, peer, m.progress, m.n_progress);
      pthread_mutex_lock(&e->mu);
      e->applied++;
      e->snapshots++;
      pthread_mutex_unlock(&e->mu);
      *transfer_out = transfer;
      murmur_tx_manifest_free(&m);
      murmur_snap_params_free(&sp);
      set_sqlrc(sqlrc, SQLITE_OK);
      return MURMUR_SYNC_OK;
    }
    struct timespec ts;
    ts.tv_sec = 0;
    ts.tv_nsec = 100 * 1000 * 1000;
    nanosleep(&ts, NULL);
  }
  murmur_tx_manifest_free(&m);
  murmur_snap_params_free(&sp);
  if (st == MURMUR_SYNC_OK) {
    if (kind) {
      *kind = 1;
    }
    set_detail(detail_out, "snapshot install did not complete");
    set_sqlrc(sqlrc, SQLITE_OK);
    return MURMUR_SYNC_OVERLOADED;
  }
  return st;
}

murmur_sync_status_t murmur_serve_fetch_snapshot(
    murmur_engine_t *e, const murmur_node_t *peer, murmur_session_if_t *sess,
    murmur_node_t *transfer_out, char **detail_out, int *sqlrc) {
  return fetch_inner(e, peer, sess, transfer_out, detail_out, sqlrc, NULL);
}

typedef struct {
  murmur_engine_t *e;
  murmur_node_t peer;
} snap_work_t;

static void snap_status_set(murmur_engine_t *e, const char *s) {
  pthread_mutex_lock(&e->mu);
  free(e->snapshot_status);
  e->snapshot_status = s ? strdup(s) : NULL;
  pthread_mutex_unlock(&e->mu);
}

static void snap_work(snap_work_t *w) {
  murmur_engine_t *e = w->e;
  murmur_session_if_t sess;
  if (!murmur_engine_get_conn(e, &w->peer, &sess)) {
    murmur_engine_fail(e, MURMUR_CODE_UNAVAILABLE, "Unavailable",
                       "Closed: snapshot peer is not connected");
    snap_status_set(e, "error: Closed: snapshot peer is not connected");
    free(w);
    return;
  }
  murmur_node_t transfer;
  memset(&transfer, 0, sizeof(transfer));
  char *detail = NULL;
  int sqlrc = SQLITE_OK;
  int kind = 0;
  murmur_sync_status_t st =
      fetch_inner(e, &w->peer, &sess, &transfer, &detail, &sqlrc, &kind);
  if (st != MURMUR_SYNC_OK) {
    int32_t code;
    const char *ks = NULL;
    char *text = NULL;
    pthread_mutex_lock(&e->mu);
    sqlite3 *db = e->db;
    pthread_mutex_unlock(&e->mu);
    if (kind == 1) {
      code = MURMUR_CODE_UNAVAILABLE;
      ks = "Unavailable";
      size_t n = strlen("Closed: ") + (detail ? strlen(detail) : 0) + 1;
      text = (char *)malloc(n);
      if (text) {
        snprintf(text, n, "Closed: %s", detail ? detail : "");
      }
    } else if (kind == 2) {
      code = MURMUR_CODE_STORAGE;
      ks = "Storage";
      text = strdup(detail ? detail : "Storage");
    } else if (st == MURMUR_SYNC_SQLITE) {
      code = sqlrc != 0 ? (int32_t)sqlrc : MURMUR_CODE_STORAGE;
      ks = "Native";
      const char *em = sqlite3_errmsg(db);
      text = strdup(em ? em : "sqlite error");
    } else {
      switch (st) {
      case MURMUR_SYNC_INVALID:
        code = MURMUR_CODE_INVALID;
        break;
      case MURMUR_SYNC_PROTOCOL:
        code = MURMUR_CODE_PROTOCOL;
        break;
      case MURMUR_SYNC_AUTH:
        code = MURMUR_CODE_AUTH;
        break;
      default:
        code = MURMUR_CODE_OVERLOADED;
        break;
      }
      ks = kind_str(st);
      text = full_error(st, detail, db);
    }
    if (!text) {
      text = strdup(ks ? ks : "Storage");
    }
    murmur_engine_fail(e, code, ks, text ? text : ks);
    size_t n = strlen("error: ") + strlen(text ? text : "") + 1;
    char *ss = (char *)malloc(n);
    if (ss) {
      snprintf(ss, n, "error: %s", text ? text : "");
      snap_status_set(e, ss);
      free(ss);
    }
    free(text);
    free(detail);
    free(w);
    return;
  }
  char hex[33];
  murmur_engine_node_format(&transfer, hex);
  size_t n = strlen("ok ") + strlen(hex) + 1;
  char *ss = (char *)malloc(n);
  if (ss) {
    snprintf(ss, n, "ok %s", hex);
    snap_status_set(e, ss);
    free(ss);
  }
  free(detail);
  free(w);
}

static void *snap_worker(void *v) {
  snap_work_t *w = (snap_work_t *)v;
  murmur_engine_t *e = w->e;
  snap_work(w);
  murmur_engine_worker_release(e);
  return NULL;
}

murmur_sync_status_t murmur_serve_request_snapshot(murmur_engine_t *e,
                                                   const murmur_node_t *peer,
                                                   int *sqlrc) {
  pthread_mutex_lock(&e->mu);
  if (e->snapshot_status && strcmp(e->snapshot_status, "running") == 0) {
    pthread_mutex_unlock(&e->mu);
    set_sqlrc(sqlrc, SQLITE_OK);
    return MURMUR_SYNC_OVERLOADED;
  }
  free(e->snapshot_status);
  e->snapshot_status = strdup("running");
  pthread_mutex_unlock(&e->mu);
  snap_work_t *w = (snap_work_t *)malloc(sizeof(*w));
  if (!w) {
    snap_status_set(e, NULL);
    set_sqlrc(sqlrc, SQLITE_OK);
    return MURMUR_SYNC_OVERLOADED;
  }
  w->e = e;
  w->peer = *peer;
  murmur_engine_worker_add(e);
  pthread_t t;
  pthread_attr_t at;
  pthread_attr_init(&at);
  pthread_attr_setdetachstate(&at, PTHREAD_CREATE_DETACHED);
  int rc = pthread_create(&t, &at, snap_worker, w);
  pthread_attr_destroy(&at);
  if (rc != 0) {
    murmur_engine_worker_release(e);
    free(w);
    snap_status_set(e, NULL);
    set_sqlrc(sqlrc, SQLITE_OK);
    return MURMUR_SYNC_OVERLOADED;
  }
  set_sqlrc(sqlrc, SQLITE_OK);
  return MURMUR_SYNC_OK;
}

void murmur_serve_vet_fetch(murmur_engine_t *e, const murmur_node_t *peer,
                            murmur_session_if_t *sess, int *verdict, int *ok) {
  *verdict = 0;
  *ok = 0;
  murmur_stream_io_t io;
  memset(&io, 0, sizeof(io));
  if (sess->open_stream(sess->ctx, &io) != 0) {
    return;
  }
  murmur_msg_t q;
  memset(&q, 0, sizeof(q));
  q.tag = MURMUR_MSG_SCHEMA_REQUEST;
  if (murmur_serve_write_msg(&io, &q, NULL, NULL) != MURMUR_SYNC_OK) {
    return;
  }
  murmur_serve_msg_t f;
  memset(&f, 0, sizeof(f));
  if (murmur_serve_read_msg(&io, &f, NULL, NULL) != MURMUR_SYNC_OK) {
    return;
  }
  if (f.msg.tag != MURMUR_MSG_SCHEMA_MANIFEST) {
    murmur_serve_msg_free(&f);
    return;
  }
  murmur_signed_schema_t s;
  memset(&s, 0, sizeof(s));
  if (murmur_signed_schema_decode(f.msg.data, f.msg.data_len, &s, NULL) !=
      MURMUR_SYNC_OK) {
    murmur_serve_msg_free(&f);
    *ok = 1;
    return;
  }
  murmur_serve_msg_free(&f);
  pthread_mutex_lock(&e->mu);
  murmur_node_t group = e->group;
  sqlite3 *db = e->db;
  pthread_mutex_unlock(&e->mu);
  if (!node_equal(&s.signer, peer) || !node_equal(&s.database, &group)) {
    murmur_signed_schema_free(&s);
    *ok = 1;
    return;
  }
  uint8_t *local = NULL;
  size_t local_len = 0;
  if (murmur_manifest_schema_bytes(db, &local, &local_len, NULL) !=
      MURMUR_SYNC_OK) {
    murmur_signed_schema_free(&s);
    return;
  }
  int compat = 0;
  murmur_sync_status_t st = murmur_puller_compatible(
      local, local_len, s.schema, s.schema_len, &compat, NULL);
  free(local);
  murmur_signed_schema_free(&s);
  if (st != MURMUR_SYNC_OK) {
    *ok = 1;
    return;
  }
  *verdict = compat != 0;
  *ok = 1;
}

murmur_sync_status_t murmur_serve_schema_request(murmur_engine_t *e,
                                                 murmur_stream_io_t *io,
                                                 char **detail_out,
                                                 int *sqlrc) {
  set_detail(detail_out, NULL);
  pthread_mutex_lock(&e->mu);
  murmur_node_t group = e->group, node = e->node;
  sqlite3 *db = e->db;
  pthread_mutex_unlock(&e->mu);
  murmur_schema_params_t params;
  memset(&params, 0, sizeof(params));
  murmur_sync_status_t st =
      murmur_schema_params_from(db, &params, sqlrc);
  if (st != MURMUR_SYNC_OK) {
    native_detail(db, st, detail_out);
    return st;
  }
  uint8_t *raw = NULL;
  size_t raw_len = 0;
  st = murmur_manifest_schema_bytes(db, &raw, &raw_len, sqlrc);
  if (st != MURMUR_SYNC_OK) {
    native_detail(db, st, detail_out);
    return st;
  }
  murmur_signed_schema_t s;
  memset(&s, 0, sizeof(s));
  st = murmur_schema_build_manifest(db, &params, &node, &group, raw, raw_len,
                                    &s, sqlrc);
  free(raw);
  if (st != MURMUR_SYNC_OK) {
    native_detail(db, st, detail_out);
    return st;
  }
  size_t enc_len = 0;
  uint8_t *enc = murmur_signed_schema_encode(&s, &enc_len);
  murmur_signed_schema_free(&s);
  if (!enc) {
    set_sqlrc(sqlrc, SQLITE_OK);
    return MURMUR_SYNC_OVERLOADED;
  }
  murmur_msg_t mm;
  memset(&mm, 0, sizeof(mm));
  mm.tag = MURMUR_MSG_SCHEMA_MANIFEST;
  mm.data = enc;
  mm.data_len = enc_len;
  st = murmur_serve_write_msg(io, &mm, detail_out, sqlrc);
  free(enc);
  return st;
}

murmur_sync_status_t murmur_serve_ingest_manifest(
    murmur_engine_t *e, const murmur_node_t *peer, const uint8_t *payload,
    size_t payload_len, uint8_t digest_out[32], uint64_t *sequence_out,
    char **detail_out, int *sqlrc) {
  set_detail(detail_out, NULL);
  pthread_mutex_lock(&e->mu);
  sqlite3 *db = e->db;
  pthread_mutex_unlock(&e->mu);
  murmur_signed_schema_t s;
  memset(&s, 0, sizeof(s));
  murmur_sync_status_t st =
      murmur_signed_schema_decode(payload, payload_len, &s, sqlrc);
  if (st != MURMUR_SYNC_OK) {
    native_detail(db, st, detail_out);
    return st;
  }
  murmur_schema_params_t params;
  memset(&params, 0, sizeof(params));
  st = murmur_schema_params_from(db, &params, sqlrc);
  if (st != MURMUR_SYNC_OK) {
    murmur_signed_schema_free(&s);
    native_detail(db, st, detail_out);
    return st;
  }
  uint8_t *local = NULL;
  size_t local_len = 0;
  st = murmur_manifest_schema_bytes(db, &local, &local_len, sqlrc);
  if (st != MURMUR_SYNC_OK) {
    murmur_signed_schema_free(&s);
    native_detail(db, st, detail_out);
    return st;
  }
  pthread_mutex_lock(&e->mu);
  murmur_node_t group = e->group, node = e->node;
  pthread_mutex_unlock(&e->mu);
  murmur_schema_decision_t decision = 0;
  st = murmur_schema_check_manifest(db, &params, &node, local, local_len, &s,
                                    &group, peer, &decision, sqlrc);
  free(local);
  if (st != MURMUR_SYNC_OK) {
    murmur_signed_schema_free(&s);
    native_detail(db, st, detail_out);
    return st;
  }
  if (decision == MURMUR_SCHEMA_ADOPT) {
    int accepted = 0;
    st = murmur_backend_accept_schema(db, s.schema, s.schema_len, &accepted,
                                      sqlrc);
    if (st != MURMUR_SYNC_OK) {
      murmur_signed_schema_free(&s);
      native_detail(db, st, detail_out);
      return st;
    }
    if (accepted) {
      st = murmur_schema_record_accepted(db, &s, sqlrc);
      if (st != MURMUR_SYNC_OK) {
        murmur_signed_schema_free(&s);
        native_detail(db, st, detail_out);
        return st;
      }
      pthread_mutex_lock(&e->mu);
      e->schema_adoptions++;
      pthread_mutex_unlock(&e->mu);
    }
  }
  murmur_sha256(s.schema, s.schema_len, digest_out);
  *sequence_out = s.sequence;
  murmur_signed_schema_free(&s);
  set_sqlrc(sqlrc, SQLITE_OK);
  return MURMUR_SYNC_OK;
}

murmur_sync_status_t murmur_serve_receive_schema_push(
    murmur_engine_t *e, const murmur_node_t *peer, murmur_stream_io_t *io,
    const uint8_t *payload, size_t payload_len, char **detail_out,
    int *sqlrc) {
  set_detail(detail_out, NULL);
  uint8_t digest[32];
  uint64_t seq = 0;
  murmur_sync_status_t st = murmur_serve_ingest_manifest(
      e, peer, payload, payload_len, digest, &seq, detail_out, sqlrc);
  if (st != MURMUR_SYNC_OK) {
    return st;
  }
  murmur_msg_t ack;
  memset(&ack, 0, sizeof(ack));
  ack.tag = MURMUR_MSG_SCHEMA_ACK;
  memcpy(ack.digest, digest, 32);
  ack.sequence = seq;
  return murmur_serve_write_msg(io, &ack, detail_out, sqlrc);
}

murmur_sync_status_t murmur_serve_adopt_from_peer(
    murmur_engine_t *e, const murmur_node_t *peer, murmur_session_if_t *sess,
    char **detail_out, int *sqlrc) {
  set_detail(detail_out, NULL);
  murmur_stream_io_t io;
  memset(&io, 0, sizeof(io));
  if (sess->open_stream(sess->ctx, &io) != 0) {
    set_detail(detail_out, sess_error(sess));
    set_sqlrc(sqlrc, SQLITE_OK);
    return MURMUR_SYNC_OVERLOADED;
  }
  murmur_msg_t q;
  memset(&q, 0, sizeof(q));
  q.tag = MURMUR_MSG_SCHEMA_REQUEST;
  murmur_sync_status_t st =
      murmur_serve_write_msg(&io, &q, detail_out, sqlrc);
  if (st != MURMUR_SYNC_OK) {
    return st;
  }
  murmur_serve_msg_t f;
  memset(&f, 0, sizeof(f));
  st = murmur_serve_read_msg(&io, &f, detail_out, sqlrc);
  if (st != MURMUR_SYNC_OK) {
    return st;
  }
  if (f.msg.tag == MURMUR_MSG_ERROR) {
    set_detail_n(detail_out, f.msg.data, f.msg.data_len);
    murmur_serve_msg_free(&f);
    set_sqlrc(sqlrc, SQLITE_OK);
    return MURMUR_SYNC_PROTOCOL;
  }
  if (f.msg.tag != MURMUR_MSG_SCHEMA_MANIFEST) {
    murmur_serve_msg_free(&f);
    set_detail(detail_out, "expected schema manifest");
    set_sqlrc(sqlrc, SQLITE_OK);
    return MURMUR_SYNC_PROTOCOL;
  }
  uint8_t digest[32];
  uint64_t seq = 0;
  st = murmur_serve_ingest_manifest(e, peer, f.msg.data, f.msg.data_len,
                                    digest, &seq, detail_out, sqlrc);
  murmur_serve_msg_free(&f);
  if (st != MURMUR_SYNC_OK) {
    return st;
  }
  murmur_msg_t ack;
  memset(&ack, 0, sizeof(ack));
  ack.tag = MURMUR_MSG_SCHEMA_ACK;
  memcpy(ack.digest, digest, 32);
  ack.sequence = seq;
  return murmur_serve_write_msg(&io, &ack, detail_out, sqlrc);
}

void murmur_serve_push_schema(murmur_engine_t *e, const murmur_node_t *peer,
                              murmur_session_if_t *sess) {
  pthread_mutex_lock(&e->mu);
  sqlite3 *db = e->db;
  pthread_mutex_unlock(&e->mu);
  murmur_schema_params_t params;
  memset(&params, 0, sizeof(params));
  if (murmur_schema_params_from(db, &params, NULL) != MURMUR_SYNC_OK ||
      !params.master_enabled) {
    return;
  }
  pthread_mutex_lock(&e->mu);
  murmur_node_t group = e->group, node = e->node;
  pthread_mutex_unlock(&e->mu);
  uint8_t *raw = NULL;
  size_t raw_len = 0;
  if (murmur_manifest_schema_bytes(db, &raw, &raw_len, NULL) !=
      MURMUR_SYNC_OK) {
    return;
  }
  murmur_signed_schema_t s;
  memset(&s, 0, sizeof(s));
  if (murmur_schema_build_manifest(db, &params, &node, &group, raw, raw_len,
                                   &s, NULL) != MURMUR_SYNC_OK) {
    free(raw);
    return;
  }
  free(raw);
  uint8_t digest[32];
  murmur_sha256(s.schema, s.schema_len, digest);
  uint64_t seq = s.sequence;
  pthread_mutex_lock(&e->mu);
  int done = 0;
  for (size_t i = 0; i < e->n_schema_sent; i++) {
    if (node_equal(&e->schema_sent[i].peer, peer) &&
        memcmp(e->schema_sent[i].digest, digest, 32) == 0 &&
        e->schema_sent[i].sequence == seq) {
      done = 1;
      break;
    }
  }
  pthread_mutex_unlock(&e->mu);
  if (done) {
    murmur_signed_schema_free(&s);
    return;
  }
  size_t enc_len = 0;
  uint8_t *enc = murmur_signed_schema_encode(&s, &enc_len);
  murmur_signed_schema_free(&s);
  if (!enc) {
    return;
  }
  murmur_stream_io_t io;
  memset(&io, 0, sizeof(io));
  if (sess->open_stream(sess->ctx, &io) != 0) {
    free(enc);
    return;
  }
  murmur_msg_t mm;
  memset(&mm, 0, sizeof(mm));
  mm.tag = MURMUR_MSG_SCHEMA_MANIFEST;
  mm.data = enc;
  mm.data_len = enc_len;
  if (murmur_serve_write_msg(&io, &mm, NULL, NULL) != MURMUR_SYNC_OK) {
    free(enc);
    return;
  }
  free(enc);
  murmur_serve_msg_t f;
  memset(&f, 0, sizeof(f));
  if (murmur_serve_read_msg(&io, &f, NULL, NULL) != MURMUR_SYNC_OK) {
    return;
  }
  int acked = f.msg.tag == MURMUR_MSG_SCHEMA_ACK &&
              memcmp(f.msg.digest, digest, 32) == 0 && f.msg.sequence == seq;
  murmur_serve_msg_free(&f);
  if (!acked) {
    return;
  }
  pthread_mutex_lock(&e->mu);
  size_t i = 0;
  for (; i < e->n_schema_sent; i++) {
    if (node_equal(&e->schema_sent[i].peer, peer)) {
      break;
    }
  }
  if (i == e->n_schema_sent) {
    if (e->n_schema_sent >= e->cap_schema_sent) {
      size_t ncap = e->cap_schema_sent ? e->cap_schema_sent * 2 : 8;
      murmur_schema_sent_t *nv = (murmur_schema_sent_t *)realloc(
          e->schema_sent, ncap * sizeof(*nv));
      if (nv) {
        e->schema_sent = nv;
        e->cap_schema_sent = ncap;
      }
    }
    if (e->n_schema_sent < e->cap_schema_sent) {
      e->schema_sent[e->n_schema_sent].peer = *peer;
      i = e->n_schema_sent++;
    } else {
      pthread_mutex_unlock(&e->mu);
      return;
    }
  }
  memcpy(e->schema_sent[i].digest, digest, 32);
  e->schema_sent[i].sequence = seq;
  e->sent++;
  e->schema_pushes++;
  pthread_mutex_unlock(&e->mu);
}
