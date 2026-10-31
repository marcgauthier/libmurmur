/* murmur sync - see sync.h. Ports sync.go: SQL text, cursor
 * rules, budget accounting, error kinds, and wire bytes match Go.
 * Export scans crsql_changes row by row (Go's 256-row batching is a
 * cgo-crossing optimization with no behavior); all budget checks
 * run in the same order. */
#include "sync.h"

#include "config.h"
#include "kv.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int apply_dbg_on(void) {
  static int v = -1;
  if (v < 0) {
    v = getenv("MURMUR_DEBUG_SYNC") != NULL;
  }
  return v;
}

#define APPLY_DBG(...)                                   \
  do {                                                   \
    if (apply_dbg_on()) {                                \
      fprintf(stderr, "murmur-apply: ");                 \
      fprintf(stderr, __VA_ARGS__);                      \
      fprintf(stderr, "\n");                             \
    }                                                    \
  } while (0)

#include "sha256.h"
#include "sqlite3.h"

#define EMPTY_CRSB_LEN 12
#define MAX_CELLS_PER_BATCH 1024

const char *murmur_sync_status_str(murmur_sync_status_t st) {
  switch (st) {
    case MURMUR_SYNC_OK:
      return "Ok";
    case MURMUR_SYNC_INVALID:
      return "Invalid";
    case MURMUR_SYNC_PROTOCOL:
      return "Protocol";
    case MURMUR_SYNC_OVERLOADED:
      return "Overloaded";
    case MURMUR_SYNC_AUTH:
      return "Auth";
    case MURMUR_SYNC_SQLITE:
      return "Sqlite";
  }
  return "Unknown";
}

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

static const char kSchemaDDL[] =
    "CREATE TABLE IF NOT EXISTS murmur_config(name TEXT PRIMARY KEY,value "
    "TEXT NOT NULL);"
    "CREATE TABLE IF NOT EXISTS murmur_identity(id INTEGER PRIMARY KEY "
    "CHECK(id=1),node BLOB,site BLOB,incarnation INTEGER NOT NULL DEFAULT "
    "0);"
    "INSERT OR IGNORE INTO murmur_identity(id) VALUES(1);"
    "CREATE TABLE IF NOT EXISTS murmur_progress(node BLOB PRIMARY KEY,site "
    "BLOB NOT NULL,cursor BLOB NOT NULL,sent BLOB);"
    "CREATE TABLE IF NOT EXISTS murmur_excluded(node BLOB PRIMARY KEY);"
    "CREATE TABLE IF NOT EXISTS murmur_stage(node BLOB NOT NULL,idx INTEGER "
    "NOT NULL,data BLOB NOT NULL,created INTEGER NOT NULL,PRIMARY "
    "KEY(node,idx));"
    "CREATE TABLE IF NOT EXISTS murmur_kv(key BLOB PRIMARY KEY,value BLOB "
    "NOT NULL);"
    "CREATE TABLE IF NOT EXISTS murmur_file_meta(name TEXT PRIMARY KEY NOT "
    "NULL,meta BLOB NOT NULL DEFAULT x'');"
    "CREATE TABLE IF NOT EXISTS murmur_file_chunks(digest BLOB NOT NULL,"
    "generation INTEGER NOT NULL,idx INTEGER NOT NULL,bytes BLOB NOT "
    "NULL,created_ms INTEGER NOT NULL,PRIMARY KEY(digest,generation,idx));"
    "CREATE TABLE IF NOT EXISTS murmur_file_transfers(transfer BLOB PRIMARY "
    "KEY,digest BLOB,generation INTEGER,total_bytes INTEGER,identity "
    "BLOB,created_ms INTEGER NOT NULL,updated_ms INTEGER NOT NULL);"
    "CREATE TABLE IF NOT EXISTS murmur_file_staging(transfer BLOB NOT "
    "NULL,idx INTEGER NOT NULL,bytes BLOB NOT NULL,created_ms INTEGER NOT "
    "NULL,PRIMARY KEY(transfer,idx));";

murmur_sync_status_t murmur_sync_ensure_schema(sqlite3 *db, int *sqlrc) {
  if (!db) {
    return sqlite_fail(sqlrc, SQLITE_MISUSE);
  }
  int rc = sqlite3_exec(db, kSchemaDDL, NULL, NULL, NULL);
  return rc == SQLITE_OK ? ok_rc(sqlrc) : sqlite_fail(sqlrc, rc);
}

void murmur_sync_cursor_free(murmur_stored_cursor_t *c) {
  if (c) {
    free(c->owned);
    memset(c, 0, sizeof(*c));
  }
}

void murmur_sync_export_free(murmur_export_t *e) {
  if (e) {
    free(e->blob);
    murmur_sync_cursor_free(&e->next);
    memset(e, 0, sizeof(*e));
  }
}

/* ---- key/cursor order (compareKey/cursorsEqual) ---- */

static int bytes_cmp(const uint8_t *a, size_t an, const uint8_t *b,
                     size_t bn) {
  size_t n = an < bn ? an : bn;
  int c = n ? memcmp(a, b, n) : 0;
  if (c != 0) {
    return c < 0 ? -1 : 1;
  }
  if (an == bn) {
    return 0;
  }
  return an < bn ? -1 : 1;
}

static int key_cmp(const murmur_key_t *a, const murmur_key_t *b) {
  if (a->version != b->version) {
    return a->version < b->version ? -1 : 1;
  }
  if (a->seq != b->seq) {
    return a->seq < b->seq ? -1 : 1;
  }
  int c = bytes_cmp(a->table, a->table_len, b->table, b->table_len);
  if (c != 0) {
    return c;
  }
  c = bytes_cmp(a->pk, a->pk_len, b->pk, b->pk_len);
  if (c != 0) {
    return c;
  }
  return bytes_cmp(a->cid, a->cid_len, b->cid, b->cid_len);
}

static int cursor_equal(const murmur_cursor_t *a, const murmur_cursor_t *b) {
  if (a->from != b->from || a->has_through != b->has_through ||
      a->has_after != b->has_after) {
    return 0;
  }
  if (a->has_through && a->through != b->through) {
    return 0;
  }
  return !a->has_after || key_cmp(&a->after, &b->after) == 0;
}

/* Replication flags (table_replication map) live in config.h. */

/* ---- kv (murmur_kv) ---- */

static murmur_sync_status_t kv_get(sqlite3 *db, const uint8_t *key,
                                   size_t key_len, uint8_t **val,
                                   size_t *val_len, int *found, int *sqlrc) {
  *val = NULL;
  *val_len = 0;
  *found = 0;
  sqlite3_stmt *st = NULL;
  int rc = sqlite3_prepare_v2(db, "SELECT value FROM murmur_kv WHERE key=?1",
                              -1, &st, NULL);
  if (rc != SQLITE_OK) {
    return sqlite_fail(sqlrc, rc);
  }
  sqlite3_bind_blob(st, 1, key, (int)key_len, SQLITE_TRANSIENT);
  rc = sqlite3_step(st);
  if (rc == SQLITE_DONE) {
    sqlite3_finalize(st);
    return ok_rc(sqlrc);
  }
  if (rc != SQLITE_ROW) {
    sqlite3_finalize(st);
    return sqlite_fail(sqlrc, rc);
  }
  const uint8_t *v = sqlite3_column_blob(st, 0);
  int n = sqlite3_column_bytes(st, 0);
  uint8_t *copy = (uint8_t *)malloc((size_t)n ? (size_t)n : 1);
  if (!copy) {
    sqlite3_finalize(st);
    return sqlite_fail(sqlrc, SQLITE_NOMEM);
  }
  if (n > 0) {
    memcpy(copy, v, (size_t)n);
  }
  sqlite3_finalize(st);
  *val = copy;
  *val_len = (size_t)n;
  *found = 1;
  return ok_rc(sqlrc);
}

static murmur_sync_status_t kv_put(sqlite3 *db, const uint8_t *key,
                                   size_t key_len, const uint8_t *val,
                                   size_t val_len, int *sqlrc) {
  sqlite3_stmt *st = NULL;
  int rc = sqlite3_prepare_v2(
      db,
      "INSERT INTO murmur_kv(key,value) VALUES(?1,?2) ON CONFLICT(key) DO "
      "UPDATE SET value=excluded.value",
      -1, &st, NULL);
  if (rc != SQLITE_OK) {
    return sqlite_fail(sqlrc, rc);
  }
  sqlite3_bind_blob(st, 1, key, (int)key_len, SQLITE_TRANSIENT);
  sqlite3_bind_blob(st, 2, val, (int)val_len, SQLITE_TRANSIENT);
  rc = sqlite3_step(st);
  sqlite3_finalize(st);
  return rc == SQLITE_DONE ? ok_rc(sqlrc) : sqlite_fail(sqlrc, rc);
}

murmur_sync_status_t murmur_sync_observed_max(sqlite3 *db,
                                              const murmur_node_t *origin,
                                              uint64_t seq, int *sqlrc) {
  if (!db || !origin) {
    return sqlite_fail(sqlrc, SQLITE_MISUSE);
  }
  char key[64];
  size_t key_len = murmur_observed_key(origin, key, sizeof(key));
  if (key_len == 0) {
    return MURMUR_SYNC_INVALID;
  }
  uint8_t *raw = NULL;
  size_t raw_len = 0;
  int found = 0;
  murmur_sync_status_t st =
      kv_get(db, (const uint8_t *)key, key_len, &raw, &raw_len, &found, sqlrc);
  if (st != MURMUR_SYNC_OK) {
    return st;
  }
  uint64_t current = 0;
  if (found) {
    if (murmur_u64_decode(raw, raw_len, &current) != MURMUR_OK) {
      free(raw);
      return MURMUR_SYNC_PROTOCOL;
    }
    free(raw);
  }
  if (seq <= current) {
    return ok_rc(sqlrc);
  }
  uint8_t enc[16];
  size_t n = murmur_u64_encode(seq, enc, sizeof(enc));
  if (n == 0) {
    return MURMUR_SYNC_INVALID;
  }
  return kv_put(db, (const uint8_t *)key, key_len, enc, n, sqlrc);
}

/* ---- site / version / ingest ---- */

murmur_sync_status_t murmur_sync_site_id(sqlite3 *db, murmur_node_t *site,
                                         int *sqlrc) {
  if (!db || !site) {
    return sqlite_fail(sqlrc, SQLITE_MISUSE);
  }
  sqlite3_stmt *st = NULL;
  int rc = sqlite3_prepare_v2(db, "SELECT crsql_site_id()", -1, &st, NULL);
  if (rc != SQLITE_OK) {
    return sqlite_fail(sqlrc, rc);
  }
  rc = sqlite3_step(st);
  if (rc != SQLITE_ROW) {
    sqlite3_finalize(st);
    if (rc == SQLITE_DONE) {
      return MURMUR_SYNC_INVALID;
    }
    return sqlite_fail(sqlrc, rc);
  }
  const uint8_t *raw = sqlite3_column_blob(st, 0);
  int n = sqlite3_column_bytes(st, 0);
  murmur_sync_status_t status;
  if (n != 16) {
    status = MURMUR_SYNC_INVALID;
  } else {
    memcpy(site->b, raw, 16);
    status = ok_rc(sqlrc);
  }
  sqlite3_finalize(st);
  return status;
}

murmur_sync_status_t murmur_sync_db_version(sqlite3 *db, int64_t *ver,
                                            int *sqlrc) {
  if (!db || !ver) {
    return sqlite_fail(sqlrc, SQLITE_MISUSE);
  }
  sqlite3_stmt *st = NULL;
  int rc =
      sqlite3_prepare_v2(db, "SELECT crsql_db_version()", -1, &st, NULL);
  if (rc != SQLITE_OK) {
    return sqlite_fail(sqlrc, rc);
  }
  rc = sqlite3_step(st);
  if (rc != SQLITE_ROW) {
    sqlite3_finalize(st);
    if (rc == SQLITE_DONE) {
      return MURMUR_SYNC_INVALID;
    }
    return sqlite_fail(sqlrc, rc);
  }
  *ver = sqlite3_column_int64(st, 0);
  sqlite3_finalize(st);
  return ok_rc(sqlrc);
}

murmur_sync_status_t murmur_sync_ingest_blob(sqlite3 *db,
                                             const uint8_t *blob, size_t len,
                                             int *sqlrc) {
  if (!db || (!blob && len > 0)) {
    return sqlite_fail(sqlrc, SQLITE_MISUSE);
  }
  sqlite3_stmt *st = NULL;
  int rc =
      sqlite3_prepare_v2(db, "SELECT crsql_ingest_blob(?)", -1, &st, NULL);
  if (rc != SQLITE_OK) {
    return sqlite_fail(sqlrc, rc);
  }
  sqlite3_bind_blob(st, 1, blob, (int)len, SQLITE_TRANSIENT);
  rc = sqlite3_step(st);
  sqlite3_finalize(st);
  if (rc == SQLITE_DONE) {
    APPLY_DBG("ingest-done len=%zu", len);
    return MURMUR_SYNC_PROTOCOL;
  }
  return rc == SQLITE_ROW ? ok_rc(sqlrc) : sqlite_fail(sqlrc, rc);
}

/* ---- stage / progress / reset ---- */

murmur_sync_status_t murmur_sync_stage_begin(sqlite3 *db,
                                             const murmur_node_t *node,
                                             int64_t timeout_ms, int *sqlrc) {
  if (!db || !node) {
    return sqlite_fail(sqlrc, SQLITE_MISUSE);
  }
  sqlite3_stmt *st = NULL;
  int rc = sqlite3_prepare_v2(
      db,
      "DELETE FROM murmur_stage WHERE node=?1 OR created < "
      "unixepoch()*1000-?2",
      -1, &st, NULL);
  if (rc != SQLITE_OK) {
    return sqlite_fail(sqlrc, rc);
  }
  sqlite3_bind_blob(st, 1, node->b, 16, SQLITE_TRANSIENT);
  sqlite3_bind_int64(st, 2, timeout_ms);
  rc = sqlite3_step(st);
  sqlite3_finalize(st);
  return rc == SQLITE_DONE ? ok_rc(sqlrc) : sqlite_fail(sqlrc, rc);
}

murmur_sync_status_t murmur_sync_stage(sqlite3 *db, const murmur_node_t *node,
                                       uint32_t idx, const uint8_t *data,
                                       size_t len, int64_t budget,
                                       int *sqlrc) {
  if (!db || !node || (!data && len > 0)) {
    return sqlite_fail(sqlrc, SQLITE_MISUSE);
  }
  sqlite3_stmt *st = NULL;
  int rc = sqlite3_prepare_v2(
      db, "SELECT coalesce(sum(length(data)),0) FROM murmur_stage", -1, &st,
      NULL);
  if (rc != SQLITE_OK) {
    return sqlite_fail(sqlrc, rc);
  }
  rc = sqlite3_step(st);
  int64_t total = 0;
  if (rc == SQLITE_ROW) {
    total = sqlite3_column_int64(st, 0);
  }
  sqlite3_finalize(st);
  if (rc != SQLITE_ROW && rc != SQLITE_DONE) {
    return sqlite_fail(sqlrc, rc);
  }
  /* Overflow-safe budget check (fails closed where Go would wrap). */
  if (len > (size_t)INT64_MAX || total < 0 ||
      total > INT64_MAX - (int64_t)len ||
      total + (int64_t)len > budget) {
    return MURMUR_SYNC_OVERLOADED;
  }
  rc = sqlite3_prepare_v2(
      db, "INSERT INTO murmur_stage VALUES(?1,?2,?3,unixepoch()*1000)", -1,
      &st, NULL);
  if (rc != SQLITE_OK) {
    return sqlite_fail(sqlrc, rc);
  }
  sqlite3_bind_blob(st, 1, node->b, 16, SQLITE_TRANSIENT);
  sqlite3_bind_int64(st, 2, (int64_t)idx);
  sqlite3_bind_blob(st, 3, data, (int)len, SQLITE_TRANSIENT);
  rc = sqlite3_step(st);
  sqlite3_finalize(st);
  return rc == SQLITE_DONE ? ok_rc(sqlrc) : sqlite_fail(sqlrc, rc);
}

murmur_sync_status_t murmur_sync_progress(sqlite3 *db,
                                          const murmur_node_t *node,
                                          murmur_node_t *site, int *has_site,
                                          murmur_stored_cursor_t *cur,
                                          int *sqlrc) {
  if (!db || !node || !site || !has_site || !cur) {
    return sqlite_fail(sqlrc, SQLITE_MISUSE);
  }
  memset(cur, 0, sizeof(*cur));
  *has_site = 0;
  sqlite3_stmt *st = NULL;
  int rc = sqlite3_prepare_v2(
      db, "SELECT site,cursor FROM murmur_progress WHERE node=?1", -1, &st,
      NULL);
  if (rc != SQLITE_OK) {
    return sqlite_fail(sqlrc, rc);
  }
  sqlite3_bind_blob(st, 1, node->b, 16, SQLITE_TRANSIENT);
  rc = sqlite3_step(st);
  if (rc == SQLITE_DONE) {
    sqlite3_finalize(st);
    return ok_rc(sqlrc);
  }
  if (rc != SQLITE_ROW) {
    sqlite3_finalize(st);
    return sqlite_fail(sqlrc, rc);
  }
  const uint8_t *site_raw = sqlite3_column_blob(st, 0);
  int site_len = sqlite3_column_bytes(st, 0);
  const uint8_t *cur_raw = sqlite3_column_blob(st, 1);
  int cur_len = sqlite3_column_bytes(st, 1);
  if (site_len != 16) {
    sqlite3_finalize(st);
    return MURMUR_SYNC_PROTOCOL;
  }
  uint8_t *copy = (uint8_t *)malloc((size_t)cur_len ? (size_t)cur_len : 1);
  if (!copy) {
    sqlite3_finalize(st);
    return sqlite_fail(sqlrc, SQLITE_NOMEM);
  }
  if (cur_len > 0) {
    memcpy(copy, cur_raw, (size_t)cur_len);
  }
  memcpy(site->b, site_raw, 16);
  sqlite3_finalize(st);
  if (murmur_cursor_decode(copy, (size_t)cur_len, &cur->cursor) !=
      MURMUR_OK) {
    if (apply_dbg_on()) {
      char hx[256];
      size_t hn = 0;
      static const char *d = "0123456789abcdef";
      for (int i = 0; i < cur_len && hn + 2 < sizeof(hx); i++) {
        hx[hn++] = d[(copy[i] >> 4) & 15];
        hx[hn++] = d[copy[i] & 15];
      }
      hx[hn] = '\0';
      APPLY_DBG("progress-decode-fail len=%d hex=%s", cur_len, hx);
    }
    free(copy);
    return MURMUR_SYNC_PROTOCOL;
  }
  cur->owned = copy;
  *has_site = 1;
  return ok_rc(sqlrc);
}

murmur_sync_status_t murmur_sync_reset(sqlite3 *db, const murmur_node_t *node,
                                       const murmur_node_t *site,
                                       int *sqlrc) {
  if (!db || !node || !site) {
    return sqlite_fail(sqlrc, SQLITE_MISUSE);
  }
  murmur_cursor_t zero;
  memset(&zero, 0, sizeof(zero));
  uint8_t enc[64];
  size_t n = murmur_cursor_encode(&zero, enc, sizeof(enc));
  if (n == 0) {
    return MURMUR_SYNC_INVALID;
  }
  sqlite3_stmt *st = NULL;
  int rc = sqlite3_prepare_v2(
      db,
      "INSERT INTO murmur_progress(node,site,cursor) VALUES(?1,?2,?3) ON "
      "CONFLICT(node) DO UPDATE SET "
      "site=excluded.site,cursor=excluded.cursor,sent=NULL",
      -1, &st, NULL);
  if (rc != SQLITE_OK) {
    return sqlite_fail(sqlrc, rc);
  }
  sqlite3_bind_blob(st, 1, node->b, 16, SQLITE_TRANSIENT);
  sqlite3_bind_blob(st, 2, site->b, 16, SQLITE_TRANSIENT);
  sqlite3_bind_blob(st, 3, enc, (int)n, SQLITE_TRANSIENT);
  rc = sqlite3_step(st);
  sqlite3_finalize(st);
  return rc == SQLITE_DONE ? ok_rc(sqlrc) : sqlite_fail(sqlrc, rc);
}

/* ---- export ---- */

static const char kExportSQL[] =
    "SELECT \"table\",pk,cid,val,col_version,db_version,site_id,cl,seq FROM "
    "crsql_changes WHERE db_version>?1 AND db_version<=?2 AND (?3 IS NULL OR "
    "(db_version,seq,\"table\",pk,cid)>(?3,?4,?5,?6,?7)) ORDER BY "
    "db_version,seq,\"table\",pk,cid";

/* Copies a resume key into one malloc block (table, pk, cid). */
static int key_copy(const murmur_key_t *src, murmur_key_t *dst,
                    uint8_t **arena) {
  size_t total = src->table_len + src->pk_len + src->cid_len;
  uint8_t *block = (uint8_t *)malloc(total ? total : 1);
  if (!block) {
    return -1;
  }
  size_t o = 0;
  *dst = *src;
  if (src->table_len) {
    memcpy(block + o, src->table, src->table_len);
    dst->table = block + o;
    o += src->table_len;
  } else {
    dst->table = NULL;
  }
  if (src->pk_len) {
    memcpy(block + o, src->pk, src->pk_len);
    dst->pk = block + o;
    o += src->pk_len;
  } else {
    dst->pk = NULL;
  }
  if (src->cid_len) {
    memcpy(block + o, src->cid, src->cid_len);
    dst->cid = block + o;
  } else {
    dst->cid = NULL;
  }
  *arena = block;
  return 0;
}

murmur_sync_status_t murmur_sync_export(sqlite3 *db,
                                        const murmur_cursor_t *cursor,
                                        int64_t batch_bytes,
                                        int64_t max_batch_bytes,
                                        murmur_export_t *out, int *sqlrc) {
  if (!db || !cursor || !out) {
    return sqlite_fail(sqlrc, SQLITE_MISUSE);
  }
  memset(out, 0, sizeof(*out));
  if (batch_bytes < 0 || max_batch_bytes < 0) {
    return MURMUR_SYNC_INVALID;
  }
  int has_through = cursor->has_through;
  int64_t through_val = has_through ? cursor->through : 0;
  int after_bad =
      cursor->has_after &&
      (cursor->after.version <= cursor->from || !has_through ||
       cursor->after.version > through_val);
  if (cursor->from < 0 || (has_through && through_val < cursor->from) ||
      after_bad) {
    return MURMUR_SYNC_PROTOCOL;
  }
  murmur_db_writer_lock();
  int rc = sqlite3_exec(db, "BEGIN", NULL, NULL, NULL);
  if (rc != SQLITE_OK) {
    murmur_db_writer_unlock();
    return sqlite_fail(sqlrc, rc);
  }
  int committed = 0;
  murmur_sync_status_t status = MURMUR_SYNC_OK;
  int fail_rc = SQLITE_OK;
  sqlite3_stmt *st = NULL;
  murmur_table_flags_t flags;
  memset(&flags, 0, sizeof(flags));
  uint8_t *blob = NULL;
  size_t blob_len = 0, blob_cap = 0;
  uint8_t *last_arena = NULL;
  murmur_key_t last;
  memset(&last, 0, sizeof(last));
  int have_last = 0;

  int64_t current = 0;
  status = murmur_sync_db_version(db, &current, &fail_rc);
  if (status != MURMUR_SYNC_OK) {
    goto rollback;
  }
  int64_t resolved = has_through ? through_val : current;
  if (resolved > current || cursor->from > current) {
    status = MURMUR_SYNC_PROTOCOL;
    goto rollback;
  }
  status = murmur_cfg_table_flags(db, &flags, &fail_rc);
  if (status != MURMUR_SYNC_OK) {
    goto rollback;
  }
  int filtering = murmur_cfg_table_filtering(&flags);

  rc = sqlite3_prepare_v2(db, kExportSQL, -1, &st, NULL);
  if (rc != SQLITE_OK) {
    status = sqlite_fail(&fail_rc, rc);
    goto rollback;
  }
  sqlite3_bind_int64(st, 1, cursor->from);
  sqlite3_bind_int64(st, 2, resolved);
  if (!cursor->has_after) {
    for (int i = 3; i <= 7; i++) {
      sqlite3_bind_null(st, i);
    }
  } else {
    sqlite3_bind_int64(st, 3, cursor->after.version);
    sqlite3_bind_int64(st, 4, cursor->after.seq);
    sqlite3_bind_text(st, 5, (const char *)cursor->after.table,
                      (int)cursor->after.table_len, SQLITE_TRANSIENT);
    sqlite3_bind_blob(st, 6, cursor->after.pk, (int)cursor->after.pk_len,
                      SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 7, (const char *)cursor->after.cid,
                      (int)cursor->after.cid_len, SQLITE_TRANSIENT);
  }

  blob_cap = 256;
  blob = (uint8_t *)malloc(blob_cap);
  if (!blob) {
    status = sqlite_fail(&fail_rc, SQLITE_NOMEM);
    goto rollback;
  }
  memcpy(blob, "CRSB", 4);
  memset(blob + 4, 0, 8);
  blob[4] = 1;
  blob_len = EMPTY_CRSB_LEN;
  uint32_t count = 0;
  int done = 1;

  for (;;) {
    rc = sqlite3_step(st);
    if (rc == SQLITE_DONE) {
      break;
    }
    if (rc != SQLITE_ROW) {
      status = sqlite_fail(&fail_rc, rc);
      goto rollback;
    }
    /* Key columns must be text or blob. */
    int t0 = sqlite3_column_type(st, 0);
    int t1 = sqlite3_column_type(st, 1);
    int t2 = sqlite3_column_type(st, 2);
    if ((t0 != SQLITE_TEXT && t0 != SQLITE_BLOB) ||
        (t1 != SQLITE_TEXT && t1 != SQLITE_BLOB) ||
        (t2 != SQLITE_TEXT && t2 != SQLITE_BLOB)) {
      status = MURMUR_SYNC_PROTOCOL;
      goto rollback;
    }
    const uint8_t *table_raw = sqlite3_column_blob(st, 0);
    int table_len = sqlite3_column_bytes(st, 0);
    const uint8_t *pk_view = sqlite3_column_blob(st, 1);
    int pk_len = sqlite3_column_bytes(st, 1);
    const uint8_t *cid_raw = sqlite3_column_blob(st, 2);
    int cid_len = sqlite3_column_bytes(st, 2);
    if (!murmur_utf8_valid(table_raw, (size_t)table_len) ||
        !murmur_utf8_valid(cid_raw, (size_t)cid_len)) {
      status = MURMUR_SYNC_PROTOCOL;
      goto rollback;
    }
    murmur_key_t key;
    memset(&key, 0, sizeof(key));
    key.version = sqlite3_column_int64(st, 5);
    key.seq = sqlite3_column_int64(st, 8);
    key.table = table_raw;
    key.table_len = (size_t)table_len;
    key.pk = pk_view;
    key.pk_len = (size_t)pk_len;
    key.cid = cid_raw;
    key.cid_len = (size_t)cid_len;
    if (cursor->has_after && key_cmp(&key, &cursor->after) <= 0) {
      continue;
    }
    if (filtering && murmur_cfg_table_disabled(&flags, table_raw, (size_t)table_len)) {
      continue;
    }
    /* Budget estimate mirrors Go: 64 + per-column bytes-or-8. */
    int64_t row_bytes = 64;
    for (int i = 0; i < 9; i++) {
      int t = sqlite3_column_type(st, i);
      if (t == SQLITE_TEXT || t == SQLITE_BLOB) {
        row_bytes += sqlite3_column_bytes(st, i);
      } else {
        row_bytes += 8;
      }
    }
    if (row_bytes > max_batch_bytes - EMPTY_CRSB_LEN) {
      status = MURMUR_SYNC_OVERLOADED;
      goto rollback;
    }
    if (count > 0 && (int64_t)blob_len + row_bytes > batch_bytes) {
      done = 0;
      break;
    }
    murmur_cell_t cell;
    memset(&cell, 0, sizeof(cell));
    cell.table = table_raw;
    cell.table_len = (size_t)table_len;
    cell.pk = pk_view;
    cell.pk_len = (size_t)pk_len;
    cell.cid = cid_raw;
    cell.cid_len = (size_t)cid_len;
    int vt = sqlite3_column_type(st, 3);
    switch (vt) {
      case SQLITE_NULL:
        cell.val_tag = 0;
        break;
      case SQLITE_INTEGER:
        cell.val_tag = 1;
        cell.val_int = sqlite3_column_int64(st, 3);
        break;
      case SQLITE_FLOAT:
        cell.val_tag = 2;
        cell.val_real = sqlite3_column_double(st, 3);
        break;
      case SQLITE_TEXT:
        cell.val_tag = 3;
        cell.val_blob = sqlite3_column_blob(st, 3);
        cell.val_blob_len = (size_t)sqlite3_column_bytes(st, 3);
        break;
      case SQLITE_BLOB:
        cell.val_tag = 4;
        cell.val_blob = sqlite3_column_blob(st, 3);
        cell.val_blob_len = (size_t)sqlite3_column_bytes(st, 3);
        break;
      default:
        status = MURMUR_SYNC_PROTOCOL;
        goto rollback;
    }
    if (sqlite3_column_type(st, 6) != SQLITE_BLOB) {
      status = MURMUR_SYNC_PROTOCOL;
      goto rollback;
    }
    cell.col_version = sqlite3_column_int64(st, 4);
    cell.db_version = sqlite3_column_int64(st, 5);
    cell.site = sqlite3_column_blob(st, 6);
    cell.site_len = (size_t)sqlite3_column_bytes(st, 6);
    cell.cl = sqlite3_column_int64(st, 7);
    cell.seq = sqlite3_column_int64(st, 8);
    /* Exact encoded length against max_batch_bytes. */
    size_t need = 128 + cell.table_len + cell.pk_len + cell.cid_len +
                  cell.val_blob_len + cell.site_len;
    uint8_t *fields = NULL;
    size_t fields_len = 0;
    for (;;) {
      uint8_t *grown_fields = (uint8_t *)realloc(fields, need);
      if (!grown_fields) {
        free(fields);
        status = sqlite_fail(&fail_rc, SQLITE_NOMEM);
        goto rollback;
      }
      fields = grown_fields;
      fields_len = murmur_cell_encode(&cell, fields, need);
      if (fields_len > 0) {
        break;
      }
      if (need > (size_t)-1 / 2) {
        free(fields);
        status = sqlite_fail(&fail_rc, SQLITE_NOMEM);
        goto rollback;
      }
      need *= 2;
    }
    if ((int64_t)blob_len + (int64_t)fields_len > max_batch_bytes) {
      free(fields);
      status = MURMUR_SYNC_OVERLOADED;
      goto rollback;
    }
    if (blob_len + fields_len > blob_cap) {
      size_t ncap = blob_cap ? blob_cap : 256;
      while (ncap < blob_len + fields_len) {
        ncap *= 2;
      }
      uint8_t *grown = (uint8_t *)realloc(blob, ncap);
      if (!grown) {
        free(fields);
        status = sqlite_fail(&fail_rc, SQLITE_NOMEM);
        goto rollback;
      }
      blob = grown;
      blob_cap = ncap;
    }
    memcpy(blob + blob_len, fields, fields_len);
    blob_len += fields_len;
    free(fields);
    count++;
    murmur_key_t cp;
    uint8_t *arena = NULL;
    if (key_copy(&key, &cp, &arena) != 0) {
      status = sqlite_fail(&fail_rc, SQLITE_NOMEM);
      goto rollback;
    }
    free(last_arena);
    last = cp;
    last_arena = arena;
    have_last = 1;
    if (count >= MAX_CELLS_PER_BATCH) {
      done = 0;
      break;
    }
  }
  sqlite3_finalize(st);
  st = NULL;
  blob[8] = (uint8_t)count;
  blob[9] = (uint8_t)(count >> 8);
  blob[10] = (uint8_t)(count >> 16);
  blob[11] = (uint8_t)(count >> 24);
  rc = sqlite3_exec(db, "COMMIT", NULL, NULL, NULL);
  if (rc != SQLITE_OK) {
    status = sqlite_fail(&fail_rc, rc);
    goto rollback;
  }
  committed = 1;
  out->blob = blob;
  out->blob_len = blob_len;
  blob = NULL;
  if (done) {
    memset(&out->next, 0, sizeof(out->next));
    out->next.cursor.from = resolved;
  } else {
    if (!have_last) {
      status = MURMUR_SYNC_PROTOCOL;
      goto rollback;
    }
    memset(&out->next, 0, sizeof(out->next));
    out->next.cursor.from = cursor->from;
    out->next.cursor.has_through = 1;
    out->next.cursor.through = resolved;
    out->next.cursor.has_after = 1;
    out->next.cursor.after = last;
    out->next.owned = last_arena;
    last_arena = NULL;
  }
  murmur_cfg_table_flags_free(&flags);
  murmur_db_writer_unlock();
  set_sqlrc(sqlrc, fail_rc);
  return MURMUR_SYNC_OK;

rollback:
  if (st) {
    sqlite3_finalize(st);
  }
  if (!committed) {
    sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
  }
  murmur_db_writer_unlock();
  murmur_cfg_table_flags_free(&flags);
  free(blob);
  free(last_arena);
  set_sqlrc(sqlrc, fail_rc);
  return status;
}

/* ---- apply ---- */

murmur_sync_status_t murmur_sync_apply(
    sqlite3 *db, const murmur_node_t *node, const murmur_node_t *site,
    const murmur_cursor_t *previous, const murmur_cursor_t *next,
    uint64_t length, const uint8_t digest[32], int *sqlrc) {
  if (!db || !node || !site || !previous || !next || !digest) {
    return sqlite_fail(sqlrc, SQLITE_MISUSE);
  }
  murmur_node_t stored_site;
  memset(&stored_site, 0, sizeof(stored_site));
  int has_site = 0;
  murmur_stored_cursor_t stored;
  memset(&stored, 0, sizeof(stored));
  int fail_rc = SQLITE_OK;
  murmur_sync_status_t status =
      murmur_sync_progress(db, node, &stored_site, &has_site, &stored,
                           &fail_rc);
  if (status != MURMUR_SYNC_OK) {
    return status;
  }
  if (!has_site || memcmp(stored_site.b, site->b, 16) != 0 ||
      !cursor_equal(&stored.cursor, previous)) {
    APPLY_DBG("cursor-mismatch has_site=%d site_eq=%d prev_from=%lld "
              "stored_from=%lld",
              has_site, memcmp(stored_site.b, site->b, 16) == 0,
              (long long)previous->from, (long long)stored.cursor.from);
    murmur_sync_cursor_free(&stored);
    set_sqlrc(sqlrc, SQLITE_OK);
    return MURMUR_SYNC_PROTOCOL;
  }
  murmur_sync_cursor_free(&stored);

  sqlite3_stmt *st = NULL;
  int rc = sqlite3_prepare_v2(
      db, "SELECT idx,data FROM murmur_stage WHERE node=?1 ORDER BY idx",
      -1, &st, NULL);
  if (rc != SQLITE_OK) {
    return sqlite_fail(sqlrc, rc);
  }
  sqlite3_bind_blob(st, 1, node->b, 16, SQLITE_TRANSIENT);
  uint8_t *blob = NULL;
  size_t blob_len = 0, blob_cap = 0;
  int64_t index = 0;
  for (;;) {
    rc = sqlite3_step(st);
    if (rc == SQLITE_DONE) {
      break;
    }
    if (rc != SQLITE_ROW) {
      sqlite3_finalize(st);
      free(blob);
      return sqlite_fail(sqlrc, rc);
    }
    int64_t idx = sqlite3_column_int64(st, 0);
    if (idx < 0 || idx != index) {
      APPLY_DBG("stage-index idx=%lld want=%u", (long long)idx, index);
      sqlite3_finalize(st);
      free(blob);
      set_sqlrc(sqlrc, SQLITE_OK);
      return MURMUR_SYNC_PROTOCOL;
    }
    const uint8_t *data = sqlite3_column_blob(st, 1);
    size_t data_len = (size_t)sqlite3_column_bytes(st, 1);
    if (data_len > length || blob_len > length - data_len) {
      APPLY_DBG("stage-overflow data=%zu blob=%zu len=%llu", data_len,
                blob_len, (unsigned long long)length);
      sqlite3_finalize(st);
      free(blob);
      set_sqlrc(sqlrc, SQLITE_OK);
      return MURMUR_SYNC_PROTOCOL;
    }
    if (blob_len + data_len > blob_cap) {
      size_t ncap = blob_cap ? blob_cap : 4096;
      while (ncap < blob_len + data_len) {
        ncap *= 2;
      }
      uint8_t *grown = (uint8_t *)realloc(blob, ncap);
      if (!grown) {
        sqlite3_finalize(st);
        free(blob);
        return sqlite_fail(sqlrc, SQLITE_NOMEM);
      }
      blob = grown;
      blob_cap = ncap;
    }
    memcpy(blob + blob_len, data, data_len);
    blob_len += data_len;
    index++;
  }
  sqlite3_finalize(st);
  st = NULL;
  if ((uint64_t)blob_len != length) {
    APPLY_DBG("length blob=%zu len=%llu", blob_len,
              (unsigned long long)length);
    free(blob);
    set_sqlrc(sqlrc, SQLITE_OK);
    return MURMUR_SYNC_PROTOCOL;
  }
  uint8_t sum[32];
  murmur_sha256(blob, blob_len, sum);
  if (memcmp(sum, digest, 32) != 0) {
    APPLY_DBG("digest blob=%zu", blob_len);
    free(blob);
    set_sqlrc(sqlrc, SQLITE_OK);
    return MURMUR_SYNC_PROTOCOL;
  }

  murmur_table_flags_t flags;
  memset(&flags, 0, sizeof(flags));
  status = murmur_cfg_table_flags(db, &flags, &fail_rc);
  if (status != MURMUR_SYNC_OK) {
    free(blob);
    return status;
  }
  const uint8_t *ingest = blob;
  size_t ingest_len = blob_len;
  uint8_t *filtered = NULL;
  if (murmur_cfg_table_filtering(&flags)) {
    murmur_cell_t *cells = NULL;
    size_t n = 0;
    /* Size the array from the header count (validated by decode). */
    uint32_t count = 0;
    if (blob_len >= 12 && memcmp(blob, "CRSB", 4) == 0) {
      count = (uint32_t)blob[8] | ((uint32_t)blob[9] << 8) |
              ((uint32_t)blob[10] << 16) | ((uint32_t)blob[11] << 24);
    }
    if (blob_len < 12 || (uint64_t)count > (uint64_t)(blob_len - 12) + 1) {
      APPLY_DBG("cell-count blob=%zu count=%u", blob_len, count);
      murmur_cfg_table_flags_free(&flags);
      free(blob);
      set_sqlrc(sqlrc, SQLITE_OK);
      return MURMUR_SYNC_PROTOCOL;
    }
    if (count > 0) {
      cells = (murmur_cell_t *)malloc(count * sizeof(*cells));
      if (!cells) {
        murmur_cfg_table_flags_free(&flags);
        free(blob);
        return sqlite_fail(sqlrc, SQLITE_NOMEM);
      }
    }
    if (murmur_cells_decode(blob, blob_len, cells, count, &n) !=
        MURMUR_OK) {
      APPLY_DBG("cell-decode blob=%zu count=%u", blob_len, count);
      free(cells);
      murmur_cfg_table_flags_free(&flags);
      free(blob);
      set_sqlrc(sqlrc, SQLITE_OK);
      return MURMUR_SYNC_PROTOCOL;
    }
    size_t kept = 0;
    for (size_t i = 0; i < n; i++) {
      if (murmur_cfg_table_disabled(&flags, cells[i].table, cells[i].table_len)) {
        continue;
      }
      if (kept != i) {
        cells[kept] = cells[i];
      }
      kept++;
    }
    if (kept > 0) {
      /* A kept subset re-encodes within the original length. */
      filtered = (uint8_t *)malloc(blob_len ? blob_len : 1);
      if (!filtered) {
        free(cells);
        murmur_cfg_table_flags_free(&flags);
        free(blob);
        return sqlite_fail(sqlrc, SQLITE_NOMEM);
      }
      size_t nenc = murmur_cells_encode(cells, kept, filtered, blob_len);
      free(cells);
      if (nenc == 0) {
        APPLY_DBG("cell-encode kept=%zu", kept);
        murmur_cfg_table_flags_free(&flags);
        free(filtered);
        free(blob);
        set_sqlrc(sqlrc, SQLITE_OK);
        return MURMUR_SYNC_PROTOCOL;
      }
      ingest = filtered;
      ingest_len = nenc;
    } else {
      free(cells);
      ingest = NULL;
      ingest_len = 0;
    }
  }

  murmur_db_writer_lock();
  rc = sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, NULL);
  if (rc != SQLITE_OK) {
    status = sqlite_fail(&fail_rc, rc);
    goto apply_fail;
  }
  if (ingest_len > 0) {
    status = murmur_sync_ingest_blob(db, ingest, ingest_len, &fail_rc);
    if (status != MURMUR_SYNC_OK) {
      goto apply_rollback;
    }
  }
  /* Advance progress. The cursor encodes small; grow if short. */
  uint8_t *cur_enc = NULL;
  size_t cur_len = 0;
  {
    size_t cap = 256;
    for (;;) {
      uint8_t *grown = (uint8_t *)realloc(cur_enc, cap);
      if (!grown) {
        free(cur_enc);
        status = sqlite_fail(&fail_rc, SQLITE_NOMEM);
        goto apply_rollback;
      }
      cur_enc = grown;
      cur_len = murmur_cursor_encode(next, cur_enc, cap);
      if (cur_len > 0) {
        break;
      }
      if (cap > (size_t)-1 / 2) {
        free(cur_enc);
        status = sqlite_fail(&fail_rc, SQLITE_NOMEM);
        goto apply_rollback;
      }
      cap *= 2;
    }
  }
  rc = sqlite3_prepare_v2(
      db,
      "UPDATE murmur_progress SET site=?1,cursor=?2,sent=NULL WHERE node=?3",
      -1, &st, NULL);
  if (rc != SQLITE_OK) {
    free(cur_enc);
    status = sqlite_fail(&fail_rc, rc);
    goto apply_rollback;
  }
  sqlite3_bind_blob(st, 1, site->b, 16, SQLITE_TRANSIENT);
  sqlite3_bind_blob(st, 2, cur_enc, (int)cur_len, SQLITE_TRANSIENT);
  sqlite3_bind_blob(st, 3, node->b, 16, SQLITE_TRANSIENT);
  free(cur_enc);
  rc = sqlite3_step(st);
  sqlite3_finalize(st);
  st = NULL;
  if (rc != SQLITE_DONE) {
    status = sqlite_fail(&fail_rc, rc);
    goto apply_rollback;
  }
  rc = sqlite3_prepare_v2(db, "DELETE FROM murmur_stage WHERE node=?1", -1,
                          &st, NULL);
  if (rc != SQLITE_OK) {
    status = sqlite_fail(&fail_rc, rc);
    goto apply_rollback;
  }
  sqlite3_bind_blob(st, 1, node->b, 16, SQLITE_TRANSIENT);
  rc = sqlite3_step(st);
  sqlite3_finalize(st);
  st = NULL;
  if (rc != SQLITE_DONE) {
    status = sqlite_fail(&fail_rc, rc);
    goto apply_rollback;
  }
  /* Heads: applied next.From, observed max(next.From, previous.From). */
  char pkey[64], okey[64];
  size_t pkey_len = murmur_progress_key(node, pkey, sizeof(pkey));
  size_t okey_len = murmur_observed_key(node, okey, sizeof(okey));
  uint8_t applied[16], observed[16];
  size_t applied_len = murmur_u64_encode((uint64_t)next->from, applied,
                                        sizeof(applied));
  int64_t omax = next->from > previous->from ? next->from : previous->from;
  size_t observed_len =
      murmur_u64_encode((uint64_t)omax, observed, sizeof(observed));
  if (pkey_len == 0 || okey_len == 0 || applied_len == 0 ||
      observed_len == 0) {
    status = MURMUR_SYNC_INVALID;
    goto apply_rollback;
  }
  status = kv_put(db, (const uint8_t *)pkey, pkey_len, applied, applied_len,
                  &fail_rc);
  if (status != MURMUR_SYNC_OK) {
    goto apply_rollback;
  }
  status = kv_put(db, (const uint8_t *)okey, okey_len, observed,
                  observed_len, &fail_rc);
  if (status != MURMUR_SYNC_OK) {
    goto apply_rollback;
  }
  rc = sqlite3_exec(db, "COMMIT", NULL, NULL, NULL);
  if (rc != SQLITE_OK) {
    status = sqlite_fail(&fail_rc, rc);
    goto apply_rollback;
  }
  murmur_cfg_table_flags_free(&flags);
  free(filtered);
  free(blob);
  murmur_db_writer_unlock();
  set_sqlrc(sqlrc, fail_rc);
  return MURMUR_SYNC_OK;

apply_rollback:
  if (st) {
    sqlite3_finalize(st);
  }
  sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
apply_fail:
  murmur_cfg_table_flags_free(&flags);
  free(filtered);
  free(blob);
  murmur_db_writer_unlock();
  set_sqlrc(sqlrc, fail_rc);
  return status;
}
