/* murmur kv - see kv.h. */
#include "kv.h"

#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "config.h"
#include "schema.h"
#include "sqlite3.h"

static pthread_mutex_t writer_mu;
static pthread_once_t writer_once = PTHREAD_ONCE_INIT;

static void writer_init(void) {
  pthread_mutexattr_t at;
  pthread_mutexattr_init(&at);
  pthread_mutexattr_settype(&at, PTHREAD_MUTEX_RECURSIVE);
  pthread_mutex_init(&writer_mu, &at);
  pthread_mutexattr_destroy(&at);
}

void murmur_db_writer_lock(void) {
  pthread_once(&writer_once, writer_init);
  pthread_mutex_lock(&writer_mu);
}

void murmur_db_writer_unlock(void) {
  pthread_mutex_unlock(&writer_mu);
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

static murmur_sync_status_t invalid_fail(int *sqlrc) {
  set_sqlrc(sqlrc, SQLITE_MISUSE);
  return MURMUR_SYNC_INVALID;
}

void murmur_kv_keys_free(uint8_t **keys, size_t *key_lens, size_t n) {
  if (keys) {
    for (size_t i = 0; i < n; i++) {
      free(keys[i]);
    }
    free(keys);
  }
  free(key_lens);
}

void murmur_kv_record_free(murmur_kv_record_t *r) {
  if (!r) {
    return;
  }
  free(r->key);
  free(r->value);
  memset(r, 0, sizeof(*r));
}

murmur_sync_status_t murmur_kv_get(sqlite3 *db, const uint8_t *key,
                                   size_t key_len, uint8_t **val,
                                   size_t *val_len, int *found, int *sqlrc) {
  if (val) {
    *val = NULL;
  }
  if (val_len) {
    *val_len = 0;
  }
  if (found) {
    *found = 0;
  }
  sqlite3_stmt *st = NULL;
  int rc = sqlite3_prepare_v2(db, "SELECT value FROM murmur_kv WHERE key=?1",
                              -1, &st, NULL);
  if (rc != SQLITE_OK) {
    return sqlite_fail(sqlrc, rc);
  }
  rc = sqlite3_bind_blob(st, 1, key_len ? key : (const uint8_t *)"", (int)key_len,
                         SQLITE_TRANSIENT);
  if (rc != SQLITE_OK) {
    sqlite3_finalize(st);
    return sqlite_fail(sqlrc, rc);
  }
  rc = sqlite3_step(st);
  if (rc != SQLITE_ROW && rc != SQLITE_DONE) {
    sqlite3_finalize(st);
    return sqlite_fail(sqlrc, rc);
  }
  if (rc == SQLITE_ROW) {
    const uint8_t *v = sqlite3_column_blob(st, 0);
    int n = sqlite3_column_bytes(st, 0);
    uint8_t *cp = (uint8_t *)malloc(n ? (size_t)n : 1);
    if (!cp) {
      sqlite3_finalize(st);
      return sqlite_fail(sqlrc, SQLITE_NOMEM);
    }
    if (n > 0) {
      memcpy(cp, v, (size_t)n);
    }
    if (val) {
      *val = cp;
    } else {
      free(cp);
    }
    if (val_len) {
      *val_len = (size_t)n;
    }
    if (found) {
      *found = 1;
    }
  }
  sqlite3_finalize(st);
  return ok_rc(sqlrc);
}

murmur_sync_status_t murmur_kv_put(sqlite3 *db, const uint8_t *key,
                                   size_t key_len, const uint8_t *val,
                                   size_t val_len, int *sqlrc) {
  murmur_kv_record_t r;
  memset(&r, 0, sizeof(r));
  /* apply borrows; put copies through the binding */
  r.key = (uint8_t *)key;
  r.key_len = key_len;
  r.value = (uint8_t *)val;
  r.value_len = val_len;
  r.is_delete = 0;
  return murmur_kv_apply(db, &r, 1, sqlrc);
}

murmur_sync_status_t murmur_kv_get_many(sqlite3 *db, const uint8_t **keys,
                                        const size_t *key_lens, size_t n,
                                        uint8_t ***vals, size_t **val_lens,
                                        int **present, int *sqlrc) {
  *vals = NULL;
  *val_lens = NULL;
  *present = NULL;
  uint8_t **v = (uint8_t **)calloc(n ? n : 1, sizeof(*v));
  size_t *vl = (size_t *)calloc(n ? n : 1, sizeof(*vl));
  int *pr = (int *)calloc(n ? n : 1, sizeof(*pr));
  if (!v || !vl || !pr) {
    free(v);
    free(vl);
    free(pr);
    return sqlite_fail(sqlrc, SQLITE_NOMEM);
  }
  sqlite3_stmt *st = NULL;
  int rc = sqlite3_prepare_v2(db, "SELECT value FROM murmur_kv WHERE key=?1",
                              -1, &st, NULL);
  if (rc != SQLITE_OK) {
    free(v);
    free(vl);
    free(pr);
    return sqlite_fail(sqlrc, rc);
  }
  murmur_sync_status_t status = MURMUR_SYNC_OK;
  for (size_t i = 0; i < n; i++) {
    rc = sqlite3_bind_blob(st, 1, key_lens[i] ? keys[i] : (const uint8_t *)"",
                           (int)key_lens[i], SQLITE_TRANSIENT);
    if (rc != SQLITE_OK) {
      status = MURMUR_SYNC_SQLITE;
      set_sqlrc(sqlrc, rc);
      break;
    }
    rc = sqlite3_step(st);
    if (rc != SQLITE_ROW && rc != SQLITE_DONE) {
      status = MURMUR_SYNC_SQLITE;
      set_sqlrc(sqlrc, rc);
      break;
    }
    if (rc == SQLITE_ROW) {
      const uint8_t *val = sqlite3_column_blob(st, 0);
      int vn = sqlite3_column_bytes(st, 0);
      v[i] = (uint8_t *)malloc(vn ? (size_t)vn : 1);
      if (!v[i]) {
        status = MURMUR_SYNC_SQLITE;
        set_sqlrc(sqlrc, SQLITE_NOMEM);
        break;
      }
      if (vn > 0) {
        memcpy(v[i], val, (size_t)vn);
      }
      vl[i] = (size_t)vn;
      pr[i] = 1;
    }
    rc = sqlite3_reset(st);
    if (rc != SQLITE_OK) {
      status = MURMUR_SYNC_SQLITE;
      set_sqlrc(sqlrc, rc);
      break;
    }
  }
  sqlite3_finalize(st);
  if (status != MURMUR_SYNC_OK) {
    murmur_kv_get_many_free(v, vl, pr, n);
    return status;
  }
  *vals = v;
  *val_lens = vl;
  *present = pr;
  return ok_rc(sqlrc);
}

void murmur_kv_get_many_free(uint8_t **vals, size_t *val_lens, int *present,
                             size_t n) {
  if (vals) {
    for (size_t i = 0; i < n; i++) {
      free(vals[i]);
    }
    free(vals);
  }
  free(val_lens);
  free(present);
}

murmur_sync_status_t murmur_kv_get_many_bounded(
    sqlite3 *db, const uint8_t **keys, const size_t *key_lens, size_t n,
    int64_t max_bytes, uint8_t ***vals, size_t **val_lens, int **present,
    size_t *kept, int *sqlrc) {
  *vals = NULL;
  *val_lens = NULL;
  *present = NULL;
  *kept = 0;
  uint8_t **v = NULL;
  size_t *vl = NULL;
  int *pr = NULL;
  murmur_sync_status_t st =
      murmur_kv_get_many(db, keys, key_lens, n, &v, &vl, &pr, sqlrc);
  if (st != MURMUR_SYNC_OK) {
    return st;
  }
  size_t k = 0;
  int64_t used = 0;
  for (size_t i = 0; i < n; i++) {
    /* missing values are NULL with length 0: consume no bytes */
    int64_t size = v[i] ? (int64_t)vl[i] : 0;
    if (k > 0 && used + size > max_bytes) {
      break;
    }
    used += size;
    if (k != i) {
      v[k] = v[i];
      vl[k] = vl[i];
      pr[k] = pr[i];
    }
    k++;
    if (used >= max_bytes) {
      break;
    }
  }
  for (size_t i = k; i < n; i++) {
    free(v[i]);
  }
  *vals = v;
  *val_lens = vl;
  *present = pr;
  *kept = k;
  return ok_rc(sqlrc);
}

int murmur_kv_prefix_end(const uint8_t *prefix, size_t prefix_len,
                         uint8_t **out, size_t *out_len, int *unbounded) {
  *out = NULL;
  *out_len = 0;
  *unbounded = 0;
  size_t n = prefix_len;
  while (n > 0 && prefix[n - 1] == 0xFF) {
    n--;
  }
  if (n == 0) {
    *unbounded = 1;
    return 0;
  }
  uint8_t *e = (uint8_t *)malloc(n);
  if (!e) {
    return -1;
  }
  memcpy(e, prefix, n);
  e[n - 1]++;
  *out = e;
  *out_len = n;
  return 0;
}

/* Shared scan driver: binds blob args in order, collects key order. */
static murmur_sync_status_t kv_scan(sqlite3 *db, const char *query,
                                    const uint8_t **blobs, const size_t *lens,
                                    size_t nblobs, int has_limit, int64_t limit,
                                    uint8_t ***keys, size_t **key_lens,
                                    size_t *n, int *sqlrc) {
  *keys = NULL;
  *key_lens = NULL;
  *n = 0;
  sqlite3_stmt *st = NULL;
  int rc = sqlite3_prepare_v2(db, query, -1, &st, NULL);
  if (rc != SQLITE_OK) {
    return sqlite_fail(sqlrc, rc);
  }
  int arg = 1;
  for (size_t i = 0; i < nblobs; i++) {
    rc = sqlite3_bind_blob(st, arg++, lens[i] ? blobs[i] : (const uint8_t *)"",
                           (int)lens[i], SQLITE_TRANSIENT);
    if (rc != SQLITE_OK) {
      sqlite3_finalize(st);
      return sqlite_fail(sqlrc, rc);
    }
  }
  if (has_limit) {
    rc = sqlite3_bind_int64(st, arg++, limit);
    if (rc != SQLITE_OK) {
      sqlite3_finalize(st);
      return sqlite_fail(sqlrc, rc);
    }
  }
  uint8_t **v = NULL;
  size_t *vl = NULL;
  size_t count = 0, cap = 0;
  murmur_sync_status_t status = MURMUR_SYNC_OK;
  for (;;) {
    rc = sqlite3_step(st);
    if (rc == SQLITE_DONE) {
      break;
    }
    if (rc != SQLITE_ROW) {
      status = MURMUR_SYNC_SQLITE;
      set_sqlrc(sqlrc, rc);
      break;
    }
    const uint8_t *k = sqlite3_column_blob(st, 0);
    int kn = sqlite3_column_bytes(st, 0);
    if (count >= cap) {
      size_t ncap = cap ? cap * 2 : 16;
      uint8_t **nv = (uint8_t **)realloc(v, ncap * sizeof(*nv));
      size_t *nl = NULL;
      if (nv) {
        nl = (size_t *)realloc(vl, ncap * sizeof(*nl));
      }
      if (!nv || !nl) {
        /* realloc failure leaves the other half valid; free the
         * collected keys through whichever halves survived */
        murmur_kv_keys_free(nv ? nv : v, vl, count);
        sqlite3_finalize(st);
        return sqlite_fail(sqlrc, SQLITE_NOMEM);
      }
      v = nv;
      vl = nl;
      cap = ncap;
    }
    v[count] = (uint8_t *)malloc(kn ? (size_t)kn : 1);
    if (!v[count]) {
      status = MURMUR_SYNC_SQLITE;
      set_sqlrc(sqlrc, SQLITE_NOMEM);
      break;
    }
    if (kn > 0) {
      memcpy(v[count], k, (size_t)kn);
    }
    vl[count] = (size_t)kn;
    count++;
  }
  sqlite3_finalize(st);
  if (status != MURMUR_SYNC_OK) {
    murmur_kv_keys_free(v, vl, count);
    return status;
  }
  *keys = v;
  *key_lens = vl;
  *n = count;
  return ok_rc(sqlrc);
}

murmur_sync_status_t murmur_kv_keys(sqlite3 *db, const uint8_t *prefix,
                                    size_t prefix_len, uint8_t ***keys,
                                    size_t **key_lens, size_t *n, int *sqlrc) {
  uint8_t *end = NULL;
  size_t end_len = 0;
  int unbounded = 0;
  if (murmur_kv_prefix_end(prefix, prefix_len, &end, &end_len, &unbounded) !=
      0) {
    return sqlite_fail(sqlrc, SQLITE_NOMEM);
  }
  murmur_sync_status_t st;
  if (unbounded) {
    const uint8_t *blobs[1] = {prefix};
    const size_t lens[1] = {prefix_len};
    st = kv_scan(db, "SELECT key FROM murmur_kv WHERE key>=?1 ORDER BY key",
                 blobs, lens, 1, 0, 0, keys, key_lens, n, sqlrc);
  } else {
    const uint8_t *blobs[2] = {prefix, end};
    const size_t lens[2] = {prefix_len, end_len};
    st = kv_scan(db,
                 "SELECT key FROM murmur_kv WHERE key>=?1 AND key<?2 ORDER BY "
                 "key",
                 blobs, lens, 2, 0, 0, keys, key_lens, n, sqlrc);
  }
  free(end);
  return st;
}

murmur_sync_status_t murmur_kv_keys_page(sqlite3 *db, const uint8_t *prefix,
                                         size_t prefix_len, const uint8_t *after,
                                         size_t after_len, int has_after,
                                         int64_t limit, uint8_t ***keys,
                                         size_t **key_lens, size_t *n,
                                         int *sqlrc) {
  uint8_t *end = NULL;
  size_t end_len = 0;
  int unbounded = 0;
  if (murmur_kv_prefix_end(prefix, prefix_len, &end, &end_len, &unbounded) !=
      0) {
    return sqlite_fail(sqlrc, SQLITE_NOMEM);
  }
  murmur_sync_status_t st;
  if (!unbounded && has_after) {
    const uint8_t *blobs[3] = {prefix, end, after};
    const size_t lens[3] = {prefix_len, end_len, after_len};
    st = kv_scan(db,
                 "SELECT key FROM murmur_kv WHERE key>=?1 AND key<?2 AND "
                 "key>?3 ORDER BY key LIMIT ?4",
                 blobs, lens, 3, 1, limit, keys, key_lens, n, sqlrc);
  } else if (!unbounded) {
    const uint8_t *blobs[2] = {prefix, end};
    const size_t lens[2] = {prefix_len, end_len};
    st = kv_scan(db,
                 "SELECT key FROM murmur_kv WHERE key>=?1 AND key<?2 ORDER BY "
                 "key LIMIT ?3",
                 blobs, lens, 2, 1, limit, keys, key_lens, n, sqlrc);
  } else if (has_after) {
    const uint8_t *blobs[2] = {prefix, after};
    const size_t lens[2] = {prefix_len, after_len};
    st = kv_scan(db,
                 "SELECT key FROM murmur_kv WHERE key>=?1 AND key>?2 ORDER BY "
                 "key LIMIT ?3",
                 blobs, lens, 2, 1, limit, keys, key_lens, n, sqlrc);
  } else {
    const uint8_t *blobs[1] = {prefix};
    const size_t lens[1] = {prefix_len};
    st = kv_scan(db,
                 "SELECT key FROM murmur_kv WHERE key>=?1 ORDER BY key LIMIT "
                 "?2",
                 blobs, lens, 1, 1, limit, keys, key_lens, n, sqlrc);
  }
  free(end);
  return st;
}

murmur_sync_status_t murmur_kv_apply(sqlite3 *db,
                                     const murmur_kv_record_t *records,
                                     size_t n, int *sqlrc) {
  sqlite3_stmt *put = NULL, *del = NULL;
  int rc = sqlite3_prepare_v2(
      db,
      "INSERT INTO murmur_kv(key,value) VALUES(?1,?2) ON CONFLICT(key) DO "
      "UPDATE SET value=excluded.value",
      -1, &put, NULL);
  if (rc != SQLITE_OK) {
    return sqlite_fail(sqlrc, rc);
  }
  rc = sqlite3_prepare_v2(db, "DELETE FROM murmur_kv WHERE key=?1", -1, &del,
                          NULL);
  if (rc != SQLITE_OK) {
    sqlite3_finalize(put);
    return sqlite_fail(sqlrc, rc);
  }
  murmur_sync_status_t status = MURMUR_SYNC_OK;
  for (size_t i = 0; i < n; i++) {
    const murmur_kv_record_t *r = &records[i];
    sqlite3_stmt *st = r->is_delete ? del : put;
    rc = sqlite3_bind_blob(st, 1, r->key_len ? r->key : (const uint8_t *)"",
                           (int)r->key_len, SQLITE_TRANSIENT);
    if (rc == SQLITE_OK && !r->is_delete) {
      rc = sqlite3_bind_blob(st, 2,
                             r->value_len ? r->value : (const uint8_t *)"",
                             (int)r->value_len, SQLITE_TRANSIENT);
    }
    if (rc == SQLITE_OK) {
      rc = sqlite3_step(st);
      if (rc != SQLITE_DONE && rc != SQLITE_ROW) {
        /* keep rc */
      } else {
        rc = SQLITE_OK;
      }
    }
    if (rc == SQLITE_OK) {
      rc = sqlite3_reset(st);
    }
    if (rc != SQLITE_OK) {
      status = MURMUR_SYNC_SQLITE;
      set_sqlrc(sqlrc, rc);
      break;
    }
  }
  sqlite3_finalize(put);
  sqlite3_finalize(del);
  if (status != MURMUR_SYNC_OK) {
    return status;
  }
  return ok_rc(sqlrc);
}

static murmur_sync_status_t exec_sql(sqlite3 *db, const char *sql, int *sqlrc) {
  char *errmsg = NULL;
  int rc = sqlite3_exec(db, sql, NULL, NULL, &errmsg);
  if (errmsg) {
    sqlite3_free(errmsg);
  }
  if (rc != SQLITE_OK) {
    return sqlite_fail(sqlrc, rc);
  }
  return ok_rc(sqlrc);
}

murmur_sync_status_t murmur_kv_commit(sqlite3 *db,
                                      const murmur_kv_record_t *records,
                                      size_t n, int *sqlrc) {
  murmur_db_writer_lock();
  murmur_sync_status_t st = exec_sql(db, "BEGIN", sqlrc);
  if (st != MURMUR_SYNC_OK) {
    murmur_db_writer_unlock();
    return st;
  }
  st = murmur_kv_apply(db, records, n, sqlrc);
  if (st != MURMUR_SYNC_OK) {
    int dummy = 0;
    exec_sql(db, "ROLLBACK", &dummy);
    murmur_db_writer_unlock();
    return st;
  }
  st = exec_sql(db, "COMMIT", sqlrc);
  murmur_db_writer_unlock();
  if (st != MURMUR_SYNC_OK) {
    return st;
  }
  return ok_rc(sqlrc);
}

murmur_sync_status_t murmur_clock_observe(sqlite3 *db, uint64_t millis,
                                          uint32_t logical, uint64_t *clock,
                                          uint32_t *clock_logical, int *sqlrc) {
  static const uint8_t clock_key[] = "07/replication/clock/hlc";
  uint8_t *raw = NULL;
  size_t raw_len = 0;
  int found = 0;
  murmur_sync_status_t st = murmur_kv_get(db, clock_key, sizeof(clock_key) - 1,
                                          &raw, &raw_len, &found, sqlrc);
  if (st != MURMUR_SYNC_OK) {
    return st;
  }
  uint64_t ck = 0;
  uint32_t ck_logical = 0;
  if (found) {
    size_t pos = 0;
    uint64_t l = 0;
    if (murmur_tx_uvarint_decode(raw, raw_len, &pos, &ck) != 0 ||
        murmur_tx_uvarint_decode(raw, raw_len, &pos, &l) != 0 ||
        pos != raw_len) {
      free(raw);
      set_sqlrc(sqlrc, SQLITE_OK);
      return MURMUR_SYNC_PROTOCOL;
    }
    ck_logical = (uint32_t)l;
  }
  free(raw);
  if (millis > ck || (millis == ck && logical > ck_logical)) {
    ck = millis;
    ck_logical = logical;
  }
  uint8_t out[20];
  size_t w = murmur_tx_uvarint_encode(ck, out, sizeof(out));
  size_t w2 = 0;
  if (w > 0) {
    w2 = murmur_tx_uvarint_encode((uint64_t)ck_logical, out + w,
                                  sizeof(out) - w);
  }
  if (w == 0 || w2 == 0) {
    return sqlite_fail(sqlrc, SQLITE_NOMEM);
  }
  st = murmur_kv_put(db, clock_key, sizeof(clock_key) - 1, out, w + w2, sqlrc);
  if (st != MURMUR_SYNC_OK) {
    return st;
  }
  if (clock) {
    *clock = ck;
  }
  if (clock_logical) {
    *clock_logical = ck_logical;
  }
  return ok_rc(sqlrc);
}

/* Parses the trailing identity of a head key (PROTOCOL on any failure). */
static murmur_sync_status_t origin_suffix(const uint8_t *k, size_t klen,
                                          murmur_node_t *id, int *sqlrc) {
  size_t slash = klen;
  for (size_t i = klen; i > 0; i--) {
    if (k[i - 1] == '/') {
      slash = i;
      break;
    }
  }
  if (slash >= klen) {
    set_sqlrc(sqlrc, SQLITE_OK);
    return MURMUR_SYNC_PROTOCOL;
  }
  if (murmur_cfg_parse_id(k + slash, klen - slash, id) != 0) {
    set_sqlrc(sqlrc, SQLITE_OK);
    return MURMUR_SYNC_PROTOCOL;
  }
  return ok_rc(sqlrc);
}

void murmur_tx_progress_free(murmur_tx_progress_t *ps, size_t n) {
  (void)n;
  free(ps);
}

murmur_sync_status_t murmur_tx_progress(sqlite3 *db, murmur_tx_progress_t **ps,
                                        size_t *n, int *sqlrc) {
  *ps = NULL;
  *n = 0;
  murmur_tx_progress_t *v = NULL;
  size_t count = 0, cap = 0;
  murmur_sync_status_t st = MURMUR_SYNC_OK;
  /* retained records seed whole watermarks */
  uint8_t **keys = NULL;
  size_t *lens = NULL, nk = 0;
  static const uint8_t retained_pfx[] = "07/replication/retained/";
  static const uint8_t applied_pfx[] = "07/replication/applied/";
  static const uint8_t observed_pfx[] = "07/replication/observed/";
  st = murmur_kv_keys(db, retained_pfx, sizeof(retained_pfx) - 1, &keys, &lens,
                      &nk, sqlrc);
  if (st != MURMUR_SYNC_OK) {
    return st;
  }
  for (size_t i = 0; i < nk && st == MURMUR_SYNC_OK; i++) {
    uint8_t *raw = NULL;
    size_t raw_len = 0;
    int found = 0;
    st = murmur_kv_get(db, keys[i], lens[i], &raw, &raw_len, &found, sqlrc);
    if (st != MURMUR_SYNC_OK) {
      break;
    }
    if (!found) {
      continue;
    }
    murmur_tx_progress_t p;
    st = murmur_tx_progress_decode(raw, raw_len, &p, sqlrc);
    free(raw);
    if (st != MURMUR_SYNC_OK) {
      break;
    }
    /* last duplicate wins (Go map assignment) */
    size_t slot = count;
    for (size_t k = 0; k < count; k++) {
      if (murmur_node_eq(&v[k].origin, &p.origin)) {
        slot = k;
        break;
      }
    }
    if (slot == count) {
      if (count >= cap) {
        size_t ncap = cap ? cap * 2 : 16;
        murmur_tx_progress_t *nv =
            (murmur_tx_progress_t *)realloc(v, ncap * sizeof(*nv));
        if (!nv) {
          st = MURMUR_SYNC_SQLITE;
          set_sqlrc(sqlrc, SQLITE_NOMEM);
          break;
        }
        v = nv;
        cap = ncap;
      }
      count++;
    }
    v[slot] = p;
  }
  murmur_kv_keys_free(keys, lens, nk);
  keys = NULL;
  /* applied/observed heads fill one field each */
  static const uint8_t *pfxs[2] = {applied_pfx, observed_pfx};
  static const size_t pfx_lens[2] = {sizeof(applied_pfx) - 1,
                                     sizeof(observed_pfx) - 1};
  for (int pi = 0; pi < 2 && st == MURMUR_SYNC_OK; pi++) {
    st = murmur_kv_keys(db, pfxs[pi], pfx_lens[pi], &keys, &lens, &nk, sqlrc);
    if (st != MURMUR_SYNC_OK) {
      break;
    }
    for (size_t i = 0; i < nk && st == MURMUR_SYNC_OK; i++) {
      uint8_t *raw = NULL;
      size_t raw_len = 0;
      int found = 0;
      st = murmur_kv_get(db, keys[i], lens[i], &raw, &raw_len, &found, sqlrc);
      if (st != MURMUR_SYNC_OK) {
        break;
      }
      if (!found) {
        continue;
      }
      murmur_node_t origin;
      uint64_t w = 0;
      if (origin_suffix(keys[i], lens[i], &origin, sqlrc) != MURMUR_SYNC_OK) {
        free(raw);
        st = MURMUR_SYNC_PROTOCOL;
        break;
      }
      st = murmur_tx_decode_u64(raw, raw_len, &w, sqlrc);
      free(raw);
      if (st != MURMUR_SYNC_OK) {
        break;
      }
      size_t slot = count;
      for (size_t k = 0; k < count; k++) {
        if (murmur_node_eq(&v[k].origin, &origin)) {
          slot = k;
          break;
        }
      }
      if (slot == count) {
        if (count >= cap) {
          size_t ncap = cap ? cap * 2 : 16;
          murmur_tx_progress_t *nv =
              (murmur_tx_progress_t *)realloc(v, ncap * sizeof(*nv));
          if (!nv) {
            st = MURMUR_SYNC_SQLITE;
            set_sqlrc(sqlrc, SQLITE_NOMEM);
            break;
          }
          v = nv;
          cap = ncap;
        }
        memset(&v[count], 0, sizeof(v[count]));
        v[count].origin = origin;
        count++;
      }
      if (pi == 0) {
        v[slot].applied = w;
      } else {
        v[slot].observed = w;
      }
    }
    murmur_kv_keys_free(keys, lens, nk);
    keys = NULL;
  }
  if (st != MURMUR_SYNC_OK) {
    free(v);
    return st;
  }
  for (size_t i = 0; i < count; i++) {
    if (v[i].applied > v[i].observed) {
      v[i].observed = v[i].applied;
    }
  }
  *ps = v;
  *n = count;
  return ok_rc(sqlrc);
}

murmur_sync_status_t murmur_serve_params(sqlite3 *db, murmur_serve_params_t *p,
                                         char **detail_out, int *sqlrc) {
  if (detail_out) {
    *detail_out = NULL;
  }
  memset(p, 0, sizeof(*p));
  static const char *names[7] = {"sessions",
                                 "queue_bytes",
                                 "batch_bytes",
                                 "max_batch_bytes",
                                 "staging_bytes",
                                 "gossip_fanout",
                                 "staging_timeout_ms"};
  int64_t *slots[7] = {&p->sessions, &p->queue_bytes,         &p->batch_bytes,
                       &p->max_batch_bytes, &p->staging_bytes, &p->gossip_fanout,
                       &p->staging_timeout_ms};
  for (int i = 0; i < 7; i++) {
    char *raw = NULL;
    murmur_sync_status_t st = murmur_cfg_setting(db, names[i], &raw, sqlrc);
    if (st != MURMUR_SYNC_OK) {
      return st;
    }
    uint64_t v = 0;
    int bad = murmur_cfg_atoi(raw, &v) != 0 || v > (uint64_t)INT64_MAX;
    free(raw);
    if (bad) {
      if (detail_out) {
        char msg[64];
        snprintf(msg, sizeof(msg), "invalid %s", names[i]);
        *detail_out = strdup(msg);
      }
      return invalid_fail(sqlrc);
    }
    *slots[i] = (int64_t)v;
  }
  if (p->batch_bytes > p->max_batch_bytes || p->max_batch_bytes > (64 << 20) ||
      p->max_batch_bytes > p->queue_bytes ||
      p->max_batch_bytes > p->staging_bytes) {
    if (detail_out) {
      *detail_out = strdup("require batch_bytes <= max_batch_bytes <= "
                           "min(queue_bytes, staging_bytes, 64 MiB)");
    }
    return invalid_fail(sqlrc);
  }
  return ok_rc(sqlrc);
}

murmur_sync_status_t murmur_backend_progress(sqlite3 *db,
                                             const murmur_node_t *node,
                                             murmur_tx_progress_t **ps,
                                             size_t *n, int *sqlrc) {
  murmur_sync_status_t st = murmur_tx_progress(db, ps, n, sqlrc);
  if (st != MURMUR_SYNC_OK) {
    return st;
  }
  int64_t live = 0;
  int dummy = 0;
  if (murmur_sync_db_version(db, &live, &dummy) == MURMUR_SYNC_OK && live > 0) {
    size_t slot = *n;
    for (size_t i = 0; i < *n; i++) {
      if (murmur_node_eq(&(*ps)[i].origin, node)) {
        slot = i;
        break;
      }
    }
    if (slot == *n) {
      murmur_tx_progress_t *nv = (murmur_tx_progress_t *)realloc(
          *ps, (*n + 1) * sizeof(**ps));
      if (!nv) {
        free(*ps);
        *ps = NULL;
        *n = 0;
        return sqlite_fail(sqlrc, SQLITE_NOMEM);
      }
      *ps = nv;
      memset(&nv[*n], 0, sizeof(nv[*n]));
      nv[*n].origin = *node;
      (*n)++;
    }
    if ((uint64_t)live > (*ps)[slot].applied) {
      (*ps)[slot].applied = (uint64_t)live;
    }
    if ((uint64_t)live > (*ps)[slot].observed) {
      (*ps)[slot].observed = (uint64_t)live;
    }
  }
  return ok_rc(sqlrc);
}

murmur_sync_status_t murmur_backend_apply(sqlite3 *db, const uint8_t **payloads,
                                          const size_t *payload_lens, size_t np,
                                          const murmur_kv_record_t *records,
                                          size_t nr, int *sqlrc) {
  murmur_db_writer_lock();
  murmur_sync_status_t st = exec_sql(db, "BEGIN IMMEDIATE", sqlrc);
  if (st != MURMUR_SYNC_OK) {
    murmur_db_writer_unlock();
    return st;
  }
  for (size_t i = 0; i < np; i++) {
    st = murmur_sync_ingest_blob(db, payloads[i], payload_lens[i], sqlrc);
    if (st != MURMUR_SYNC_OK) {
      int dummy = 0;
      exec_sql(db, "ROLLBACK", &dummy);
      murmur_db_writer_unlock();
      return st;
    }
  }
  st = murmur_kv_apply(db, records, nr, sqlrc);
  if (st != MURMUR_SYNC_OK) {
    int dummy = 0;
    exec_sql(db, "ROLLBACK", &dummy);
    murmur_db_writer_unlock();
    return st;
  }
  st = exec_sql(db, "COMMIT", sqlrc);
  murmur_db_writer_unlock();
  if (st != MURMUR_SYNC_OK) {
    return st;
  }
  return ok_rc(sqlrc);
}

murmur_sync_status_t murmur_backend_schema(sqlite3 *db, uint8_t **blob,
                                           size_t *len, int *sqlrc) {
  return murmur_schema_bytes(db, blob, len, sqlrc);
}

murmur_sync_status_t murmur_backend_accept_schema(sqlite3 *db,
                                                  const uint8_t *schema,
                                                  size_t schema_len,
                                                  int *accepted, int *sqlrc) {
  if (accepted) {
    *accepted = 0;
  }
  murmur_schema_params_t params;
  murmur_sync_status_t st = murmur_schema_params_from(db, &params, sqlrc);
  if (st != MURMUR_SYNC_OK) {
    return st;
  }
  if (!params.accept_remote) {
    return ok_rc(sqlrc);
  }
  uint8_t *local = NULL;
  size_t local_len = 0;
  st = murmur_manifest_schema_bytes(db, &local, &local_len, sqlrc);
  if (st != MURMUR_SYNC_OK) {
    return st;
  }
  murmur_schema_diff_t d;
  memset(&d, 0, sizeof(d));
  st = murmur_schema_diff(local, local_len, schema, schema_len, &d, sqlrc);
  free(local);
  if (st != MURMUR_SYNC_OK) {
    return st;
  }
  if (!d.additive) {
    murmur_schema_diff_free(&d);
    return ok_rc(sqlrc);
  }
  st = murmur_apply_additive(db, d.new_tables, d.n_tables, d.add_columns,
                             d.n_columns, sqlrc);
  murmur_schema_diff_free(&d);
  if (st != MURMUR_SYNC_OK) {
    return st;
  }
  if (accepted) {
    *accepted = 1;
  }
  return ok_rc(sqlrc);
}

static murmur_sync_status_t export_full(sqlite3 *db, uint8_t **blob,
                                        size_t *len, int *sqlrc) {
  *blob = NULL;
  *len = 0;
  murmur_serve_params_t p;
  murmur_sync_status_t st = murmur_serve_params(db, &p, NULL, sqlrc);
  if (st != MURMUR_SYNC_OK) {
    return st;
  }
  uint8_t digest[32];
  st = murmur_schema_digest(db, digest, sqlrc);
  if (st != MURMUR_SYNC_OK) {
    return st;
  }
  uint8_t **segs = NULL;
  size_t *seg_lens = NULL;
  size_t nsegs = 0, seg_cap = 0;
  int64_t total = 0;
  murmur_cursor_t cursor;
  memset(&cursor, 0, sizeof(cursor));
  uint8_t *cursor_owned = NULL;
  int64_t version = 0;
  for (;;) {
    murmur_export_t batch;
    memset(&batch, 0, sizeof(batch));
    st = murmur_sync_export(db, &cursor, p.batch_bytes, p.max_batch_bytes,
                            &batch, sqlrc);
    if (st != MURMUR_SYNC_OK) {
      break;
    }
    total += (int64_t)batch.blob_len;
    if (total > p.staging_bytes) {
      murmur_sync_export_free(&batch);
      st = MURMUR_SYNC_OVERLOADED;
      set_sqlrc(sqlrc, SQLITE_OK);
      break;
    }
    if (nsegs >= seg_cap) {
      size_t ncap = seg_cap ? seg_cap * 2 : 16;
      uint8_t **nsg = (uint8_t **)realloc(segs, ncap * sizeof(*nsg));
      size_t *nln = NULL;
      if (nsg) {
        nln = (size_t *)realloc(seg_lens, ncap * sizeof(*nln));
      }
      if (!nsg || !nln) {
        uint8_t **sg = nsg ? nsg : segs;
        for (size_t k = 0; k < nsegs; k++) {
          free(sg[k]);
        }
        free(sg);
        free(seg_lens);
        segs = NULL;
        seg_lens = NULL;
        nsegs = 0;
        murmur_sync_export_free(&batch);
        st = MURMUR_SYNC_SQLITE;
        set_sqlrc(sqlrc, SQLITE_NOMEM);
        break;
      }
      segs = nsg;
      seg_lens = nln;
      seg_cap = ncap;
    }
    /* steal the blob; the resume cursor borrows batch.next.owned */
    segs[nsegs] = batch.blob;
    seg_lens[nsegs] = batch.blob_len;
    nsegs++;
    batch.blob = NULL;
    version = batch.next.cursor.from;
    int end = !batch.next.cursor.has_through && !batch.next.cursor.has_after;
    free(cursor_owned);
    cursor = batch.next.cursor;
    cursor_owned = batch.next.owned;
    batch.next.owned = NULL;
    murmur_sync_export_free(&batch);
    if (end) {
      free(cursor_owned);
      cursor_owned = NULL;
      murmur_crr_snapshot_t snap;
      memset(&snap, 0, sizeof(snap));
      memcpy(snap.schema, digest, 32);
      snap.version = version;
      snap.segments = segs;
      snap.segment_lens = seg_lens;
      snap.n_segments = nsegs;
      segs = NULL;
      seg_lens = NULL;
      uint8_t *out = murmur_crr_snapshot_encode(&snap, len);
      murmur_crr_snapshot_free(&snap);
      if (!out) {
        return sqlite_fail(sqlrc, SQLITE_NOMEM);
      }
      *blob = out;
      return ok_rc(sqlrc);
    }
    if (nsegs > (1u << 20)) {
      st = MURMUR_SYNC_OVERLOADED;
      set_sqlrc(sqlrc, SQLITE_OK);
      break;
    }
  }
  free(cursor_owned);
  if (segs) {
    for (size_t i = 0; i < nsegs; i++) {
      free(segs[i]);
    }
    free(segs);
    free(seg_lens);
  }
  return st;
}

murmur_sync_status_t murmur_backend_snapshot(sqlite3 *db, int online,
                                             uint8_t **blob, size_t *len,
                                             int *sqlrc) {
  if (!online) {
    set_sqlrc(sqlrc, SQLITE_OK);
    return MURMUR_SYNC_OVERLOADED;
  }
  return export_full(db, blob, len, sqlrc);
}

murmur_sync_status_t murmur_backend_snapshot_with_progress(
    sqlite3 *db, int online, uint8_t **blob, size_t *len,
    murmur_tx_progress_t **ps, size_t *n, int *sqlrc) {
  *blob = NULL;
  *len = 0;
  *ps = NULL;
  *n = 0;
  if (!online) {
    set_sqlrc(sqlrc, SQLITE_OK);
    return MURMUR_SYNC_OVERLOADED;
  }
  murmur_sync_status_t st = export_full(db, blob, len, sqlrc);
  if (st != MURMUR_SYNC_OK) {
    return st;
  }
  st = murmur_tx_progress(db, ps, n, sqlrc);
  if (st != MURMUR_SYNC_OK) {
    free(*blob);
    *blob = NULL;
    *len = 0;
    return st;
  }
  return ok_rc(sqlrc);
}
