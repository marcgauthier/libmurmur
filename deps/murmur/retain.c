/* murmur retain - see retain.h. */
#include "retain.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "config.h"
#include "sqlite3.h"

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

/* ---- settings ----
 *
 * Reads go through the shared config module (murmur_cfg_setting);
 * params parsing keeps Go atoi strictness (murmur_cfg_atoi), which
 * differs from Validate's ParseUint (leading '+' allowed). */

murmur_sync_status_t murmur_retain_params_from(sqlite3 *db,
                                              murmur_retain_params_t *out,
                                              int *sqlrc) {
  if (!db || !out) {
    return sqlite_fail(sqlrc, SQLITE_MISUSE);
  }
  memset(out, 0, sizeof(*out));
  char *raw = NULL;
  murmur_sync_status_t st = murmur_cfg_setting(db, "retention_min_kept", &raw,
                                        sqlrc);
  if (st != MURMUR_SYNC_OK) {
    return st;
  }
  int bad = murmur_cfg_atoi(raw, &out->min_retained) != 0;
  free(raw);
  if (bad) {
    return MURMUR_SYNC_INVALID;
  }
  st = murmur_cfg_setting(db, "retention_max_offline_ms", &raw, sqlrc);
  if (st != MURMUR_SYNC_OK) {
    return st;
  }
  bad = murmur_cfg_atoi(raw, &out->max_offline_ms) != 0;
  free(raw);
  if (bad) {
    return MURMUR_SYNC_INVALID;
  }
  st = murmur_cfg_setting(db, "bootstrap", &raw, sqlrc);
  if (st != MURMUR_SYNC_OK) {
    return st;
  }
  out->bootstrap_nonempty = strcmp(raw, "[]") != 0;
  free(raw);
  return ok_rc(sqlrc);
}

void murmur_snap_params_free(murmur_snap_params_t *p) {
  if (p) {
    free(p->trusted);
    memset(p, 0, sizeof(*p));
  }
}

murmur_sync_status_t murmur_snap_params_from(sqlite3 *db,
                                            murmur_snap_params_t *out,
                                            int *sqlrc) {
  if (!db || !out) {
    return sqlite_fail(sqlrc, SQLITE_MISUSE);
  }
  memset(out, 0, sizeof(*out));
  char *raw = NULL;
  murmur_sync_status_t st =
      murmur_cfg_setting(db, "snapshot_trusted_sources", &raw, sqlrc);
  if (st != MURMUR_SYNC_OK) {
    return st;
  }
  /* JSON array of id strings, via JSON1 with Go unmarshal
   * semantics: the top value must be an array of strings. */
  sqlite3_stmt *jt = NULL;
  int rc = sqlite3_prepare_v2(db, "SELECT json_type(?)", -1, &jt, NULL);
  if (rc != SQLITE_OK) {
    free(raw);
    return sqlite_fail(sqlrc, rc);
  }
  sqlite3_bind_text(jt, 1, raw, -1, SQLITE_TRANSIENT);
  rc = sqlite3_step(jt);
  const uint8_t *type =
      rc == SQLITE_ROW ? sqlite3_column_text(jt, 0) : NULL;
  int is_array = type && strcmp((const char *)type, "array") == 0;
  sqlite3_finalize(jt);
  jt = NULL;
  if (!is_array) {
    free(raw);
    return MURMUR_SYNC_INVALID;
  }
  rc = sqlite3_prepare_v2(db, "SELECT value, type FROM json_each(?)", -1,
                          &jt, NULL);
  if (rc != SQLITE_OK) {
    free(raw);
    return sqlite_fail(sqlrc, rc);
  }
  sqlite3_bind_text(jt, 1, raw, -1, SQLITE_TRANSIENT);
  murmur_sync_status_t status = MURMUR_SYNC_OK;
  for (;;) {
    rc = sqlite3_step(jt);
    if (rc == SQLITE_DONE) {
      break;
    }
    if (rc != SQLITE_ROW) {
      status = MURMUR_SYNC_INVALID;
      break;
    }
    const uint8_t *jtp = sqlite3_column_text(jt, 1);
    if (strcmp((const char *)jtp, "text") != 0) {
      status = MURMUR_SYNC_INVALID;
      break;
    }
    const uint8_t *v = sqlite3_column_text(jt, 0);
    int vn = sqlite3_column_bytes(jt, 0);
    murmur_node_t id;
    if (murmur_cfg_parse_id(v, (size_t)vn, &id) != 0) {
      status = MURMUR_SYNC_INVALID;
      break;
    }
    int dup = 0;
    for (size_t i = 0; i < out->n_trusted; i++) {
      if (memcmp(out->trusted[i].b, id.b, 16) == 0) {
        dup = 1;
        break;
      }
    }
    if (!dup) {
      murmur_node_t *grown = (murmur_node_t *)realloc(
          out->trusted, (out->n_trusted + 1) * sizeof(*grown));
      if (!grown) {
        status = sqlite_fail(sqlrc, SQLITE_NOMEM);
        break;
      }
      out->trusted = grown;
      out->trusted[out->n_trusted++] = id;
    }
  }
  sqlite3_finalize(jt);
  free(raw);
  if (status != MURMUR_SYNC_OK) {
    murmur_snap_params_free(out);
    return status;
  }
  static const char *nums[] = {
      "snapshot_bytes", "snapshot_staging_bytes", "snapshot_lifetime_ms",
      "snapshot_staging_transfers", "max_batch_bytes", "batch_bytes",
  };
  uint64_t vals[6];
  for (int i = 0; i < 6; i++) {
    st = murmur_cfg_setting(db, nums[i], &raw, sqlrc);
    if (st != MURMUR_SYNC_OK) {
      murmur_snap_params_free(out);
      return st;
    }
    int bad = murmur_cfg_atoi(raw, &vals[i]) != 0;
    free(raw);
    if (bad) {
      murmur_snap_params_free(out);
      return MURMUR_SYNC_INVALID;
    }
  }
  /* intOf rejects values past MaxInt64 (unlike the u64 lifetime). */
  for (int i = 0; i < 6; i++) {
    if (i != 2 && vals[i] > (uint64_t)INT64_MAX) {
      murmur_snap_params_free(out);
      return MURMUR_SYNC_INVALID;
    }
  }
  out->snapshot_bytes = (int64_t)vals[0];
  out->snapshot_staging_bytes = (int64_t)vals[1];
  out->transfer_lifetime_ms = vals[2];
  out->staging_transfers = (int64_t)vals[3];
  out->max_transaction_bytes = (int64_t)vals[4];
  out->batch_bytes = (int64_t)vals[5];
  return ok_rc(sqlrc);
}

/* ---- staging sweep (Engine.GC) ---- */

murmur_sync_status_t murmur_gc_stage(sqlite3 *db, int64_t *removed,
                                     int *sqlrc) {
  if (!db || !removed) {
    return sqlite_fail(sqlrc, SQLITE_MISUSE);
  }
  *removed = 0;
  char *raw = NULL;
  murmur_sync_status_t st =
      murmur_cfg_setting(db, "staging_timeout_ms", &raw, sqlrc);
  if (st != MURMUR_SYNC_OK) {
    return st;
  }
  uint64_t ms = 0;
  int bad = murmur_cfg_atoi(raw, &ms) != 0;
  free(raw);
  if (bad) {
    return MURMUR_SYNC_INVALID;
  }
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  /* Wraparound-exact cutoff: now_ms - int64(ms), like Go. */
  uint64_t now_ms =
      (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
  int64_t cutoff;
  {
    uint64_t w = now_ms - (uint64_t)(int64_t)ms;
    memcpy(&cutoff, &w, sizeof(cutoff));
  }
  sqlite3_stmt *del = NULL;
  int rc = sqlite3_prepare_v2(
      db, "DELETE FROM murmur_stage WHERE created < ?", -1, &del, NULL);
  if (rc != SQLITE_OK) {
    return sqlite_fail(sqlrc, rc);
  }
  sqlite3_bind_int64(del, 1, cutoff);
  rc = sqlite3_step(del);
  sqlite3_finalize(del);
  if (rc != SQLITE_DONE) {
    if (rc == SQLITE_ROW) {
      return MURMUR_SYNC_PROTOCOL;
    }
    return sqlite_fail(sqlrc, rc);
  }
  *removed = sqlite3_changes(db);
  return ok_rc(sqlrc);
}

/* ---- tombstone GC + watermark ---- */

static int valid_side_prefix(const char *p, size_t n) {
  if (n == 0) {
    return 0;
  }
  /* Go ranges runes; every accepted rune is ASCII, so a byte
   * scan agrees. */
  for (size_t i = 0; i < n; i++) {
    char c = p[i];
    if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
          (c >= '0' && c <= '9') || c == '_' || c == '$')) {
      return 0;
    }
  }
  return 1;
}

static int has_suffix(const char *s, size_t n, const char *suf) {
  size_t m = strlen(suf);
  return n > m && memcmp(s + n - m, suf, m) == 0;
}

/* quote_ident mirrors Go ("\"" + doubled quotes + "\""). */
static char *quote_ident(const uint8_t *s, size_t n) {
  char *o = (char *)malloc(2 * n + 3);
  if (!o) {
    return NULL;
  }
  size_t w = 0;
  o[w++] = '"';
  for (size_t i = 0; i < n; i++) {
    if (s[i] == '"') {
      o[w++] = '"';
    }
    o[w++] = (char)s[i];
  }
  o[w++] = '"';
  o[w] = '\0';
  return o;
}

/* table_list runs a sqlite_schema discovery query, returning
 * malloc'd names (caller frees each plus the array). */
static murmur_sync_status_t table_list(sqlite3 *db, const char *sql,
                                       char ***names, size_t **lens,
                                       size_t *count, int *sqlrc) {
  *names = NULL;
  *lens = NULL;
  *count = 0;
  sqlite3_stmt *st = NULL;
  int rc = sqlite3_prepare_v2(db, sql, -1, &st, NULL);
  if (rc != SQLITE_OK) {
    return sqlite_fail(sqlrc, rc);
  }
  murmur_sync_status_t status = MURMUR_SYNC_OK;
  for (;;) {
    rc = sqlite3_step(st);
    if (rc == SQLITE_DONE) {
      break;
    }
    if (rc != SQLITE_ROW) {
      status = sqlite_fail(sqlrc, rc);
      break;
    }
    const uint8_t *v = sqlite3_column_text(st, 0);
    int n = sqlite3_column_bytes(st, 0);
    char *cp = (char *)malloc((size_t)n + 1);
    char **nn = NULL;
    size_t *nl = NULL;
    if (!cp) {
      status = sqlite_fail(sqlrc, SQLITE_NOMEM);
      break;
    }
    memcpy(cp, v, (size_t)n);
    cp[n] = '\0';
    nn = (char **)realloc(*names, (*count + 1) * sizeof(*nn));
    nl = (size_t *)realloc(*lens, (*count + 1) * sizeof(*nl));
    if (!nn || !nl) {
      free(cp);
      free(nn);
      free(nl);
      status = sqlite_fail(sqlrc, SQLITE_NOMEM);
      break;
    }
    *names = nn;
    *lens = nl;
    (*names)[*count] = cp;
    (*lens)[*count] = (size_t)n;
    (*count)++;
  }
  sqlite3_finalize(st);
  if (status != MURMUR_SYNC_OK) {
    for (size_t i = 0; i < *count; i++) {
      free((*names)[i]);
    }
    free(*names);
    free(*lens);
    *names = NULL;
    *lens = NULL;
    *count = 0;
  }
  return status;
}

murmur_sync_status_t murmur_gc_watermark(sqlite3 *db, uint64_t *mark,
                                         int *sqlrc) {
  if (!db || !mark) {
    return sqlite_fail(sqlrc, SQLITE_MISUSE);
  }
  *mark = 0;
  sqlite3_stmt *st = NULL;
  int rc = sqlite3_prepare_v2(
      db, "SELECT value FROM murmur_config WHERE name='gc_watermark'", -1,
      &st, NULL);
  if (rc != SQLITE_OK) {
    return sqlite_fail(sqlrc, rc);
  }
  rc = sqlite3_step(st);
  if (rc == SQLITE_DONE) {
    sqlite3_finalize(st);
    return ok_rc(sqlrc);
  }
  if (rc != SQLITE_ROW) {
    sqlite3_finalize(st);
    return sqlite_fail(sqlrc, rc);
  }
  const uint8_t *v = sqlite3_column_text(st, 0);
  int n = sqlite3_column_bytes(st, 0);
  char *copy = (char *)malloc((size_t)n + 1);
  if (!copy) {
    sqlite3_finalize(st);
    return sqlite_fail(sqlrc, SQLITE_NOMEM);
  }
  memcpy(copy, v, (size_t)n);
  copy[n] = '\0';
  sqlite3_finalize(st);
  int bad = murmur_cfg_atoi(copy, mark) != 0;
  free(copy);
  return bad ? MURMUR_SYNC_INVALID : ok_rc(sqlrc);
}

murmur_sync_status_t murmur_gc_tombstones(sqlite3 *db, uint64_t floor,
                                          uint64_t *deleted, int *sqlrc) {
  if (!db || !deleted) {
    return sqlite_fail(sqlrc, SQLITE_MISUSE);
  }
  *deleted = 0;
  char **names = NULL;
  size_t *lens = NULL;
  size_t count = 0;
  murmur_sync_status_t st = table_list(
      db,
      "SELECT name FROM sqlite_schema WHERE type='table' AND name LIKE "
      "'%__crsql_clock' ESCAPE '\\'",
      &names, &lens, &count, sqlrc);
  if (st != MURMUR_SYNC_OK) {
    return st;
  }
  static const char kSuffix[] = "__crsql_clock";
  for (size_t i = 0; i < count; i++) {
    if (!has_suffix(names[i], lens[i], kSuffix) ||
        !valid_side_prefix(names[i], lens[i] - strlen(kSuffix))) {
      continue;
    }
    char *q = quote_ident((const uint8_t *)names[i], lens[i]);
    if (!q) {
      st = sqlite_fail(sqlrc, SQLITE_NOMEM);
      break;
    }
    size_t sql_len = strlen(q) + 64;
    char *sql = (char *)malloc(sql_len);
    if (!sql) {
      free(q);
      st = sqlite_fail(sqlrc, SQLITE_NOMEM);
      break;
    }
    snprintf(sql, sql_len, "DELETE FROM %s WHERE col_name='-1' AND db_version<=?", q);
    free(q);
    sqlite3_stmt *del = NULL;
    int rc = sqlite3_prepare_v2(db, sql, -1, &del, NULL);
    free(sql);
    if (rc != SQLITE_OK) {
      st = sqlite_fail(sqlrc, rc);
      break;
    }
    int64_t bound;
    memcpy(&bound, &floor, sizeof(bound));
    sqlite3_bind_int64(del, 1, bound);
    rc = sqlite3_step(del);
    sqlite3_finalize(del);
    if (rc != SQLITE_ROW && rc != SQLITE_DONE) {
      st = sqlite_fail(sqlrc, rc);
      break;
    }
    if (rc != SQLITE_DONE) {
      st = MURMUR_SYNC_PROTOCOL;
      break;
    }
    *deleted += (uint64_t)sqlite3_changes(db);
  }
  for (size_t i = 0; i < count; i++) {
    free(names[i]);
  }
  free(names);
  free(lens);
  if (st != MURMUR_SYNC_OK) {
    return st;
  }
  uint64_t mark = 0;
  st = murmur_gc_watermark(db, &mark, sqlrc);
  if (st != MURMUR_SYNC_OK) {
    return st;
  }
  if (floor > mark) {
    mark = floor;
  }
  char val[24];
  snprintf(val, sizeof(val), "%llu", (unsigned long long)mark);
  sqlite3_stmt *up = NULL;
  int rc = sqlite3_prepare_v2(
      db,
      "INSERT INTO murmur_config(name,value) VALUES('gc_watermark',?) ON "
      "CONFLICT(name) DO UPDATE SET value=excluded.value",
      -1, &up, NULL);
  if (rc != SQLITE_OK) {
    return sqlite_fail(sqlrc, rc);
  }
  sqlite3_bind_text(up, 1, val, -1, SQLITE_TRANSIENT);
  rc = sqlite3_step(up);
  sqlite3_finalize(up);
  return rc == SQLITE_DONE ? ok_rc(sqlrc) : sqlite_fail(sqlrc, rc);
}

/* side_base strips a side-table suffix, reporting a match. */
static int side_base(const char *s, size_t n, size_t *base_len) {
  static const char *sufs[] = {"__crsql_clock", "__crsql_pks"};
  for (int i = 0; i < 2; i++) {
    if (has_suffix(s, n, sufs[i])) {
      *base_len = n - strlen(sufs[i]);
      return 1;
    }
  }
  return 0;
}

static murmur_sync_status_t pin_version_floor(sqlite3 *db, char **orphans,
                                              size_t *lens, size_t count,
                                              int *sqlrc) {
  sqlite3_stmt *st = NULL;
  int rc = sqlite3_prepare_v2(
      db,
      "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND "
      "name='crsql_master')",
      -1, &st, NULL);
  if (rc != SQLITE_OK) {
    return sqlite_fail(sqlrc, rc);
  }
  rc = sqlite3_step(st);
  int has = rc == SQLITE_ROW && sqlite3_column_int64(st, 0) != 0;
  sqlite3_finalize(st);
  if (rc != SQLITE_ROW && rc != SQLITE_DONE) {
    return sqlite_fail(sqlrc, rc);
  }
  if (!has) {
    return ok_rc(sqlrc);
  }
  int have_peak = 0;
  int64_t peak = 0;
  for (size_t i = 0; i < count; i++) {
    if (!has_suffix(orphans[i], lens[i], "__crsql_clock")) {
      continue;
    }
    sqlite3_stmt *col = NULL;
    rc = sqlite3_prepare_v2(
        db,
        "SELECT EXISTS(SELECT 1 FROM pragma_table_info(?) WHERE "
        "name='db_version')",
        -1, &col, NULL);
    if (rc != SQLITE_OK) {
      return sqlite_fail(sqlrc, rc);
    }
    sqlite3_bind_text(col, 1, orphans[i], (int)lens[i], SQLITE_TRANSIENT);
    rc = sqlite3_step(col);
    int ok = rc == SQLITE_ROW && sqlite3_column_int64(col, 0) != 0;
    sqlite3_finalize(col);
    if (rc != SQLITE_ROW && rc != SQLITE_DONE) {
      return sqlite_fail(sqlrc, rc);
    }
    if (!ok) {
      continue;
    }
    char *q = quote_ident((const uint8_t *)orphans[i], lens[i]);
    if (!q) {
      return sqlite_fail(sqlrc, SQLITE_NOMEM);
    }
    size_t sql_len = strlen(q) + 32;
    char *sql = (char *)malloc(sql_len);
    if (!sql) {
      free(q);
      return sqlite_fail(sqlrc, SQLITE_NOMEM);
    }
    snprintf(sql, sql_len, "SELECT max(db_version) FROM %s", q);
    free(q);
    sqlite3_stmt *mx = NULL;
    rc = sqlite3_prepare_v2(db, sql, -1, &mx, NULL);
    free(sql);
    if (rc != SQLITE_OK) {
      return sqlite_fail(sqlrc, rc);
    }
    rc = sqlite3_step(mx);
    if (rc == SQLITE_ROW && sqlite3_column_type(mx, 0) != SQLITE_NULL) {
      int64_t v = sqlite3_column_int64(mx, 0);
      if (!have_peak || v > peak) {
        peak = v;
        have_peak = 1;
      }
    }
    sqlite3_finalize(mx);
    if (rc != SQLITE_ROW && rc != SQLITE_DONE) {
      return sqlite_fail(sqlrc, rc);
    }
  }
  if (!have_peak) {
    return ok_rc(sqlrc);
  }
  sqlite3_stmt *cur = NULL;
  rc = sqlite3_prepare_v2(
      db,
      "SELECT CAST(value AS INTEGER) FROM crsql_master WHERE "
      "key='pre_compact_dbversion'",
      -1, &cur, NULL);
  if (rc != SQLITE_OK) {
    return sqlite_fail(sqlrc, rc);
  }
  rc = sqlite3_step(cur);
  int64_t pinned = 0;
  if (rc == SQLITE_ROW) {
    pinned = sqlite3_column_int64(cur, 0);
  }
  sqlite3_finalize(cur);
  if (rc != SQLITE_ROW && rc != SQLITE_DONE) {
    return sqlite_fail(sqlrc, rc);
  }
  if (peak <= pinned) {
    return ok_rc(sqlrc);
  }
  sqlite3_stmt *up = NULL;
  rc = sqlite3_prepare_v2(
      db,
      "INSERT OR REPLACE INTO crsql_master(key,value) VALUES('pre_compact_"
      "dbversion',?1)",
      -1, &up, NULL);
  if (rc != SQLITE_OK) {
    return sqlite_fail(sqlrc, rc);
  }
  sqlite3_bind_int64(up, 1, peak);
  rc = sqlite3_step(up);
  sqlite3_finalize(up);
  return rc == SQLITE_DONE ? ok_rc(sqlrc) : sqlite_fail(sqlrc, rc);
}

murmur_sync_status_t murmur_reap_orphan_clocks(sqlite3 *db, uint64_t *reaped,
                                               int *sqlrc) {
  if (!db || !reaped) {
    return sqlite_fail(sqlrc, SQLITE_MISUSE);
  }
  *reaped = 0;
  char **names = NULL;
  size_t *lens = NULL;
  size_t count = 0;
  murmur_sync_status_t st = table_list(
      db,
      "SELECT name FROM sqlite_schema WHERE type='table' AND (name LIKE "
      "'%__crsql_clock' ESCAPE '\\' OR name LIKE '%__crsql_pks' ESCAPE "
      "'\\')",
      &names, &lens, &count, sqlrc);
  if (st != MURMUR_SYNC_OK) {
    return st;
  }
  char **orphans = NULL;
  size_t *olens = NULL;
  size_t norph = 0;
  for (size_t i = 0; i < count; i++) {
    size_t blen = 0;
    if (!side_base(names[i], lens[i], &blen) ||
        !valid_side_prefix(names[i], blen)) {
      continue;
    }
    sqlite3_stmt *ex = NULL;
    int rc = sqlite3_prepare_v2(
        db,
        "SELECT 1 FROM sqlite_schema WHERE type='table' AND name=?", -1,
        &ex, NULL);
    if (rc != SQLITE_OK) {
      st = sqlite_fail(sqlrc, rc);
      break;
    }
    sqlite3_bind_text(ex, 1, names[i], (int)blen, SQLITE_TRANSIENT);
    rc = sqlite3_step(ex);
    sqlite3_finalize(ex);
    if (rc != SQLITE_ROW && rc != SQLITE_DONE) {
      st = sqlite_fail(sqlrc, rc);
      break;
    }
    if (rc == SQLITE_ROW) {
      continue;
    }
    char **no = (char **)realloc(orphans, (norph + 1) * sizeof(*no));
    size_t *nl = (size_t *)realloc(olens, (norph + 1) * sizeof(*nl));
    if (!no || !nl) {
      free(no);
      free(nl);
      st = sqlite_fail(sqlrc, SQLITE_NOMEM);
      break;
    }
    orphans = no;
    olens = nl;
    orphans[norph] = names[i];
    olens[norph] = lens[i];
    norph++;
  }
  if (st == MURMUR_SYNC_OK) {
    st = pin_version_floor(db, orphans, olens, norph, sqlrc);
  }
  if (st == MURMUR_SYNC_OK) {
    for (size_t i = 0; i < norph; i++) {
      char *q = quote_ident((const uint8_t *)orphans[i], olens[i]);
      if (!q) {
        st = sqlite_fail(sqlrc, SQLITE_NOMEM);
        break;
      }
      size_t sql_len = strlen(q) + 16;
      char *sql = (char *)malloc(sql_len);
      if (!sql) {
        free(q);
        st = sqlite_fail(sqlrc, SQLITE_NOMEM);
        break;
      }
      snprintf(sql, sql_len, "DROP TABLE %s", q);
      free(q);
      int rc = sqlite3_exec(db, sql, NULL, NULL, NULL);
      free(sql);
      if (rc != SQLITE_OK) {
        st = sqlite_fail(sqlrc, rc);
        break;
      }
      (*reaped)++;
    }
  }
  free(orphans);
  free(olens);
  for (size_t i = 0; i < count; i++) {
    free(names[i]);
  }
  free(names);
  free(lens);
  return st;
}
