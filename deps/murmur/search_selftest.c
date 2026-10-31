/* Search manager selftest over real SQLite + FTS5 + vec0. Suites:
 * open validation, FTS5 rebuild+query, incremental hook keys, vector
 * end-to-end + embedding guards, bounded ticks + overflow, guard /
 * status / publications / drop / refresh / clone, WITHOUT ROWID. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "search.h"
#include "sqlite3.h"

static int failures = 0;

#define CHECK(cond, ...)                                                     \
  do {                                                                       \
    if (!(cond)) {                                                           \
      printf("FAIL search:%d: ", __LINE__);                                  \
      printf(__VA_ARGS__);                                                   \
      printf("\n");                                                          \
      failures++;                                                            \
    }                                                                        \
  } while (0)

static sqlite3 *open_db(void) {
  sqlite3 *db = NULL;
  if (sqlite3_open(":memory:", &db) != SQLITE_OK) {
    printf("FAIL open: %s\n", sqlite3_errmsg(db));
    failures++;
    return NULL;
  }
  return db;
}

static int exec_ok(sqlite3 *db, const char *sql) {
  char *err = NULL;
  int rc = sqlite3_exec(db, sql, NULL, NULL, &err);
  if (rc != SQLITE_OK) {
    printf("FAIL exec[%d]: %s (%s)\n", rc, sql, err ? err : "?");
    failures++;
  }
  sqlite3_free(err);
  return rc == SQLITE_OK;
}

static int64_t count_query(sqlite3 *db, const char *sql) {
  sqlite3_stmt *st = NULL;
  if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK) {
    printf("FAIL prepare: %s (%s)\n", sql, sqlite3_errmsg(db));
    failures++;
    return -1;
  }
  int rc = sqlite3_step(st);
  int64_t n = rc == SQLITE_ROW ? sqlite3_column_int64(st, 0) : -1;
  if (rc != SQLITE_ROW) {
    printf("FAIL step: %s (%s)\n", sql, sqlite3_errmsg(db));
    failures++;
  }
  sqlite3_finalize(st);
  return n;
}

static murmur_search_manager_t *open_fts(const char *name,
                                         const char *source,
                                         const char **cols, size_t ncols,
                                         size_t batch) {
  murmur_search_def_t d;
  memset(&d, 0, sizeof(d));
  d.tag = MURMUR_SEARCH_FTS5;
  d.name = name;
  d.source_table = source;
  d.columns = cols;
  d.n_columns = ncols;
  murmur_search_manager_t *m = NULL;
  char *detail = NULL;
  murmur_search_status_t s =
      murmur_search_open(&d, 1, 1 << 20, batch, &m, &detail);
  if (s != MURMUR_SEARCH_OK) {
    printf("FAIL open_fts %s: %s\n", name, detail ? detail : "?");
    failures++;
  }
  free(detail);
  return m;
}

static int64_t *knn_ids(sqlite3 *db, const char *sql, int *n_out) {
  *n_out = -1;
  sqlite3_stmt *st = NULL;
  if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK) {
    printf("FAIL knn prepare: %s (%s)\n", sql, sqlite3_errmsg(db));
    failures++;
    return NULL;
  }
  int64_t *ids = NULL;
  int n = 0, cap = 0;
  int rc = 0;
  while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
    if (n == cap) {
      int ncap = cap ? cap * 2 : 8;
      int64_t *nv = realloc(ids, (size_t)ncap * sizeof(*nv));
      if (!nv) {
        free(ids);
        sqlite3_finalize(st);
        return NULL;
      }
      ids = nv;
      cap = ncap;
    }
    ids[n++] = sqlite3_column_int64(st, 0);
  }
  if (rc != SQLITE_DONE) {
    printf("FAIL knn step: %s (%s)\n", sql, sqlite3_errmsg(db));
    failures++;
    free(ids);
    sqlite3_finalize(st);
    return NULL;
  }
  sqlite3_finalize(st);
  *n_out = n;
  return ids;
}

int main(void) {
  /* Suite 1: open validation. */
  {
    murmur_search_manager_t *m = NULL;
    char *detail = NULL;
    murmur_search_def_t d;
    memset(&d, 0, sizeof(d));
    const char *cols[] = {"body"};
    d.tag = MURMUR_SEARCH_FTS5;
    d.name = "ft";
    d.source_table = "docs";
    d.columns = cols;
    d.n_columns = 1;
    CHECK(murmur_search_open(&d, 1, 0, 64, &m, &detail) ==
              MURMUR_SEARCH_INVALID,
          "zero budget accepted");
    free(detail);
    detail = NULL;
    CHECK(murmur_search_open(&d, 1, 1 << 20, 0, &m, &detail) ==
              MURMUR_SEARCH_INVALID,
          "zero batch accepted");
    free(detail);
    detail = NULL;
    CHECK(murmur_search_open(&d, 1, 1 << 20, 65537, &m, &detail) ==
              MURMUR_SEARCH_INVALID,
          "huge batch accepted");
    free(detail);
    detail = NULL;
    murmur_search_def_t bad = d;
    bad.name = "sqlite_x";
    CHECK(murmur_search_open(&bad, 1, 1 << 20, 64, &m, &detail) ==
              MURMUR_SEARCH_INVALID,
          "sqlite_ name accepted");
    free(detail);
    detail = NULL;
    bad = d;
    bad.tokenizer = "bogus";
    CHECK(murmur_search_open(&bad, 1, 1 << 20, 64, &m, &detail) ==
              MURMUR_SEARCH_INVALID,
          "bad tokenizer accepted");
    free(detail);
    detail = NULL;
    bad = d;
    bad.columns = NULL;
    bad.n_columns = 0;
    CHECK(murmur_search_open(&bad, 1, 1 << 20, 64, &m, &detail) ==
              MURMUR_SEARCH_INVALID,
          "empty columns accepted");
    free(detail);
    detail = NULL;
    const char *dupcols[] = {"a", "A"};
    bad = d;
    bad.columns = dupcols;
    bad.n_columns = 2;
    CHECK(murmur_search_open(&bad, 1, 1 << 20, 64, &m, &detail) ==
              MURMUR_SEARCH_INVALID,
          "dup columns accepted");
    free(detail);
    detail = NULL;
    murmur_search_def_t v;
    memset(&v, 0, sizeof(v));
    v.tag = MURMUR_SEARCH_VECTOR;
    v.name = "vv";
    v.source_table = "emb";
    v.vector_column = "vec";
    v.dimensions = 4;
    v.distance = MURMUR_DIST_L2;
    CHECK(murmur_search_open(&v, 1, 1 << 20, 64, &m, &detail) ==
              MURMUR_SEARCH_OK,
          "vector open %s", detail ? detail : "");
    free(detail);
    detail = NULL;
    murmur_search_close(m);
    m = NULL;
    bad = v;
    bad.dimensions = 0;
    CHECK(murmur_search_open(&bad, 1, 1 << 20, 64, &m, &detail) ==
              MURMUR_SEARCH_INVALID,
          "dims 0 accepted");
    free(detail);
    detail = NULL;
    bad = v;
    bad.vector_column = "9bad";
    CHECK(murmur_search_open(&bad, 1, 1 << 20, 64, &m, &detail) ==
              MURMUR_SEARCH_INVALID,
          "bad vec column accepted");
    free(detail);
    detail = NULL;
    bad = v;
    bad.distance = (murmur_distance_t)9;
    CHECK(murmur_search_open(&bad, 1, 1 << 20, 64, &m, &detail) ==
              MURMUR_SEARCH_INVALID,
          "bad distance accepted");
    free(detail);
    detail = NULL;
    murmur_search_def_t two[] = {d, d};
    CHECK(murmur_search_open(two, 2, 1 << 20, 64, &m, &detail) ==
              MURMUR_SEARCH_INVALID,
          "dup names accepted");
    free(detail);
  }

  /* Suite 2: FTS5 rebuild + query. */
  {
    sqlite3 *db = open_db();
    const char *cols[] = {"title", "body"};
    murmur_search_manager_t *m = open_fts("ft", "docs", cols, 2, 64);
    if (!db || !m) {
      return 1;
    }
    char *detail = NULL;
    int sqlrc = 0;
    /* Missing source fails closed without allow_missing. */
    CHECK(murmur_search_sync_schema(m, db, 0, &detail, &sqlrc) ==
              MURMUR_SEARCH_INVALID,
          "missing source accepted");
    free(detail);
    detail = NULL;
    CHECK(murmur_search_sync_schema(m, db, 1, &detail, &sqlrc) ==
              MURMUR_SEARCH_OK,
          "allow_missing failed %s", detail ? detail : "");
    free(detail);
    detail = NULL;
    exec_ok(db, "CREATE TABLE docs(id INTEGER PRIMARY KEY, title TEXT, "
                "body TEXT);");
    exec_ok(db, "INSERT INTO docs VALUES(1,'hello','brave new world'),"
                "(2,'bye','nothing here'),(3,'hello again','world tour');");
    CHECK(murmur_search_sync_schema(m, db, 0, &detail, &sqlrc) ==
              MURMUR_SEARCH_OK,
          "sync %s", detail ? detail : "");
    free(detail);
    detail = NULL;
    CHECK(murmur_search_pending(m), "rebuild not pending");
    char **pub = NULL;
    size_t npub = 0;
    CHECK(murmur_search_tick(m, db, &pub, &npub, &detail, &sqlrc) ==
              MURMUR_SEARCH_OK,
          "tick %s", detail ? detail : "");
    free(detail);
    detail = NULL;
    CHECK(npub == 1 && strcmp(pub[0], "ft") == 0, "published ft");
    murmur_search_published_free(pub, npub);
    CHECK(count_query(db, "SELECT COUNT(*) FROM temp.ft WHERE ft MATCH 'hello'") ==
              2,
          "fts hello");
    CHECK(count_query(db, "SELECT COUNT(*) FROM temp.ft WHERE ft MATCH 'world'") ==
              2,
          "fts world");
    int ready = 0;
    CHECK(murmur_search_guard_ready(m, "ft", &ready) && ready, "guard ready");
    CHECK(murmur_search_guard_ready(m, "FT", &ready) && ready,
          "guard case-insensitive");
    CHECK(!murmur_search_guard_ready(m, "nope", &ready), "guard phantom");
    murmur_search_close(m);
    sqlite3_close(db);
  }

  /* Suite 3: incremental hook keys (insert/update/delete). */
  {
    sqlite3 *db = open_db();
    const char *cols[] = {"body"};
    murmur_search_manager_t *m = open_fts("ft", "docs", cols, 1, 64);
    if (!db || !m) {
      return 1;
    }
    char *detail = NULL;
    int sqlrc = 0;
    exec_ok(db, "CREATE TABLE docs(id INTEGER PRIMARY KEY, body TEXT);");
    exec_ok(db, "INSERT INTO docs VALUES(1,'alpha'),(2,'beta');");
    CHECK(murmur_search_register(db, m, &detail, &sqlrc) == MURMUR_SEARCH_OK,
          "register %s", detail ? detail : "");
    free(detail);
    detail = NULL;
    CHECK(murmur_search_sync_schema(m, db, 0, &detail, &sqlrc) ==
              MURMUR_SEARCH_OK,
          "sync %s", detail ? detail : "");
    free(detail);
    detail = NULL;
    murmur_search_attach(m, db);
    CHECK(murmur_search_refresh(m, db, NULL, NULL, &detail, &sqlrc) ==
              MURMUR_SEARCH_OK,
          "refresh %s", detail ? detail : "");
    free(detail);
    detail = NULL;
    CHECK(!murmur_search_pending(m), "still pending after refresh");
    /* Writes land as keys, not rebuilds. */
    exec_ok(db, "INSERT INTO docs VALUES(3,'gamma rays');");
    exec_ok(db, "UPDATE docs SET body='beta updated' WHERE id=2;");
    exec_ok(db, "DELETE FROM docs WHERE id=1;");
    CHECK(murmur_search_pending(m), "writes not pending");
    murmur_search_index_status_t *st = NULL;
    size_t nst = 0;
    CHECK(murmur_search_status(m, &st, &nst) == MURMUR_SEARCH_OK && nst == 1,
          "status");
    CHECK(!st[0].rebuilding, "unexpected rebuild");
    murmur_search_status_free(st, nst);
    CHECK(murmur_search_refresh(m, db, NULL, NULL, &detail, &sqlrc) ==
              MURMUR_SEARCH_OK,
          "refresh2 %s", detail ? detail : "");
    free(detail);
    detail = NULL;
    CHECK(count_query(db, "SELECT COUNT(*) FROM temp.ft WHERE ft MATCH 'gamma'") ==
              1,
          "incremental insert");
    CHECK(count_query(db, "SELECT COUNT(*) FROM temp.ft WHERE ft MATCH 'alpha'") ==
              0,
          "incremental delete");
    CHECK(count_query(db, "SELECT COUNT(*) FROM temp.ft WHERE ft MATCH 'updated'") ==
              1,
          "incremental update");
    /* Unrelated tables do not pend. detach stops the feed. */
    exec_ok(db, "CREATE TABLE other(id INTEGER PRIMARY KEY, x TEXT);");
    exec_ok(db, "INSERT INTO other VALUES(1,'zzz');");
    CHECK(!murmur_search_pending(m), "unrelated table pends");
    murmur_search_detach(m, db);
    exec_ok(db, "INSERT INTO docs VALUES(4,'detached');");
    CHECK(!murmur_search_pending(m), "detached hook pends");
    murmur_search_close(m);
    sqlite3_close(db);
  }

  /* Suite 4: vector index end-to-end + embedding guards. */
  {
    sqlite3 *db = open_db();
    if (!db) {
      return 1;
    }
    murmur_search_def_t v;
    memset(&v, 0, sizeof(v));
    v.tag = MURMUR_SEARCH_VECTOR;
    v.name = "vv";
    v.source_table = "emb";
    v.vector_column = "vec";
    v.dimensions = 2;
    v.distance = MURMUR_DIST_L2;
    murmur_search_manager_t *m = NULL;
    char *detail = NULL;
    int sqlrc = 0;
    CHECK(murmur_search_open(&v, 1, 1 << 20, 64, &m, &detail) ==
              MURMUR_SEARCH_OK,
          "vec open %s", detail ? detail : "");
    free(detail);
    detail = NULL;
    exec_ok(db, "CREATE TABLE emb(id INTEGER PRIMARY KEY, vec BLOB);");
    float a[2] = {0, 0}, b[2] = {3, 4}, c[2] = {1, 0};
    sqlite3_stmt *st = NULL;
    sqlite3_prepare_v2(db, "INSERT INTO emb VALUES(?,?)", -1, &st, NULL);
    sqlite3_bind_int(st, 1, 1);
    sqlite3_bind_blob(st, 2, a, 8, SQLITE_TRANSIENT);
    sqlite3_step(st);
    sqlite3_reset(st);
    sqlite3_bind_int(st, 1, 2);
    sqlite3_bind_blob(st, 2, b, 8, SQLITE_TRANSIENT);
    sqlite3_step(st);
    sqlite3_reset(st);
    sqlite3_bind_int(st, 1, 3);
    sqlite3_bind_blob(st, 2, c, 8, SQLITE_TRANSIENT);
    sqlite3_step(st);
    sqlite3_finalize(st);
    exec_ok(db, "INSERT INTO emb VALUES(4,NULL);");
    CHECK(murmur_search_register(db, m, &detail, &sqlrc) == MURMUR_SEARCH_OK,
          "vec register %s", detail ? detail : "");
    free(detail);
    detail = NULL;
    CHECK(murmur_search_sync_schema(m, db, 0, &detail, &sqlrc) ==
              MURMUR_SEARCH_OK,
          "vec sync %s", detail ? detail : "");
    free(detail);
    detail = NULL;
    CHECK(murmur_search_refresh(m, db, NULL, NULL, &detail, &sqlrc) ==
              MURMUR_SEARCH_OK,
          "vec refresh %s", detail ? detail : "");
    free(detail);
    detail = NULL;
    int n = 0;
    int64_t *ids = knn_ids(db, "SELECT rowid FROM temp.vv WHERE vec MATCH "
                               "'[0,0]' AND k=3 ORDER BY distance",
                           &n);
    CHECK(n == 3 && ids[0] == 1 && ids[1] == 3 && ids[2] == 2,
          "vec order n=%d", n);
    free(ids);
    /* NULL embedding skipped, not indexed. */
    CHECK(count_query(db, "SELECT COUNT(*) FROM temp.vv") == 3, "vec count");
    /* Bad embedding fails the tick and latches the error. */
    exec_ok(db, "INSERT INTO emb VALUES(5,x'00');");
    murmur_search_attach(m, db);
    exec_ok(db, "UPDATE emb SET vec=x'00' WHERE id=5;");
    CHECK(murmur_search_tick(m, db, NULL, NULL, &detail, &sqlrc) ==
              MURMUR_SEARCH_INVALID,
          "bad embedding accepted");
    CHECK(detail && strstr(detail, "invalid embedding") != NULL,
          "bad embedding detail %s", detail ? detail : "-");
    free(detail);
    detail = NULL;
    murmur_search_index_status_t *sst = NULL;
    size_t nsst = 0;
    CHECK(murmur_search_status(m, &sst, &nsst) == MURMUR_SEARCH_OK, "vec status");
    CHECK(nsst == 1 && !sst[0].ready && sst[0].error != NULL, "vec err latched");
    murmur_search_status_free(sst, nsst);
    int ready = 1;
    CHECK(murmur_search_guard_ready(m, "vv", &ready) && !ready,
          "vec guard not ready");
    /* Fix the row: the error clears and the index goes ready. */
    sqlite3_prepare_v2(db, "UPDATE emb SET vec=? WHERE id=5", -1, &st, NULL);
    sqlite3_bind_blob(st, 1, a, 8, SQLITE_TRANSIENT);
    sqlite3_step(st);
    sqlite3_finalize(st);
    CHECK(murmur_search_refresh(m, db, NULL, NULL, &detail, &sqlrc) ==
              MURMUR_SEARCH_OK,
          "vec recover %s", detail ? detail : "");
    free(detail);
    detail = NULL;
    CHECK(count_query(db, "SELECT COUNT(*) FROM temp.vv") == 4, "vec recovered");
    murmur_search_close(m);
    sqlite3_close(db);
  }

  /* Suite 5: bounded ticks + small-batch resume + overflow. */
  {
    sqlite3 *db = open_db();
    const char *cols[] = {"body"};
    murmur_search_manager_t *m = open_fts("ft", "docs", cols, 1, 2);
    if (!db || !m) {
      return 1;
    }
    char *detail = NULL;
    int sqlrc = 0;
    exec_ok(db, "CREATE TABLE docs(id INTEGER PRIMARY KEY, body TEXT);");
    exec_ok(db, "INSERT INTO docs VALUES(1,'one'),(2,'two'),(3,'three'),"
                "(4,'four'),(5,'five');");
    CHECK(murmur_search_sync_schema(m, db, 0, &detail, &sqlrc) ==
              MURMUR_SEARCH_OK,
          "sync %s", detail ? detail : "");
    free(detail);
    detail = NULL;
    int ticks = 0;
    while (murmur_search_pending(m) && ticks < 10) {
      char **pub = NULL;
      size_t npub = 0;
      CHECK(murmur_search_tick(m, db, &pub, &npub, &detail, &sqlrc) ==
                MURMUR_SEARCH_OK,
            "tick %d %s", ticks, detail ? detail : "");
      free(detail);
      detail = NULL;
      murmur_search_published_free(pub, npub);
      ticks++;
    }
    CHECK(ticks == 3, "bounded ticks=%d", ticks);
    CHECK(count_query(db, "SELECT COUNT(*) FROM temp.ft") == 5, "rebuild rows");
    murmur_search_close(m);
    /* Overflow: a tiny budget with many pending keys still converges
     * through invalidate+rebuild. */
    const char *cols2[] = {"body"};
    murmur_search_def_t d;
    memset(&d, 0, sizeof(d));
    d.tag = MURMUR_SEARCH_FTS5;
    d.name = "ft2";
    d.source_table = "docs";
    d.columns = cols2;
    d.n_columns = 1;
    CHECK(murmur_search_open(&d, 1, 64, 64, &m, &detail) == MURMUR_SEARCH_OK,
          "small budget open %s", detail ? detail : "");
    free(detail);
    detail = NULL;
    CHECK(murmur_search_sync_schema(m, db, 0, &detail, &sqlrc) ==
              MURMUR_SEARCH_OK,
          "sync2 %s", detail ? detail : "");
    free(detail);
    detail = NULL;
    murmur_search_attach(m, db);
    for (int i = 6; i < 60; i++) {
      char sql[128];
      snprintf(sql, sizeof(sql), "INSERT INTO docs VALUES(%d,'bulk %d');", i,
               i);
      exec_ok(db, sql);
    }
    CHECK(murmur_search_refresh(m, db, NULL, NULL, &detail, &sqlrc) ==
              MURMUR_SEARCH_OK,
          "overflow refresh %s", detail ? detail : "");
    free(detail);
    detail = NULL;
    CHECK(count_query(db, "SELECT COUNT(*) FROM temp.ft2") == 59,
          "overflow rows");
    int ready = 0;
    CHECK(murmur_search_guard_ready(m, "ft2", &ready) && ready,
          "overflow ready");
    murmur_search_close(m);
    sqlite3_close(db);
  }

  /* Suite 6: publications, drop, refresh names, allow-missing install,
   * clone, note_table. */
  {
    sqlite3 *db = open_db();
    const char *cols[] = {"body"};
    murmur_search_def_t d;
    memset(&d, 0, sizeof(d));
    d.tag = MURMUR_SEARCH_FTS5;
    d.name = "ft";
    d.source_table = "docs";
    d.columns = cols;
    d.n_columns = 1;
    murmur_search_manager_t *m = NULL;
    char *detail = NULL;
    int sqlrc = 0;
    CHECK(murmur_search_open(&d, 1, 1 << 20, 64, &m, &detail) ==
              MURMUR_SEARCH_OK,
          "open %s", detail ? detail : "");
    free(detail);
    detail = NULL;
    /* Source appears after allow-missing sync: install on resync. */
    CHECK(murmur_search_sync_schema(m, db, 1, &detail, &sqlrc) ==
              MURMUR_SEARCH_OK,
          "sync missing %s", detail ? detail : "");
    free(detail);
    detail = NULL;
    CHECK(!murmur_search_pending(m), "missing source pends");
    exec_ok(db, "CREATE TABLE docs(id INTEGER PRIMARY KEY, body TEXT);");
    exec_ok(db, "INSERT INTO docs VALUES(1,'hello');");
    CHECK(murmur_search_sync_schema(m, db, 1, &detail, &sqlrc) ==
              MURMUR_SEARCH_OK,
          "sync late %s", detail ? detail : "");
    free(detail);
    detail = NULL;
    char **pub = NULL;
    size_t npub = 0;
    CHECK(murmur_search_refresh(m, db, &pub, &npub, &detail, &sqlrc) ==
              MURMUR_SEARCH_OK,
          "refresh %s", detail ? detail : "");
    free(detail);
    detail = NULL;
    CHECK(npub == 1 && strcmp(pub[0], "ft") == 0, "refresh names");
    murmur_search_published_free(pub, npub);
    char **taken = NULL;
    size_t ntaken = 0;
    CHECK(murmur_search_take_publications(m, &taken, &ntaken) ==
              MURMUR_SEARCH_OK,
          "take");
    CHECK(ntaken == 1 && strcmp(taken[0], "ft") == 0, "taken names");
    murmur_search_published_free(taken, ntaken);
    CHECK(murmur_search_take_publications(m, &taken, &ntaken) ==
              MURMUR_SEARCH_OK && ntaken == 0,
          "take drains");
    /* note_table invalidates; clone carries state. */
    murmur_search_note_table(m, "docs");
    CHECK(murmur_search_pending(m), "noted table not pending");
    murmur_search_manager_t *c2 = murmur_search_clone(m);
    CHECK(c2 != NULL, "clone null");
    CHECK(murmur_search_pending(c2), "clone not pending");
    CHECK(murmur_search_refresh(m, db, NULL, NULL, &detail, &sqlrc) ==
              MURMUR_SEARCH_OK,
          "noted refresh %s", detail ? detail : "");
    free(detail);
    detail = NULL;
    CHECK(!murmur_search_pending(m), "noted still pending");
    murmur_search_close(c2);
    /* Wrong column type fails validation. */
    exec_ok(db, "CREATE TABLE bad(id INTEGER PRIMARY KEY, v BLOB);");
    murmur_search_def_t bd = d;
    bd.name = "fbad";
    bd.source_table = "bad";
    murmur_search_manager_t *mb = NULL;
    CHECK(murmur_search_open(&bd, 1, 1 << 20, 64, &mb, &detail) ==
              MURMUR_SEARCH_OK,
          "bad open %s", detail ? detail : "");
    free(detail);
    detail = NULL;
    CHECK(murmur_search_sync_schema(mb, db, 0, &detail, &sqlrc) ==
              MURMUR_SEARCH_INVALID,
          "blob fts column accepted");
    free(detail);
    detail = NULL;
    murmur_search_close(mb);
    /* Drop removes temp tables. */
    CHECK(murmur_search_drop(m, db, &detail, &sqlrc) == MURMUR_SEARCH_OK,
          "drop %s", detail ? detail : "");
    free(detail);
    detail = NULL;
    CHECK(count_query(db, "SELECT COUNT(*) FROM sqlite_temp_schema WHERE "
                          "name LIKE 'ft%'") == 0,
          "temp residue");
    murmur_search_close(m);
    sqlite3_close(db);
  }

  /* Suite 7: WITHOUT ROWID source invalidates but still serves. */
  {
    sqlite3 *db = open_db();
    const char *cols[] = {"body"};
    murmur_search_manager_t *m = open_fts("ft", "docs", cols, 1, 64);
    if (!db || !m) {
      return 1;
    }
    char *detail = NULL;
    int sqlrc = 0;
    exec_ok(db, "CREATE TABLE docs(id INTEGER PRIMARY KEY, body TEXT) WITHOUT "
                "ROWID;");
    exec_ok(db, "INSERT INTO docs VALUES(1,'alpha'),(2,'beta');");
    CHECK(murmur_search_sync_schema(m, db, 0, &detail, &sqlrc) ==
              MURMUR_SEARCH_OK,
          "sync %s", detail ? detail : "");
    free(detail);
    detail = NULL;
    murmur_search_attach(m, db);
    CHECK(murmur_search_refresh(m, db, NULL, NULL, &detail, &sqlrc) ==
              MURMUR_SEARCH_OK,
          "refresh %s", detail ? detail : "");
    free(detail);
    detail = NULL;
    exec_ok(db, "INSERT INTO docs VALUES(3,'gamma');");
    murmur_search_index_status_t *st = NULL;
    size_t nst = 0;
    CHECK(murmur_search_pending(m), "worowid write not pending");
    CHECK(murmur_search_tick(m, db, NULL, NULL, &detail, &sqlrc) ==
              MURMUR_SEARCH_OK,
          "tick %s", detail ? detail : "");
    free(detail);
    detail = NULL;
    /* The tripwire rebuilt the index in one bounded turn. */
    CHECK(murmur_search_status(m, &st, &nst) == MURMUR_SEARCH_OK && nst == 1,
          "status");
    CHECK(st[0].ready && !st[0].rebuilding, "worowid not ready after tick");
    murmur_search_status_free(st, nst);
    CHECK(count_query(db, "SELECT COUNT(*) FROM temp.ft WHERE ft MATCH 'gamma'") ==
              1,
          "worowid query");
    murmur_search_close(m);
    sqlite3_close(db);
  }

  if (failures) {
    printf("SEARCH-FAIL (%d)\n", failures);
    return 1;
  }
  printf("SEARCH-OK (7 suites)\n");
  return 0;
}
