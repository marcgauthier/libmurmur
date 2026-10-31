/* vec0 module selftest: murmur's brute-force vector index over real
 * SQLite. Suites: DDL validation, L2 ordering/distances/k, query
 * forms, L1/cosine orderings, update/delete/size guards,
 * transactional shadow behavior. */
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sqlite3.h"
#include "vec0.h"

static int failures = 0;

#define CHECK(cond, ...)                                                     \
  do {                                                                       \
    if (!(cond)) {                                                           \
      printf("FAIL vec0:%d: ", __LINE__);                                    \
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
  if (murmurRegisterVec0(db) != SQLITE_OK) {
    printf("FAIL register\n");
    failures++;
    sqlite3_close(db);
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

static int exec_fails(sqlite3 *db, const char *sql) {
  char *err = NULL;
  int rc = sqlite3_exec(db, sql, NULL, NULL, &err);
  sqlite3_free(err);
  return rc != SQLITE_OK;
}

/* Rows of (rowid, distance) for a KNN query. */
static int knn(sqlite3 *db, const char *sql, int64_t *ids, double *dist,
               int cap) {
  sqlite3_stmt *st = NULL;
  if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK) {
    printf("FAIL prepare: %s (%s)\n", sql, sqlite3_errmsg(db));
    failures++;
    return -1;
  }
  int n = 0;
  int rc = 0;
  while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
    if (n < cap) {
      ids[n] = sqlite3_column_int64(st, 0);
      dist[n] = sqlite3_column_double(st, 1);
    }
    n++;
  }
  if (rc != SQLITE_DONE) {
    printf("FAIL step: %s (%s)\n", sql, sqlite3_errmsg(db));
    failures++;
    sqlite3_finalize(st);
    return -1;
  }
  sqlite3_finalize(st);
  return n;
}

static void bind_vec(sqlite3 *db, const char *table, int64_t id,
                     const float *v, int dims) {
  char sql[256];
  snprintf(sql, sizeof(sql), "INSERT INTO temp.%s(rowid, embedding) VALUES(?,?)",
           table);
  sqlite3_stmt *st = NULL;
  if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK) {
    printf("FAIL prepare insert %s\n", sqlite3_errmsg(db));
    failures++;
    return;
  }
  sqlite3_bind_int64(st, 1, id);
  sqlite3_bind_blob(st, 2, v, dims * 4, SQLITE_TRANSIENT);
  if (sqlite3_step(st) != SQLITE_DONE) {
    printf("FAIL insert %s\n", sqlite3_errmsg(db));
    failures++;
  }
  sqlite3_finalize(st);
}

static int dbl_eq(double a, double b) { return fabs(a - b) < 1e-6; }

int main(void) {
  /* Suite 1: DDL validation. */
  {
    sqlite3 *db = open_db();
    if (!db) {
      return 1;
    }
    CHECK(exec_ok(db, "CREATE VIRTUAL TABLE temp.v USING "
                      "vec0(embedding float[2] distance_metric=l2)"),
          "create l2");
    CHECK(exec_fails(db, "CREATE VIRTUAL TABLE temp.b0 USING vec0(embedding "
                         "float[0])"),
          "dims 0 accepted");
    CHECK(exec_fails(db, "CREATE VIRTUAL TABLE temp.b1 USING vec0(embedding "
                         "float[8193])"),
          "dims 8193 accepted");
    CHECK(exec_fails(db, "CREATE VIRTUAL TABLE temp.b2 USING vec0(embedding "
                         "float[2] distance_metric=dot)"),
          "bad metric accepted");
    CHECK(exec_fails(db, "CREATE VIRTUAL TABLE temp.b3 USING vec0(float[2])"),
          "missing column accepted");
    CHECK(exec_ok(db, "CREATE VIRTUAL TABLE temp.vl1 USING "
                      "vec0(embedding float[3] distance_metric=l1)"),
          "create l1");
    CHECK(exec_ok(db, "CREATE VIRTUAL TABLE temp.vc USING "
                      "vec0(embedding float[3] distance_metric=cosine)"),
          "create cosine");
    CHECK(exec_ok(db, "CREATE VIRTUAL TABLE temp.vd USING "
                      "vec0(embedding float[4])"),
          "default metric");
    sqlite3_close(db);
  }

  /* Suite 2: L2 ordering, distances, k limit. */
  {
    sqlite3 *db = open_db();
    if (!db) {
      return 1;
    }
    exec_ok(db, "CREATE VIRTUAL TABLE temp.v USING "
                "vec0(embedding float[2] distance_metric=l2)");
    float a[2] = {0.0f, 0.0f};
    float b[2] = {3.0f, 4.0f};
    float c[2] = {1.0f, 0.0f};
    bind_vec(db, "v", 1, a, 2);
    bind_vec(db, "v", 2, b, 2);
    bind_vec(db, "v", 3, c, 2);
    int64_t ids[8];
    double dist[8];
    int n = knn(db, "SELECT rowid, distance FROM temp.v WHERE embedding MATCH "
                    "'[0,0]' AND k=2",
                ids, dist, 8);
    CHECK(n == 2 && ids[0] == 1 && ids[1] == 3, "l2 order n=%d", n);
    CHECK(dbl_eq(dist[0], 0.0) && dbl_eq(dist[1], 1.0), "l2 dist %f %f",
          dist[0], dist[1]);
    n = knn(db, "SELECT rowid, distance FROM temp.v WHERE embedding MATCH "
                 "'[0,0]' AND k=10",
            ids, dist, 8);
    CHECK(n == 3 && ids[2] == 2 && dbl_eq(dist[2], 5.0), "l2 full n=%d", n);
    n = knn(db, "SELECT rowid, distance FROM temp.v WHERE embedding MATCH "
                 "'[0,0]' AND k=0",
            ids, dist, 8);
    CHECK(n == 0, "k=0 n=%d", n);
    sqlite3_close(db);
  }

  /* Suite 3: query forms (text variants, blob, rowid point lookup). */
  {
    sqlite3 *db = open_db();
    if (!db) {
      return 1;
    }
    exec_ok(db, "CREATE VIRTUAL TABLE temp.v USING "
                "vec0(embedding float[2] distance_metric=l2)");
    float a[2] = {0.0f, 0.0f};
    float b[2] = {10.0f, 0.0f};
    bind_vec(db, "v", 7, a, 2);
    bind_vec(db, "v", 9, b, 2);
    int64_t ids[8];
    double dist[8];
    int n = knn(db, "SELECT rowid, distance FROM temp.v WHERE embedding MATCH "
                    "'10, 0' AND k=1",
                ids, dist, 8);
    CHECK(n == 1 && ids[0] == 9, "bare text query");
    n = knn(db, "SELECT rowid, distance FROM temp.v WHERE embedding MATCH "
                 "'(10,0)' AND k=1",
            ids, dist, 8);
    CHECK(n == 1 && ids[0] == 9, "paren text query");
    /* Blob query binds the raw float32 bytes. */
    sqlite3_stmt *st = NULL;
    CHECK(sqlite3_prepare_v2(db, "SELECT rowid, distance FROM temp.v WHERE "
                                 "embedding MATCH ? AND k=1",
                             -1, &st, NULL) == SQLITE_OK,
          "blob prepare");
    if (st) {
      sqlite3_bind_blob(st, 1, b, 8, SQLITE_TRANSIENT);
      int rc = sqlite3_step(st);
      CHECK(rc == SQLITE_ROW && sqlite3_column_int64(st, 0) == 9, "blob query");
      sqlite3_finalize(st);
    }
    /* Rowid point lookup returns the stored vector. */
    CHECK(sqlite3_prepare_v2(db, "SELECT embedding FROM temp.v WHERE rowid=7",
                             -1, &st, NULL) == SQLITE_OK,
          "rowid prepare");
    if (st) {
      int rc = sqlite3_step(st);
      CHECK(rc == SQLITE_ROW && sqlite3_column_bytes(st, 0) == 8, "rowid hit");
      const float *got = sqlite3_column_blob(st, 0);
      CHECK(got && got[0] == 0.0f && got[1] == 0.0f, "rowid bytes");
      sqlite3_finalize(st);
    }
    /* Malformed query text fails the statement. */
    CHECK(exec_fails(db, "SELECT rowid FROM temp.v WHERE embedding MATCH "
                         "'[1]' AND k=1"),
          "short query accepted");
    sqlite3_close(db);
  }

  /* Suite 4: L1 and cosine orderings. */
  {
    sqlite3 *db = open_db();
    if (!db) {
      return 1;
    }
    exec_ok(db, "CREATE VIRTUAL TABLE temp.vl USING "
                "vec0(embedding float[2] distance_metric=l1)");
    exec_ok(db, "CREATE VIRTUAL TABLE temp.vc USING "
                "vec0(embedding float[2] distance_metric=cosine)");
    float a[2] = {0.0f, 0.0f};
    float b[2] = {2.0f, 1.0f};
    bind_vec(db, "vl", 1, a, 2);
    bind_vec(db, "vl", 2, b, 2);
    int64_t ids[8];
    double dist[8];
    int n = knn(db, "SELECT rowid, distance FROM temp.vl WHERE embedding MATCH "
                    "'[0,0]' AND k=2",
                ids, dist, 8);
    CHECK(n == 2 && ids[0] == 1 && dbl_eq(dist[1], 3.0), "l1 order/dist");
    float u[2] = {1.0f, 0.0f};
    float v[2] = {0.0f, 1.0f};
    float w[2] = {1.0f, 1.0f};
    bind_vec(db, "vc", 1, u, 2);
    bind_vec(db, "vc", 2, v, 2);
    bind_vec(db, "vc", 3, w, 2);
    n = knn(db, "SELECT rowid, distance FROM temp.vc WHERE embedding MATCH "
                 "'[1,0]' AND k=3",
            ids, dist, 8);
    CHECK(n == 3 && ids[0] == 1 && ids[1] == 3 && ids[2] == 2,
          "cosine order");
    CHECK(dbl_eq(dist[0], 0.0) && dbl_eq(dist[2], 1.0), "cosine dist");
    sqlite3_close(db);
  }

  /* Suite 5: update/delete/size guards. */
  {
    sqlite3 *db = open_db();
    if (!db) {
      return 1;
    }
    exec_ok(db, "CREATE VIRTUAL TABLE temp.v USING "
                "vec0(embedding float[2] distance_metric=l2)");
    float a[2] = {5.0f, 5.0f};
    bind_vec(db, "v", 1, a, 2);
    CHECK(exec_fails(db, "INSERT INTO temp.v(rowid, embedding) VALUES(2, x'00')"),
          "short blob accepted");
    CHECK(exec_fails(db, "INSERT INTO temp.v(rowid, embedding) VALUES(2, 'text')"),
          "text insert accepted");
    float b[2] = {1.0f, 1.0f};
    sqlite3_stmt *st = NULL;
    CHECK(sqlite3_prepare_v2(db, "UPDATE temp.v SET embedding=? WHERE rowid=1",
                             -1, &st, NULL) == SQLITE_OK,
          "update prepare");
    if (st) {
      sqlite3_bind_blob(st, 1, b, 8, SQLITE_TRANSIENT);
      CHECK(sqlite3_step(st) == SQLITE_DONE, "update step");
      sqlite3_finalize(st);
    }
    int64_t ids[8];
    double dist[8];
    int n = knn(db, "SELECT rowid, distance FROM temp.v WHERE embedding MATCH "
                    "'[1,1]' AND k=1",
                ids, dist, 8);
    CHECK(n == 1 && ids[0] == 1 && dbl_eq(dist[0], 0.0), "update visible");
    CHECK(exec_ok(db, "DELETE FROM temp.v WHERE rowid=1"), "delete");
    n = knn(db, "SELECT rowid, distance FROM temp.v WHERE embedding MATCH "
                 "'[1,1]' AND k=1",
            ids, dist, 8);
    CHECK(n == 0, "delete visible n=%d", n);
    sqlite3_close(db);
  }

  /* Suite 6: transactional shadow behavior + drop cleanup. */
  {
    sqlite3 *db = open_db();
    if (!db) {
      return 1;
    }
    exec_ok(db, "CREATE VIRTUAL TABLE temp.v USING "
                "vec0(embedding float[2] distance_metric=l2)");
    float a[2] = {2.0f, 0.0f};
    CHECK(exec_ok(db, "BEGIN"), "begin");
    bind_vec(db, "v", 1, a, 2);
    CHECK(exec_ok(db, "ROLLBACK"), "rollback");
    int64_t ids[8];
    double dist[8];
    int n = knn(db, "SELECT rowid, distance FROM temp.v WHERE embedding MATCH "
                    "'[0,0]' AND k=1",
                ids, dist, 8);
    CHECK(n == 0, "rollback n=%d", n);
    CHECK(exec_ok(db, "SAVEPOINT sp"), "savepoint");
    bind_vec(db, "v", 2, a, 2);
    CHECK(exec_ok(db, "ROLLBACK TO sp; RELEASE sp"), "savepoint rollback");
    n = knn(db, "SELECT rowid, distance FROM temp.v WHERE embedding MATCH "
                 "'[0,0]' AND k=1",
            ids, dist, 8);
    CHECK(n == 0, "savepoint rollback n=%d", n);
    sqlite3_stmt *st = NULL;
    CHECK(sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM sqlite_temp_schema "
                                 "WHERE name='v_vec0_data'",
                             -1, &st, NULL) == SQLITE_OK,
          "shadow probe");
    int64_t shadow = -1;
    if (st) {
      if (sqlite3_step(st) == SQLITE_ROW) {
        shadow = sqlite3_column_int64(st, 0);
      }
      sqlite3_finalize(st);
    }
    CHECK(shadow == 1, "shadow exists");
    CHECK(exec_ok(db, "DROP TABLE temp.v"), "drop");
    CHECK(sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM sqlite_temp_schema "
                                 "WHERE name='v_vec0_data'",
                             -1, &st, NULL) == SQLITE_OK,
          "shadow probe2");
    shadow = -1;
    if (st) {
      if (sqlite3_step(st) == SQLITE_ROW) {
        shadow = sqlite3_column_int64(st, 0);
      }
      sqlite3_finalize(st);
    }
    CHECK(shadow == 0, "shadow dropped");
    sqlite3_close(db);
  }

  if (failures) {
    printf("VEC-FAIL (%d)\n", failures);
    return 1;
  }
  printf("VEC-OK (6 suites)\n");
  return 0;
}
