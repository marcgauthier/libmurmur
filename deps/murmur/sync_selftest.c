/* sync_selftest - ports TestExportRoundTrip, TestExportPaginates,
 * TestExportValidation, TestExportOptOut, TestExportOverloaded,
 * TestStageApplyRoundTrip, TestApplyGuards, TestProgressReset,
 * TestStageBudget and TestObservedMax (sync_test.go) against the
 * native sync plane. Links libmurmur.a (SQLite + cr-sqlite + sync).
 *
 * Or: make selftest
 */
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "config.h"
#include "engine.h"
#include "kv.h"
#include "msgcodec.h"
#include "retain.h"
#include "retainpass.h"
#include "schema.h"
#include "schemaadopt.h"
#include "serve.h"
#include "snapbuild.h"
#include "txcodec.h"
#include "txretain.h"
#include "txsnap.h"
#include "sha256.h"
#include "sqlite3.h"
#include "sqlite_murmur_crsqlite.h"
#include "sync.h"

static int failures = 0;

#define CHECK(cond, ...)                                                 \
  do {                                                                   \
    if (!(cond)) {                                                       \
      printf("FAIL %s:%d: ", __func__, __LINE__);                        \
      printf(__VA_ARGS__);                                               \
      printf("\n");                                                      \
      failures++;                                                        \
    }                                                                    \
  } while (0)

static sqlite3 *open_crr(void) {
  sqlite3 *db = NULL;
  if (sqlite3_open(":memory:", &db) != SQLITE_OK) {
    printf("FAIL open: %s\n", sqlite3_errmsg(db));
    failures++;
    return NULL;
  }
  int sqlrc = 0;
  if (murmur_sync_ensure_schema(db, &sqlrc) != MURMUR_SYNC_OK) {
    printf("FAIL schema: %d\n", sqlrc);
    failures++;
    sqlite3_close(db);
    return NULL;
  }
  char *err = NULL;
  if (sqlite3_crsqlite_init(db, &err, NULL) != SQLITE_OK) {
    printf("FAIL crsqlite: %s\n", err ? err : "?");
    failures++;
    sqlite3_free(err);
    sqlite3_close(db);
    return NULL;
  }
  return db;
}

static void close_crr(sqlite3 *db) {
  sqlite3_exec(db, "SELECT crsql_finalize()", NULL, NULL, NULL);
  sqlite3_close(db);
}

static int exec_ok(sqlite3 *db, const char *sql, const char *what) {
  char *err = NULL;
  int rc = sqlite3_exec(db, sql, NULL, NULL, &err);
  if (rc != SQLITE_OK) {
    printf("FAIL %s: %s\n", what, err ? err : "?");
    failures++;
  }
  sqlite3_free(err);
  return rc == SQLITE_OK;
}

static int make_sync_table(sqlite3 *db, const char *name) {
  char sql[256];
  snprintf(sql, sizeof(sql),
           "CREATE TABLE %s(a INTEGER PRIMARY KEY NOT NULL, b TEXT);", name);
  if (!exec_ok(db, sql, "create")) {
    return 0;
  }
  /* Same text as Go MakeCRR: the name travels as a double-quoted
   * SQL identifier, which SQLite resolves to the table-name string. */
  snprintf(sql, sizeof(sql), "SELECT crsql_as_crr('main',\"%s\")", name);
  return exec_ok(db, sql, "crr");
}

static int64_t count_rows(sqlite3 *db, const char *query) {
  sqlite3_stmt *st = NULL;
  if (sqlite3_prepare_v2(db, query, -1, &st, NULL) != SQLITE_OK) {
    return -1;
  }
  int rc = sqlite3_step(st);
  int64_t n = rc == SQLITE_ROW ? sqlite3_column_int64(st, 0) : -1;
  sqlite3_finalize(st);
  return n;
}

static murmur_node_t node_fill(uint8_t b) {
  murmur_node_t n;
  memset(n.b, b, sizeof(n.b));
  return n;
}

static void test_export_roundtrip(void) {
  sqlite3 *db = open_crr();
  if (!db) {
    return;
  }
  make_sync_table(db, "t");
  exec_ok(db, "INSERT INTO t VALUES(1,'x'),(2,'y');", "insert");
  int64_t current = 0;
  int sqlrc = 0;
  CHECK(murmur_sync_db_version(db, &current, &sqlrc) == MURMUR_SYNC_OK,
        "db version st");
  CHECK(current > 0, "db version %lld", (long long)current);
  murmur_cursor_t from;
  memset(&from, 0, sizeof(from));
  murmur_export_t out;
  memset(&out, 0, sizeof(out));
  murmur_sync_status_t est =
      murmur_sync_export(db, &from, 1 << 20, 1 << 20, &out, &sqlrc);
  CHECK(est == MURMUR_SYNC_OK, "export st=%s sqlrc=%d",
        murmur_sync_status_str(est), sqlrc);
  murmur_cell_t cells[8];
  size_t n = 0;
  CHECK(murmur_cells_decode(out.blob, out.blob_len, cells, 8, &n) ==
            MURMUR_OK,
        "decode");
  /* Two rows x one data column (b; the PK is the identity) = 2. */
  CHECK(n == 2, "cells = %zu", n);
  for (size_t i = 0; i < n; i++) {
    CHECK(cells[i].table_len == 1 && cells[i].table[0] == 't',
          "cell %zu table", i);
    CHECK(cells[i].db_version > 0, "cell %zu version", i);
    CHECK(cells[i].site_len == 16, "cell %zu site", i);
  }
  CHECK(out.next.cursor.from == current, "resume from");
  CHECK(!out.next.cursor.has_after, "resume after");
  murmur_cursor_t resume = out.next.cursor;
  murmur_export_t empty;
  memset(&empty, 0, sizeof(empty));
  CHECK(murmur_sync_export(db, &resume, 1 << 20, 1 << 20, &empty, &sqlrc) ==
            MURMUR_SYNC_OK,
        "re-export");
  CHECK(empty.blob_len == 12, "empty len %zu", empty.blob_len);
  CHECK(empty.next.cursor.from == current, "empty from");
  CHECK(!empty.next.cursor.has_after, "empty after");
  murmur_sync_export_free(&out);
  murmur_sync_export_free(&empty);
  close_crr(db);
}

static void test_export_paginates(void) {
  sqlite3 *db = open_crr();
  if (!db) {
    return;
  }
  make_sync_table(db, "t");
  for (int i = 0; i < 12; i++) {
    char sql[64];
    snprintf(sql, sizeof(sql), "INSERT INTO t VALUES(%d,'r%d');", i, i);
    exec_ok(db, sql, "insert");
  }
  murmur_cursor_t from;
  memset(&from, 0, sizeof(from));
  int sqlrc = 0;
  murmur_export_t full;
  memset(&full, 0, sizeof(full));
  CHECK(murmur_sync_export(db, &from, 1 << 20, 1 << 20, &full, &sqlrc) ==
            MURMUR_SYNC_OK,
        "full export");
  murmur_cell_t fcells[64];
  size_t nfull = 0;
  murmur_cells_decode(full.blob, full.blob_len, fcells, 64, &nfull);
  size_t total = 0;
  int rounds = 0;
  murmur_stored_cursor_t cur;
  memset(&cur, 0, sizeof(cur));
  for (;;) {
    murmur_export_t page;
    memset(&page, 0, sizeof(page));
    if (murmur_sync_export(db, &cur.cursor, 300, 65536, &page, &sqlrc) !=
        MURMUR_SYNC_OK) {
      CHECK(0, "page export st");
      break;
    }
    murmur_cell_t pcells[64];
    size_t np = 0;
    murmur_cells_decode(page.blob, page.blob_len, pcells, 64, &np);
    total += np;
    rounds++;
    int last_page = !page.next.cursor.has_after;
    murmur_sync_cursor_free(&cur);
    cur = page.next;
    memset(&page.next, 0, sizeof(page.next));
    murmur_sync_export_free(&page);
    if (last_page || rounds > 64) {
      break;
    }
  }
  CHECK(rounds >= 2, "rounds = %d", rounds);
  CHECK(total == nfull, "paged %zu vs full %zu", total, nfull);
  murmur_sync_cursor_free(&cur);
  murmur_sync_export_free(&full);
  close_crr(db);
}

static void test_export_validation(void) {
  sqlite3 *db = open_crr();
  if (!db) {
    return;
  }
  make_sync_table(db, "t");
  exec_ok(db, "INSERT INTO t VALUES(1,'x');", "insert");
  int64_t current = 0;
  int sqlrc = 0;
  murmur_sync_db_version(db, &current, &sqlrc);
  murmur_export_t out;
  memset(&out, 0, sizeof(out));
  murmur_cursor_t neg;
  memset(&neg, 0, sizeof(neg));
  neg.from = -1;
  CHECK(murmur_sync_export(db, &neg, 1 << 20, 1 << 20, &out, &sqlrc) ==
            MURMUR_SYNC_PROTOCOL,
        "negative from");
  int64_t through = current - 1;
  if (through < 0) {
    through = 0;
  }
  murmur_cursor_t below;
  memset(&below, 0, sizeof(below));
  below.from = current;
  below.has_through = 1;
  below.through = through;
  CHECK(murmur_sync_export(db, &below, 1 << 20, 1 << 20, &out, &sqlrc) ==
            MURMUR_SYNC_PROTOCOL,
        "through<from");
  static const uint8_t pk1[] = {1};
  murmur_cursor_t orphan;
  memset(&orphan, 0, sizeof(orphan));
  orphan.from = 0;
  orphan.has_after = 1;
  orphan.after.version = current;
  orphan.after.seq = 1;
  orphan.after.table = (const uint8_t *)"t";
  orphan.after.table_len = 1;
  orphan.after.pk = pk1;
  orphan.after.pk_len = 1;
  orphan.after.cid = (const uint8_t *)"b";
  orphan.after.cid_len = 1;
  CHECK(murmur_sync_export(db, &orphan, 1 << 20, 1 << 20, &out, &sqlrc) ==
            MURMUR_SYNC_PROTOCOL,
        "after-without-through");
  murmur_cursor_t future;
  memset(&future, 0, sizeof(future));
  future.from = current + 1;
  CHECK(murmur_sync_export(db, &future, 1 << 20, 1 << 20, &out, &sqlrc) ==
            MURMUR_SYNC_PROTOCOL,
        "from>current");
  int64_t tt = current + 1;
  murmur_cursor_t fthrough;
  memset(&fthrough, 0, sizeof(fthrough));
  fthrough.from = 0;
  fthrough.has_through = 1;
  fthrough.through = tt;
  CHECK(murmur_sync_export(db, &fthrough, 1 << 20, 1 << 20, &out, &sqlrc) ==
            MURMUR_SYNC_PROTOCOL,
        "through>current");
  murmur_sync_export_free(&out);
  close_crr(db);
}

static void test_export_optout(void) {
  sqlite3 *db = open_crr();
  if (!db) {
    return;
  }
  make_sync_table(db, "t");
  make_sync_table(db, "u");
  exec_ok(db, "INSERT INTO t VALUES(1,'x'); INSERT INTO u VALUES(1,'y');",
          "insert");
  exec_ok(db,
          "INSERT INTO murmur_config(name,value) "
          "VALUES('table_replication','{\"t\":false}')",
          "optout");
  murmur_cursor_t from;
  memset(&from, 0, sizeof(from));
  int sqlrc = 0;
  murmur_export_t out;
  memset(&out, 0, sizeof(out));
  CHECK(murmur_sync_export(db, &from, 1 << 20, 1 << 20, &out, &sqlrc) ==
            MURMUR_SYNC_OK,
        "export");
  murmur_cell_t cells[16];
  size_t n = 0;
  CHECK(murmur_cells_decode(out.blob, out.blob_len, cells, 16, &n) ==
            MURMUR_OK,
        "decode");
  CHECK(n > 0, "all cells skipped");
  for (size_t i = 0; i < n; i++) {
    CHECK(!(cells[i].table_len == 1 && cells[i].table[0] == 't'),
          "opted-out cell exported");
  }
  murmur_sync_export_free(&out);
  close_crr(db);
}

static void test_export_overloaded(void) {
  sqlite3 *db = open_crr();
  if (!db) {
    return;
  }
  make_sync_table(db, "t");
  char *big = (char *)malloc(70001);
  memset(big, 'v', 70000);
  big[70000] = '\0';
  char *sql = (char *)malloc(70064);
  snprintf(sql, 70064, "INSERT INTO t VALUES(1,'%s');", big);
  exec_ok(db, sql, "big insert");
  free(sql);
  free(big);
  murmur_cursor_t from;
  memset(&from, 0, sizeof(from));
  int sqlrc = 0;
  murmur_export_t out;
  memset(&out, 0, sizeof(out));
  CHECK(murmur_sync_export(db, &from, 1 << 20, 65536, &out, &sqlrc) ==
            MURMUR_SYNC_OVERLOADED,
        "oversize not overloaded");
  murmur_sync_export_free(&out);
  close_crr(db);
}

static int stage_all(sqlite3 *db, const murmur_node_t *node,
                     const uint8_t *blob, size_t len) {
  int sqlrc = 0;
  if (murmur_sync_stage_begin(db, node, 300000, &sqlrc) != MURMUR_SYNC_OK) {
    return 0;
  }
  size_t mid = len / 2;
  if (murmur_sync_stage(db, node, 0, blob, mid, 1 << 20, &sqlrc) !=
      MURMUR_SYNC_OK) {
    return 0;
  }
  return murmur_sync_stage(db, node, 1, blob + mid, len - mid, 1 << 20,
                           &sqlrc) == MURMUR_SYNC_OK;
}

static void sha256sum(const uint8_t *blob, size_t len, uint8_t out[32]) {
  murmur_sha256_t c;
  murmur_sha256_init(&c);
  murmur_sha256_update(&c, blob, len);
  murmur_sha256_final(&c, out);
}

static void test_stage_apply(void) {
  sqlite3 *donor = open_crr();
  if (!donor) {
    return;
  }
  make_sync_table(donor, "t");
  exec_ok(donor, "INSERT INTO t VALUES(1,'x'),(2,'y');", "insert");
  murmur_node_t donor_node = node_fill(0x11);
  murmur_node_t donor_site;
  int sqlrc = 0;
  CHECK(murmur_sync_site_id(donor, &donor_site, &sqlrc) == MURMUR_SYNC_OK,
        "donor site");
  murmur_cursor_t from;
  memset(&from, 0, sizeof(from));
  murmur_export_t batch;
  memset(&batch, 0, sizeof(batch));
  CHECK(murmur_sync_export(donor, &from, 1 << 20, 1 << 20, &batch, &sqlrc) ==
            MURMUR_SYNC_OK,
        "export");

  sqlite3 *db = open_crr();
  if (!db) {
    murmur_sync_export_free(&batch);
    close_crr(donor);
    return;
  }
  make_sync_table(db, "t");
  CHECK(murmur_sync_reset(db, &donor_node, &donor_site, &sqlrc) ==
            MURMUR_SYNC_OK,
        "reset");
  murmur_node_t site;
  int has_site = 0;
  murmur_stored_cursor_t previous;
  memset(&previous, 0, sizeof(previous));
  CHECK(murmur_sync_progress(db, &donor_node, &site, &has_site, &previous,
                             &sqlrc) == MURMUR_SYNC_OK &&
            has_site && memcmp(site.b, donor_site.b, 16) == 0,
        "progress after reset");
  CHECK(stage_all(db, &donor_node, batch.blob, batch.blob_len), "stage");
  uint8_t digest[32];
  sha256sum(batch.blob, batch.blob_len, digest);
  CHECK(murmur_sync_apply(db, &donor_node, &donor_site, &previous.cursor,
                          &batch.next.cursor, batch.blob_len, digest,
                          &sqlrc) == MURMUR_SYNC_OK,
        "apply");
  sqlite3_stmt *st = NULL;
  if (sqlite3_prepare_v2(db, "SELECT b FROM t WHERE a=1", -1, &st, NULL) ==
      SQLITE_OK) {
    int rc = sqlite3_step(st);
    const uint8_t *b = rc == SQLITE_ROW ? sqlite3_column_text(st, 0) : NULL;
    CHECK(rc == SQLITE_ROW && b && strcmp((const char *)b, "x") == 0,
          "row content");
    sqlite3_finalize(st);
  } else {
    CHECK(0, "row query");
  }
  murmur_stored_cursor_t stored;
  memset(&stored, 0, sizeof(stored));
  CHECK(murmur_sync_progress(db, &donor_node, &site, &has_site, &stored,
                             &sqlrc) == MURMUR_SYNC_OK,
        "progress after apply");
  uint8_t e1[512], e2[512];
  size_t n1 = murmur_cursor_encode(&stored.cursor, e1, sizeof(e1));
  size_t n2 =
      murmur_cursor_encode(&batch.next.cursor, e2, sizeof(e2));
  CHECK(n1 == n2 && memcmp(e1, e2, n1) == 0, "stored cursor");
  char pkey[64];
  size_t pkey_len = murmur_progress_key(&donor_node, pkey, sizeof(pkey));
  sqlite3_stmt *kv = NULL;
  uint64_t applied = 0;
  int have_head = 0;
  if (sqlite3_prepare_v2(db, "SELECT value FROM murmur_kv WHERE key=?1", -1,
                         &kv, NULL) == SQLITE_OK) {
    sqlite3_bind_blob(kv, 1, pkey, (int)pkey_len, SQLITE_TRANSIENT);
    if (sqlite3_step(kv) == SQLITE_ROW) {
      const uint8_t *v = sqlite3_column_blob(kv, 0);
      int vn = sqlite3_column_bytes(kv, 0);
      have_head = murmur_u64_decode(v, (size_t)vn, &applied) == MURMUR_OK;
    }
    sqlite3_finalize(kv);
  }
  CHECK(have_head && applied == (uint64_t)batch.next.cursor.from,
        "applied head");
  CHECK(count_rows(db, "SELECT COUNT(*) FROM murmur_stage") == 0,
        "stage drained");
  murmur_sync_cursor_free(&previous);
  murmur_sync_cursor_free(&stored);
  murmur_sync_export_free(&batch);
  close_crr(db);
  close_crr(donor);
}

static void test_apply_guards(void) {
  /* moved progress */
  {
    sqlite3 *donor = open_crr();
    sqlite3 *db = open_crr();
    if (donor && db) {
      make_sync_table(donor, "t");
      exec_ok(donor, "INSERT INTO t VALUES(1,'x');", "insert");
      murmur_node_t node = node_fill(0x11), site;
      int sqlrc = 0;
      murmur_sync_site_id(donor, &site, &sqlrc);
      murmur_cursor_t from;
      memset(&from, 0, sizeof(from));
      murmur_export_t batch;
      memset(&batch, 0, sizeof(batch));
      murmur_sync_export(donor, &from, 1 << 20, 1 << 20, &batch, &sqlrc);
      make_sync_table(db, "t");
      murmur_sync_reset(db, &node, &site, &sqlrc);
      stage_all(db, &node, batch.blob, batch.blob_len);
      murmur_cursor_t wrong;
      memset(&wrong, 0, sizeof(wrong));
      wrong.from = 999;
      uint8_t digest[32];
      sha256sum(batch.blob, batch.blob_len, digest);
      CHECK(murmur_sync_apply(db, &node, &site, &wrong, &batch.next.cursor,
                              batch.blob_len, digest, &sqlrc) ==
                MURMUR_SYNC_PROTOCOL,
            "moved progress accepted");
      murmur_sync_export_free(&batch);
    }
    if (db) {
      close_crr(db);
    }
    if (donor) {
      close_crr(donor);
    }
  }
  /* wrong site */
  {
    sqlite3 *donor = open_crr();
    sqlite3 *db = open_crr();
    if (donor && db) {
      make_sync_table(donor, "t");
      exec_ok(donor, "INSERT INTO t VALUES(1,'x');", "insert");
      murmur_node_t node = node_fill(0x11), site;
      int sqlrc = 0;
      murmur_sync_site_id(donor, &site, &sqlrc);
      murmur_cursor_t from;
      memset(&from, 0, sizeof(from));
      murmur_export_t batch;
      memset(&batch, 0, sizeof(batch));
      murmur_sync_export(donor, &from, 1 << 20, 1 << 20, &batch, &sqlrc);
      make_sync_table(db, "t");
      murmur_sync_reset(db, &node, &site, &sqlrc);
      stage_all(db, &node, batch.blob, batch.blob_len);
      murmur_node_t other = node_fill(0x33);
      murmur_cursor_t prev;
      memset(&prev, 0, sizeof(prev));
      uint8_t digest[32];
      sha256sum(batch.blob, batch.blob_len, digest);
      CHECK(murmur_sync_apply(db, &node, &other, &prev, &batch.next.cursor,
                              batch.blob_len, digest, &sqlrc) ==
                MURMUR_SYNC_PROTOCOL,
            "wrong site accepted");
      murmur_sync_export_free(&batch);
    }
    if (db) {
      close_crr(db);
    }
    if (donor) {
      close_crr(donor);
    }
  }
  /* missing chunk */
  {
    sqlite3 *donor = open_crr();
    sqlite3 *db = open_crr();
    if (donor && db) {
      make_sync_table(donor, "t");
      exec_ok(donor, "INSERT INTO t VALUES(1,'x');", "insert");
      murmur_node_t node = node_fill(0x11), site;
      int sqlrc = 0;
      murmur_sync_site_id(donor, &site, &sqlrc);
      murmur_cursor_t from;
      memset(&from, 0, sizeof(from));
      murmur_export_t batch;
      memset(&batch, 0, sizeof(batch));
      murmur_sync_export(donor, &from, 1 << 20, 1 << 20, &batch, &sqlrc);
      make_sync_table(db, "t");
      murmur_sync_reset(db, &node, &site, &sqlrc);
      murmur_sync_stage_begin(db, &node, 300000, &sqlrc);
      size_t mid = batch.blob_len / 2;
      murmur_sync_stage(db, &node, 0, batch.blob, mid, 1 << 20, &sqlrc);
      murmur_sync_stage(db, &node, 2, batch.blob + mid, batch.blob_len - mid,
                        1 << 20, &sqlrc);
      murmur_cursor_t prev;
      memset(&prev, 0, sizeof(prev));
      uint8_t digest[32];
      sha256sum(batch.blob, batch.blob_len, digest);
      CHECK(murmur_sync_apply(db, &node, &site, &prev, &batch.next.cursor,
                              batch.blob_len, digest, &sqlrc) ==
                MURMUR_SYNC_PROTOCOL,
            "missing chunk accepted");
      murmur_sync_export_free(&batch);
    }
    if (db) {
      close_crr(db);
    }
    if (donor) {
      close_crr(donor);
    }
  }
  /* bad digest and bad length */
  {
    sqlite3 *donor = open_crr();
    sqlite3 *db = open_crr();
    if (donor && db) {
      make_sync_table(donor, "t");
      exec_ok(donor, "INSERT INTO t VALUES(1,'x');", "insert");
      murmur_node_t node = node_fill(0x11), site;
      int sqlrc = 0;
      murmur_sync_site_id(donor, &site, &sqlrc);
      murmur_cursor_t from;
      memset(&from, 0, sizeof(from));
      murmur_export_t batch;
      memset(&batch, 0, sizeof(batch));
      murmur_sync_export(donor, &from, 1 << 20, 1 << 20, &batch, &sqlrc);
      make_sync_table(db, "t");
      murmur_sync_reset(db, &node, &site, &sqlrc);
      stage_all(db, &node, batch.blob, batch.blob_len);
      murmur_cursor_t prev;
      memset(&prev, 0, sizeof(prev));
      uint8_t bad[32];
      memset(bad, 0, sizeof(bad));
      CHECK(murmur_sync_apply(db, &node, &site, &prev, &batch.next.cursor,
                              batch.blob_len, bad, &sqlrc) ==
                MURMUR_SYNC_PROTOCOL,
            "bad digest accepted");
      uint8_t digest[32];
      sha256sum(batch.blob, batch.blob_len, digest);
      CHECK(murmur_sync_apply(db, &node, &site, &prev, &batch.next.cursor,
                              batch.blob_len + 1, digest, &sqlrc) ==
                MURMUR_SYNC_PROTOCOL,
            "bad length accepted");
      murmur_sync_export_free(&batch);
    }
    if (db) {
      close_crr(db);
    }
    if (donor) {
      close_crr(donor);
    }
  }
  /* all-filtered apply skips ingest but advances progress */
  {
    sqlite3 *donor = open_crr();
    sqlite3 *db = open_crr();
    if (donor && db) {
      make_sync_table(donor, "t");
      exec_ok(donor, "INSERT INTO t VALUES(1,'x');", "insert");
      murmur_node_t node = node_fill(0x11), site;
      int sqlrc = 0;
      murmur_sync_site_id(donor, &site, &sqlrc);
      murmur_cursor_t from;
      memset(&from, 0, sizeof(from));
      murmur_export_t batch;
      memset(&batch, 0, sizeof(batch));
      murmur_sync_export(donor, &from, 1 << 20, 1 << 20, &batch, &sqlrc);
      make_sync_table(db, "t");
      murmur_sync_reset(db, &node, &site, &sqlrc);
      exec_ok(db,
              "INSERT INTO murmur_config(name,value) "
              "VALUES('table_replication','{\"t\":false}')",
              "optout");
      stage_all(db, &node, batch.blob, batch.blob_len);
      murmur_cursor_t prev;
      memset(&prev, 0, sizeof(prev));
      uint8_t digest[32];
      sha256sum(batch.blob, batch.blob_len, digest);
      CHECK(murmur_sync_apply(db, &node, &site, &prev, &batch.next.cursor,
                              batch.blob_len, digest, &sqlrc) ==
                MURMUR_SYNC_OK,
            "filtered apply");
      CHECK(count_rows(db, "SELECT COUNT(*) FROM t") == 0, "filtered rows");
      murmur_sync_export_free(&batch);
    }
    if (db) {
      close_crr(db);
    }
    if (donor) {
      close_crr(donor);
    }
  }
}

static void test_progress_misc(void) {
  sqlite3 *db = open_crr();
  if (!db) {
    return;
  }
  int sqlrc = 0;
  murmur_node_t node = node_fill(0x11);
  murmur_node_t site = node_fill(0x22);
  /* Missing progress: no site, default cursor. */
  murmur_node_t got;
  int has = 0;
  murmur_stored_cursor_t cur;
  memset(&cur, 0, sizeof(cur));
  CHECK(murmur_sync_progress(db, &node, &got, &has, &cur, &sqlrc) ==
            MURMUR_SYNC_OK && !has,
        "missing progress");
  CHECK(cur.cursor.from == 0 && !cur.cursor.has_after, "default cursor");
  murmur_sync_cursor_free(&cur);
  /* Reset stores site + default cursor. */
  CHECK(murmur_sync_reset(db, &node, &site, &sqlrc) == MURMUR_SYNC_OK,
        "reset");
  memset(&cur, 0, sizeof(cur));
  CHECK(murmur_sync_progress(db, &node, &got, &has, &cur, &sqlrc) ==
            MURMUR_SYNC_OK && has && memcmp(got.b, site.b, 16) == 0,
        "progress after reset");
  CHECK(cur.cursor.from == 0 && !cur.cursor.has_after, "reset cursor");
  murmur_sync_cursor_free(&cur);
  /* Stage budget refuses past the cap. */
  static const uint8_t ten[10] = {0};
  CHECK(murmur_sync_stage_begin(db, &node, 300000, &sqlrc) == MURMUR_SYNC_OK,
        "stage begin");
  CHECK(murmur_sync_stage(db, &node, 0, ten, sizeof(ten), 15, &sqlrc) ==
            MURMUR_SYNC_OK,
        "stage under budget");
  CHECK(murmur_sync_stage(db, &node, 1, ten, sizeof(ten), 15, &sqlrc) ==
            MURMUR_SYNC_OVERLOADED,
        "stage past budget accepted");
  /* Stage begin sweeps expired rows. */
  exec_ok(db,
          "INSERT INTO murmur_stage VALUES(x'00',0,x'01',unixepoch()*1000-"
          "99999)",
          "aged row");
  CHECK(count_rows(db, "SELECT COUNT(*) FROM murmur_stage") == 2,
        "staged rows");
  CHECK(murmur_sync_stage_begin(db, &node, 30000, &sqlrc) == MURMUR_SYNC_OK,
        "sweep begin");
  CHECK(count_rows(db, "SELECT COUNT(*) FROM murmur_stage") == 0,
        "sweep leftovers");
  /* Observed max merges upward only. */
  murmur_node_t origin = node_fill(0x33);
  CHECK(murmur_sync_observed_max(db, &origin, 7, &sqlrc) == MURMUR_SYNC_OK,
        "observed 7");
  CHECK(murmur_sync_observed_max(db, &origin, 5, &sqlrc) == MURMUR_SYNC_OK,
        "observed 5");
  char okey[64];
  size_t okey_len = murmur_observed_key(&origin, okey, sizeof(okey));
  sqlite3_stmt *st = NULL;
  uint64_t obs = 0;
  int have = 0;
  if (sqlite3_prepare_v2(db, "SELECT value FROM murmur_kv WHERE key=?1", -1,
                         &st, NULL) == SQLITE_OK) {
    sqlite3_bind_blob(st, 1, okey, (int)okey_len, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_ROW) {
      const uint8_t *v = sqlite3_column_blob(st, 0);
      int vn = sqlite3_column_bytes(st, 0);
      have = murmur_u64_decode(v, (size_t)vn, &obs) == MURMUR_OK;
    }
    sqlite3_finalize(st);
  }
  CHECK(have && obs == 7, "observed max");
  /* Site id is a stable 16-byte blob. */
  murmur_node_t s1, s2;
  CHECK(murmur_sync_site_id(db, &s1, &sqlrc) == MURMUR_SYNC_OK, "site id");
  CHECK(murmur_sync_site_id(db, &s2, &sqlrc) == MURMUR_SYNC_OK &&
            memcmp(s1.b, s2.b, 16) == 0,
        "site stable");
  close_crr(db);
}

static void test_retain_params(void) {
  sqlite3 *db = open_crr();
  if (!db) {
    return;
  }
  int sqlrc = 0;
  murmur_retain_params_t rp;
  CHECK(murmur_retain_params_from(db, &rp, &sqlrc) == MURMUR_SYNC_OK,
        "retain defaults");
  CHECK(rp.min_retained == 1000 && rp.max_offline_ms == 604800000 &&
            !rp.bootstrap_nonempty,
        "retain default values");
  murmur_snap_params_t sp;
  CHECK(murmur_snap_params_from(db, &sp, &sqlrc) == MURMUR_SYNC_OK,
        "snap defaults");
  CHECK(sp.snapshot_bytes == 536870912 &&
            sp.snapshot_staging_bytes == 536870912 &&
            sp.transfer_lifetime_ms == 604800000 &&
            sp.staging_transfers == 4096 &&
            sp.max_transaction_bytes == 67108864 &&
            sp.batch_bytes == 1048576 && sp.n_trusted == 0,
        "snap default values");
  murmur_snap_params_free(&sp);
  /* Overrides, including a dashed duplicate trust id. */
  exec_ok(db,
          "INSERT INTO murmur_config(name,value) VALUES"
          "('retention_min_kept','5'),"
          "('bootstrap','[\"a:1\"]'),"
          "('snapshot_trusted_sources','[\"11111111111111111111111111111111\","
          "\"11-11-11-11-11-11-11-11-11-11-11-11-11-11-11-11\","
          "\"22222222222222222222222222222222\"]')",
          "overrides");
  CHECK(murmur_retain_params_from(db, &rp, &sqlrc) == MURMUR_SYNC_OK,
        "retain overrides");
  CHECK(rp.min_retained == 5 && rp.bootstrap_nonempty, "retain override");
  CHECK(murmur_snap_params_from(db, &sp, &sqlrc) == MURMUR_SYNC_OK,
        "snap overrides");
  CHECK(sp.n_trusted == 2, "trusted count %zu", sp.n_trusted);
  if (sp.n_trusted == 2) {
    CHECK(sp.trusted[0].b[0] == 0x11 && sp.trusted[1].b[0] == 0x22,
          "trusted ids");
  }
  murmur_snap_params_free(&sp);
  /* Invalid values fail closed. */
  exec_ok(db,
          "INSERT INTO murmur_config(name,value) VALUES"
          "('retention_min_kept','x') ON CONFLICT(name) DO UPDATE SET "
          "value=excluded.value",
          "bad kept");
  CHECK(murmur_retain_params_from(db, &rp, &sqlrc) == MURMUR_SYNC_INVALID,
        "bad kept accepted");
  exec_ok(db,
          "INSERT INTO murmur_config(name,value) VALUES"
          "('retention_min_kept','5'),('snapshot_bytes','18446744073709551615')"
          " ON CONFLICT(name) DO UPDATE SET value=excluded.value",
          "big bytes");
  CHECK(murmur_snap_params_from(db, &sp, &sqlrc) == MURMUR_SYNC_INVALID,
        "oversize int accepted");
  exec_ok(db,
          "INSERT INTO murmur_config(name,value) VALUES"
          "('snapshot_bytes','1'),('snapshot_trusted_sources','{}')"
          " ON CONFLICT(name) DO UPDATE SET value=excluded.value",
          "bad trust");
  CHECK(murmur_snap_params_from(db, &sp, &sqlrc) == MURMUR_SYNC_INVALID,
        "non-array trust accepted");
  exec_ok(db,
          "UPDATE murmur_config SET value='[\"00000000000000000000000000000000\"]'"
          " WHERE name='snapshot_trusted_sources'",
          "zero trust");
  CHECK(murmur_snap_params_from(db, &sp, &sqlrc) == MURMUR_SYNC_INVALID,
        "zero id accepted");
  close_crr(db);
}

static void test_gc_stage(void) {
  sqlite3 *db = open_crr();
  if (!db) {
    return;
  }
  int sqlrc = 0;
  /* One aged row (past the 300000ms default), one fresh. */
  exec_ok(db,
          "INSERT INTO murmur_stage VALUES(x'11',0,x'01',unixepoch()*1000-"
          "300001)",
          "aged row");
  exec_ok(db,
          "INSERT INTO murmur_stage VALUES(x'11',1,x'02',unixepoch()*1000)",
          "fresh row");
  int64_t removed = 0;
  CHECK(murmur_gc_stage(db, &removed, &sqlrc) == MURMUR_SYNC_OK, "gc");
  CHECK(removed == 1, "removed = %lld", (long long)removed);
  CHECK(count_rows(db, "SELECT COUNT(*) FROM murmur_stage") == 1,
        "leftovers");
  /* Bad timeout fails closed. */
  exec_ok(db,
          "INSERT INTO murmur_config(name,value) VALUES('staging_timeout_ms','x')",
          "bad timeout");
  CHECK(murmur_gc_stage(db, &removed, &sqlrc) == MURMUR_SYNC_INVALID,
        "bad timeout accepted");
  close_crr(db);
}

static void test_gc_tombstones(void) {
  sqlite3 *db = open_crr();
  if (!db) {
    return;
  }
  make_sync_table(db, "t");
  exec_ok(db, "INSERT INTO t VALUES(1,'x'),(2,'y');", "insert");
  exec_ok(db, "DELETE FROM t WHERE a=1;", "delete");
  int sqlrc = 0;
  uint64_t mark = 99;
  CHECK(murmur_gc_watermark(db, &mark, &sqlrc) == MURMUR_SYNC_OK,
        "fresh watermark");
  CHECK(mark == 0, "fresh mark %llu", (unsigned long long)mark);
  /* Floor below the tombstone version: nothing deleted, but the
   * watermark still advances (Go advances unconditionally). */
  uint64_t deleted = 99;
  CHECK(murmur_gc_tombstones(db, 1, &deleted, &sqlrc) == MURMUR_SYNC_OK,
        "gc floor 1");
  CHECK(deleted == 0, "deleted = %llu", (unsigned long long)deleted);
  CHECK(murmur_gc_watermark(db, &mark, &sqlrc) == MURMUR_SYNC_OK,
        "mark after 1");
  CHECK(mark == 1, "mark = %llu", (unsigned long long)mark);
  CHECK(murmur_gc_tombstones(db, 2, &deleted, &sqlrc) == MURMUR_SYNC_OK,
        "gc floor 2");
  CHECK(deleted == 1, "deleted = %llu", (unsigned long long)deleted);
  CHECK(murmur_gc_watermark(db, &mark, &sqlrc) == MURMUR_SYNC_OK,
        "mark after 2");
  CHECK(mark == 2, "mark = %llu", (unsigned long long)mark);
  /* Live clocks survive. */
  CHECK(count_rows(db, "SELECT COUNT(*) FROM \"t__crsql_clock\"") == 1,
        "live clocks");
  /* Corrupt watermark fails closed. */
  exec_ok(db,
          "INSERT INTO murmur_config(name,value) VALUES('gc_watermark','x') "
          "ON CONFLICT(name) DO UPDATE SET value=excluded.value",
          "bad mark");
  CHECK(murmur_gc_watermark(db, &mark, &sqlrc) == MURMUR_SYNC_INVALID,
        "bad mark accepted");
  close_crr(db);
}

static void test_reap_orphans(void) {
  sqlite3 *db = open_crr();
  if (!db) {
    return;
  }
  make_sync_table(db, "t");
  make_sync_table(db, "u");
  exec_ok(db, "INSERT INTO t VALUES(1,'x'); INSERT INTO u VALUES(1,'y');",
          "insert");
  exec_ok(db, "DROP TABLE t;", "drop t");
  int sqlrc = 0;
  uint64_t reaped = 0;
  CHECK(murmur_reap_orphan_clocks(db, &reaped, &sqlrc) == MURMUR_SYNC_OK,
        "reap");
  CHECK(reaped >= 1, "reaped = %llu", (unsigned long long)reaped);
  CHECK(count_rows(db,
                   "SELECT COUNT(*) FROM sqlite_schema WHERE name="
                   "'t__crsql_clock'") == 0,
        "orphan clock survives");
  CHECK(count_rows(db,
                   "SELECT COUNT(*) FROM sqlite_schema WHERE name="
                   "'u__crsql_clock'") == 1,
        "live clock reaped");
  /* The peak version pinned into crsql_master. */
  sqlite3_stmt *st = NULL;
  int64_t pinned = 0;
  if (sqlite3_prepare_v2(db,
                         "SELECT CAST(value AS INTEGER) FROM crsql_master "
                         "WHERE key='pre_compact_dbversion'",
                         -1, &st, NULL) == SQLITE_OK) {
    if (sqlite3_step(st) == SQLITE_ROW) {
      pinned = sqlite3_column_int64(st, 0);
    }
    sqlite3_finalize(st);
  }
  CHECK(pinned >= 1, "pinned = %lld", (long long)pinned);
  /* Second reap is a no-op. */
  reaped = 99;
  CHECK(murmur_reap_orphan_clocks(db, &reaped, &sqlrc) == MURMUR_SYNC_OK,
        "reap again");
  CHECK(reaped == 0, "reaped = %llu", (unsigned long long)reaped);
  close_crr(db);
}

static void check_valid(sqlite3 *db, const char *name, const char *value,
                        int want) {
  int got = murmur_cfg_validate(db, name, (const uint8_t *)value,
                                value ? strlen(value) : 0);
  CHECK((got == 0) == (want != 0), "validate %s='%s' want %d", name,
        value ? value : "(null)", want);
}

static void test_config_validate(void) {
  sqlite3 *db = open_crr();
  if (!db) {
    return;
  }
  /* Unknown names, NULs, oversize. */
  check_valid(db, "nope", "1", 0);
  check_valid(db, "sessions", "32", 1);
  {
    static const uint8_t nul[] = {'3', 0, '2'};
    CHECK(murmur_cfg_validate(db, "sessions", nul, sizeof(nul)) != 0,
          "NUL accepted");
  }
  /* Ids and toggles. */
  check_valid(db, "group_id", "11111111111111111111111111111111", 1);
  check_valid(db, "group_id", "1111-1111-1111-1111-111111111111", 0);
  check_valid(db, "group_id", "", 0);
  check_valid(db, "group_id", "00000000000000000000000000000000", 0);
  check_valid(db, "schema_master", "", 1);
  check_valid(db, "schema_master", "zz", 0);
  check_valid(db, "retention_gc", "1", 1);
  check_valid(db, "retention_gc", "2", 0);
  check_valid(db, "kdf", "direct", 1);
  check_valid(db, "kdf", "argon2id", 1);
  check_valid(db, "kdf", "AES", 0);
  /* Addresses. */
  check_valid(db, "bind", "0.0.0.0:7443", 1);
  check_valid(db, "bind", "[::1]:7443", 1);
  check_valid(db, "bind", "localhost:80", 1);
  check_valid(db, "bind", "nonexistent.invalid:80", 0);
  check_valid(db, "bind", ":80", 0);
  check_valid(db, "bind", "1.2.3.4", 0);
  check_valid(db, "bind", "1.2.3.4:99999", 0);
  check_valid(db, "advertise", "", 1);
  check_valid(db, "advertise", "example.com:80", 1);
  check_valid(db, "advertise", "nonexistent.invalid:80", 1);
  check_valid(db, "advertise", "exa_mple:80", 1);
  check_valid(db, "advertise", ":80", 1);
  check_valid(db, "advertise", "localhost:+80", 1);
  check_valid(db, "advertise", "host:badport", 0);
  check_valid(db, "advertise", "a b:80", 0);
  check_valid(db, "advertise", "host", 0);
  check_valid(db, "bootstrap", "[\"a:1\",\"[::1]:2\"]", 1);
  check_valid(db, "bootstrap", "[]", 1);
  check_valid(db, "bootstrap", "[\"a\"]", 0);
  check_valid(db, "bootstrap", "[1]", 0);
  check_valid(db, "bootstrap", "{}", 0);
  check_valid(db, "allowed_peers",
              "[\"11111111111111111111111111111111\"]", 1);
  check_valid(db, "allowed_peers", "[\"zz\"]", 0);
  check_valid(db, "allowed_networks", "[\"10.0.0.0/8\",\"::/0\"]", 1);
  check_valid(db, "allowed_networks", "[\"10.0.0.0/33\"]", 0);
  check_valid(db, "allowed_networks", "[\"10.0.0.0\"]", 0);
  check_valid(db, "allowed_networks", "[\"10.0.0.0/-1\"]", 0);
  /* Ranges (ParseUint: leading '+' allowed). */
  check_valid(db, "sessions", "32", 1);
  check_valid(db, "sessions", "+32", 0);
  check_valid(db, "sessions", "0", 0);
  check_valid(db, "sessions", "257", 0);
  check_valid(db, "sessions", " 32", 0);
  check_valid(db, "sessions", "18446744073709551616", 0);
  check_valid(db, "gossip_fanout", "1", 1);
  check_valid(db, "gossip_fanout", "33", 0);
  check_valid(db, "poll_ms", "10", 1);
  check_valid(db, "poll_ms", "9", 0);
  check_valid(db, "staging_timeout_ms", "60000", 1);
  check_valid(db, "staging_timeout_ms", "59999", 0);
  check_valid(db, "writer_local_share", "90", 1);
  check_valid(db, "writer_local_share", "100", 0);
  check_valid(db, "writer_remote_share", "10", 0);
  check_valid(db, "batch_bytes", "65536", 1);
  check_valid(db, "batch_bytes", "65535", 0);
  check_valid(db, "snapshot_bytes", "1099511627776", 1);
  check_valid(db, "snapshot_bytes", "1099511627777", 0);
  check_valid(db, "kdf_memory_kib", "1024", 1);
  check_valid(db, "kdf_memory_kib", "1023", 0);
  /* JSON maps. */
  check_valid(db, "table_replication", "{\"t\":false}", 1);
  check_valid(db, "table_replication", "{\"t\":0}", 0);
  check_valid(db, "table_replication", "{\"t\":{}}", 0);
  check_valid(db, "table_replication", "{\"\":true}", 0);
  check_valid(db, "column_policies", "{\"t.c\":\"Lww\"}", 1);
  check_valid(db, "column_policies", "{\"t\":\"Lww\"}", 0);
  check_valid(db, "column_policies", "{\"a.b.c\":\"Lww\"}", 0);
  check_valid(db, "column_policies", "{\"t.c\":\"Nope\"}", 0);
  check_valid(db, "snapshot_trusted_sources",
              "[\"11111111111111111111111111111111\"]", 1);
  check_valid(db, "snapshot_trusted_sources", "[\"x\"]", 0);
  check_valid(db, "files_dir", "/tmp/x", 1);
  check_valid(db, "bridge_role", "anything", 1);
  close_crr(db);
}

static void test_config_setting(void) {
  sqlite3 *db = open_crr();
  if (!db) {
    return;
  }
  int sqlrc = 0;
  char *v = NULL;
  CHECK(murmur_cfg_setting(db, "sessions", &v, &sqlrc) == MURMUR_SYNC_OK,
        "default read");
  CHECK(v && strcmp(v, "32") == 0, "default value %s", v ? v : "?");
  free(v);
  CHECK(murmur_cfg_setting(db, "nope", &v, &sqlrc) == MURMUR_SYNC_INVALID,
        "unknown accepted");
  /* Derived share tracks the local value. */
  CHECK(murmur_cfg_setting(db, "writer_remote_share", &v, &sqlrc) ==
            MURMUR_SYNC_OK,
        "derived default");
  CHECK(v && strcmp(v, "10") == 0, "derived %s", v ? v : "?");
  free(v);
  static const uint8_t eighty[] = "80";
  CHECK(murmur_cfg_set_setting(db, "writer_local_share", eighty,
                               sizeof(eighty) - 1,
                               &sqlrc) == MURMUR_SYNC_OK,
        "set local");
  CHECK(murmur_cfg_setting(db, "writer_remote_share", &v, &sqlrc) ==
            MURMUR_SYNC_OK && v && strcmp(v, "20") == 0,
        "derived tracks");
  free(v);
  /* Set validates before persisting. */
  static const uint8_t bad[] = "999";
  CHECK(murmur_cfg_set_setting(db, "sessions", bad, sizeof(bad) - 1,
                               &sqlrc) == MURMUR_SYNC_INVALID,
        "bad set accepted");
  CHECK(murmur_cfg_setting(db, "sessions", &v, &sqlrc) == MURMUR_SYNC_OK &&
            v && strcmp(v, "32") == 0,
        "bad set persisted");
  free(v);
  static const uint8_t remote[] = "10";
  CHECK(murmur_cfg_set_setting(db, "writer_remote_share", remote,
                               sizeof(remote) - 1,
                               &sqlrc) == MURMUR_SYNC_INVALID,
        "derived set accepted");
  close_crr(db);
}

static uint8_t *pairs_blob(const char *tables[], const char *ddls[],
                           size_t n, size_t *len) {
  static uint8_t scratch[65536];
  murmur_schema_pair_t *v = NULL;
  if (n > 0) {
    v = (murmur_schema_pair_t *)malloc(n * sizeof(*v));
    if (!v) {
      return NULL;
    }
    for (size_t i = 0; i < n; i++) {
      size_t tl = strlen(tables[i]), dl = strlen(ddls[i]);
      v[i].table = tl ? (const uint8_t *)tables[i] : NULL;
      v[i].table_len = tl;
      v[i].ddl = dl ? (const uint8_t *)ddls[i] : NULL;
      v[i].ddl_len = dl;
    }
  }
  size_t w = murmur_schema_pairs_encode(v, n, scratch, sizeof(scratch));
  free(v);
  if (w == 0) {
    return NULL;
  }
  uint8_t *out = (uint8_t *)malloc(w);
  if (!out) {
    return NULL;
  }
  memcpy(out, scratch, w);
  *len = w;
  return out;
}

static void test_schema_discovery(void) {
  sqlite3 *db = open_crr();
  if (!db) {
    return;
  }
  int sqlrc = 0;
  murmur_schema_entry_t *pairs = NULL;
  size_t n = 0;
  CHECK(murmur_schema_pairs(db, &pairs, &n, &sqlrc) == MURMUR_SYNC_INVALID,
        "empty pairs accepted");
  uint8_t *blob = NULL;
  size_t len = 0;
  CHECK(murmur_schema_bytes(db, &blob, &len, &sqlrc) == MURMUR_SYNC_INVALID,
        "empty bytes accepted");
  make_sync_table(db, "u");
  make_sync_table(db, "t");
  CHECK(murmur_schema_pairs(db, &pairs, &n, &sqlrc) == MURMUR_SYNC_OK && n == 2,
        "pairs n=%zu rc=%d", n, sqlrc);
  if (n == 2) {
    CHECK(strcmp(pairs[0].table, "t") == 0 && strcmp(pairs[1].table, "u") == 0,
          "pairs order");
    CHECK(strstr(pairs[0].ddl, "CREATE TABLE t") != NULL, "pairs ddl");
  }
  murmur_schema_pairs_free(pairs, n);
  pairs = NULL;
  /* murmur_file_meta is the replicated internal table: converting it
   * leaves the subset unchanged (still just u+t). */
  static const uint8_t file_meta[] = "murmur_file_meta";
  CHECK(murmur_schema_make_crr(db, file_meta, sizeof(file_meta) - 1, &sqlrc) ==
            MURMUR_SYNC_OK,
        "file_meta make_crr rc=%d", sqlrc);
  CHECK(murmur_schema_pairs(db, &pairs, &n, &sqlrc) == MURMUR_SYNC_OK &&
            n == 2,
        "file_meta pairs n=%zu rc=%d", n, sqlrc);
  if (n == 2) {
    CHECK(strcmp(pairs[0].table, "t") == 0 && strcmp(pairs[1].table, "u") == 0,
          "file_meta excluded");
  }
  murmur_schema_pairs_free(pairs, n);
  pairs = NULL;
  CHECK(murmur_schema_make_crr(db, file_meta, sizeof(file_meta) - 1, &sqlrc) ==
            MURMUR_SYNC_OK,
        "file_meta make_crr idempotent rc=%d", sqlrc);
  CHECK(murmur_schema_bytes(db, &blob, &len, &sqlrc) == MURMUR_SYNC_OK &&
            len > 2 && blob[0] == 2,
        "bytes header len=%zu", len);
  uint8_t digest[32], expect[32];
  CHECK(murmur_schema_digest(db, digest, &sqlrc) == MURMUR_SYNC_OK,
        "digest rc=%d", sqlrc);
  murmur_sha256(blob, len, expect);
  CHECK(memcmp(digest, expect, 32) == 0, "digest mismatch");
  int yes = 0;
  static const uint8_t tname[] = "t";
  static const uint8_t xname[] = "nope";
  CHECK(murmur_schema_is_crr(db, tname, 1, &yes, &sqlrc) == MURMUR_SYNC_OK &&
            yes == 1,
        "is_crr t");
  CHECK(murmur_schema_is_crr(db, xname, 4, &yes, &sqlrc) == MURMUR_SYNC_OK &&
            yes == 0,
        "is_crr nope");
  /* native make_crr on a plain table, twice */
  exec_ok(db, "CREATE TABLE p(id INTEGER PRIMARY KEY NOT NULL);", "mkp");
  static const uint8_t pname[] = "p";
  CHECK(murmur_schema_make_crr(db, pname, 1, &sqlrc) == MURMUR_SYNC_OK,
        "make_crr rc=%d", sqlrc);
  CHECK(murmur_schema_is_crr(db, pname, 1, &yes, &sqlrc) == MURMUR_SYNC_OK &&
            yes == 1,
        "made crr");
  CHECK(murmur_schema_make_crr(db, pname, 1, &sqlrc) == MURMUR_SYNC_OK,
        "make_crr idempotent");
  /* manifest honors opt-outs; all-out signs the empty vec */
  free(blob);
  blob = NULL;
  exec_ok(db,
          "INSERT INTO murmur_config(name,value) "
          "VALUES('table_replication','{\"u\":false}') "
          "ON CONFLICT(name) DO UPDATE SET value=excluded.value;",
          "optout");
  CHECK(murmur_manifest_schema_bytes(db, &blob, &len, &sqlrc) ==
                MURMUR_SYNC_OK &&
            len > 1 && blob[0] == 2,
        "manifest kept len=%zu head=%u", len, blob ? blob[0] : 99);
  free(blob);
  blob = NULL;
  exec_ok(db,
          "INSERT INTO murmur_config(name,value) "
          "VALUES('table_replication','{\"t\":false,\"u\":false,\"p\":false}') "
          "ON CONFLICT(name) DO UPDATE SET value=excluded.value;",
          "optout all");
  CHECK(murmur_manifest_schema_bytes(db, &blob, &len, &sqlrc) ==
                MURMUR_SYNC_OK &&
            len == 1 && blob[0] == 0,
        "manifest empty len=%zu", len);
  free(blob);
  blob = NULL;
  /* murmur_ CRRs fail closed */
  exec_ok(db, "DELETE FROM murmur_config WHERE name='table_replication';",
          "optout clear");
  make_sync_table(db, "murmur_x");
  CHECK(murmur_schema_pairs(db, &pairs, &n, &sqlrc) == MURMUR_SYNC_INVALID,
        "murmur_ crr accepted");
  close_crr(db);
}

static void check_create_expect(const char *table, const char *ddl, int ok) {
  int sqlrc = 0;
  murmur_sync_status_t st = murmur_check_create_table(
      (const uint8_t *)table, strlen(table), (const uint8_t *)ddl, strlen(ddl),
      &sqlrc);
  CHECK((st == MURMUR_SYNC_OK) == ok, "create %s <%s> st=%d", table, ddl,
        (int)st);
}

static void check_addcol_expect(const char *def, int ok, const char *name) {
  int sqlrc = 0;
  char *got = NULL;
  murmur_sync_status_t st = murmur_check_add_column(
      (const uint8_t *)def, strlen(def), &got, &sqlrc);
  CHECK((st == MURMUR_SYNC_OK) == ok, "addcol <%s> st=%d", def, (int)st);
  if (ok && st == MURMUR_SYNC_OK) {
    CHECK(got && strcmp(got, name) == 0, "addcol name <%s> got <%s>", def,
          got ? got : "?");
  }
  free(got);
}

static void test_schema_checks(void) {
  check_create_expect("t", "CREATE TABLE t(a INT)", 1);
  check_create_expect("t", "create table t(a int)", 1);
  check_create_expect("t", "CREATE TABLE IF NOT EXISTS t(a INT)", 1);
  check_create_expect("t", "CREATE TABLE IF EXISTS t(a INT)", 0);
  check_create_expect("t", "CREATE TABLE t(a INT);", 1);
  check_create_expect("t", "CREATE TABLE t(a INT);  ", 1);
  check_create_expect("t", "CREATE TABLE t(a INT); SELECT 1", 0);
  check_create_expect("t", "CREATE TABLE main.t(a INT)", 1);
  check_create_expect("t", "CREATE TABLE \"t\"(a INT)", 1);
  check_create_expect("t", "CREATE TABLE [t](a INT)", 1);
  check_create_expect("t", "CREATE TABLE `t`(a INT)", 1);
  check_create_expect("t", "CREATE TABLE t(a INT) STRICT", 1);
  check_create_expect("t", "CREATE TABLE t(a INT, FOREIGN KEY(a) REFERENCES "
                           "u(a))",
                      1);
  check_create_expect("t", "CREATE VIEW t AS SELECT 1", 0);
  check_create_expect("t", "CREATE TABLE u(a INT)", 0);
  check_create_expect("t", "CREATE TABLE other.t(a INT)", 0);
  check_create_expect("t", "CREATE TABLE t", 0);
  check_create_expect("t", "CREATE TABLE \"t(a INT)", 0);
  check_create_expect("t", "CREATE TABLE t(a INT); DROP TABLE t", 0);
  check_create_expect("t", "CREATE TABLE t(a DEFAULT ';')", 1);
  check_create_expect("no-good!", "CREATE TABLE t(a INT)", 0);
  check_create_expect("t", "", 0);
  check_addcol_expect("c TEXT", 1, "c");
  check_addcol_expect("AbC TEXT", 1, "AbC");
  check_addcol_expect("\"c\" TEXT", 0, NULL);
  check_addcol_expect("ab\" TEXT", 0, NULL);
  check_addcol_expect("c TEXT DEFAULT 'x;y'", 1, "c");
  check_addcol_expect("c TEXT DEFAULT \"q\"", 1, "c");
  check_addcol_expect("", 0, NULL);
  check_addcol_expect("   ", 0, NULL);
  check_addcol_expect("PRIMARY KEY(x)", 0, NULL);
  check_addcol_expect("CHECK(x > 0)", 0, NULL);
  check_addcol_expect("INDEX i ON t(x)", 1, "INDEX");
  check_addcol_expect("c TEXT, d INT", 0, NULL);
  check_addcol_expect("c TEXT; SELECT 1", 0, NULL);
  check_addcol_expect("c TEXT;", 0, NULL);
  check_addcol_expect("a-b INT", 0, NULL);
  check_addcol_expect("\"a\"\"b\" INT", 0, NULL);
}

static void test_schema_diff(void) {
  int sqlrc = 0;
  const char *lt[] = {"t", "u"};
  const char *ld[] = {"CREATE TABLE t(a INT)", "CREATE TABLE u(a INT)"};
  size_t llen = 0;
  uint8_t *local = pairs_blob(lt, ld, 2, &llen);
  CHECK(local != NULL, "local blob");
  murmur_schema_diff_t d;
  memset(&d, 0, sizeof(d));
  CHECK(murmur_schema_diff(local, llen, local, llen, &d, &sqlrc) ==
                MURMUR_SYNC_OK &&
            d.additive && d.n_tables == 0 && d.n_columns == 0 &&
            !d.incompatible,
        "identical diff");
  murmur_schema_diff_free(&d);
  /* new table */
  const char *nt[] = {"t", "u", "v"};
  const char *nd[] = {"CREATE TABLE t(a INT)", "CREATE TABLE u(a INT)",
                      "CREATE TABLE v(a INT)"};
  size_t nlen = 0;
  uint8_t *remote = pairs_blob(nt, nd, 3, &nlen);
  CHECK(murmur_schema_diff(local, llen, remote, nlen, &d, &sqlrc) ==
                MURMUR_SYNC_OK &&
            d.additive && d.n_tables == 1 && d.n_columns == 0,
        "new table st=%d", sqlrc);
  if (d.n_tables == 1) {
    CHECK(strcmp(d.new_tables[0].table, "v") == 0 &&
              strcmp(d.new_tables[0].def, "CREATE TABLE v(a INT)") == 0,
          "new table ent");
  }
  murmur_schema_diff_free(&d);
  /* added column keeps the original element text */
  const char *ct[] = {"t", "u"};
  const char *cd[] = {"CREATE TABLE t(a INT,  b   TEXT  )",
                      "CREATE TABLE u(a INT)"};
  size_t clen = 0;
  uint8_t *coladd = pairs_blob(ct, cd, 2, &clen);
  CHECK(murmur_schema_diff(local, llen, coladd, clen, &d, &sqlrc) ==
                MURMUR_SYNC_OK &&
            d.additive && d.n_tables == 0 && d.n_columns == 1,
        "add column");
  if (d.n_columns == 1) {
    CHECK(strcmp(d.add_columns[0].table, "t") == 0 &&
              strcmp(d.add_columns[0].def, "b   TEXT") == 0,
          "add column ent <%s>", d.add_columns[0].def);
  }
  murmur_schema_diff_free(&d);
  /* whitespace/case-only drift is a silent no-op */
  const char *wt[] = {"t", "u"};
  const char *wd[] = {"create table t( a  int )", "CREATE TABLE u(a INT)"};
  size_t wlen = 0;
  uint8_t *ws = pairs_blob(wt, wd, 2, &wlen);
  CHECK(murmur_schema_diff(local, llen, ws, wlen, &d, &sqlrc) ==
                MURMUR_SYNC_OK &&
            d.additive && d.n_tables == 0 && d.n_columns == 0,
        "ws drift");
  murmur_schema_diff_free(&d);
  /* incompatible kinds arrive as data (OK + reason), like Go */
  static const char *bad_ddls[] = {
      "CREATE TABLE t(a TEXT)",                /* redefined */
      "CREATE TABLE t(a INT, PRIMARY KEY(a))", /* constraint */
      "CREATE TABLE t(oops",                   /* unparseable remote */
  };
  static const char *bad_reason[] = {
      "column redefined: t.a",
      "table constraint change: t",
      "unparseable remote DDL: t",
  };
  for (size_t i = 0; i < 3; i++) {
    const char *bt[] = {"t", "u"};
    const char *bd[] = {bad_ddls[i], "CREATE TABLE u(a INT)"};
    size_t blen = 0;
    uint8_t *bad = pairs_blob(bt, bd, 2, &blen);
    memset(&d, 0, sizeof(d));
    CHECK(murmur_schema_diff(local, llen, bad, blen, &d, &sqlrc) ==
                  MURMUR_SYNC_OK &&
              !d.additive && d.n_tables == 0 && d.n_columns == 0 &&
              d.incompatible && strcmp(d.incompatible, bad_reason[i]) == 0,
          "incompat %zu got <%s>", i, d.incompatible ? d.incompatible : "?");
    murmur_schema_diff_free(&d);
    /* swapped roles: the same DDL is unparseable local */
    if (i == 2) {
      memset(&d, 0, sizeof(d));
      CHECK(murmur_schema_diff(bad, blen, local, llen, &d, &sqlrc) ==
                      MURMUR_SYNC_OK &&
                  !d.additive && d.incompatible &&
                  strcmp(d.incompatible, "unparseable local DDL: t") == 0,
              "unparseable local got <%s>",
              d.incompatible ? d.incompatible : "?");
      murmur_schema_diff_free(&d);
    }
    free(bad);
  }
  /* local-extra column: kept, subset remote adopts as a no-op */
  {
    const char *bt[] = {"t", "u"};
    const char *bd[] = {"CREATE TABLE t(b TEXT)", "CREATE TABLE u(a INT)"};
    size_t blen = 0;
    uint8_t *sub = pairs_blob(bt, bd, 2, &blen);
    memset(&d, 0, sizeof(d));
    CHECK(murmur_schema_diff(coladd, clen, sub, blen, &d, &sqlrc) ==
                  MURMUR_SYNC_OK &&
              d.additive && d.n_tables == 0 && d.n_columns == 0 &&
              !d.incompatible,
          "subset st=%d", sqlrc);
    murmur_schema_diff_free(&d);
    free(sub);
  }
  /* divergent branches merge: local extras kept, remote extras adopted */
  {
    const char *bt[] = {"t", "u"};
    const char *bd[] = {"CREATE TABLE t(a INT, c TEXT)",
                        "CREATE TABLE u(a INT)"};
    size_t blen = 0;
    uint8_t *right = pairs_blob(bt, bd, 2, &blen);
    memset(&d, 0, sizeof(d));
    CHECK(murmur_schema_diff(coladd, clen, right, blen, &d, &sqlrc) ==
                  MURMUR_SYNC_OK &&
              d.additive && d.n_tables == 0 && d.n_columns == 1,
          "branch st=%d", sqlrc);
    if (d.n_columns == 1) {
      CHECK(strcmp(d.add_columns[0].table, "t") == 0 &&
                strcmp(d.add_columns[0].def, "c TEXT") == 0,
            "branch ent <%s>", d.add_columns[0].def);
    }
    murmur_schema_diff_free(&d);
    free(right);
  }
  /* retired table: kept, no-op adopt */
  const char *rt[] = {"t"};
  const char *rd[] = {"CREATE TABLE t(a INT)"};
  size_t rlen = 0;
  uint8_t *ret = pairs_blob(rt, rd, 1, &rlen);
  memset(&d, 0, sizeof(d));
  CHECK(murmur_schema_diff(local, llen, ret, rlen, &d, &sqlrc) ==
                MURMUR_SYNC_OK &&
            d.additive && d.n_tables == 0 && d.n_columns == 0 &&
            !d.incompatible,
        "retired st=%d", sqlrc);
  murmur_schema_diff_free(&d);
  free(ret);
  /* garbage fails closed */
  static const uint8_t garbage[] = {0x05, 0x01, 'x'};
  memset(&d, 0, sizeof(d));
  CHECK(murmur_schema_diff(garbage, sizeof(garbage), local, llen, &d,
                           &sqlrc) == MURMUR_SYNC_INVALID,
        "garbage local accepted");
  CHECK(murmur_schema_diff(local, llen, garbage, sizeof(garbage), &d,
                           &sqlrc) == MURMUR_SYNC_INVALID,
        "garbage remote accepted");
  int compat = 0;
  CHECK(murmur_puller_compatible(local, llen, local, llen, &compat, &sqlrc) ==
                MURMUR_SYNC_OK &&
            compat == 1,
        "puller self");
  CHECK(murmur_puller_compatible(local, llen, remote, nlen, &compat, &sqlrc) ==
                MURMUR_SYNC_OK &&
            compat == 1,
        "puller superset");
  CHECK(murmur_puller_compatible(remote, nlen, local, llen, &compat, &sqlrc) ==
                MURMUR_SYNC_OK &&
            compat == 0,
        "puller missing");
  CHECK(murmur_puller_compatible(local, llen, coladd, clen, &compat, &sqlrc) ==
                MURMUR_SYNC_OK &&
            compat == 1,
        "puller extra column");
  CHECK(murmur_puller_compatible(coladd, clen, local, llen, &compat, &sqlrc) ==
                MURMUR_SYNC_OK &&
            compat == 0,
        "puller missing column");
  /* same shape, different column order: merged branches stay compatible */
  {
    const char *bt[] = {"t", "u"};
    const char *bd[] = {"CREATE TABLE t(b TEXT, a INT)",
                        "CREATE TABLE u(a INT)"};
    size_t blen = 0;
    uint8_t *reord = pairs_blob(bt, bd, 2, &blen);
    CHECK(murmur_puller_compatible(coladd, clen, reord, blen, &compat,
                                   &sqlrc) == MURMUR_SYNC_OK &&
              compat == 1,
          "puller reorder");
    free(reord);
  }
  /* redefined column still fails */
  {
    const char *bt[] = {"t", "u"};
    const char *bd[] = {"CREATE TABLE t(a TEXT)", "CREATE TABLE u(a INT)"};
    size_t blen = 0;
    uint8_t *redef = pairs_blob(bt, bd, 2, &blen);
    CHECK(murmur_puller_compatible(local, llen, redef, blen, &compat,
                                   &sqlrc) == MURMUR_SYNC_OK &&
              compat == 0,
          "puller redefined");
    free(redef);
  }
  CHECK(murmur_puller_compatible(local, llen, garbage, sizeof(garbage),
                                 &compat,
                                 &sqlrc) == MURMUR_SYNC_INVALID,
        "puller garbage accepted");
  free(local);
  free(remote);
  free(coladd);
  free(ws);
}

static void test_schema_apply(void) {
  sqlite3 *db = open_crr();
  if (!db) {
    return;
  }
  int sqlrc = 0;
  make_sync_table(db, "t");
  murmur_schema_delta_ent_t tables[1];
  tables[0].table = "nt";
  tables[0].def = "CREATE TABLE nt(id INTEGER PRIMARY KEY NOT NULL, v TEXT)";
  murmur_schema_delta_ent_t cols[1];
  cols[0].table = "t";
  cols[0].def = "c TEXT DEFAULT 'hi'";
  CHECK(murmur_apply_additive(db, tables, 1, cols, 1, &sqlrc) ==
            MURMUR_SYNC_OK,
        "apply rc=%d", sqlrc);
  int yes = 0;
  static const uint8_t nt[] = "nt";
  CHECK(murmur_schema_is_crr(db, nt, 2, &yes, &sqlrc) == MURMUR_SYNC_OK &&
            yes == 1,
        "adopted crr");
  CHECK(count_rows(db, "SELECT count(*) FROM pragma_table_info(\"t\") WHERE "
                      "name='c'") == 1,
        "adopted column");
  /* re-applying converged state is a no-op */
  CHECK(murmur_apply_additive(db, tables, 1, cols, 1, &sqlrc) ==
            MURMUR_SYNC_OK,
        "reapply rc=%d", sqlrc);
  /* divergences fail closed */
  murmur_schema_delta_ent_t badt[1];
  badt[0].table = "t";
  badt[0].def = "CREATE TABLE t(other INT)";
  CHECK(murmur_apply_additive(db, badt, 1, NULL, 0, &sqlrc) ==
            MURMUR_SYNC_PROTOCOL,
        "table diverge st=%d", sqlrc);
  murmur_schema_delta_ent_t badc[1];
  badc[0].table = "t";
  badc[0].def = "c BLOB";
  CHECK(murmur_apply_additive(db, NULL, 0, badc, 1, &sqlrc) ==
            MURMUR_SYNC_PROTOCOL,
        "column diverge st=%d", sqlrc);
  murmur_schema_delta_ent_t badn[1];
  badn[0].table = "no-good!";
  badn[0].def = "c TEXT";
  CHECK(murmur_apply_additive(db, NULL, 0, badn, 1, &sqlrc) ==
            MURMUR_SYNC_INVALID,
        "bad table accepted");
  murmur_schema_delta_ent_t badv[1];
  badv[0].table = "vv";
  badv[0].def = "CREATE VIEW vv AS SELECT 1";
  CHECK(murmur_apply_additive(db, badv, 1, NULL, 0, &sqlrc) ==
            MURMUR_SYNC_INVALID,
        "bad ddl accepted");
  /* params: compiled-in defaults, then persistence and rejection */
  murmur_schema_params_t p;
  CHECK(murmur_schema_params_from(db, &p, &sqlrc) == MURMUR_SYNC_OK &&
            p.accept_remote == 1 && p.master_enabled == 0 &&
            p.has_master == 0 && p.max_schema_bytes == 67108864,
        "params defaults %d/%d/%d/%lld", p.accept_remote, p.master_enabled,
        p.has_master, (long long)p.max_schema_bytes);
  exec_ok(db,
          "INSERT INTO murmur_config(name,value) VALUES('accept_remote_schema',"
          "'0') ON CONFLICT(name) DO UPDATE SET value=excluded.value;",
          "params set");
  exec_ok(db,
          "INSERT INTO murmur_config(name,value) VALUES('schema_master','001122"
          "33445566778899aabbccddeeff') ON CONFLICT(name) DO UPDATE SET "
          "value=excluded.value;",
          "params master");
  CHECK(murmur_schema_params_from(db, &p, &sqlrc) == MURMUR_SYNC_OK &&
            p.accept_remote == 0 && p.has_master == 1 && p.master.b[0] == 0x00 &&
            p.master.b[15] == 0xff,
        "params persisted");
  exec_ok(db,
          "INSERT INTO murmur_config(name,value) VALUES('max_batch_bytes',"
          "'abc') ON CONFLICT(name) DO UPDATE SET value=excluded.value;",
          "params bad");
  CHECK(murmur_schema_params_from(db, &p, &sqlrc) == MURMUR_SYNC_INVALID,
        "params bad max accepted");
  close_crr(db);
}

static void test_txcodec(void) {
  int sqlrc = 0;
  static const uint64_t uvals[] = {0, 1, 127, 128, 300, 16384,
                                   0xFFFFFFFFFFFFFFFFull};
  for (size_t i = 0; i < sizeof(uvals) / sizeof(uvals[0]); i++) {
    size_t len = 0;
    uint8_t *enc = murmur_tx_encode_u64(uvals[i], &len);
    CHECK(enc != NULL && len > 0, "u64 enc %llu",
          (unsigned long long)uvals[i]);
    if (enc) {
      uint64_t back = 0;
      CHECK(murmur_tx_decode_u64(enc, len, &back, &sqlrc) == MURMUR_SYNC_OK &&
                back == uvals[i],
            "u64 rt %llu", (unsigned long long)uvals[i]);
      free(enc);
    }
  }
  static const uint8_t trail[] = {0x01, 0x00};
  uint64_t dummy = 0;
  CHECK(murmur_tx_decode_u64(trail, sizeof(trail), &dummy, &sqlrc) ==
            MURMUR_SYNC_PROTOCOL,
        "u64 trailing accepted");
  static const uint8_t trunc[] = {0x80};
  CHECK(murmur_tx_decode_u64(trunc, sizeof(trunc), &dummy, &sqlrc) ==
            MURMUR_SYNC_PROTOCOL,
        "u64 truncated accepted");
  static const uint8_t ovf[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                0xFF, 0xFF, 0xFF, 0x02};
  CHECK(murmur_tx_decode_u64(ovf, sizeof(ovf), &dummy, &sqlrc) ==
            MURMUR_SYNC_PROTOCOL,
        "u64 overflow accepted");
  CHECK(murmur_tx_zig_encode(0) == 0 && murmur_tx_zig_decode(0) == 0,
        "zig 0");
  CHECK(murmur_tx_zig_encode(-1) == 1 && murmur_tx_zig_decode(1) == -1,
        "zig -1");
  CHECK(murmur_tx_zig_encode(2) == 4 && murmur_tx_zig_decode(4) == 2, "zig 2");
  CHECK(murmur_tx_zig_decode(murmur_tx_zig_encode(-9223372036854775807LL - 1)) ==
            -9223372036854775807LL - 1,
        "zig min");
  murmur_tx_progress_t pin;
  memset(&pin, 0, sizeof(pin));
  for (int i = 0; i < 16; i++) {
    pin.origin.b[i] = (uint8_t)(i + 1);
  }
  pin.applied = 7;
  pin.observed = 9;
  pin.retained_from = 3;
  pin.retained_through = 7;
  size_t plen = 0;
  uint8_t *penc = murmur_tx_progress_encode(&pin, &plen);
  CHECK(penc != NULL && plen == 20, "progress enc len=%zu", plen);
  if (penc) {
    murmur_tx_progress_t pout;
    CHECK(murmur_tx_progress_decode(penc, plen, &pout, &sqlrc) ==
                  MURMUR_SYNC_OK &&
              memcmp(&pout, &pin, sizeof(pin)) == 0,
          "progress rt");
    CHECK(murmur_tx_progress_decode(penc, plen - 1, &pout, &sqlrc) ==
              MURMUR_SYNC_PROTOCOL,
          "progress trunc accepted");
    free(penc);
  }
  size_t klen = 0;
  uint8_t *k = murmur_tx_progress_key(&pin.origin, &klen);
  CHECK(k != NULL && klen == 55 &&
            memcmp(k, "07/replication/applied/0102030405060708090a0b0c0d0e0f10",
                   55) == 0,
        "progress key");
  free(k);
  k = murmur_tx_retained_key(&pin.origin, &klen);
  CHECK(k != NULL && klen == 56 && memcmp(k, "07/replication/retained/", 24) == 0,
        "retained key");
  free(k);
  k = murmur_tx_floor_key(&pin.origin, &klen);
  CHECK(k != NULL && klen == 63 &&
            memcmp(k, "07/replication/retention/floor/", 31) == 0,
        "floor key");
  free(k);
  k = murmur_tx_schema_manifest_key(&klen);
  CHECK(k != NULL && klen == 30 &&
            memcmp(k, "07/replication/schema/manifest", 30) == 0,
        "manifest key");
  free(k);
  k = murmur_tx_chunk_prefix(&pin.origin, 42, &klen);
  CHECK(k != NULL && klen == 76 &&
            memcmp(k + klen - 21, "00000000000000000042/", 21) == 0,
        "chunk prefix");
  free(k);
  murmur_signed_schema_t sin;
  memset(&sin, 0, sizeof(sin));
  sin.database.b[0] = 0xAA;
  sin.signer.b[15] = 0xBB;
  sin.sequence = 9;
  static const uint8_t sc[] = "schema-bytes";
  static const uint8_t sg[] = "sig";
  sin.schema = (uint8_t *)sc;
  sin.schema_len = sizeof(sc) - 1;
  sin.signature = (uint8_t *)sg;
  sin.signature_len = sizeof(sg) - 1;
  size_t slen = 0;
  uint8_t *senc = murmur_signed_schema_encode(&sin, &slen);
  CHECK(senc != NULL, "signed enc");
  if (senc) {
    murmur_signed_schema_t sout;
    memset(&sout, 0, sizeof(sout));
    CHECK(murmur_signed_schema_decode(senc, slen, &sout, &sqlrc) ==
                  MURMUR_SYNC_OK &&
              sout.sequence == 9 && sout.schema_len == sizeof(sc) - 1 &&
              memcmp(sout.schema, sc, sizeof(sc) - 1) == 0,
          "signed rt");
    murmur_signed_schema_free(&sout);
    CHECK(murmur_signed_schema_decode(senc, slen - 1, &sout, &sqlrc) ==
              MURMUR_SYNC_PROTOCOL,
          "signed trunc accepted");
    free(senc);
  }
  sin.schema = NULL;
  sin.schema_len = 0;
  sin.signature = NULL;
  sin.signature_len = 0;
  size_t blen = 0;
  uint8_t *sb = murmur_signed_schema_bytes(&sin, &blen);
  CHECK(sb != NULL && blen == 23 + 16 + 16 + 1 + 1 + 32 &&
            memcmp(sb, "murmur/sqlite-schema/v1", 23) == 0,
        "signed bytes len=%zu", blen);
  free(sb);
  murmur_crr_snapshot_t cin;
  memset(&cin, 0, sizeof(cin));
  memset(cin.schema, 0x5A, 32);
  cin.version = -3;
  static uint8_t sg0[] = {1, 2, 3};
  static uint8_t sg1[] = {4, 5};
  uint8_t *csegs[2] = {sg0, sg1};
  size_t clens[2] = {3, 2};
  cin.segments = csegs;
  cin.segment_lens = clens;
  cin.n_segments = 2;
  size_t clen = 0;
  uint8_t *cenc = murmur_crr_snapshot_encode(&cin, &clen);
  CHECK(cenc != NULL, "crr enc");
  if (cenc) {
    murmur_crr_snapshot_t cout;
    memset(&cout, 0, sizeof(cout));
    CHECK(murmur_crr_snapshot_decode(cenc, clen, &cout, &sqlrc) ==
                  MURMUR_SYNC_OK &&
              cout.version == -3 && cout.n_segments == 2 &&
              cout.segment_lens[1] == 2 && cout.segments[1][0] == 4,
          "crr rt");
    murmur_crr_snapshot_free(&cout);
    CHECK(murmur_crr_snapshot_decode(cenc, clen - 1, &cout, &sqlrc) ==
              MURMUR_SYNC_PROTOCOL,
          "crr trunc accepted");
    free(cenc);
  }
  /* segment count past 1<<20 fails closed */
  uint8_t big[64];
  memset(big, 0, 32);
  big[32] = 0x00;
  size_t bn = murmur_tx_uvarint_encode((1u << 20) + 1, big + 33,
                                       sizeof(big) - 33);
  murmur_crr_snapshot_t cbig;
  memset(&cbig, 0, sizeof(cbig));
  CHECK(murmur_crr_snapshot_decode(big, 33 + bn, &cbig, &sqlrc) ==
            MURMUR_SYNC_PROTOCOL,
        "crr many accepted");
}

static void test_kv_backend(void) {
  sqlite3 *db = open_crr();
  if (!db) {
    return;
  }
  int sqlrc = 0;
  static const uint8_t ka[] = "k/a";
  static const uint8_t kb[] = "k/b";
  static const uint8_t kc[] = "k/c";
  static const uint8_t va[] = "va";
  CHECK(murmur_kv_put(db, ka, 3, va, 2, &sqlrc) == MURMUR_SYNC_OK, "put");
  CHECK(murmur_kv_put(db, kb, 3, NULL, 0, &sqlrc) == MURMUR_SYNC_OK,
        "put empty");
  uint8_t *got = NULL;
  size_t got_len = 0;
  int found = 0;
  CHECK(murmur_kv_get(db, ka, 3, &got, &got_len, &found, &sqlrc) ==
                MURMUR_SYNC_OK &&
            found && got_len == 2 && memcmp(got, "va", 2) == 0,
        "get");
  free(got);
  got = NULL;
  CHECK(murmur_kv_get(db, kb, 3, &got, &got_len, &found, &sqlrc) ==
                MURMUR_SYNC_OK &&
            found && got_len == 0,
        "get empty");
  free(got);
  got = NULL;
  CHECK(murmur_kv_get(db, kc, 3, &got, &got_len, &found, &sqlrc) ==
                MURMUR_SYNC_OK &&
            !found && got == NULL,
        "get missing");
  const uint8_t *mkeys[3] = {ka, kb, kc};
  const size_t mlens[3] = {3, 3, 3};
  uint8_t **mvals = NULL;
  size_t *mvlens = NULL;
  int *mpresent = NULL;
  CHECK(murmur_kv_get_many(db, mkeys, mlens, 3, &mvals, &mvlens, &mpresent,
                           &sqlrc) == MURMUR_SYNC_OK &&
            mpresent[0] && mpresent[1] && !mpresent[2] && mvals[2] == NULL,
        "get many");
  murmur_kv_get_many_free(mvals, mvlens, mpresent, 3);
  mvals = NULL;
  size_t kept = 0;
  CHECK(murmur_kv_get_many_bounded(db, mkeys, mlens, 3, 1, &mvals, &mvlens,
                                   &mpresent, &kept, &sqlrc) == MURMUR_SYNC_OK &&
            kept == 1,
        "bounded kept=%zu", kept);
  murmur_kv_get_many_free(mvals, mvlens, mpresent, kept);
  uint8_t **sk = NULL;
  size_t *sl = NULL, sn = 0;
  static const uint8_t pfx[] = "k/";
  CHECK(murmur_kv_keys(db, pfx, 2, &sk, &sl, &sn, &sqlrc) == MURMUR_SYNC_OK &&
            sn == 2,
        "keys n=%zu", sn);
  murmur_kv_keys_free(sk, sl, sn);
  sk = NULL;
  CHECK(murmur_kv_keys_page(db, pfx, 2, NULL, 0, 0, 1, &sk, &sl, &sn,
                            &sqlrc) == MURMUR_SYNC_OK &&
            sn == 1,
        "keys page n=%zu", sn);
  CHECK(sn == 1 && sl[0] == 3 && memcmp(sk[0], "k/a", 3) == 0, "keys page key");
  uint8_t first[3];
  memcpy(first, sk[0], 3);
  murmur_kv_keys_free(sk, sl, sn);
  sk = NULL;
  CHECK(murmur_kv_keys_page(db, pfx, 2, first, 3, 1, 10, &sk, &sl, &sn,
                            &sqlrc) == MURMUR_SYNC_OK &&
            sn == 1 && memcmp(sk[0], "k/b", 3) == 0,
        "keys page after n=%zu", sn);
  murmur_kv_keys_free(sk, sl, sn);
  sk = NULL;
  static const uint8_t ff[] = {0xFF, 0xFF};
  CHECK(murmur_kv_keys(db, ff, 2, &sk, &sl, &sn, &sqlrc) == MURMUR_SYNC_OK &&
            sn == 0,
        "keys unbounded n=%zu", sn);
  murmur_kv_keys_free(sk, sl, sn);
  sk = NULL;
  /* commit applies puts/deletes atomically */
  murmur_kv_record_t recs[2];
  memset(recs, 0, sizeof(recs));
  static uint8_t rk1[] = "k/d";
  static uint8_t rv1[] = "vd";
  recs[0].key = rk1;
  recs[0].key_len = 3;
  recs[0].value = rv1;
  recs[0].value_len = 2;
  recs[1].key = (uint8_t *)ka;
  recs[1].key_len = 3;
  recs[1].is_delete = 1;
  CHECK(murmur_kv_commit(db, recs, 2, &sqlrc) == MURMUR_SYNC_OK, "commit");
  CHECK(murmur_kv_get(db, rk1, 3, &got, &got_len, &found, &sqlrc) ==
                MURMUR_SYNC_OK &&
            found,
        "commit put");
  free(got);
  got = NULL;
  CHECK(murmur_kv_get(db, ka, 3, &got, &got_len, &found, &sqlrc) ==
                MURMUR_SYNC_OK &&
            !found,
        "commit del");
  /* hybrid clock max-merge */
  uint64_t ck = 0;
  uint32_t cl = 0;
  CHECK(murmur_clock_observe(db, 100, 2, &ck, &cl, &sqlrc) == MURMUR_SYNC_OK &&
            ck == 100 && cl == 2,
        "clock init");
  CHECK(murmur_clock_observe(db, 50, 9, &ck, &cl, &sqlrc) == MURMUR_SYNC_OK &&
            ck == 100 && cl == 2,
        "clock stale");
  CHECK(murmur_clock_observe(db, 100, 5, &ck, &cl, &sqlrc) == MURMUR_SYNC_OK &&
            ck == 100 && cl == 5,
        "clock logical");
  static const uint8_t clk[] = "07/replication/clock/hlc";
  static const uint8_t bad1[] = {0xFF};
  CHECK(murmur_kv_put(db, clk, sizeof(clk) - 1, bad1, 1, &sqlrc) ==
            MURMUR_SYNC_OK,
        "clock corrupt setup");
  CHECK(murmur_clock_observe(db, 200, 0, &ck, &cl, &sqlrc) ==
            MURMUR_SYNC_PROTOCOL,
        "clock corrupt accepted");
  exec_ok(db, "DELETE FROM murmur_kv WHERE key='07/replication/clock/hlc';",
          "clock clear");
  /* progress merge across the three head families */
  murmur_node_t o1, o2;
  memset(&o1, 0x11, sizeof(o1));
  memset(&o2, 0x22, sizeof(o2));
  size_t kl2 = 0;
  uint8_t *rk = murmur_tx_retained_key(&o1, &kl2);
  murmur_tx_progress_t seed;
  memset(&seed, 0, sizeof(seed));
  seed.origin = o1;
  seed.retained_from = 4;
  seed.retained_through = 8;
  size_t sel = 0;
  uint8_t *senc = murmur_tx_progress_encode(&seed, &sel);
  CHECK(murmur_kv_put(db, rk, kl2, senc, sel, &sqlrc) == MURMUR_SYNC_OK,
        "seed retained");
  free(rk);
  free(senc);
  uint8_t *ak = murmur_tx_progress_key(&o1, &kl2);
  size_t al = 0;
  uint8_t *aenc = murmur_tx_encode_u64(8, &al);
  CHECK(murmur_kv_put(db, ak, kl2, aenc, al, &sqlrc) == MURMUR_SYNC_OK,
        "seed applied");
  free(ak);
  free(aenc);
  uint8_t *ok2 = murmur_tx_observed_key(&o2, &kl2);
  uint8_t *oenc = murmur_tx_encode_u64(5, &al);
  CHECK(murmur_kv_put(db, ok2, kl2, oenc, al, &sqlrc) == MURMUR_SYNC_OK,
        "seed observed");
  free(ok2);
  free(oenc);
  murmur_tx_progress_t *ps = NULL;
  size_t nps = 0;
  CHECK(murmur_tx_progress(db, &ps, &nps, &sqlrc) == MURMUR_SYNC_OK &&
            nps == 2,
        "progress n=%zu", nps);
  if (nps == 2) {
    /* scan order: retained seeds o1 first, observed scan adds o2 */
    CHECK(murmur_node_eq(&ps[0].origin, &o1) && ps[0].applied == 8 &&
              ps[0].observed == 8 && ps[0].retained_from == 4,
          "progress o1 %llu/%llu", (unsigned long long)ps[0].applied,
          (unsigned long long)ps[0].observed);
    CHECK(murmur_node_eq(&ps[1].origin, &o2) && ps[1].observed == 5,
          "progress o2");
  }
  murmur_tx_progress_free(ps, nps);
  ps = NULL;
  /* corrupt head value fails closed */
  static const uint8_t bad2[] = {0x80, 0x80};
  uint8_t *ak2 = murmur_tx_progress_key(&o1, &kl2);
  CHECK(murmur_kv_put(db, ak2, kl2, bad2, 2, &sqlrc) == MURMUR_SYNC_OK,
        "progress corrupt setup");
  free(ak2);
  CHECK(murmur_tx_progress(db, &ps, &nps, &sqlrc) == MURMUR_SYNC_PROTOCOL,
        "progress corrupt accepted");
  murmur_tx_progress_free(ps, nps);
  ps = NULL;
  exec_ok(db, "DELETE FROM murmur_kv;", "kv clear");
  /* serve params: defaults load, the invariant bites */
  murmur_serve_params_t sp;
  CHECK(murmur_serve_params(db, &sp, NULL, &sqlrc) == MURMUR_SYNC_OK &&
            sp.batch_bytes > 0 && sp.max_batch_bytes >= sp.batch_bytes,
        "serve params %lld/%lld", (long long)sp.batch_bytes,
        (long long)sp.max_batch_bytes);
  exec_ok(db,
          "INSERT INTO murmur_config(name,value) VALUES('batch_bytes',"
          "'999999999999') ON CONFLICT(name) DO UPDATE SET value=excluded.value;",
          "params break");
  char *pdetail = NULL;
  CHECK(murmur_serve_params(db, &sp, &pdetail, &sqlrc) == MURMUR_SYNC_INVALID &&
            pdetail != NULL && strstr(pdetail, "batch_bytes") != NULL,
        "params invariant accepted");
  free(pdetail);
  exec_ok(db, "DELETE FROM murmur_config WHERE name='batch_bytes';",
          "params restore");
  /* backend progress merges the live head */
  make_sync_table(db, "t");
  exec_ok(db, "INSERT INTO t(a,b) VALUES(1,'x');", "live row");
  murmur_node_t self;
  CHECK(murmur_sync_site_id(db, &self, &sqlrc) == MURMUR_SYNC_OK, "site id");
  CHECK(murmur_backend_progress(db, &self, &ps, &nps, &sqlrc) ==
                MURMUR_SYNC_OK &&
            nps == 1 && ps[0].applied >= 1 && ps[0].observed == ps[0].applied,
        "backend progress n=%zu", nps);
  murmur_tx_progress_free(ps, nps);
  ps = NULL;
  /* backend snapshot captures the image */
  uint8_t *snap = NULL;
  size_t snap_len = 0;
  CHECK(murmur_backend_snapshot(db, 1, &snap, &snap_len, &sqlrc) ==
                MURMUR_SYNC_OK &&
            snap_len > 32,
        "snapshot len=%zu", snap_len);
  if (snap) {
    murmur_crr_snapshot_t dec;
    memset(&dec, 0, sizeof(dec));
    uint8_t digest[32];
    CHECK(murmur_schema_digest(db, digest, &sqlrc) == MURMUR_SYNC_OK,
          "snap digest");
    CHECK(murmur_crr_snapshot_decode(snap, snap_len, &dec, &sqlrc) ==
                  MURMUR_SYNC_OK &&
              memcmp(dec.schema, digest, 32) == 0 && dec.n_segments >= 1,
          "snapshot image segs=%zu", dec.n_segments);
    murmur_crr_snapshot_free(&dec);
    free(snap);
    snap = NULL;
  }
  CHECK(murmur_backend_snapshot(db, 0, &snap, &snap_len, &sqlrc) ==
            MURMUR_SYNC_OVERLOADED,
        "snapshot offline accepted");
  /* backend accept: additive applies, closed declines */
  murmur_schema_delta_ent_t nt[1];
  nt[0].table = "nt2";
  nt[0].def = "CREATE TABLE nt2(id INTEGER PRIMARY KEY NOT NULL)";
  CHECK(murmur_apply_additive(db, nt, 1, NULL, 0, &sqlrc) == MURMUR_SYNC_OK,
        "accept setup");
  uint8_t *full = NULL;
  size_t full_len = 0;
  CHECK(murmur_manifest_schema_bytes(db, &full, &full_len, &sqlrc) ==
            MURMUR_SYNC_OK,
        "accept bytes");
  exec_ok(db, "DROP TABLE nt2;", "accept drop");
  int accepted = 0;
  CHECK(murmur_backend_accept_schema(db, full, full_len, &accepted, &sqlrc) ==
                MURMUR_SYNC_OK &&
            accepted == 1,
        "accept additive");
  free(full);
  full = NULL;
  exec_ok(db,
          "INSERT INTO murmur_config(name,value) VALUES('accept_remote_schema',"
          "'0') ON CONFLICT(name) DO UPDATE SET value=excluded.value;",
          "accept close");
  CHECK(murmur_manifest_schema_bytes(db, &full, &full_len, &sqlrc) ==
            MURMUR_SYNC_OK,
        "accept bytes2");
  exec_ok(db, "DROP TABLE nt2;", "accept drop2");
  CHECK(murmur_backend_accept_schema(db, full, full_len, &accepted, &sqlrc) ==
                MURMUR_SYNC_OK &&
            accepted == 0,
        "accept closed");
  free(full);
  close_crr(db);
}

static murmur_node_t node_seq(uint64_t v) {
  murmur_node_t n;
  memset(n.b, 0, sizeof(n.b));
  for (int i = 0; i < 8; i++) {
    n.b[i] = (uint8_t)(v >> (8 * i));
  }
  return n;
}

static void test_txtransfer(void) {
  int sqlrc = 0;
  /* boundary: sorted encode, wire-order decode, dup last-wins */
  murmur_tx_ack_t acks[3];
  acks[0].origin = node_fill(9);
  acks[0].seq = 30;
  acks[1].origin = node_fill(1);
  acks[1].seq = 10;
  acks[2].origin = node_fill(5);
  acks[2].seq = 20;
  size_t bl = 0;
  uint8_t *bnd = murmur_tx_boundary_encode(acks, 3, &bl);
  CHECK(bnd != NULL && bl > 0, "boundary encode");
  murmur_tx_ack_t *got = NULL;
  size_t ngot = 0, pos = 0;
  CHECK(murmur_tx_boundary_decode(bnd, bl, &pos, &got, &ngot, &sqlrc) ==
                MURMUR_SYNC_OK &&
            pos == bl && ngot == 3 &&
            got[0].origin.b[0] == 1 && got[0].seq == 10 &&
            got[1].origin.b[0] == 5 && got[1].seq == 20 &&
            got[2].origin.b[0] == 9 && got[2].seq == 30,
        "boundary order n=%zu", ngot);
  murmur_tx_acks_free(got, ngot);
  got = NULL;
  /* empty boundary roundtrips */
  free(bnd);
  bnd = murmur_tx_boundary_encode(NULL, 0, &bl);
  pos = 0;
  CHECK(bnd != NULL &&
            murmur_tx_boundary_decode(bnd, bl, &pos, &got, &ngot, &sqlrc) ==
                MURMUR_SYNC_OK &&
            ngot == 0,
        "boundary empty");
  murmur_tx_acks_free(got, ngot);
  got = NULL;
  free(bnd);
  /* count past 4096 fails closed */
  uint8_t big[8];
  size_t biglen = murmur_tx_uvarint_encode(4097, big, sizeof(big));
  pos = 0;
  CHECK(murmur_tx_boundary_decode(big, biglen, &pos, &got, &ngot, &sqlrc) ==
            MURMUR_SYNC_PROTOCOL,
        "boundary cap accepted");
  murmur_tx_acks_free(got, ngot);
  got = NULL;
  /* truncated entry fails */
  uint8_t trunc[] = {0x01, 0x02, 0x03};
  pos = 0;
  CHECK(murmur_tx_boundary_decode(trunc, sizeof(trunc), &pos, &got, &ngot,
                                  &sqlrc) == MURMUR_SYNC_PROTOCOL,
        "boundary trunc accepted");
  murmur_tx_acks_free(got, ngot);
  /* progress vector roundtrip */
  murmur_tx_progress_t ps[2];
  memset(ps, 0, sizeof(ps));
  ps[0].origin = node_fill(2);
  ps[0].applied = 7;
  ps[0].observed = 9;
  ps[1].origin = node_fill(4);
  ps[1].retained_from = 3;
  ps[1].retained_through = 5;
  size_t vl = 0;
  uint8_t *vec = murmur_tx_progress_vec_encode(ps, 2, &vl);
  murmur_tx_progress_t *pv = NULL;
  size_t npv = 0;
  pos = 0;
  CHECK(vec != NULL &&
            murmur_tx_progress_vec_decode(vec, vl, &pos, &pv, &npv, &sqlrc) ==
                MURMUR_SYNC_OK &&
            pos == vl && npv == 2 && pv[0].applied == 7 &&
            pv[1].retained_through == 5,
        "progress vec n=%zu", npv);
  free(pv);
  free(vec);
  /* peer record roundtrip, both flag values */
  for (int retired = 0; retired <= 1; retired++) {
    murmur_tx_peer_t peer;
    memset(&peer, 0, sizeof(peer));
    peer.node = node_fill(6);
    peer.last_seen_millis = 1234567;
    peer.retired = retired;
    peer.acks = acks;
    peer.n_acks = 3;
    size_t pl = 0;
    uint8_t *penc = murmur_tx_peer_encode(&peer, &pl);
    murmur_tx_peer_t dec;
    memset(&dec, 0, sizeof(dec));
    CHECK(penc != NULL &&
              murmur_tx_peer_decode(penc, pl, &dec, &sqlrc) == MURMUR_SYNC_OK &&
              murmur_node_eq(&dec.node, &peer.node) &&
              dec.last_seen_millis == 1234567 && dec.retired == retired &&
              dec.n_acks == 3 && dec.acks[0].seq == 10,
          "peer rt retired=%d", retired);
    murmur_tx_peer_free(&dec);
    /* trailing byte fails */
    uint8_t *bad = (uint8_t *)malloc(pl + 1);
    memcpy(bad, penc, pl);
    bad[pl] = 0;
    memset(&dec, 0, sizeof(dec));
    CHECK(murmur_tx_peer_decode(bad, pl + 1, &dec, &sqlrc) ==
              MURMUR_SYNC_PROTOCOL,
          "peer trailing accepted r=%d", retired);
    murmur_tx_peer_free(&dec);
    free(bad);
    free(penc);
  }
  /* bad retired flag fails */
  {
    murmur_tx_peer_t peer;
    memset(&peer, 0, sizeof(peer));
    peer.node = node_fill(6);
    size_t pl = 0;
    uint8_t *penc = murmur_tx_peer_encode(&peer, &pl);
    penc[17] = 2; /* node(16) + last_seen(1); flag follows */
    murmur_tx_peer_t dec;
    memset(&dec, 0, sizeof(dec));
    CHECK(murmur_tx_peer_decode(penc, pl, &dec, &sqlrc) == MURMUR_SYNC_PROTOCOL,
          "peer flag accepted");
    murmur_tx_peer_free(&dec);
    free(penc);
  }
  /* manifest roundtrip with progress, chunks, signature */
  murmur_tx_manifest_t m;
  memset(&m, 0, sizeof(m));
  m.database = node_fill(0xdb);
  m.donor = node_fill(0xd0);
  m.recipient = node_fill(0xe1);
  m.transfer = node_fill(0x77);
  m.expires = 999;
  m.bytes = 70000;
  memset(m.digest, 0xab, 32);
  memset(m.schema, 0xcd, 32);
  m.progress = ps;
  m.n_progress = 2;
  static uint8_t chunks[2][32];
  memset(chunks, 0x11, 32);
  memset(chunks[1], 0x22, 32);
  m.chunks = chunks;
  m.n_chunks = 2;
  static uint8_t sig[] = {0xde, 0xad, 0xbe, 0xef};
  m.signature = sig;
  m.signature_len = sizeof(sig);
  size_t ml = 0;
  uint8_t *menc = murmur_tx_manifest_encode(&m, &ml);
  murmur_tx_manifest_t mdec;
  memset(&mdec, 0, sizeof(mdec));
  CHECK(menc != NULL &&
            murmur_tx_manifest_decode(menc, ml, &mdec, &sqlrc) ==
                MURMUR_SYNC_OK &&
            murmur_node_eq(&mdec.transfer, &m.transfer) &&
            mdec.expires == 999 && mdec.bytes == 70000 &&
            mdec.digest[0] == 0xab && mdec.schema[31] == 0xcd &&
            mdec.n_progress == 2 && mdec.n_chunks == 2 &&
            mdec.chunks[1][0] == 0x22 && mdec.signature_len == 4 &&
            mdec.signature[3] == 0xef,
        "manifest rt");
  murmur_tx_manifest_free(&mdec);
  free(menc);
  /* incoming appends the deadline */
  murmur_tx_incoming_t inc;
  memset(&inc, 0, sizeof(inc));
  inc.manifest = m;
  inc.deadline = 4242;
  size_t il = 0;
  uint8_t *ienc = murmur_tx_incoming_encode(&inc, &il);
  murmur_tx_incoming_t idec;
  memset(&idec, 0, sizeof(idec));
  CHECK(ienc != NULL &&
            murmur_tx_incoming_decode(ienc, il, &idec, &sqlrc) ==
                MURMUR_SYNC_OK &&
            idec.deadline == 4242 && idec.manifest.n_chunks == 2,
        "incoming rt");
  murmur_tx_incoming_free(&idec);
  free(ienc);
  /* pin with and without target */
  for (int ht = 0; ht <= 1; ht++) {
    murmur_tx_pin_t pin;
    memset(&pin, 0, sizeof(pin));
    pin.recipient = node_fill(3);
    pin.boundary = acks;
    pin.n_boundary = 3;
    pin.has_target = ht;
    pin.target = acks + 1;
    pin.n_target = ht ? 2 : 0;
    pin.expires = 555;
    memset(pin.digest, 0x99, 32);
    size_t yl = 0;
    uint8_t *yenc = murmur_tx_pin_encode(&pin, &yl);
    murmur_tx_pin_t ydec;
    memset(&ydec, 0, sizeof(ydec));
    CHECK(yenc != NULL &&
              murmur_tx_pin_decode(yenc, yl, &ydec, &sqlrc) == MURMUR_SYNC_OK &&
              murmur_node_eq(&ydec.recipient, &pin.recipient) &&
              ydec.has_target == ht && ydec.n_boundary == 3 &&
              ydec.n_target == (ht ? (size_t)2 : (size_t)0) &&
              ydec.expires == 555 && ydec.digest[0] == 0x99,
          "pin rt ht=%d", ht);
    murmur_tx_pin_free(&ydec);
    free(yenc);
  }
  /* transfer key builders: exact strings */
  {
    murmur_node_t t = node_fill(0);
    t.b[0] = 0xde;
    t.b[15] = 0xad;
    static const char hex[] = "de0000000000000000000000000000ad";
    size_t kl = 0;
    uint8_t *k = murmur_tx_header_key(MURMUR_TX_IN, &t, &kl);
    char want[128];
    snprintf(want, sizeof(want), "%s%s/header", MURMUR_TX_IN, hex);
    CHECK(k != NULL && kl == strlen(want) && memcmp(k, want, kl) == 0,
          "header key");
    free(k);
    k = murmur_tx_chunk_key(MURMUR_TX_IN, &t, 42, &kl);
    snprintf(want, sizeof(want), "%s%s/chunk/00000042", MURMUR_TX_IN, hex);
    CHECK(k != NULL && kl == strlen(want) && memcmp(k, want, kl) == 0,
          "chunk key");
    free(k);
    k = murmur_tx_pin_key(&t, &kl);
    snprintf(want, sizeof(want), "%s%s", MURMUR_TX_PINS, hex);
    CHECK(k != NULL && kl == strlen(want) && memcmp(k, want, kl) == 0,
          "pin key");
    free(k);
    k = murmur_tx_receipt_key(&t, &kl);
    snprintf(want, sizeof(want), "%s%s", MURMUR_TX_RECEIPTS, hex);
    CHECK(k != NULL && kl == strlen(want) && memcmp(k, want, kl) == 0,
          "receipt key");
    free(k);
    k = murmur_tx_install_key(&t, &kl);
    snprintf(want, sizeof(want), "%s%s/install", MURMUR_TX_IN, hex);
    CHECK(k != NULL && kl == strlen(want) && memcmp(k, want, kl) == 0,
          "install key");
    free(k);
    k = murmur_tx_peer_key(&t, &kl);
    snprintf(want, sizeof(want), "07/replication/retention/peers/%s", hex);
    CHECK(k != NULL && kl == strlen(want) && memcmp(k, want, kl) == 0,
          "peer key");
    free(k);
    k = murmur_tx_excluded_key(&t, &kl);
    snprintf(want, sizeof(want), "07/replication/excluded/%s", hex);
    CHECK(k != NULL && kl == strlen(want) && memcmp(k, want, kl) == 0,
          "excluded key");
    free(k);
  }
}

static int kv_has(sqlite3 *db, const uint8_t *key, size_t klen) {
  uint8_t *v = NULL;
  size_t vl = 0;
  int found = 0, sqlrc = 0;
  int ok = murmur_kv_get(db, key, klen, &v, &vl, &found, &sqlrc) ==
           MURMUR_SYNC_OK;
  free(v);
  return ok && found;
}

static void test_txretain(void) {
  sqlite3 *db = open_crr();
  if (!db) {
    return;
  }
  int sqlrc = 0;
  murmur_node_t n1 = node_fill(0x11);
  murmur_node_t o1 = node_fill(0xa1);
  murmur_node_t o2 = node_fill(0xa2);
  /* empty status */
  murmur_tx_retention_status_t st;
  memset(&st, 0, sizeof(st));
  CHECK(murmur_tx_status(db, &st, &sqlrc) == MURMUR_SYNC_OK &&
            st.n_peers == 0 && st.collected_transactions == 0 &&
            st.last_collection_millis == 0,
        "retain empty status");
  murmur_tx_retention_status_free(&st);
  /* missing peer */
  murmur_tx_peer_t peer;
  memset(&peer, 0, sizeof(peer));
  int found = 0;
  CHECK(murmur_tx_peer(db, &n1, &peer, &found, &sqlrc) == MURMUR_SYNC_OK &&
            found == 0,
        "retain missing peer");
  murmur_tx_peer_free(&peer);
  /* touch a new peer, merging two origins */
  murmur_tx_progress_t ps[2];
  memset(ps, 0, sizeof(ps));
  ps[0].origin = o1;
  ps[0].applied = 5;
  ps[1].origin = o2;
  ps[1].applied = 9;
  CHECK(murmur_tx_touch(db, &n1, ps, 2, &sqlrc) == MURMUR_SYNC_OK,
        "retain touch");
  memset(&peer, 0, sizeof(peer));
  CHECK(murmur_tx_peer(db, &n1, &peer, &found, &sqlrc) == MURMUR_SYNC_OK &&
            found == 1 && peer.retired == 0 && peer.last_seen_millis > 0 &&
            peer.n_acks == 2,
        "retain peer back n=%zu", peer.n_acks);
  uint64_t first_seen = peer.last_seen_millis;
  murmur_tx_peer_free(&peer);
  /* quiet re-touch succeeds (no-op within 10s) */
  CHECK(murmur_tx_touch(db, &n1, ps, 2, &sqlrc) == MURMUR_SYNC_OK,
        "retain quiet touch");
  /* regressions never move acks backwards, advances merge */
  ps[0].applied = 3;
  ps[1].applied = 12;
  CHECK(murmur_tx_touch(db, &n1, ps, 2, &sqlrc) == MURMUR_SYNC_OK,
        "retain merge touch");
  memset(&peer, 0, sizeof(peer));
  CHECK(murmur_tx_peer(db, &n1, &peer, &found, &sqlrc) == MURMUR_SYNC_OK &&
            peer.n_acks == 2,
        "retain merged n=%zu", peer.n_acks);
  if (peer.n_acks == 2) {
    /* sorted by origin: o1(0xa1) before o2(0xa2) */
    CHECK(peer.acks[0].seq == 5 && peer.acks[1].seq == 12, "retain max merge");
  }
  CHECK(peer.last_seen_millis >= first_seen, "retain seen monotonic");
  murmur_tx_peer_free(&peer);
  /* corrupt record fails closed */
  size_t kl = 0;
  uint8_t *pk = murmur_tx_peer_key(&n1, &kl);
  static const uint8_t bad[] = {0x01, 0x02};
  CHECK(murmur_kv_put(db, pk, kl, bad, sizeof(bad), &sqlrc) == MURMUR_SYNC_OK,
        "retain corrupt setup");
  free(pk);
  memset(&peer, 0, sizeof(peer));
  CHECK(murmur_tx_peer(db, &n1, &peer, &found, &sqlrc) == MURMUR_SYNC_PROTOCOL,
        "retain corrupt accepted");
  murmur_tx_peer_free(&peer);
  CHECK(murmur_tx_status(db, &st, &sqlrc) == MURMUR_SYNC_PROTOCOL,
        "retain corrupt status accepted");
  murmur_tx_retention_status_free(&st);
  exec_ok(db, "DELETE FROM murmur_kv;", "retain clear");
  /* past-4096 distinct origins overloads without writing */
  murmur_node_t n2 = node_fill(0x22);
  murmur_tx_progress_t *many =
      (murmur_tx_progress_t *)calloc(4097, sizeof(*many));
  for (int i = 0; i < 4097; i++) {
    many[i].origin = node_seq((uint64_t)i + 1);
    many[i].applied = 1;
  }
  CHECK(murmur_tx_touch(db, &n2, many, 4097, &sqlrc) ==
            MURMUR_SYNC_OVERLOADED,
        "retain cap accepted");
  pk = murmur_tx_peer_key(&n2, &kl);
  CHECK(!kv_has(db, pk, kl), "retain cap wrote");
  free(pk);
  free(many);
  /* retire writes the record plus the exclusion tombstone */
  CHECK(murmur_tx_retire(db, &n1, &sqlrc) == MURMUR_SYNC_OK, "retain retire");
  memset(&peer, 0, sizeof(peer));
  CHECK(murmur_tx_peer(db, &n1, &peer, &found, &sqlrc) == MURMUR_SYNC_OK &&
            found == 1 && peer.retired == 1,
        "retain retired flag");
  murmur_tx_peer_free(&peer);
  pk = murmur_tx_excluded_key(&n1, &kl);
  CHECK(kv_has(db, pk, kl), "retain excluded missing");
  free(pk);
  /* retired peers refuse touch with AUTH */
  CHECK(murmur_tx_touch(db, &n1, ps, 2, &sqlrc) == MURMUR_SYNC_AUTH,
        "retain retired touch accepted");
  /* status surfaces the peer plus counters */
  static const uint8_t ckey[] = "07/replication/retention/collected";
  static const uint8_t lkey[] = "07/replication/retention/last";
  size_t el = 0;
  uint8_t *enc = murmur_tx_encode_u64(42, &el);
  CHECK(murmur_kv_put(db, ckey, sizeof(ckey) - 1, enc, el, &sqlrc) ==
            MURMUR_SYNC_OK,
        "retain counter setup");
  free(enc);
  enc = murmur_tx_encode_u64(777, &el);
  CHECK(murmur_kv_put(db, lkey, sizeof(lkey) - 1, enc, el, &sqlrc) ==
            MURMUR_SYNC_OK,
        "retain counter setup2");
  free(enc);
  memset(&st, 0, sizeof(st));
  CHECK(murmur_tx_status(db, &st, &sqlrc) == MURMUR_SYNC_OK &&
            st.n_peers == 1 && st.collected_transactions == 42 &&
            st.last_collection_millis == 777 &&
            murmur_node_eq(&st.peers[0].node, &n1),
        "retain status n=%zu", st.n_peers);
  murmur_tx_retention_status_free(&st);
  close_crr(db);
}

typedef struct {
  murmur_tx_manifest_t m;
  uint8_t *payload;
  size_t payload_len;
} snap_fix_t;

static void snap_fix_free(snap_fix_t *f) {
  murmur_tx_manifest_free(&f->m);
  free(f->payload);
  memset(f, 0, sizeof(*f));
}

/* Builds a manifest over a deterministic payload and stages the IN
 * header plus every chunk. Deadline far future, expires far future. */
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic push
/* -O1 false positive: payload is a null-checked malloc on every path
 * (-O2 and isolated builds are clean). */
#pragma GCC diagnostic ignored "-Wmaybe-uninitialized"
#endif
static int snap_stage(sqlite3 *db, snap_fix_t *f, murmur_node_t transfer,
                      size_t total) {
  int sqlrc = 0;
  memset(f, 0, sizeof(*f));
  uint8_t *payload = NULL;
  payload = (uint8_t *)malloc(total ? total : 1);
  if (!payload) {
    return 0;
  }
  f->payload = payload;
  for (size_t i = 0; i < total; i++) {
    /* position-dependent past 64KiB: chunk prefixes must differ */
    payload[i] = (uint8_t)(i * 31 + (i >> 8) * 17 + (i >> 16) * 5 + 7);
  }
  f->payload_len = total;
  murmur_sha256(payload, total, f->m.digest);
  f->m.database = node_fill(0xdb);
  f->m.donor = node_fill(0xd0);
  f->m.recipient = node_fill(0xe1);
  f->m.transfer = transfer;
  f->m.expires = UINT64_MAX;
  f->m.bytes = total;
  memset(f->m.schema, 0xcd, 32);
  size_t nch = (total + MURMUR_TX_CHUNK_BYTES - 1) / MURMUR_TX_CHUNK_BYTES;
  f->m.chunks = malloc(nch ? nch * 32 : 1);
  if (!f->m.chunks) {
    snap_fix_free(f);
    return 0;
  }
  f->m.n_chunks = nch;
  for (size_t i = 0; i < nch; i++) {
    size_t off = i * MURMUR_TX_CHUNK_BYTES;
    size_t len = total - off;
    if (len > MURMUR_TX_CHUNK_BYTES) {
      len = MURMUR_TX_CHUNK_BYTES;
    }
    murmur_sha256(f->payload + off, len, f->m.chunks[i]);
  }
  murmur_tx_incoming_t inc;
  memset(&inc, 0, sizeof(inc));
  inc.manifest = f->m;
  inc.deadline = UINT64_MAX;
  size_t hl = 0, kl = 0;
  uint8_t *henc = murmur_tx_incoming_encode(&inc, &hl);
  uint8_t *hkey = murmur_tx_header_key(MURMUR_TX_IN, &transfer, &kl);
  int ok = henc && hkey &&
           murmur_kv_put(db, hkey, kl, henc, hl, &sqlrc) == MURMUR_SYNC_OK;
  free(henc);
  free(hkey);
  /* inc shares f->m pointers; free only the struct shell */
  for (size_t i = 0; ok && i < nch; i++) {
    size_t off = i * MURMUR_TX_CHUNK_BYTES;
    size_t len = total - off;
    if (len > MURMUR_TX_CHUNK_BYTES) {
      len = MURMUR_TX_CHUNK_BYTES;
    }
    uint8_t *ck = murmur_tx_chunk_key(MURMUR_TX_IN, &transfer, (uint32_t)i,
                                      &kl);
    ok = ck && murmur_kv_put(db, ck, kl, f->payload + off, len, &sqlrc) ==
                    MURMUR_SYNC_OK;
    free(ck);
  }
  if (!ok) {
    snap_fix_free(f);
  }
  return ok;
}
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic pop
#endif

static void test_txsnap(void) {
  sqlite3 *db = open_crr();
  if (!db) {
    return;
  }
  int sqlrc = 0;
  snap_fix_t f;
  murmur_node_t t1 = node_fill(0x71);
  size_t total = MURMUR_TX_CHUNK_BYTES + 100;
  CHECK(snap_stage(db, &f, t1, total), "snap stage");
  /* validate_chunk verdicts */
  size_t c0len = MURMUR_TX_CHUNK_BYTES, c1len = 100;
  CHECK(murmur_tx_validate_chunk(&f.m, &f.m.donor, 0, f.payload, c0len,
                                 &sqlrc) == MURMUR_SYNC_OK,
        "snap validate ok");
  murmur_node_t wrong = node_fill(0x77);
  CHECK(murmur_tx_validate_chunk(&f.m, &wrong, 0, f.payload, c0len, &sqlrc) ==
            MURMUR_SYNC_AUTH,
        "snap validate donor accepted");
  CHECK(murmur_tx_validate_chunk(&f.m, &f.m.donor, 2, f.payload, c0len,
                                 &sqlrc) == MURMUR_SYNC_AUTH,
        "snap validate oob accepted");
  CHECK(murmur_tx_validate_chunk(&f.m, &f.m.donor, 0, f.payload, c0len - 1,
                                 &sqlrc) == MURMUR_SYNC_AUTH,
        "snap validate short accepted");
  CHECK(murmur_tx_validate_chunk(&f.m, &f.m.donor, 1, f.payload, c1len,
                                 &sqlrc) == MURMUR_SYNC_AUTH,
        "snap validate hash accepted");
  /* stream_read reassembles across the chunk seam */
  uint8_t *out = NULL;
  size_t olen = 0;
  CHECK(murmur_tx_stream_read(db, &f.m, 0, (int64_t)total, &out, &olen,
                              &sqlrc) == MURMUR_SYNC_OK &&
            olen == total && memcmp(out, f.payload, total) == 0,
        "snap stream full len=%zu", olen);
  free(out);
  out = NULL;
  CHECK(murmur_tx_stream_read(db, &f.m, MURMUR_TX_CHUNK_BYTES - 10, 20, &out,
                              &olen, &sqlrc) == MURMUR_SYNC_OK &&
            olen == 20 &&
            memcmp(out, f.payload + MURMUR_TX_CHUNK_BYTES - 10, 20) == 0,
        "snap stream seam");
  free(out);
  out = NULL;
  CHECK(murmur_tx_stream_read(db, &f.m, 5, 0, &out, &olen, &sqlrc) ==
                MURMUR_SYNC_OK &&
            olen == 0,
        "snap stream empty");
  free(out);
  out = NULL;
  CHECK(murmur_tx_stream_read(db, &f.m, 0, -1, &out, &olen, &sqlrc) ==
            MURMUR_SYNC_PROTOCOL,
        "snap stream neglength accepted");
  CHECK(murmur_tx_stream_read(db, &f.m, total - 10, 11, &out, &olen, &sqlrc) ==
            MURMUR_SYNC_PROTOCOL,
        "snap stream overrun accepted");
  CHECK(murmur_tx_stream_read(db, &f.m, UINT64_MAX, 1, &out, &olen, &sqlrc) ==
            MURMUR_SYNC_PROTOCOL,
        "snap stream wrap accepted");
  /* missing chunk surfaces OVERLOADED */
  size_t kl = 0;
  uint8_t *c1k = murmur_tx_chunk_key(MURMUR_TX_IN, &t1, 1, &kl);
  {
    char del[256];
    snprintf(del, sizeof(del),
             "DELETE FROM murmur_kv WHERE key = CAST('%s' AS BLOB);",
             (const char *)c1k);
    exec_ok(db, del, "snap drop chunk");
  }
  CHECK(!kv_has(db, c1k, kl), "snap chunk still there");
  CHECK(murmur_tx_stream_read(db, &f.m, 0, (int64_t)total, &out, &olen,
                              &sqlrc) == MURMUR_SYNC_OVERLOADED,
        "snap stream gap accepted");
  /* missing lists exactly the absent index */
  murmur_tx_incoming_t inc;
  memset(&inc, 0, sizeof(inc));
  inc.manifest = f.m;
  uint32_t *miss = NULL;
  size_t nmiss = 0;
  CHECK(murmur_tx_missing(db, &inc, &miss, &nmiss, &sqlrc) == MURMUR_SYNC_OK &&
            nmiss == 1 && miss[0] == 1,
        "snap missing n=%zu", nmiss);
  free(miss);
  miss = NULL;
  /* receive restages the dropped chunk */
  CHECK(murmur_tx_receive(db, &f.m.donor, &t1, 1,
                          f.payload + MURMUR_TX_CHUNK_BYTES, c1len,
                          (uint64_t)1000, &sqlrc) == MURMUR_SYNC_OK,
        "snap receive");
  CHECK(kv_has(db, c1k, kl), "snap receive lost");
  free(c1k);
  /* receive is idempotent on equal bytes, AUTH on conflict */
  CHECK(murmur_tx_receive(db, &f.m.donor, &t1, 1,
                          f.payload + MURMUR_TX_CHUNK_BYTES, c1len,
                          (uint64_t)1000, &sqlrc) == MURMUR_SYNC_OK,
        "snap receive idempotent");
  static uint8_t conflict[100];
  memset(conflict, 0x55, sizeof(conflict));
  CHECK(murmur_tx_receive(db, &f.m.donor, &t1, 1, conflict, sizeof(conflict),
                          (uint64_t)1000, &sqlrc) == MURMUR_SYNC_AUTH,
        "snap receive conflict accepted");
  CHECK(murmur_tx_missing(db, &inc, &miss, &nmiss, &sqlrc) == MURMUR_SYNC_OK &&
            nmiss == 0 && miss == NULL,
        "snap missing drained");
  free(miss);
  /* unknown transfer has no header: OVERLOADED, not AUTH */
  murmur_node_t tunknown = node_fill(0x99);
  CHECK(murmur_tx_receive(db, &f.m.donor, &tunknown, 0, f.payload, c0len,
                          (uint64_t)1000, &sqlrc) == MURMUR_SYNC_OVERLOADED,
        "snap receive unknown accepted");
  /* completed transfers validate without staging */
  murmur_node_t t2 = node_fill(0x72);
  snap_fix_t f2;
  CHECK(snap_stage(db, &f2, t2, 500), "snap stage2");
  {
    /* drop t1 chunk 0/1 and t2 chunk 0 by exact key */
    uint8_t *drop[3];
    size_t dl[3];
    drop[0] = murmur_tx_chunk_key(MURMUR_TX_IN, &t1, 0, &dl[0]);
    drop[1] = murmur_tx_chunk_key(MURMUR_TX_IN, &t1, 1, &dl[1]);
    drop[2] = murmur_tx_chunk_key(MURMUR_TX_IN, &t2, 0, &dl[2]);
    for (int i = 0; i < 3; i++) {
      char del[256];
      snprintf(del, sizeof(del),
               "DELETE FROM murmur_kv WHERE key = CAST('%s' AS BLOB);",
               (const char *)drop[i]);
      exec_ok(db, del, "snap drop all chunks");
      free(drop[i]);
    }
  }
  murmur_tx_incoming_t rcpt;
  memset(&rcpt, 0, sizeof(rcpt));
  rcpt.manifest = f2.m;
  rcpt.deadline = UINT64_MAX;
  size_t rl = 0, rkl = 0;
  uint8_t *renc = murmur_tx_incoming_encode(&rcpt, &rl);
  uint8_t *rkey = murmur_tx_receipt_key(&t2, &rkl);
  CHECK(murmur_kv_put(db, rkey, rkl, renc, rl, &sqlrc) == MURMUR_SYNC_OK,
        "snap receipt setup");
  free(renc);
  uint8_t *c0k = murmur_tx_chunk_key(MURMUR_TX_IN, &t2, 0, &kl);
  CHECK(murmur_tx_receive(db, &f2.m.donor, &t2, 0, f2.payload, 500,
                          (uint64_t)1000, &sqlrc) == MURMUR_SYNC_OK &&
            !kv_has(db, c0k, kl),
        "snap receipt staged");
  CHECK(murmur_tx_receive(db, &f2.m.donor, &t2, 0, conflict, 100,
                          (uint64_t)1000, &sqlrc) == MURMUR_SYNC_AUTH,
        "snap receipt bad accepted");
  free(c0k);
  free(rkey);
  snap_fix_free(&f2);
  snap_fix_free(&f);
  /* missing caps at 128 indexes in order */
  {
    murmur_tx_manifest_t m200;
    memset(&m200, 0, sizeof(m200));
    m200.transfer = node_fill(0xc8);
    m200.n_chunks = 200;
    murmur_tx_incoming_t inc200;
    memset(&inc200, 0, sizeof(inc200));
    inc200.manifest = m200;
    uint32_t *m2 = NULL;
    size_t n2 = 0;
    CHECK(murmur_tx_missing(db, &inc200, &m2, &n2, &sqlrc) == MURMUR_SYNC_OK &&
              n2 == 128 && m2[0] == 0 && m2[127] == 127,
          "snap missing cap n=%zu", n2);
    free(m2);
  }
  exec_ok(db, "DELETE FROM murmur_kv;", "snap clear2");
  /* prune_limit: min across live pins, 0 when a live pin skips origin */
  {
    murmur_node_t o1 = node_fill(0xa1);
    murmur_node_t o2 = node_fill(0xa2);
    murmur_node_t o3 = node_fill(0xa3);
    uint64_t lim = 0;
    CHECK(murmur_tx_prune_limit(db, &o1, 1000, &lim, &sqlrc) ==
                  MURMUR_SYNC_OK &&
              lim == UINT64_MAX,
          "prune empty");
    murmur_tx_ack_t b1[2];
    memset(b1, 0, sizeof(b1));
    b1[0].origin = o1;
    b1[0].seq = 10;
    b1[1].origin = o2;
    b1[1].seq = 20;
    murmur_tx_pin_t p1;
    memset(&p1, 0, sizeof(p1));
    p1.recipient = node_fill(0xe1);
    p1.boundary = b1;
    p1.n_boundary = 2;
    p1.expires = 2000;
    size_t pkl = 0, pyl = 0;
    murmur_node_t tp1 = node_fill(0xb1);
    uint8_t *pkey = murmur_tx_pin_key(&tp1, &pkl);
    uint8_t *py = murmur_tx_pin_encode(&p1, &pyl);
    CHECK(murmur_kv_put(db, pkey, pkl, py, pyl, &sqlrc) == MURMUR_SYNC_OK,
          "prune pin setup");
    free(pkey);
    free(py);
    CHECK(murmur_tx_prune_limit(db, &o1, 1000, &lim, &sqlrc) ==
                  MURMUR_SYNC_OK &&
              lim == 10,
          "prune one lim=%llu", (unsigned long long)lim);
    CHECK(murmur_tx_prune_limit(db, &o3, 1000, &lim, &sqlrc) ==
                  MURMUR_SYNC_OK &&
              lim == 0,
          "prune absent lim=%llu", (unsigned long long)lim);
    murmur_tx_ack_t b2[1];
    memset(b2, 0, sizeof(b2));
    b2[0].origin = o1;
    b2[0].seq = 5;
    murmur_tx_pin_t p2;
    memset(&p2, 0, sizeof(p2));
    p2.recipient = node_fill(0xe2);
    p2.boundary = b2;
    p2.n_boundary = 1;
    p2.expires = 2000;
    murmur_node_t tp2 = node_fill(0xb2);
    pkey = murmur_tx_pin_key(&tp2, &pkl);
    py = murmur_tx_pin_encode(&p2, &pyl);
    CHECK(murmur_kv_put(db, pkey, pkl, py, pyl, &sqlrc) == MURMUR_SYNC_OK,
          "prune pin setup2");
    free(pkey);
    free(py);
    CHECK(murmur_tx_prune_limit(db, &o1, 1000, &lim, &sqlrc) ==
                  MURMUR_SYNC_OK &&
              lim == 5,
          "prune min lim=%llu", (unsigned long long)lim);
    /* expires == now reads expired (live needs expires > now) */
    murmur_tx_ack_t b3[1];
    memset(b3, 0, sizeof(b3));
    b3[0].origin = o1;
    b3[0].seq = 1;
    murmur_tx_pin_t p3;
    memset(&p3, 0, sizeof(p3));
    p3.recipient = node_fill(0xe3);
    p3.boundary = b3;
    p3.n_boundary = 1;
    p3.expires = 1000;
    murmur_node_t tp3 = node_fill(0xb3);
    pkey = murmur_tx_pin_key(&tp3, &pkl);
    py = murmur_tx_pin_encode(&p3, &pyl);
    CHECK(murmur_kv_put(db, pkey, pkl, py, pyl, &sqlrc) == MURMUR_SYNC_OK,
          "prune pin setup3");
    free(pkey);
    free(py);
    CHECK(murmur_tx_prune_limit(db, &o1, 1000, &lim, &sqlrc) ==
                  MURMUR_SYNC_OK &&
              lim == 5,
          "prune edge lim=%llu", (unsigned long long)lim);
  }
  exec_ok(db, "DELETE FROM murmur_kv;", "snap clear3");
  /* maintain sweeps pins, headers, orphans, receipts, v8 keys */
  {
    const uint64_t now = 1000;
    murmur_node_t o1 = node_fill(0xa1);
    /* pins: expired drops, live stays, caught-up targeted drops */
    murmur_tx_ack_t bd[1];
    memset(bd, 0, sizeof(bd));
    bd[0].origin = o1;
    bd[0].seq = 5;
    struct {
      murmur_node_t tid;
      murmur_node_t rcpt;
      int targeted;
      uint64_t expires;
      int want_kept;
    } pins[] = {
        {node_fill(0xd1), node_fill(0xe1), 0, 500, 0},
        {node_fill(0xd2), node_fill(0xe2), 0, 5000, 1},
        {node_fill(0xd3), node_fill(0xe3), 1, 5000, 0},
        {node_fill(0xd4), node_fill(0xe4), 1, 5000, 1},
    };
    for (size_t i = 0; i < 4; i++) {
      murmur_tx_pin_t p;
      memset(&p, 0, sizeof(p));
      p.recipient = pins[i].rcpt;
      p.boundary = bd;
      p.n_boundary = 1;
      p.has_target = pins[i].targeted;
      p.target = bd;
      p.n_target = pins[i].targeted ? (size_t)1 : (size_t)0;
      p.expires = pins[i].expires;
      size_t pkl = 0, pyl = 0;
      uint8_t *pkey = murmur_tx_pin_key(&pins[i].tid, &pkl);
      uint8_t *py = murmur_tx_pin_encode(&p, &pyl);
      int ok = pkey && py &&
               murmur_kv_put(db, pkey, pkl, py, pyl, &sqlrc) == MURMUR_SYNC_OK;
      CHECK(ok, "maintain pin setup %zu", i);
      free(pkey);
      free(py);
    }
    /* d3's recipient covers the target, d4's does not */
    for (size_t i = 0; i < 2; i++) {
      murmur_tx_peer_t pr;
      memset(&pr, 0, sizeof(pr));
      pr.node = pins[2 + i].rcpt;
      pr.last_seen_millis = now;
      murmur_tx_ack_t pa[1];
      memset(pa, 0, sizeof(pa));
      pa[0].origin = o1;
      pa[0].seq = i == 0 ? 9 : 1;
      pr.acks = pa;
      pr.n_acks = 1;
      size_t pkl = 0, pyl = 0;
      uint8_t *pkey = murmur_tx_peer_key(&pr.node, &pkl);
      uint8_t *py = murmur_tx_peer_encode(&pr, &pyl);
      int ok = pkey && py &&
               murmur_kv_put(db, pkey, pkl, py, pyl, &sqlrc) == MURMUR_SYNC_OK;
      CHECK(ok, "maintain peer setup %zu", i);
      free(pkey);
      free(py);
    }
    /* IN headers: expired deadline drops with chunks, live keeps all */
    murmur_node_t in_old = node_fill(0x41);
    murmur_node_t in_new = node_fill(0x42);
    for (size_t i = 0; i < 2; i++) {
      murmur_node_t tid = i == 0 ? in_old : in_new;
      murmur_tx_manifest_t hm;
      memset(&hm, 0, sizeof(hm));
      hm.donor = node_fill(0xd0);
      hm.transfer = tid;
      hm.expires = UINT64_MAX;
      murmur_tx_incoming_t hi;
      memset(&hi, 0, sizeof(hi));
      hi.manifest = hm;
      hi.deadline = i == 0 ? 500 : 5000;
      size_t hkl = 0, hvl = 0;
      uint8_t *hkey = murmur_tx_header_key(MURMUR_TX_IN, &tid, &hkl);
      uint8_t *hv = murmur_tx_incoming_encode(&hi, &hvl);
      int ok = hkey && hv &&
               murmur_kv_put(db, hkey, hkl, hv, hvl, &sqlrc) == MURMUR_SYNC_OK;
      CHECK(ok, "maintain in header %zu", i);
      free(hkey);
      free(hv);
      static const uint8_t cdata[] = {1, 2, 3};
      uint8_t *ck = murmur_tx_chunk_key(MURMUR_TX_IN, &tid, 0, &hkl);
      ok = ck && murmur_kv_put(db, ck, hkl, cdata, sizeof(cdata), &sqlrc) ==
                      MURMUR_SYNC_OK;
      CHECK(ok, "maintain in chunk %zu", i);
      free(ck);
    }
    size_t ikl = 0;
    uint8_t *inst = murmur_tx_install_key(&in_new, &ikl);
    static const uint8_t idata[] = {9};
    CHECK(murmur_kv_put(db, inst, ikl, idata, sizeof(idata), &sqlrc) ==
              MURMUR_SYNC_OK,
          "maintain install setup");
    /* OUT headers: expiry, pin targeting, and missing pins */
    murmur_node_t out_old = node_fill(0x51);
    murmur_node_t out_keep = node_fill(0x52);
    murmur_node_t out_targ = node_fill(0x53);
    murmur_node_t out_nopin = node_fill(0x54);
    murmur_node_t tids[] = {out_old, out_keep, out_targ, out_nopin};
    for (size_t i = 0; i < 4; i++) {
      murmur_tx_manifest_t om;
      memset(&om, 0, sizeof(om));
      om.donor = node_fill(0xd0);
      om.transfer = tids[i];
      om.expires = i == 0 ? 500 : 5000;
      size_t hkl = 0, hvl = 0;
      uint8_t *hkey = murmur_tx_header_key(MURMUR_TX_OUT, &tids[i], &hkl);
      uint8_t *hv = murmur_tx_manifest_encode(&om, &hvl);
      int ok = hkey && hv &&
               murmur_kv_put(db, hkey, hkl, hv, hvl, &sqlrc) == MURMUR_SYNC_OK;
      CHECK(ok, "maintain out header %zu", i);
      free(hkey);
      free(hv);
      static const uint8_t cdata[] = {4, 5};
      uint8_t *ck = murmur_tx_chunk_key(MURMUR_TX_OUT, &tids[i], 0, &hkl);
      ok = ck && murmur_kv_put(db, ck, hkl, cdata, sizeof(cdata), &sqlrc) ==
                      MURMUR_SYNC_OK;
      CHECK(ok, "maintain out chunk %zu", i);
      free(ck);
    }
    /* out_keep gets a fresh untargeted pin; out_targ a fresh targeted
     * one with no peer, so the pins phase keeps both */
    for (size_t i = 0; i < 2; i++) {
      murmur_tx_pin_t p;
      memset(&p, 0, sizeof(p));
      p.recipient = node_fill((uint8_t)(0xf0 + i));
      p.boundary = bd;
      p.n_boundary = 1;
      p.has_target = (int)i;
      p.target = bd;
      p.n_target = i;
      p.expires = 5000;
      size_t pkl = 0, pyl = 0;
      murmur_node_t tid = i == 0 ? out_keep : out_targ;
      uint8_t *pkey = murmur_tx_pin_key(&tid, &pkl);
      uint8_t *py = murmur_tx_pin_encode(&p, &pyl);
      int ok = pkey && py &&
               murmur_kv_put(db, pkey, pkl, py, pyl, &sqlrc) == MURMUR_SYNC_OK;
      CHECK(ok, "maintain out pin %zu", i);
      free(pkey);
      free(py);
    }
    /* junk under dead ids drops; receipts split by deadline */
    static const uint8_t junk[] = "07/replication/snapshot-v1/out/deadbeef/zzz";
    static const uint8_t jval[] = {1};
    CHECK(murmur_kv_put(db, junk, sizeof(junk) - 1, jval, sizeof(jval),
                        &sqlrc) == MURMUR_SYNC_OK,
          "maintain junk setup");
    murmur_node_t r_old = node_fill(0x61);
    murmur_node_t r_new = node_fill(0x62);
    for (size_t i = 0; i < 2; i++) {
      murmur_node_t tid = i == 0 ? r_old : r_new;
      murmur_tx_manifest_t rm;
      memset(&rm, 0, sizeof(rm));
      rm.transfer = tid;
      murmur_tx_incoming_t ri;
      memset(&ri, 0, sizeof(ri));
      ri.manifest = rm;
      ri.deadline = i == 0 ? 500 : 5000;
      size_t rkl = 0, rvl = 0;
      uint8_t *rkey = murmur_tx_receipt_key(&tid, &rkl);
      uint8_t *rv = murmur_tx_incoming_encode(&ri, &rvl);
      int ok = rkey && rv &&
               murmur_kv_put(db, rkey, rkl, rv, rvl, &sqlrc) == MURMUR_SYNC_OK;
      CHECK(ok, "maintain receipt setup %zu", i);
      free(rkey);
      free(rv);
    }
    static const uint8_t v8[] = "07/replication/snapshot/leftover";
    CHECK(murmur_kv_put(db, v8, sizeof(v8) - 1, jval, sizeof(jval), &sqlrc) ==
              MURMUR_SYNC_OK,
          "maintain v8 setup");
    CHECK(murmur_tx_maintain(db, now, &sqlrc) == MURMUR_SYNC_OK,
          "maintain run");
    for (size_t i = 0; i < 4; i++) {
      size_t pkl = 0;
      uint8_t *pkey = murmur_tx_pin_key(&pins[i].tid, &pkl);
      CHECK(kv_has(db, pkey, pkl) == pins[i].want_kept, "maintain pin %zu", i);
      free(pkey);
    }
    {
      size_t hkl = 0, ckl = 0;
      uint8_t *hk = murmur_tx_header_key(MURMUR_TX_IN, &in_old, &hkl);
      uint8_t *ck = murmur_tx_chunk_key(MURMUR_TX_IN, &in_old, 0, &ckl);
      CHECK(!kv_has(db, hk, hkl) && !kv_has(db, ck, ckl), "maintain in old");
      free(hk);
      free(ck);
      hk = murmur_tx_header_key(MURMUR_TX_IN, &in_new, &hkl);
      ck = murmur_tx_chunk_key(MURMUR_TX_IN, &in_new, 0, &ckl);
      CHECK(kv_has(db, hk, hkl) && kv_has(db, ck, ckl) &&
                kv_has(db, inst, ikl),
            "maintain in new");
      free(hk);
      free(ck);
    }
    {
      int want[] = {0, 1, 0, 0};
      for (size_t i = 0; i < 4; i++) {
        size_t hkl = 0, ckl = 0;
        uint8_t *hk = murmur_tx_header_key(MURMUR_TX_OUT, &tids[i], &hkl);
        uint8_t *ck = murmur_tx_chunk_key(MURMUR_TX_OUT, &tids[i], 0, &ckl);
        CHECK(kv_has(db, hk, hkl) == want[i] &&
                  kv_has(db, ck, ckl) == want[i],
              "maintain out %zu", i);
        free(hk);
        free(ck);
      }
      size_t pkl = 0;
      uint8_t *pkey = murmur_tx_pin_key(&out_keep, &pkl);
      CHECK(kv_has(db, pkey, pkl), "maintain out pin kept");
      free(pkey);
      pkey = murmur_tx_pin_key(&out_targ, &pkl);
      CHECK(kv_has(db, pkey, pkl), "maintain out pin kept2");
      free(pkey);
    }
    CHECK(!kv_has(db, junk, sizeof(junk) - 1), "maintain junk kept");
    {
      size_t rkl = 0;
      uint8_t *rkey = murmur_tx_receipt_key(&r_old, &rkl);
      CHECK(!kv_has(db, rkey, rkl), "maintain receipt old kept");
      free(rkey);
      rkey = murmur_tx_receipt_key(&r_new, &rkl);
      CHECK(kv_has(db, rkey, rkl), "maintain receipt new lost");
      free(rkey);
    }
    CHECK(!kv_has(db, v8, sizeof(v8) - 1), "maintain v8 kept");
    free(inst);
  }
  exec_ok(db, "DELETE FROM murmur_kv;", "snap clear4");
  /* reap drops retired, stale-offline, and fulfilled pins only */
  {
    const uint64_t now = 10000, max_off = 1000;
    murmur_node_t o1 = node_fill(0xa1);
    murmur_node_t r_on = node_fill(0xe0);
    struct {
      murmur_node_t tid;
      murmur_node_t rcpt;
      int has_target;
      int peer; /* 0 none, 1 normal, 2 retired */
      uint64_t seen;
      uint64_t ack;
      int want_kept;
    } cases[] = {
        /* retired, offline */
        {node_fill(0x91), node_fill(0xe1), 0, 2, 9000, 9, 0},
        /* stale offline */
        {node_fill(0x92), node_fill(0xe2), 0, 1, 1000, 9, 0},
        /* fresh offline, boundary uncovered */
        {node_fill(0x93), node_fill(0xe3), 0, 1, 9500, 5, 1},
        /* fulfilled online */
        {node_fill(0x94), r_on, 0, 1, 1000, 9, 0},
        /* targeted pins never fulfill */
        {node_fill(0x95), r_on, 1, 1, 9500, 9, 1},
        /* no peer record */
        {node_fill(0x96), node_fill(0xe6), 0, 0, 0, 0, 1},
        /* future timestamp saturates, wraps recency when offline */
        {node_fill(0x97), node_fill(0xe7), 0, 1, 20000, 9, 1},
    };
    for (size_t i = 0; i < 7; i++) {
      murmur_tx_ack_t bnd[1];
      memset(bnd, 0, sizeof(bnd));
      bnd[0].origin = o1;
      bnd[0].seq = 6;
      murmur_tx_pin_t p;
      memset(&p, 0, sizeof(p));
      p.recipient = cases[i].rcpt;
      p.boundary = bnd;
      p.n_boundary = 1;
      p.has_target = cases[i].has_target;
      p.expires = 50000;
      size_t pkl = 0, pyl = 0;
      uint8_t *pkey = murmur_tx_pin_key(&cases[i].tid, &pkl);
      uint8_t *py = murmur_tx_pin_encode(&p, &pyl);
      int ok = pkey && py &&
               murmur_kv_put(db, pkey, pkl, py, pyl, &sqlrc) == MURMUR_SYNC_OK;
      CHECK(ok, "reap pin setup %zu", i);
      free(pkey);
      free(py);
      if (cases[i].peer) {
        murmur_tx_peer_t pr;
        memset(&pr, 0, sizeof(pr));
        pr.node = cases[i].rcpt;
        pr.last_seen_millis = cases[i].seen;
        pr.retired = cases[i].peer == 2;
        murmur_tx_ack_t pa[1];
        memset(pa, 0, sizeof(pa));
        pa[0].origin = o1;
        pa[0].seq = cases[i].ack;
        pr.acks = pa;
        pr.n_acks = 1;
        uint8_t *pkey2 = murmur_tx_peer_key(&pr.node, &pkl);
        uint8_t *py2 = murmur_tx_peer_encode(&pr, &pyl);
        ok = pkey2 && py2 &&
             murmur_kv_put(db, pkey2, pkl, py2, pyl, &sqlrc) == MURMUR_SYNC_OK;
        CHECK(ok, "reap peer setup %zu", i);
        free(pkey2);
        free(py2);
      }
    }
    CHECK(murmur_tx_reap_forgotten_pins(db, now, max_off, &r_on, 1, &sqlrc) ==
              MURMUR_SYNC_OK,
          "reap run");
    for (size_t i = 0; i < 7; i++) {
      size_t pkl = 0;
      uint8_t *pkey = murmur_tx_pin_key(&cases[i].tid, &pkl);
      CHECK(kv_has(db, pkey, pkl) == cases[i].want_kept, "reap case %zu", i);
      free(pkey);
    }
  }
  close_crr(db);
}

typedef struct {
  sqlite3 *db;
  int calls;
  int empty_tail;
} snap_emit_ctx_t;

static murmur_sync_status_t snap_emit_fn(void *c,
                                         const murmur_kv_record_t *rs, size_t n,
                                         int *s) {
  snap_emit_ctx_t *e = (snap_emit_ctx_t *)c;
  e->calls++;
  if (n == 0) {
    e->empty_tail = 1;
  }
  return murmur_kv_commit(e->db, rs, n, s);
}

static void snap_params_fix(murmur_snap_params_t *p, murmur_node_t donor) {
  memset(p, 0, sizeof(*p));
  p->snapshot_bytes = 8 << 20;
  p->snapshot_staging_bytes = 8 << 20;
  p->transfer_lifetime_ms = 60000;
  p->staging_transfers = 4;
  p->max_transaction_bytes = 1 << 20;
  p->batch_bytes = 256 << 10;
  p->trusted = (murmur_node_t *)malloc(sizeof(donor));
  p->trusted[0] = donor;
  p->n_trusted = 1;
}

static void test_snapbuild(void) {
  int sqlrc = 0;
  murmur_node_t database = node_fill(0xaa);
  murmur_node_t donor = node_fill(0xd0);
  murmur_node_t rcpt = node_fill(0xe1);
  murmur_snap_params_t params;
  snap_params_fix(&params, donor);
  /* verify verdicts over a hand-built manifest */
  murmur_tx_manifest_t m;
  memset(&m, 0, sizeof(m));
  m.database = database;
  m.donor = donor;
  m.recipient = rcpt;
  m.transfer = node_fill(0x77);
  m.expires = 5000;
  m.bytes = 100;
  static uint8_t one_chunk[1][32];
  memset(one_chunk, 0x11, 32);
  m.chunks = one_chunk;
  m.n_chunks = 1;
  murmur_tx_progress_t pg[1];
  memset(pg, 0, sizeof(pg));
  pg[0].origin = donor;
  pg[0].applied = 5;
  pg[0].observed = 5;
  m.progress = pg;
  m.n_progress = 1;
  CHECK(murmur_snap_verify(&m, &database, &rcpt, &donor, &params, 1000,
                           &sqlrc) == MURMUR_SYNC_OK,
        "snapverify ok");
  murmur_node_t other = node_fill(0x99);
  CHECK(murmur_snap_verify(&m, &database, &rcpt, &other, &params, 1000,
                           &sqlrc) == MURMUR_SYNC_AUTH,
        "snapverify donor accepted");
  CHECK(murmur_snap_verify(&m, &database, &rcpt, &donor, &params, 5000,
                           &sqlrc) == MURMUR_SYNC_AUTH,
        "snapverify expiry accepted");
  murmur_snap_params_t untrusted;
  snap_params_fix(&untrusted, other);
  CHECK(murmur_snap_verify(&m, &database, &rcpt, &donor, &untrusted, 1000,
                           &sqlrc) == MURMUR_SYNC_AUTH,
        "snapverify trust accepted");
  murmur_snap_params_free(&untrusted);
  m.bytes = (uint64_t)params.snapshot_bytes + 1;
  CHECK(murmur_snap_verify(&m, &database, &rcpt, &donor, &params, 1000,
                           &sqlrc) == MURMUR_SYNC_OVERLOADED,
        "snapverify size accepted");
  m.bytes = 100;
  m.n_chunks = 2;
  CHECK(murmur_snap_verify(&m, &database, &rcpt, &donor, &params, 1000,
                           &sqlrc) == MURMUR_SYNC_OVERLOADED,
        "snapverify chunks accepted");
  m.n_chunks = 1;
  pg[0].observed = 4;
  CHECK(murmur_snap_verify(&m, &database, &rcpt, &donor, &params, 1000,
                           &sqlrc) == MURMUR_SYNC_PROTOCOL,
        "snapverify regress accepted");
  pg[0].observed = 5;
  pg[0].retained_from = 9;
  pg[0].retained_through = 3;
  CHECK(murmur_snap_verify(&m, &database, &rcpt, &donor, &params, 1000,
                           &sqlrc) == MURMUR_SYNC_PROTOCOL,
        "snapverify window accepted");
  pg[0].retained_from = 0;
  pg[0].retained_through = 0;
  /* streaming build stages OUT chunks, pin, and header */
  {
    sqlite3 *db = open_crr();
    CHECK(db != NULL, "snapbuild db");
    if (!db) {
      murmur_snap_params_free(&params);
      return;
    }
    static const uint8_t p0[] = "page-zero-payload";
    static const uint8_t p1[] = "page-one-payload-longer";
    const uint8_t *pages[2] = {p0, p1};
    size_t lens[2] = {sizeof(p0) - 1, sizeof(p1) - 1};
    uint8_t schema[32];
    memset(schema, 0xcd, 32);
    murmur_tx_manifest_t built;
    memset(&built, 0, sizeof(built));
    snap_emit_ctx_t ctx;
    ctx.db = db;
    ctx.calls = 0;
    ctx.empty_tail = 0;
    CHECK(murmur_snap_build_streaming(&database, &donor, &rcpt, pages, lens,
                                      2, pg, 1, schema, &params, 1000,
                                      snap_emit_fn, &ctx, &built,
                                      &sqlrc) == MURMUR_SYNC_OK,
          "snapbuild run");
    size_t want_total = MURMUR_TX_STREAM_MAGIC_LEN + (4 + lens[0]) + (4 + lens[1]);
    CHECK(built.bytes == want_total && built.n_chunks == 1 &&
              murmur_node_eq(&built.donor, &donor) &&
              built.expires == 1000 + params.transfer_lifetime_ms &&
              memcmp(built.schema, schema, 32) == 0 &&
              built.n_progress == 1 && built.progress[0].applied == 5,
          "snapbuild manifest bytes=%llu",
          (unsigned long long)built.bytes);
    /* digest covers magic + length-prefixed pages */
    {
      uint8_t expect[32];
      murmur_sha256_t h;
      murmur_sha256_init(&h);
      static const uint8_t magic[] = MURMUR_TX_STREAM_MAGIC;
      murmur_sha256_update(&h, magic, MURMUR_TX_STREAM_MAGIC_LEN);
      for (int i = 0; i < 2; i++) {
        uint8_t ln[4] = {0, 0, (uint8_t)(lens[i] >> 8),
                         (uint8_t)lens[i]};
        murmur_sha256_update(&h, ln, 4);
        murmur_sha256_update(&h, pages[i], lens[i]);
      }
      murmur_sha256_final(&h, expect);
      CHECK(memcmp(expect, built.digest, 32) == 0, "snapbuild digest");
      CHECK(memcmp(expect, built.chunks[0], 32) == 0, "snapbuild chunk hash");
    }
    /* OUT header, pin, and chunk all staged */
    {
      size_t kl = 0;
      uint8_t *hk = murmur_tx_header_key(MURMUR_TX_OUT, &built.transfer, &kl);
      CHECK(kv_has(db, hk, kl), "snapbuild header lost");
      free(hk);
      uint8_t *pk = murmur_tx_pin_key(&built.transfer, &kl);
      CHECK(kv_has(db, pk, kl), "snapbuild pin lost");
      free(pk);
      uint8_t *ck = murmur_tx_chunk_key(MURMUR_TX_OUT, &built.transfer, 0,
                                        &kl);
      CHECK(kv_has(db, ck, kl), "snapbuild chunk lost");
      free(ck);
    }
    CHECK(ctx.empty_tail == 1, "snapbuild empty tail emit");
    murmur_tx_manifest_free(&built);
    /* empty and oversize pages fail */
    {
      const uint8_t *bad[1] = {p0};
      size_t badlens[1] = {0};
      murmur_tx_manifest_t ign;
      memset(&ign, 0, sizeof(ign));
      CHECK(murmur_snap_build_streaming(&database, &donor, &rcpt, bad,
                                        badlens, 1, pg, 1, schema, &params,
                                        1000, snap_emit_fn, &ctx, &ign,
                                        &sqlrc) == MURMUR_SYNC_OVERLOADED,
            "snapbuild empty page accepted");
      murmur_snap_params_t tiny = params;
      tiny.snapshot_bytes = 10;
      tiny.trusted = params.trusted; /* borrowed, not freed */
      tiny.n_trusted = params.n_trusted;
      memset(&ign, 0, sizeof(ign));
      CHECK(murmur_snap_build_streaming(&database, &donor, &rcpt, pages,
                                        lens, 2, pg, 1, schema, &tiny, 1000,
                                        snap_emit_fn, &ctx, &ign,
                                        &sqlrc) == MURMUR_SYNC_OVERLOADED,
            "snapbuild budget accepted");
    }
    close_crr(db);
  }
  /* accept stages verified manifests, idempotent on restage */
  {
    sqlite3 *db = open_crr();
    if (!db) {
      murmur_snap_params_free(&params);
      return;
    }
    snap_emit_ctx_t ctx;
    ctx.db = db;
    ctx.calls = 0;
    ctx.empty_tail = 0;
    static const uint8_t p0[] = "accept-page";
    const uint8_t *pages[1] = {p0};
    size_t lens[1] = {sizeof(p0) - 1};
    uint8_t schema[32];
    memset(schema, 0xcd, 32);
    murmur_tx_manifest_t m1;
    memset(&m1, 0, sizeof(m1));
    CHECK(murmur_snap_build_streaming(&database, &donor, &rcpt, pages, lens,
                                      1, pg, 1, schema, &params, 1000,
                                      snap_emit_fn, &ctx, &m1,
                                      &sqlrc) == MURMUR_SYNC_OK,
          "snapaccept build");
    CHECK(murmur_snap_accept(db, &database, &rcpt, &params, &donor, &m1,
                             1000, &sqlrc) == MURMUR_SYNC_OK,
          "snapaccept run");
    size_t kl = 0;
    uint8_t *hk = murmur_tx_header_key(MURMUR_TX_IN, &m1.transfer, &kl);
    CHECK(kv_has(db, hk, kl), "snapaccept header lost");
    free(hk);
    CHECK(murmur_snap_accept(db, &database, &rcpt, &params, &donor, &m1,
                             1000, &sqlrc) == MURMUR_SYNC_OK,
          "snapaccept idempotent");
    /* a second staged transfer conflicts */
    murmur_tx_manifest_t m2 = m1;
    m2.transfer = node_fill(0x78);
    m2.expires = 6000;
    CHECK(murmur_snap_accept(db, &database, &rcpt, &params, &donor, &m2,
                             1000, &sqlrc) == MURMUR_SYNC_OVERLOADED,
          "snapaccept second accepted");
    /* chunkless manifests read as builds in progress */
    murmur_tx_manifest_t m0;
    memset(&m0, 0, sizeof(m0));
    m0.database = database;
    m0.donor = donor;
    m0.recipient = rcpt;
    m0.transfer = node_fill(0x79);
    m0.expires = 5000;
    m0.bytes = 0;
    exec_ok(db, "DELETE FROM murmur_kv;", "snapaccept clear");
    CHECK(murmur_snap_accept(db, &database, &rcpt, &params, &donor, &m0,
                             1000, &sqlrc) == MURMUR_SYNC_OVERLOADED,
          "snapaccept chunkless accepted");
    /* conflicting receipt bytes are AUTH */
    murmur_tx_incoming_t rcpt_inc;
    memset(&rcpt_inc, 0, sizeof(rcpt_inc));
    rcpt_inc.manifest = m1;
    rcpt_inc.deadline = 9000;
    size_t rl = 0, rkl = 0;
    uint8_t *renc = murmur_tx_incoming_encode(&rcpt_inc, &rl);
    uint8_t *rkey = murmur_tx_receipt_key(&m1.transfer, &rkl);
    CHECK(murmur_kv_put(db, rkey, rkl, renc, rl, &sqlrc) == MURMUR_SYNC_OK,
          "snapaccept receipt setup");
    free(renc);
    free(rkey);
    CHECK(murmur_snap_accept(db, &database, &rcpt, &params, &donor, &m1,
                             1000, &sqlrc) == MURMUR_SYNC_OK,
          "snapaccept receipt idempotent");
    m2 = m1;
    m2.transfer = m1.transfer;
    m2.expires = 7000;
    CHECK(murmur_snap_accept(db, &database, &rcpt, &params, &donor, &m2,
                             1000, &sqlrc) == MURMUR_SYNC_AUTH,
          "snapaccept receipt conflict accepted");
    murmur_tx_manifest_free(&m1);
    close_crr(db);
  }
  /* build_for over a live export, installed on a fresh peer */
  {
    sqlite3 *donor_db = open_crr();
    sqlite3 *rcpt_db = open_crr();
    if (!donor_db || !rcpt_db) {
      if (donor_db) {
        close_crr(donor_db);
      }
      if (rcpt_db) {
        close_crr(rcpt_db);
      }
      murmur_snap_params_free(&params);
      return;
    }
    make_sync_table(donor_db, "t");
    make_sync_table(rcpt_db, "t");
    exec_ok(donor_db, "INSERT INTO t VALUES(1,'x'),(2,'y');", "snap rows");
    murmur_tx_manifest_t m;
    memset(&m, 0, sizeof(m));
    CHECK(murmur_snap_build_for(donor_db, &database, &donor, &params,
                                1 << 20, 4 << 20, &rcpt, 1000, &m,
                                &sqlrc) == MURMUR_SYNC_OK &&
              m.n_chunks >= 1,
          "snapbuildfor run chunks=%zu", m.n_chunks);
    CHECK(murmur_snap_accept(rcpt_db, &database, &rcpt, &params, &donor, &m,
                             1000, &sqlrc) == MURMUR_SYNC_OK,
          "snapfinish accept");
    /* ferry OUT chunks to the recipient's IN staging */
    for (size_t i = 0; i < m.n_chunks; i++) {
      size_t okl = 0, ikl = 0;
      uint8_t *okey =
          murmur_tx_chunk_key(MURMUR_TX_OUT, &m.transfer, (uint32_t)i, &okl);
      uint8_t *ikey =
          murmur_tx_chunk_key(MURMUR_TX_IN, &m.transfer, (uint32_t)i, &ikl);
      uint8_t *raw = NULL;
      size_t raw_len = 0;
      int found = 0;
      int ok = okey && ikey &&
               murmur_kv_get(donor_db, okey, okl, &raw, &raw_len, &found,
                             &sqlrc) == MURMUR_SYNC_OK &&
               found &&
               murmur_kv_put(rcpt_db, ikey, ikl, raw, raw_len, &sqlrc) ==
                   MURMUR_SYNC_OK;
      CHECK(ok, "snapfinish ferry %zu", i);
      free(okey);
      free(ikey);
      free(raw);
    }
    int done = 0;
    CHECK(murmur_snap_finish(rcpt_db, &database, &rcpt, &params, &donor,
                             &m.transfer, 1000, &done,
                             &sqlrc) == MURMUR_SYNC_OK &&
              done == 1,
          "snapfinish run done=%d", done);
    CHECK(count_rows(rcpt_db, "SELECT COUNT(*) FROM t;") == 2,
          "snapfinish rows applied");
    size_t kl = 0;
    uint8_t *rkey = murmur_tx_receipt_key(&m.transfer, &kl);
    CHECK(kv_has(rcpt_db, rkey, kl), "snapfinish receipt lost");
    free(rkey);
    uint8_t *hkey = murmur_tx_header_key(MURMUR_TX_IN, &m.transfer, &kl);
    CHECK(!kv_has(rcpt_db, hkey, kl), "snapfinish header kept");
    free(hkey);
    /* second finish short-circuits on the receipt */
    done = 0;
    CHECK(murmur_snap_finish(rcpt_db, &database, &rcpt, &params, &donor,
                             &m.transfer, 1000, &done,
                             &sqlrc) == MURMUR_SYNC_OK &&
              done == 1,
          "snapfinish again");
    /* wrong donor against the receipt is AUTH */
    CHECK(murmur_snap_finish(rcpt_db, &database, &rcpt, &params, &other,
                             &m.transfer, 1000, &done,
                             &sqlrc) == MURMUR_SYNC_AUTH,
          "snapfinish donor accepted");
    murmur_tx_manifest_free(&m);
    close_crr(donor_db);
    close_crr(rcpt_db);
  }
  /* build_for on an empty export still ships the CRSB framing */
  {
    sqlite3 *db = open_crr();
    if (!db) {
      murmur_snap_params_free(&params);
      return;
    }
    make_sync_table(db, "t");
    murmur_tx_manifest_t m;
    memset(&m, 0, sizeof(m));
    CHECK(murmur_snap_build_for(db, &database, &donor, &params, 1 << 20,
                                4 << 20, &rcpt, 1000, &m,
                                &sqlrc) == MURMUR_SYNC_OK &&
              m.n_chunks == 1 && m.bytes == MURMUR_TX_STREAM_MAGIC_LEN + 16,
          "snapbuildfor empty chunks=%zu bytes=%llu", m.n_chunks,
          (unsigned long long)m.bytes);
    murmur_tx_manifest_free(&m);
    close_crr(db);
  }
  murmur_snap_params_free(&params);
}

static void put_floor_head(sqlite3 *db, murmur_node_t origin,
                             uint64_t applied) {
  int sqlrc = 0;
  murmur_tx_progress_t p;
  memset(&p, 0, sizeof(p));
  p.origin = origin;
  p.applied = applied;
  p.observed = applied;
  size_t kl = 0, vl = 0;
  uint8_t *key = murmur_tx_retained_key(&origin, &kl);
  uint8_t *val = murmur_tx_progress_encode(&p, &vl);
  if (key && val) {
    murmur_kv_put(db, key, kl, val, vl, &sqlrc);
  }
  free(key);
  free(val);
}

static void put_peer_ack(sqlite3 *db, murmur_node_t node, uint64_t seen,
                         int retired, murmur_node_t origin, uint64_t ack) {
  int sqlrc = 0;
  murmur_tx_peer_t pr;
  memset(&pr, 0, sizeof(pr));
  pr.node = node;
  pr.last_seen_millis = seen;
  pr.retired = retired;
  murmur_tx_ack_t a[1];
  a[0].origin = origin;
  a[0].seq = ack;
  pr.acks = a;
  pr.n_acks = 1;
  size_t kl = 0, vl = 0;
  uint8_t *key = murmur_tx_peer_key(&node, &kl);
  uint8_t *val = murmur_tx_peer_encode(&pr, &vl);
  if (key && val) {
    murmur_kv_put(db, key, kl, val, vl, &sqlrc);
  }
  free(key);
  free(val);
}

static uint64_t get_floor(sqlite3 *db, murmur_node_t origin) {
  int sqlrc = 0;
  size_t kl = 0;
  uint8_t *key = murmur_tx_floor_key(&origin, &kl);
  uint8_t *raw = NULL;
  size_t raw_len = 0;
  int found = 0;
  uint64_t v = UINT64_MAX;
  if (key && murmur_kv_get(db, key, kl, &raw, &raw_len, &found, &sqlrc) ==
                  MURMUR_SYNC_OK &&
      found) {
    uint64_t dec = UINT64_MAX;
    if (murmur_tx_decode_u64(raw, raw_len, &dec, &sqlrc) == MURMUR_SYNC_OK) {
      v = dec;
    }
  }
  free(key);
  free(raw);
  return v;
}

static void test_retainpass(void) {
  sqlite3 *db = open_crr();
  if (!db) {
    return;
  }
  int sqlrc = 0;
  murmur_node_t self = node_fill(0x11);
  murmur_node_t remote = node_fill(0xa1);
  murmur_node_t peer = node_fill(0xe1);
  murmur_retain_params_t params;
  memset(&params, 0, sizeof(params));
  params.min_retained = 2;
  params.max_offline_ms = 60000;
  params.bootstrap_nonempty = 0;
  /* one remote head at applied 10, acked to 8 by a live peer */
  put_floor_head(db, remote, 10);
  put_peer_ack(db, peer, 9000, 0, remote, 8);
  uint64_t moved = 0;
  CHECK(murmur_collect_floors(db, &self, &params, &peer, 1, 10000, 0,
                              &moved, &sqlrc) == MURMUR_SYNC_OK &&
            moved == 1,
        "floors moved=%llu", (unsigned long long)moved);
  CHECK(get_floor(db, remote) == 8, "floors value");
  /* retained head records from=floor+1, through=applied */
  {
    size_t kl = 0;
    uint8_t *key = murmur_tx_retained_key(&remote, &kl);
    uint8_t *raw = NULL;
    size_t raw_len = 0;
    int found = 0;
    murmur_tx_progress_t rp;
    memset(&rp, 0, sizeof(rp));
    CHECK(murmur_kv_get(db, key, kl, &raw, &raw_len, &found, &sqlrc) ==
                  MURMUR_SYNC_OK &&
              found &&
              murmur_tx_progress_decode(raw, raw_len, &rp, &sqlrc) ==
                  MURMUR_SYNC_OK &&
              rp.retained_from == 9 && rp.retained_through == 10,
          "floors retained");
    free(key);
    free(raw);
  }
  /* collection stamp lands */
  {
    static const uint8_t last[] = "07/replication/retention/last";
    uint8_t *raw = NULL;
    size_t raw_len = 0;
    int found = 0;
    uint64_t stamp = 0;
    CHECK(murmur_kv_get(db, last, sizeof(last) - 1, &raw, &raw_len, &found,
                        &sqlrc) == MURMUR_SYNC_OK &&
              found &&
              murmur_tx_decode_u64(raw, raw_len, &stamp, &sqlrc) ==
                  MURMUR_SYNC_OK &&
              stamp == 10000,
          "floors stamp");
    free(raw);
  }
  /* floors never decrease: a lower ack changes nothing */
  put_peer_ack(db, peer, 11000, 0, remote, 3);
  moved = 0;
  CHECK(murmur_collect_floors(db, &self, &params, &peer, 1, 12000, 0,
                              &moved, &sqlrc) == MURMUR_SYNC_OK &&
            moved == 0,
        "floors regress moved=%llu", (unsigned long long)moved);
  CHECK(get_floor(db, remote) == 8, "floors regressed");
  /* unrecorded online peers pin to 0 */
  {
    murmur_node_t online[2] = {peer, node_fill(0xe2)};
    moved = 0;
    CHECK(murmur_collect_floors(db, &self, &params, online, 2, 12000, 0,
                                &moved, &sqlrc) == MURMUR_SYNC_OK &&
              moved == 0,
          "floors unrecorded");
  }
  /* snapshot pins cap the floor */
  exec_ok(db, "DELETE FROM murmur_kv WHERE key >= CAST('07/replication/retention/floor/' AS BLOB) AND key < CAST('07/replication/retention/floor0' AS BLOB);",
          "floors clear");
  {
    murmur_tx_ack_t bnd[1];
    bnd[0].origin = remote;
    bnd[0].seq = 5;
    murmur_tx_pin_t pin;
    memset(&pin, 0, sizeof(pin));
    pin.recipient = peer;
    pin.boundary = bnd;
    pin.n_boundary = 1;
    pin.expires = 50000;
    size_t pkl = 0, pyl = 0;
    murmur_node_t tid = node_fill(0xb1);
    uint8_t *pkey = murmur_tx_pin_key(&tid, &pkl);
    uint8_t *py = murmur_tx_pin_encode(&pin, &pyl);
    CHECK(murmur_kv_put(db, pkey, pkl, py, pyl, &sqlrc) == MURMUR_SYNC_OK,
          "floors pin setup");
    free(pkey);
    free(py);
    put_peer_ack(db, peer, 12000, 0, remote, 9);
    moved = 0;
    CHECK(murmur_collect_floors(db, &self, &params, &peer, 1, 12000, 0,
                                &moved, &sqlrc) == MURMUR_SYNC_OK &&
              moved == 1,
          "floors pin moved=%llu", (unsigned long long)moved);
    CHECK(get_floor(db, remote) == 5, "floors pin cap");
  }
  /* my stream floor: min live ack minus the kept tail */
  {
    uint64_t fl = 0;
    CHECK(murmur_my_stream_floor(db, &params, &peer, 1, &remote, 10, 12000,
                                 0, &fl, &sqlrc) == MURMUR_SYNC_OK &&
              fl == 7,
          "myfloor live fl=%llu", (unsigned long long)fl);
    /* retired peers do not count */
    put_peer_ack(db, peer, 12000, 1, remote, 9);
    CHECK(murmur_my_stream_floor(db, &params, &peer, 1, &remote, 10, 12000,
                                 0, &fl, &sqlrc) == MURMUR_SYNC_OK &&
              fl == 8,
          "myfloor retired fl=%llu", (unsigned long long)fl);
    /* unrecorded online pins to 0 */
    murmur_node_t online2[2] = {peer, node_fill(0xe9)};
    CHECK(murmur_my_stream_floor(db, &params, online2, 2, &remote, 10,
                                 12000, 0, &fl,
                                 &sqlrc) == MURMUR_SYNC_OK &&
              fl == 0,
          "myfloor unrecorded fl=%llu", (unsigned long long)fl);
    /* young seeded nodes pin to 0 with no counting peers */
    murmur_retain_params_t young = params;
    young.bootstrap_nonempty = 1;
    CHECK(murmur_my_stream_floor(db, &young, NULL, 0, &remote, 10, 12000,
                                 11000, &fl, &sqlrc) == MURMUR_SYNC_OK &&
              fl == 0,
          "myfloor young fl=%llu", (unsigned long long)fl);
    /* mature solo nodes prune through their own head */
    CHECK(murmur_my_stream_floor(db, &params, NULL, 0, &remote, 10, 12000,
                                 0, &fl, &sqlrc) == MURMUR_SYNC_OK &&
              fl == 8,
          "myfloor solo fl=%llu", (unsigned long long)fl);
  }
  close_crr(db);
}

static void test_schemaadopt(void) {
  sqlite3 *db = open_crr();
  if (!db) {
    return;
  }
  int sqlrc = 0;
  murmur_node_t own = node_fill(0x11);
  murmur_node_t database = node_fill(0xaa);
  murmur_node_t src = node_fill(0x22);
  murmur_schema_params_t params;
  memset(&params, 0, sizeof(params));
  params.accept_remote = 1;
  params.max_schema_bytes = 1 << 20;
  static const uint8_t s1[] = "schema-one";
  static const uint8_t s2[] = "schema-two";
  /* monotonic sequences per digest */
  murmur_signed_schema_t m1;
  memset(&m1, 0, sizeof(m1));
  CHECK(murmur_schema_build_manifest(db, &params, &own, &database, s1,
                                     sizeof(s1) - 1, &m1,
                                     &sqlrc) == MURMUR_SYNC_OK &&
            m1.sequence == 1 && murmur_node_eq(&m1.signer, &own) &&
            m1.schema_len == sizeof(s1) - 1,
        "adopt build seq=%llu", (unsigned long long)m1.sequence);
  murmur_signed_schema_free(&m1);
  memset(&m1, 0, sizeof(m1));
  CHECK(murmur_schema_build_manifest(db, &params, &own, &database, s1,
                                     sizeof(s1) - 1, &m1,
                                     &sqlrc) == MURMUR_SYNC_OK &&
            m1.sequence == 1,
        "adopt rebuild kept seq=%llu", (unsigned long long)m1.sequence);
  murmur_signed_schema_free(&m1);
  memset(&m1, 0, sizeof(m1));
  CHECK(murmur_schema_build_manifest(db, &params, &own, &database, s2,
                                     sizeof(s2) - 1, &m1,
                                     &sqlrc) == MURMUR_SYNC_OK &&
            m1.sequence == 2,
        "adopt bump seq=%llu", (unsigned long long)m1.sequence);
  /* master must designate self */
  murmur_schema_params_t mp = params;
  mp.master_enabled = 1;
  CHECK(murmur_schema_build_manifest(db, &mp, &own, &database, s1,
                                     sizeof(s1) - 1, NULL,
                                     &sqlrc) == MURMUR_SYNC_INVALID,
        "adopt masterless accepted");
  mp.has_master = 1;
  mp.master = src;
  CHECK(murmur_schema_build_manifest(db, &mp, &own, &database, s1,
                                     sizeof(s1) - 1, NULL,
                                     &sqlrc) == MURMUR_SYNC_INVALID,
        "adopt foreign master accepted");
  mp.master = own;
  memset(&m1, 0, sizeof(m1));
  CHECK(murmur_schema_build_manifest(db, &mp, &own, &database, s1,
                                     sizeof(s1) - 1, &m1,
                                     &sqlrc) == MURMUR_SYNC_OK,
        "adopt self master");
  murmur_signed_schema_free(&m1);
  /* oversize fails */
  murmur_schema_params_t tiny = params;
  tiny.max_schema_bytes = 4;
  CHECK(murmur_schema_build_manifest(db, &tiny, &own, &database, s1,
                                     sizeof(s1) - 1, NULL,
                                     &sqlrc) == MURMUR_SYNC_OVERLOADED,
        "adopt oversize accepted");
  /* corrupt cursor fails closed */
  static const uint8_t ckey[] = "07/replication/schema/manifest";
  static const uint8_t cbad[] = {1, 2, 3};
  CHECK(murmur_kv_put(db, ckey, sizeof(ckey) - 1, cbad, sizeof(cbad),
                      &sqlrc) == MURMUR_SYNC_OK,
        "adopt corrupt setup");
  CHECK(murmur_schema_build_manifest(db, &params, &own, &database, s1,
                                     sizeof(s1) - 1, NULL,
                                     &sqlrc) == MURMUR_SYNC_PROTOCOL,
        "adopt corrupt accepted");
  exec_ok(db, "DELETE FROM murmur_kv;", "adopt clear");
  /* transport verification */
  murmur_signed_schema_t v;
  memset(&v, 0, sizeof(v));
  v.database = database;
  v.signer = src;
  v.sequence = 3;
  v.schema = (uint8_t *)s1;
  v.schema_len = sizeof(s1) - 1;
  CHECK(murmur_schema_verify_transport(&v, &database, &src, &params,
                                       &sqlrc) == MURMUR_SYNC_OK,
        "adopt verify ok");
  v.sequence = 0;
  CHECK(murmur_schema_verify_transport(&v, &database, &src, &params,
                                       &sqlrc) == MURMUR_SYNC_AUTH,
        "adopt verify seq accepted");
  v.sequence = 3;
  v.signer = own;
  CHECK(murmur_schema_verify_transport(&v, &database, &src, &params,
                                       &sqlrc) == MURMUR_SYNC_AUTH,
        "adopt verify signer accepted");
  v.signer = src;
  /* check: current, stale, adopt, record */
  murmur_schema_decision_t dec = MURMUR_SCHEMA_ADOPT;
  CHECK(murmur_schema_check_manifest(db, &params, &own, s1, sizeof(s1) - 1,
                                     &v, &database, &src, &dec,
                                     &sqlrc) == MURMUR_SYNC_OK &&
            dec == MURMUR_SCHEMA_CURRENT,
        "adopt check current dec=%d", (int)dec);
  CHECK(murmur_schema_check_manifest(db, &params, &own, s1, sizeof(s1) - 1,
                                     &v, &database, &src, &dec,
                                     &sqlrc) == MURMUR_SYNC_OK &&
            dec == MURMUR_SCHEMA_STALE,
        "adopt check stale dec=%d", (int)dec);
  /* additive delta over real pair bytes: one table vs two */
  make_sync_table(db, "t");
  sqlite3 *full = open_crr();
  if (full) {
    make_sync_table(full, "t");
    make_sync_table(full, "u");
    uint8_t *local = NULL, *remote = NULL;
    size_t lloc = 0, rloc = 0;
    if (murmur_schema_bytes(db, &local, &lloc, &sqlrc) == MURMUR_SYNC_OK &&
        murmur_schema_bytes(full, &remote, &rloc, &sqlrc) == MURMUR_SYNC_OK) {
      murmur_signed_schema_t r;
      memset(&r, 0, sizeof(r));
      r.database = database;
      r.signer = src;
      r.sequence = 9;
      r.schema = remote;
      r.schema_len = rloc;
      CHECK(murmur_schema_check_manifest(db, &params, &own, local, lloc, &r,
                                         &database, &src, &dec,
                                         &sqlrc) == MURMUR_SYNC_OK &&
                dec == MURMUR_SCHEMA_ADOPT,
            "adopt check adopt dec=%d", (int)dec);
      /* subset reverse delta adopts as a no-op (local extras kept) */
      murmur_signed_schema_t r2;
      memset(&r2, 0, sizeof(r2));
      r2.database = database;
      r2.signer = src;
      r2.sequence = 10;
      r2.schema = local;
      r2.schema_len = lloc;
      CHECK(murmur_schema_check_manifest(full, &params, &own, remote, rloc,
                                         &r2, &database, &src, &dec,
                                         &sqlrc) == MURMUR_SYNC_OK &&
                dec == MURMUR_SCHEMA_ADOPT,
            "adopt check subset dec=%d", (int)dec);
      /* opt-out records additive manifests too */
      murmur_schema_params_t off = params;
      off.accept_remote = 0;
      r.sequence = 11;
      CHECK(murmur_schema_check_manifest(db, &off, &own, local, lloc, &r,
                                         &database, &src, &dec,
                                         &sqlrc) == MURMUR_SYNC_OK &&
                dec == MURMUR_SCHEMA_RECORD,
            "adopt check optout dec=%d", (int)dec);
    } else {
      CHECK(0, "adopt pair bytes");
    }
    free(local);
    free(remote);
    close_crr(full);
  }
  close_crr(db);
}

/* Blocking in-memory full-duplex pipe pair for serve tests. */
typedef struct {
  pthread_mutex_t mu;
  pthread_cond_t cond;
  uint8_t *b;
  size_t len, cap, pos;
  int eof;
  char err[64];
} mempipe_t;

static void mempipe_init(mempipe_t *p) {
  memset(p, 0, sizeof(*p));
  pthread_mutex_init(&p->mu, NULL);
  pthread_cond_init(&p->cond, NULL);
}

static void mempipe_destroy(mempipe_t *p) {
  free(p->b);
  pthread_mutex_destroy(&p->mu);
  pthread_cond_destroy(&p->cond);
}

typedef struct {
  mempipe_t *out; /* written by this end */
  mempipe_t *in;  /* read by this end */
} memio_t;

static int memio_write(void *ctx, const uint8_t *b, size_t n) {
  memio_t *io = (memio_t *)ctx;
  mempipe_t *p = io->out;
  pthread_mutex_lock(&p->mu);
  if (p->eof) {
    snprintf(p->err, sizeof(p->err), "closed");
    pthread_mutex_unlock(&p->mu);
    return 1;
  }
  if (p->len + n > p->cap) {
    size_t ncap = p->cap ? p->cap * 2 : 4096;
    while (ncap < p->len + n) {
      ncap *= 2;
    }
    uint8_t *nb = (uint8_t *)realloc(p->b, ncap);
    if (!nb) {
      pthread_mutex_unlock(&p->mu);
      return 1;
    }
    p->b = nb;
    p->cap = ncap;
  }
  memcpy(p->b + p->len, b, n);
  p->len += n;
  pthread_cond_broadcast(&p->cond);
  pthread_mutex_unlock(&p->mu);
  return 0;
}

static int memio_read(void *ctx, uint8_t *b, size_t n) {
  memio_t *io = (memio_t *)ctx;
  mempipe_t *p = io->in;
  pthread_mutex_lock(&p->mu);
  for (;;) {
    if (p->len - p->pos >= n) {
      break;
    }
    if (p->eof) {
      snprintf(p->err, sizeof(p->err), "eof");
      pthread_mutex_unlock(&p->mu);
      return 1;
    }
    pthread_cond_wait(&p->cond, &p->mu);
  }
  memcpy(b, p->b + p->pos, n);
  p->pos += n;
  pthread_mutex_unlock(&p->mu);
  return 0;
}

static int memio_close(void *ctx) {
  memio_t *io = (memio_t *)ctx;
  pthread_mutex_lock(&io->out->mu);
  io->out->eof = 1;
  pthread_cond_broadcast(&io->out->cond);
  pthread_mutex_unlock(&io->out->mu);
  return 0;
}

static const char *memio_error(void *ctx) {
  memio_t *io = (memio_t *)ctx;
  return io->in->err[0] ? io->in->err : NULL;
}

typedef struct {
  mempipe_t ab, ba;
  memio_t a_end, b_end;
  murmur_stream_io_t a_io, b_io;
} mempair_t;

static void mempair_init(mempair_t *mp) {
  mempipe_init(&mp->ab);
  mempipe_init(&mp->ba);
  mp->a_end.out = &mp->ab;
  mp->a_end.in = &mp->ba;
  mp->b_end.out = &mp->ba;
  mp->b_end.in = &mp->ab;
  mp->a_io.write = memio_write;
  mp->a_io.read_full = memio_read;
  mp->a_io.close = memio_close;
  mp->a_io.error_text = memio_error;
  mp->a_io.ctx = &mp->a_end;
  mp->b_io = mp->a_io;
  mp->b_io.ctx = &mp->b_end;
}

static void mempair_destroy(mempair_t *mp) {
  mempipe_destroy(&mp->ab);
  mempipe_destroy(&mp->ba);
}

static void engine_test_init(murmur_engine_t *e, sqlite3 *db,
                             const murmur_node_t *group,
                             const murmur_node_t *node,
                             const murmur_node_t *site, uint64_t incarnation,
                             const char *addr) {
  murmur_engine_init(e, db);
  e->group = *group;
  e->node = *node;
  e->site = *site;
  e->incarnation = incarnation;
  murmur_addr_parse(&e->advertise, addr);
  e->serving_max = (uint64_t)64 << 20;
  e->receiving_max = (uint64_t)64 << 20;
}

static void test_serve_frames(void) {
  mempair_t mp;
  mempair_init(&mp);
  /* Roundtrip one hello. */
  murmur_msg_t h;
  memset(&h, 0, sizeof(h));
  h.tag = MURMUR_MSG_HELLO;
  h.group = node_fill(1);
  h.node = node_fill(2);
  h.site = node_fill(3);
  memset(h.schema, 0xAB, 32);
  h.incarnation = 42;
  murmur_addr_parse(&h.addr, "127.0.0.1:4443");
  char *detail = NULL;
  int sqlrc = -1;
  CHECK(murmur_serve_write_msg(&mp.a_io, &h, &detail, &sqlrc) ==
            MURMUR_SYNC_OK,
        "frame write");
  CHECK(detail == NULL && sqlrc == SQLITE_OK, "frame write rc");
  murmur_serve_msg_t got;
  memset(&got, 0, sizeof(got));
  CHECK(murmur_serve_read_msg(&mp.b_io, &got, &detail, &sqlrc) ==
            MURMUR_SYNC_OK,
        "frame read");
  CHECK(got.msg.tag == MURMUR_MSG_HELLO, "frame tag");
  CHECK(murmur_node_eq(&got.msg.group, &h.group), "frame group");
  CHECK(murmur_node_eq(&got.msg.node, &h.node), "frame node");
  CHECK(murmur_node_eq(&got.msg.site, &h.site), "frame site");
  CHECK(memcmp(got.msg.schema, h.schema, 32) == 0, "frame schema");
  CHECK(got.msg.incarnation == 42, "frame incarnation");
  char abuf[64];
  murmur_addr_format(&got.msg.addr, abuf, sizeof(abuf));
  CHECK(strcmp(abuf, "127.0.0.1:4443") == 0, "frame addr %s", abuf);
  murmur_serve_msg_free(&got);
  free(detail);
  detail = NULL;
  /* Truncated header. */
  uint8_t two[2] = {0, 1};
  CHECK(memio_write(&mp.a_end, two, 2) == 0, "short write");
  memio_close(&mp.a_end);
  CHECK(murmur_serve_read_msg(&mp.b_io, &got, &detail, &sqlrc) ==
            MURMUR_SYNC_PROTOCOL,
        "truncated header status");
  CHECK(detail && strcmp(detail, "truncated frame header") == 0,
        "truncated header detail");
  free(detail);
  detail = NULL;
  mempair_destroy(&mp);
  /* Bad lengths. */
  mempair_init(&mp);
  uint8_t zero[4] = {0, 0, 0, 0};
  CHECK(memio_write(&mp.a_end, zero, 4) == 0, "zero write");
  CHECK(murmur_serve_read_msg(&mp.b_io, &got, &detail, &sqlrc) ==
            MURMUR_SYNC_PROTOCOL,
        "zero length status");
  CHECK(detail && strcmp(detail, "invalid frame length") == 0,
        "zero length detail");
  free(detail);
  detail = NULL;
  uint8_t big[4] = {0x00, 0x02, 0x00, 0x01}; /* 128 KiB + 1 */
  CHECK(memio_write(&mp.a_end, big, 4) == 0, "big write");
  CHECK(murmur_serve_read_msg(&mp.b_io, &got, &detail, &sqlrc) ==
            MURMUR_SYNC_PROTOCOL,
        "big length status");
  CHECK(detail && strcmp(detail, "invalid frame length") == 0,
        "big length detail");
  free(detail);
  detail = NULL;
  /* Truncated body. */
  uint8_t hdr[4] = {0, 0, 0, 10};
  CHECK(memio_write(&mp.a_end, hdr, 4) == 0, "hdr write");
  CHECK(memio_write(&mp.a_end, two, 2) == 0, "body write");
  memio_close(&mp.a_end);
  CHECK(murmur_serve_read_msg(&mp.b_io, &got, &detail, &sqlrc) ==
            MURMUR_SYNC_PROTOCOL,
        "truncated body status");
  CHECK(detail && strcmp(detail, "truncated frame") == 0,
        "truncated body detail");
  free(detail);
  detail = NULL;
  mempair_destroy(&mp);
  /* Oversized encode. */
  mempair_init(&mp);
  murmur_msg_t ch;
  memset(&ch, 0, sizeof(ch));
  ch.tag = MURMUR_MSG_CHUNK;
  static uint8_t huge[200 << 10];
  ch.data = huge;
  ch.data_len = sizeof(huge);
  CHECK(murmur_serve_write_msg(&mp.a_io, &ch, &detail, &sqlrc) ==
            MURMUR_SYNC_OVERLOADED,
        "oversize status");
  CHECK(detail && strcmp(detail, "frame too large") == 0, "oversize detail");
  free(detail);
  mempair_destroy(&mp);
}

typedef struct {
  murmur_engine_t *e;
  murmur_node_t peer;
  murmur_stream_io_t *io;
  int outgoing;
  murmur_sync_status_t st;
  char *detail;
  int sqlrc;
  uint64_t incarnation;
  murmur_addr_t addr;
} hs_arg_t;

static void *hs_thread(void *v) {
  hs_arg_t *a = (hs_arg_t *)v;
  a->st = murmur_serve_handshake(a->e, &a->peer, a->io, a->outgoing,
                                 &a->incarnation, &a->addr, &a->detail,
                                 &a->sqlrc);
  return NULL;
}

static void hs_arg_init(hs_arg_t *a, murmur_engine_t *e,
                        const murmur_node_t *peer, murmur_stream_io_t *io,
                        int outgoing) {
  memset(a, 0, sizeof(*a));
  a->e = e;
  a->peer = *peer;
  a->io = io;
  a->outgoing = outgoing;
}

/* Runs both sides; closing after the incoming side returns
 * releases a peer left waiting by a reject. */
static void hs_pair(hs_arg_t *in, hs_arg_t *out, mempair_t *mp) {
  pthread_t t0, t1;
  pthread_create(&t0, NULL, hs_thread, in);
  pthread_create(&t1, NULL, hs_thread, out);
  pthread_join(t0, NULL);
  memio_close(&mp->a_end);
  memio_close(&mp->b_end);
  pthread_join(t1, NULL);
}

static void test_serve_handshake(void) {
  sqlite3 *da = open_crr();
  sqlite3 *db = open_crr();
  if (!da || !db) {
    if (da) {
      close_crr(da);
    }
    if (db) {
      close_crr(db);
    }
    return;
  }
  make_sync_table(da, "t");
  make_sync_table(db, "t");
  murmur_node_t group = node_fill(7);
  murmur_node_t na = node_fill(0xA0);
  murmur_node_t sa = node_fill(0xA1);
  murmur_node_t nb = node_fill(0xB0);
  murmur_node_t sb = node_fill(0xB1);
  murmur_engine_t ea, eb;
  engine_test_init(&ea, da, &group, &na, &sa, 11, "127.0.0.1:1111");
  engine_test_init(&eb, db, &group, &nb, &sb, 22, "127.0.0.1:2222");
  mempair_t mp;
  mempair_init(&mp);
  hs_arg_t ina, outb;
  hs_arg_init(&ina, &ea, &nb, &mp.a_io, 0);
  hs_arg_init(&outb, &eb, &na, &mp.b_io, 1);
  hs_pair(&ina, &outb, &mp);
  CHECK(ina.st == MURMUR_SYNC_OK, "hs incoming status %d", (int)ina.st);
  CHECK(outb.st == MURMUR_SYNC_OK, "hs outgoing status %d", (int)outb.st);
  CHECK(ina.incarnation == 22, "hs incoming incarnation");
  CHECK(outb.incarnation == 11, "hs outgoing incarnation");
  char abuf[64];
  murmur_addr_format(&ina.addr, abuf, sizeof(abuf));
  CHECK(strcmp(abuf, "127.0.0.1:2222") == 0, "hs incoming addr %s", abuf);
  murmur_addr_format(&outb.addr, abuf, sizeof(abuf));
  CHECK(strcmp(abuf, "127.0.0.1:1111") == 0, "hs outgoing addr %s", abuf);
  free(ina.detail);
  free(outb.detail);
  mempair_destroy(&mp);
  /* Group reject. */
  sqlite3 *dc = open_crr();
  make_sync_table(dc, "t");
  murmur_node_t group2 = node_fill(8);
  murmur_node_t nc = node_fill(0xC0);
  murmur_node_t sc = node_fill(0xC1);
  murmur_engine_t ec;
  engine_test_init(&ec, dc, &group2, &nc, &sc, 33, "127.0.0.1:3333");
  mempair_init(&mp);
  hs_arg_t inc, outc;
  hs_arg_init(&inc, &ea, &nc, &mp.a_io, 0);
  hs_arg_init(&outc, &ec, &na, &mp.b_io, 1);
  hs_pair(&inc, &outc, &mp);
  CHECK(inc.st == MURMUR_SYNC_AUTH, "hs group reject status %d", (int)inc.st);
  CHECK(inc.detail &&
            strcmp(inc.detail, "session group or identity mismatch") == 0,
        "hs group reject detail");
  free(inc.detail);
  free(outc.detail);
  mempair_destroy(&mp);
  /* Schema mismatch. Reject only when adoption is off (Go
   * Handshake: schemas are a fast-fail hint then); adopters
   * proceed and converge through manifests. */
  make_sync_table(dc, "u");
  murmur_engine_destroy(&ec);
  engine_test_init(&ec, dc, &group, &nc, &sc, 33, "127.0.0.1:3333");
  exec_ok(da,
          "INSERT INTO murmur_config(name,value) "
          "VALUES('accept_remote_schema','0')",
          "hs adoption off");
  mempair_init(&mp);
  hs_arg_t ins, outs;
  hs_arg_init(&ins, &ea, &nc, &mp.a_io, 0);
  hs_arg_init(&outs, &ec, &na, &mp.b_io, 1);
  hs_pair(&ins, &outs, &mp);
  CHECK(ins.st == MURMUR_SYNC_PROTOCOL, "hs schema status %d", (int)ins.st);
  CHECK(ins.detail && strcmp(ins.detail, "CRR schema mismatch; provision "
                                         "matching table definitions") == 0,
        "hs schema detail");
  free(ins.detail);
  free(outs.detail);
  mempair_destroy(&mp);
  exec_ok(da, "UPDATE murmur_config SET value='1' WHERE name='accept_remote_schema'",
          "hs adoption on");
  mempair_init(&mp);
  hs_arg_t ina2, outb2;
  hs_arg_init(&ina2, &ea, &nc, &mp.a_io, 0);
  hs_arg_init(&outb2, &ec, &na, &mp.b_io, 1);
  hs_pair(&ina2, &outb2, &mp);
  CHECK(ina2.st == MURMUR_SYNC_OK, "hs adopter incoming status %d",
        (int)ina2.st);
  CHECK(outb2.st == MURMUR_SYNC_OK, "hs adopter outgoing status %d",
        (int)outb2.st);
  free(ina2.detail);
  free(outb2.detail);
  mempair_destroy(&mp);
  /* Wrong first tag. */
  mempair_init(&mp);
  murmur_msg_t idle;
  memset(&idle, 0, sizeof(idle));
  idle.tag = MURMUR_MSG_IDLE;
  char *wd = NULL;
  int wrc = 0;
  CHECK(murmur_serve_write_msg(&mp.b_io, &idle, &wd, &wrc) == MURMUR_SYNC_OK,
        "idle write");
  free(wd);
  uint64_t inc2 = 0;
  murmur_addr_t ad2;
  memset(&ad2, 0, sizeof(ad2));
  char *dd = NULL;
  int sqlrc = 0;
  CHECK(murmur_serve_handshake(&ea, &nb, &mp.a_io, 0, &inc2, &ad2, &dd,
                               &sqlrc) == MURMUR_SYNC_PROTOCOL,
        "hs wrong tag status");
  CHECK(dd && strcmp(dd, "expected hello") == 0, "hs wrong tag detail");
  free(dd);
  mempair_destroy(&mp);
  murmur_engine_destroy(&ea);
  murmur_engine_destroy(&eb);
  murmur_engine_destroy(&ec);
  close_crr(da);
  close_crr(db);
  close_crr(dc);
}

typedef struct {
  murmur_engine_t *e;
  murmur_node_t peer;
  murmur_stream_io_t *io;
  int pull; /* 1 = pull_once, 0 = serve_stream */
  murmur_sync_status_t st;
  char *detail;
  int sqlrc;
  int more;
} xfer_arg_t;

static void *xfer_thread(void *v) {
  xfer_arg_t *a = (xfer_arg_t *)v;
  if (a->pull) {
    a->st = murmur_serve_pull_once(a->e, &a->peer, a->io, &a->more,
                                   &a->detail, &a->sqlrc);
  } else {
    a->st = murmur_serve_stream(a->e, &a->peer, a->io, &a->detail, &a->sqlrc);
  }
  return NULL;
}

static void xfer_arg_init(xfer_arg_t *a, murmur_engine_t *e,
                          const murmur_node_t *peer, murmur_stream_io_t *io,
                          int pull) {
  memset(a, 0, sizeof(*a));
  a->e = e;
  a->peer = *peer;
  a->io = io;
  a->pull = pull;
}

/* One pull round: donor serves on a thread, puller on the caller. */
static void pull_round(xfer_arg_t *srv, xfer_arg_t *cli) {
  pthread_t t;
  pthread_create(&t, NULL, xfer_thread, srv);
  xfer_thread(cli);
  pthread_join(t, NULL);
}

static void test_serve_pull(void) {
  sqlite3 *da = open_crr();
  sqlite3 *db = open_crr();
  if (!da || !db) {
    if (da) {
      close_crr(da);
    }
    if (db) {
      close_crr(db);
    }
    return;
  }
  make_sync_table(da, "t");
  make_sync_table(db, "t");
  exec_ok(da, "INSERT INTO t VALUES(1,'x'),(2,'y');", "donor rows");
  murmur_node_t group = node_fill(7);
  murmur_node_t na = node_fill(0xA0);
  murmur_node_t sa = node_fill(0xA1);
  murmur_node_t nb = node_fill(0xB0);
  murmur_node_t sb = node_fill(0xB1);
  murmur_engine_t ea, eb;
  engine_test_init(&ea, da, &group, &na, &sa, 11, "127.0.0.1:1111");
  engine_test_init(&eb, db, &group, &nb, &sb, 22, "127.0.0.1:2222");
  mempair_t mp;
  xfer_arg_t srv, cli;
  /* Round 1: unknown site resets. */
  mempair_init(&mp);
  xfer_arg_init(&srv, &ea, &nb, &mp.a_io, 0);
  xfer_arg_init(&cli, &eb, &na, &mp.b_io, 1);
  pull_round(&srv, &cli);
  CHECK(srv.st == MURMUR_SYNC_OK, "reset serve status %d", (int)srv.st);
  CHECK(cli.st == MURMUR_SYNC_OK, "reset pull status %d", (int)cli.st);
  CHECK(cli.more == 1, "reset more");
  CHECK(ea.serve_ok == 1, "reset serve_ok");
  free(srv.detail);
  free(cli.detail);
  mempair_destroy(&mp);
  murmur_node_t psite;
  int phas = 0;
  murmur_stored_cursor_t pcur;
  memset(&pcur, 0, sizeof(pcur));
  int prc = 0;
  CHECK(murmur_sync_progress(db, &na, &psite, &phas, &pcur, &prc) ==
            MURMUR_SYNC_OK,
        "reset progress");
  CHECK(phas && murmur_node_eq(&psite, &sa), "reset site");
  murmur_sync_cursor_free(&pcur);
  /* Round 2: the batch flows. */
  mempair_init(&mp);
  xfer_arg_init(&srv, &ea, &nb, &mp.a_io, 0);
  xfer_arg_init(&cli, &eb, &na, &mp.b_io, 1);
  pull_round(&srv, &cli);
  CHECK(srv.st == MURMUR_SYNC_OK, "batch serve status %d", (int)srv.st);
  CHECK(cli.st == MURMUR_SYNC_OK, "batch pull status %d", (int)cli.st);
  CHECK(cli.more == 0, "batch more");
  CHECK(count_rows(db, "SELECT COUNT(*) FROM t") == 2, "batch rows");
  CHECK(eb.applied == 1, "batch applied");
  CHECK(ea.sent == 1, "batch sent");
  CHECK(ea.serve_ok == 2, "batch serve_ok");
  CHECK(ea.serving_in_use == 0 && eb.receiving_in_use == 0, "batch gauges");
  free(srv.detail);
  free(cli.detail);
  mempair_destroy(&mp);
  /* Round 3: drained idles. */
  mempair_init(&mp);
  xfer_arg_init(&srv, &ea, &nb, &mp.a_io, 0);
  xfer_arg_init(&cli, &eb, &na, &mp.b_io, 1);
  pull_round(&srv, &cli);
  CHECK(srv.st == MURMUR_SYNC_OK, "idle serve status %d", (int)srv.st);
  CHECK(cli.st == MURMUR_SYNC_OK, "idle pull status %d", (int)cli.st);
  CHECK(cli.more == 0, "idle more");
  CHECK(eb.applied == 1, "idle applied");
  CHECK(ea.sent == 1, "idle sent");
  CHECK(ea.serve_ok == 3, "idle serve_ok");
  free(srv.detail);
  free(cli.detail);
  mempair_destroy(&mp);
  /* Reject: MsgError text reaches the puller verbatim. */
  sqlite3 *dc = open_crr();
  make_sync_table(dc, "t");
  murmur_node_t group2 = node_fill(8);
  murmur_node_t nc = node_fill(0xC0);
  murmur_node_t sc = node_fill(0xC1);
  murmur_engine_t ec;
  engine_test_init(&ec, dc, &group2, &nc, &sc, 33, "127.0.0.1:3333");
  mempair_init(&mp);
  xfer_arg_init(&srv, &ec, &nb, &mp.a_io, 0);
  xfer_arg_init(&cli, &eb, &nc, &mp.b_io, 1);
  pull_round(&srv, &cli);
  CHECK(srv.st == MURMUR_SYNC_AUTH, "reject serve status %d", (int)srv.st);
  CHECK(srv.detail &&
            strcmp(srv.detail, "replication group or identity mismatch") ==
                0,
        "reject serve detail");
  CHECK(cli.st == MURMUR_SYNC_PROTOCOL, "reject pull status %d", (int)cli.st);
  CHECK(cli.detail && strcmp(cli.detail, "Auth: replication group or "
                                         "identity mismatch") == 0,
        "reject pull detail");
  CHECK(ec.serve_reject == 1, "reject counter");
  CHECK(ec.last_error_text &&
            strcmp(ec.last_error_text, "Auth: replication group or identity "
                                       "mismatch") == 0,
        "reject record");
  free(srv.detail);
  free(cli.detail);
  mempair_destroy(&mp);
  murmur_engine_destroy(&ea);
  murmur_engine_destroy(&eb);
  murmur_engine_destroy(&ec);
  close_crr(da);
  close_crr(db);
  close_crr(dc);
}

/* Multi-batch pull: >1024 cells force paged batches whose next cursor
 * carries an after resume key. Apply re-encodes that cursor into
 * progress; the key borrows the reply buffer, so freeing the reply
 * first stores heap garbage that fails every later pull (log-boundedness
 * one-directional stall). Under ASan the use-after-free reports here. */
static void test_serve_pull_multibatch(void) {
  sqlite3 *da = open_crr();
  sqlite3 *db = open_crr();
  if (!da || !db) {
    if (da) {
      close_crr(da);
    }
    if (db) {
      close_crr(db);
    }
    return;
  }
  make_sync_table(da, "t");
  make_sync_table(db, "t");
  for (int i = 0; i < 2000; i++) {
    char sql[64];
    snprintf(sql, sizeof(sql), "INSERT INTO t VALUES(%d,'r%d');", i, i);
    exec_ok(da, sql, "bulk rows");
  }
  murmur_node_t group = node_fill(7);
  murmur_node_t na = node_fill(0xA0);
  murmur_node_t sa = node_fill(0xA1);
  murmur_node_t nb = node_fill(0xB0);
  murmur_node_t sb = node_fill(0xB1);
  murmur_engine_t ea, eb;
  engine_test_init(&ea, da, &group, &na, &sa, 11, "127.0.0.1:1111");
  engine_test_init(&eb, db, &group, &nb, &sb, 22, "127.0.0.1:2222");
  mempair_t mp;
  xfer_arg_t srv, cli;
  mempair_init(&mp);
  xfer_arg_init(&srv, &ea, &nb, &mp.a_io, 0);
  xfer_arg_init(&cli, &eb, &na, &mp.b_io, 1);
  pull_round(&srv, &cli);
  free(srv.detail);
  free(cli.detail);
  mempair_destroy(&mp);
  int rounds = 0;
  for (;;) {
    mempair_init(&mp);
    xfer_arg_init(&srv, &ea, &nb, &mp.a_io, 0);
    xfer_arg_init(&cli, &eb, &na, &mp.b_io, 1);
    pull_round(&srv, &cli);
    CHECK(srv.st == MURMUR_SYNC_OK, "multibatch serve %d", (int)srv.st);
    CHECK(cli.st == MURMUR_SYNC_OK, "multibatch pull %d", (int)cli.st);
    int more = cli.more;
    free(srv.detail);
    free(cli.detail);
    mempair_destroy(&mp);
    if (++rounds > 8 || !more) {
      CHECK(!more, "multibatch drained");
      break;
    }
  }
  CHECK(count_rows(db, "SELECT COUNT(*) FROM t") == 2000, "multibatch rows");
  CHECK(rounds > 1, "multibatch paged");
  murmur_node_t psite;
  int phas = 0;
  murmur_stored_cursor_t pcur;
  memset(&pcur, 0, sizeof(pcur));
  int prc = 0;
  CHECK(murmur_sync_progress(db, &na, &psite, &phas, &pcur, &prc) ==
            MURMUR_SYNC_OK,
        "multibatch progress decodes");
  murmur_sync_cursor_free(&pcur);
  murmur_engine_destroy(&ea);
  murmur_engine_destroy(&eb);
  close_crr(da);
  close_crr(db);
}

/* Loopback session: open_stream mints a pipe pair and queues the
 * server end for a donor serve thread. */
typedef struct {
  murmur_engine_t *donor;
  murmur_node_t peer;
  pthread_mutex_t mu;
  pthread_cond_t cond;
  murmur_stream_io_t *queue;
  size_t n, cap;
  mempair_t **mps;
  size_t n_mps, cap_mps;
  int stop;
  int opened;
  pthread_t thread;
  int thread_on;
} loop_sess_t;

static void loop_sess_init(loop_sess_t *s, murmur_engine_t *donor,
                           const murmur_node_t *peer) {
  memset(s, 0, sizeof(*s));
  s->donor = donor;
  s->peer = *peer;
  pthread_mutex_init(&s->mu, NULL);
  pthread_cond_init(&s->cond, NULL);
}

static int loop_open(void *ctx, murmur_stream_io_t *out) {
  loop_sess_t *s = (loop_sess_t *)ctx;
  mempair_t *mp = (mempair_t *)malloc(sizeof(*mp));
  if (!mp) {
    return 1;
  }
  mempair_init(mp);
  pthread_mutex_lock(&s->mu);
  if (s->n_mps >= s->cap_mps) {
    size_t ncap = s->cap_mps ? s->cap_mps * 2 : 8;
    mempair_t **nv = (mempair_t **)realloc(s->mps, ncap * sizeof(*nv));
    if (!nv) {
      pthread_mutex_unlock(&s->mu);
      mempair_destroy(mp);
      free(mp);
      return 1;
    }
    s->mps = nv;
    s->cap_mps = ncap;
  }
  s->mps[s->n_mps++] = mp;
  if (s->n >= s->cap) {
    size_t ncap = s->cap ? s->cap * 2 : 8;
    murmur_stream_io_t *nq =
        (murmur_stream_io_t *)realloc(s->queue, ncap * sizeof(*nq));
    if (!nq) {
      pthread_mutex_unlock(&s->mu);
      return 1;
    }
    s->queue = nq;
    s->cap = ncap;
  }
  s->queue[s->n++] = mp->a_io;
  s->opened++;
  pthread_cond_signal(&s->cond);
  pthread_mutex_unlock(&s->mu);
  *out = mp->b_io;
  return 0;
}

static void *loop_serve_thread(void *v) {
  loop_sess_t *s = (loop_sess_t *)v;
  for (;;) {
    pthread_mutex_lock(&s->mu);
    while (s->n == 0 && !s->stop) {
      pthread_cond_wait(&s->cond, &s->mu);
    }
    if (s->n == 0 && s->stop) {
      pthread_mutex_unlock(&s->mu);
      break;
    }
    murmur_stream_io_t io = s->queue[--s->n];
    pthread_mutex_unlock(&s->mu);
    murmur_serve_stream(s->donor, &s->peer, &io, NULL, NULL);
  }
  return NULL;
}

static void loop_start(loop_sess_t *s) {
  pthread_create(&s->thread, NULL, loop_serve_thread, s);
  s->thread_on = 1;
}

static void loop_stop(loop_sess_t *s) {
  pthread_mutex_lock(&s->mu);
  s->stop = 1;
  pthread_cond_broadcast(&s->cond);
  pthread_mutex_unlock(&s->mu);
  if (s->thread_on) {
    pthread_join(s->thread, NULL);
    s->thread_on = 0;
  }
  for (size_t i = 0; i < s->n_mps; i++) {
    mempair_destroy(s->mps[i]);
    free(s->mps[i]);
  }
  free(s->mps);
  free(s->queue);
  pthread_mutex_destroy(&s->mu);
  pthread_cond_destroy(&s->cond);
}

static void loop_iface(loop_sess_t *s, murmur_session_if_t *out) {
  memset(out, 0, sizeof(*out));
  out->open_stream = loop_open;
  out->ctx = s;
}

static int set_setting(sqlite3 *db, const char *name, const char *value) {
  int sqlrc = 0;
  if (murmur_cfg_set_setting(db, name, (const uint8_t *)value, strlen(value),
                             &sqlrc) != MURMUR_SYNC_OK) {
    printf("FAIL setting %s: %d\n", name, sqlrc);
    failures++;
    return 0;
  }
  return 1;
}

static void test_serve_snapshot(void) {
  sqlite3 *da = open_crr();
  sqlite3 *db = open_crr();
  if (!da || !db) {
    if (da) {
      close_crr(da);
    }
    if (db) {
      close_crr(db);
    }
    return;
  }
  make_sync_table(da, "t");
  make_sync_table(db, "t");
  exec_ok(da, "INSERT INTO t VALUES(1,'x'),(2,'y');", "donor rows");
  murmur_node_t group = node_fill(7);
  murmur_node_t na = node_fill(0xA0);
  murmur_node_t sa = node_fill(0xA1);
  murmur_node_t nb = node_fill(0xB0);
  murmur_node_t sb = node_fill(0xB1);
  murmur_engine_t ea, eb;
  engine_test_init(&ea, da, &group, &na, &sa, 11, "127.0.0.1:1111");
  engine_test_init(&eb, db, &group, &nb, &sb, 22, "127.0.0.1:2222");
  char hex[33];
  murmur_engine_node_format(&na, hex);
  char trust[64];
  snprintf(trust, sizeof(trust), "[\"%s\"]", hex);
  set_setting(db, "snapshot_trusted_sources", trust);
  loop_sess_t ls;
  loop_sess_init(&ls, &ea, &nb);
  murmur_session_if_t si;
  loop_iface(&ls, &si);
  int sqlrc = 0;
  CHECK(murmur_engine_add_conn(&eb, &na, &si, &sqlrc) == MURMUR_SYNC_OK,
        "snap add conn");
  loop_start(&ls);
  murmur_node_t transfer;
  memset(&transfer, 0, sizeof(transfer));
  char *detail = NULL;
  CHECK(murmur_serve_fetch_snapshot(&eb, &na, &si, &transfer, &detail,
                                    &sqlrc) == MURMUR_SYNC_OK,
        "snap fetch %s", detail ? detail : "");
  CHECK(count_rows(db, "SELECT COUNT(*) FROM t") == 2, "snap rows");
  CHECK(eb.applied == 1, "snap applied");
  murmur_node_t zero;
  memset(&zero, 0, sizeof(zero));
  CHECK(!murmur_node_eq(&transfer, &zero), "snap transfer");
  free(detail);
  detail = NULL;
  /* Unconnected peer fails without touching the stream. */
  murmur_node_t nc = node_fill(0xC0);
  CHECK(murmur_serve_fetch_snapshot(&eb, &nc, &si, &transfer, &detail,
                                    &sqlrc) == MURMUR_SYNC_OVERLOADED,
        "snap unconnected status");
  CHECK(detail && strcmp(detail, "snapshot peer is not connected") == 0,
        "snap unconnected detail");
  free(detail);
  detail = NULL;
  loop_stop(&ls);
  /* The fetcher can finish reading before the donor updates its counter.
   * Join the donor thread before inspecting donor-owned state. */
  CHECK(ea.sent == 1, "snap sent");
  /* Donor reject text reaches the fetcher verbatim. */
  sqlite3 *dc = open_crr();
  make_sync_table(dc, "t");
  murmur_node_t group2 = node_fill(8);
  murmur_node_t sc = node_fill(0xC1);
  murmur_engine_t ec;
  engine_test_init(&ec, dc, &group2, &nc, &sc, 33, "127.0.0.1:3333");
  loop_sess_t lc;
  loop_sess_init(&lc, &ec, &nb);
  murmur_session_if_t sic;
  loop_iface(&lc, &sic);
  CHECK(murmur_engine_add_conn(&eb, &nc, &sic, &sqlrc) == MURMUR_SYNC_OK,
        "snap add conn c");
  loop_start(&lc);
  CHECK(murmur_serve_fetch_snapshot(&eb, &nc, &sic, &transfer, &detail,
                                    &sqlrc) == MURMUR_SYNC_PROTOCOL,
        "snap reject status");
  CHECK(detail && strcmp(detail, "Auth: replication group or identity "
                                 "mismatch") == 0,
        "snap reject detail");
  free(detail);
  loop_stop(&lc);
  murmur_engine_destroy(&ea);
  murmur_engine_destroy(&eb);
  murmur_engine_destroy(&ec);
  close_crr(da);
  close_crr(db);
  close_crr(dc);
}

static int wait_status_idle(murmur_engine_t *e, int iters) {
  for (int i = 0; i < iters; i++) {
    pthread_mutex_lock(&e->mu);
    const char *s = e->snapshot_status;
    int running = s && strcmp(s, "running") == 0;
    pthread_mutex_unlock(&e->mu);
    if (!running) {
      return 1;
    }
    struct timespec ts;
    ts.tv_sec = 0;
    ts.tv_nsec = 50 * 1000 * 1000;
    nanosleep(&ts, NULL);
  }
  return 0;
}

static void test_serve_request(void) {
  sqlite3 *da = open_crr();
  sqlite3 *db = open_crr();
  if (!da || !db) {
    if (da) {
      close_crr(da);
    }
    if (db) {
      close_crr(db);
    }
    return;
  }
  make_sync_table(da, "t");
  make_sync_table(db, "t");
  exec_ok(da, "INSERT INTO t VALUES(1,'x');", "donor rows");
  murmur_node_t group = node_fill(7);
  murmur_node_t na = node_fill(0xA0);
  murmur_node_t sa = node_fill(0xA1);
  murmur_node_t nb = node_fill(0xB0);
  murmur_node_t sb = node_fill(0xB1);
  murmur_engine_t ea, eb;
  engine_test_init(&ea, da, &group, &na, &sa, 11, "127.0.0.1:1111");
  engine_test_init(&eb, db, &group, &nb, &sb, 22, "127.0.0.1:2222");
  char hex[33];
  murmur_engine_node_format(&na, hex);
  char trust[64];
  snprintf(trust, sizeof(trust), "[\"%s\"]", hex);
  set_setting(db, "snapshot_trusted_sources", trust);
  loop_sess_t ls;
  loop_sess_init(&ls, &ea, &nb);
  murmur_session_if_t si;
  loop_iface(&ls, &si);
  int sqlrc = 0;
  CHECK(murmur_engine_add_conn(&eb, &na, &si, &sqlrc) == MURMUR_SYNC_OK,
        "req add conn");
  /* Queue before the donor serves: the worker waits, so a second
   * request deterministically hits the in-flight guard. */
  CHECK(murmur_serve_request_snapshot(&eb, &na, &sqlrc) == MURMUR_SYNC_OK,
        "req queue");
  int guard = 0;
  for (int i = 0; i < 100 && !guard; i++) {
    pthread_mutex_lock(&eb.mu);
    guard = eb.snapshot_status &&
            strcmp(eb.snapshot_status, "running") == 0;
    pthread_mutex_unlock(&eb.mu);
    if (!guard) {
      struct timespec ts;
      ts.tv_sec = 0;
      ts.tv_nsec = 10 * 1000 * 1000;
      nanosleep(&ts, NULL);
    }
  }
  CHECK(guard, "req running");
  CHECK(murmur_serve_request_snapshot(&eb, &na, &sqlrc) ==
            MURMUR_SYNC_OVERLOADED,
        "req guard");
  loop_start(&ls);
  CHECK(wait_status_idle(&eb, 100), "req done");
  pthread_mutex_lock(&eb.mu);
  const char *st = eb.snapshot_status;
  int okfmt = st && strncmp(st, "ok ", 3) == 0 && strlen(st) == 3 + 32;
  pthread_mutex_unlock(&eb.mu);
  CHECK(okfmt, "req status");
  CHECK(count_rows(db, "SELECT COUNT(*) FROM t") == 1, "req rows");
  loop_stop(&ls);
  /* Unconnected peer records Unavailable in the status. */
  murmur_engine_destroy(&eb);
  engine_test_init(&eb, db, &group, &nb, &sb, 22, "127.0.0.1:2222");
  murmur_node_t nc = node_fill(0xC0);
  CHECK(murmur_serve_request_snapshot(&eb, &nc, &sqlrc) == MURMUR_SYNC_OK,
        "req queue unconnected");
  CHECK(wait_status_idle(&eb, 100), "req unconnected done");
  pthread_mutex_lock(&eb.mu);
  int errfmt = eb.snapshot_status && strcmp(eb.snapshot_status, "error: "
                                                         "Closed: snapshot "
                                                         "peer is not "
                                                         "connected") == 0;
  int has_err = eb.has_last_err;
  int32_t code = eb.last_err_code;
  char *kind = eb.last_err_kind ? strdup(eb.last_err_kind) : NULL;
  pthread_mutex_unlock(&eb.mu);
  CHECK(errfmt, "req unconnected status");
  CHECK(has_err && code == (int32_t)0x530D0E && kind &&
            strcmp(kind, "Unavailable") == 0,
        "req unconnected lastErr");
  free(kind);
  murmur_engine_destroy(&ea);
  murmur_engine_destroy(&eb);
  close_crr(da);
  close_crr(db);
}

static int fail_open(void *ctx, murmur_stream_io_t *out) {
  (void)ctx;
  (void)out;
  return 1;
}

static void test_serve_schema(void) {
  sqlite3 *da = open_crr();
  sqlite3 *db = open_crr();
  if (!da || !db) {
    if (da) {
      close_crr(da);
    }
    if (db) {
      close_crr(db);
    }
    return;
  }
  make_sync_table(da, "t");
  make_sync_table(db, "t");
  murmur_node_t group = node_fill(7);
  murmur_node_t na = node_fill(0xA0);
  murmur_node_t sa = node_fill(0xA1);
  murmur_node_t nb = node_fill(0xB0);
  murmur_node_t sb = node_fill(0xB1);
  murmur_engine_t ea, eb;
  engine_test_init(&ea, da, &group, &na, &sa, 11, "127.0.0.1:1111");
  engine_test_init(&eb, db, &group, &nb, &sb, 22, "127.0.0.1:2222");
  loop_sess_t ls;
  loop_sess_init(&ls, &ea, &nb);
  murmur_session_if_t si;
  loop_iface(&ls, &si);
  loop_start(&ls);
  /* Vet allow on identical schema. */
  int verdict = 0, ok = 0;
  murmur_serve_vet_fetch(&eb, &na, &si, &verdict, &ok);
  CHECK(ok && verdict, "vet allow");
  /* Vet deny when local has a table the peer lacks. */
  make_sync_table(db, "u");
  murmur_serve_vet_fetch(&eb, &na, &si, &verdict, &ok);
  CHECK(ok && !verdict, "vet deny");
  /* Transport failure is ok=0. */
  murmur_session_if_t bad;
  memset(&bad, 0, sizeof(bad));
  bad.open_stream = fail_open;
  murmur_serve_vet_fetch(&eb, &na, &bad, &verdict, &ok);
  CHECK(!ok, "vet transport");
  /* Adopt the peer's additive table. */
  exec_ok(db, "DROP TABLE u;", "drop u");
  make_sync_table(da, "u");
  set_setting(db, "accept_remote_schema", "1");
  char *detail = NULL;
  int sqlrc = 0;
  CHECK(murmur_serve_adopt_from_peer(&eb, &na, &si, &detail, &sqlrc) ==
            MURMUR_SYNC_OK,
        "adopt %s", detail ? detail : "");
  free(detail);
  detail = NULL;
  CHECK(count_rows(db, "SELECT COUNT(*) FROM sqlite_master WHERE type='table'"
                       " AND name='u'") == 1,
        "adopt table");
  CHECK(eb.schema_adoptions == 1, "adopt counter");
  loop_stop(&ls);
  /* Master push over serve_stream, then silent no-op. Fresh B: the
   * adopt above already recorded the sequence. */
  char hex[33];
  murmur_engine_node_format(&na, hex);
  set_setting(da, "schema_master_enabled", "1");
  set_setting(da, "schema_master", hex);
  murmur_engine_destroy(&eb);
  close_crr(db);
  db = open_crr();
  if (!db) {
    murmur_engine_destroy(&ea);
    close_crr(da);
    return;
  }
  make_sync_table(db, "t");
  set_setting(db, "accept_remote_schema", "1");
  engine_test_init(&eb, db, &group, &nb, &sb, 22, "127.0.0.1:2222");
  loop_sess_t lp;
  loop_sess_init(&lp, &eb, &na);
  murmur_session_if_t sip;
  loop_iface(&lp, &sip);
  loop_start(&lp);
  uint64_t sent0 = ea.sent;
  murmur_serve_push_schema(&ea, &nb, &sip);
  CHECK(count_rows(db, "SELECT COUNT(*) FROM sqlite_master WHERE type='table'"
                       " AND name='u'") == 1,
        "push table");
  CHECK(ea.sent == sent0 + 1, "push sent");
  CHECK(ea.n_schema_sent == 1, "push cache");
  int opened = lp.opened;
  murmur_serve_push_schema(&ea, &nb, &sip);
  CHECK(lp.opened == opened, "push dedup");
  loop_stop(&lp);
  murmur_engine_destroy(&ea);
  murmur_engine_destroy(&eb);
  close_crr(da);
  close_crr(db);
}

typedef struct {
  sqlite3 *db;
  pthread_barrier_t *bar;
  murmur_sync_status_t st;
  int sqlrc;
} conc_arg_t;

static void *conc_commit_thread(void *v) {
  conc_arg_t *a = (conc_arg_t *)v;
  pthread_barrier_wait(a->bar);
  static const uint8_t k[] = "conc/k";
  static const uint8_t val[] = "v";
  murmur_kv_record_t r;
  memset(&r, 0, sizeof(r));
  r.key = (uint8_t *)k;
  r.key_len = sizeof(k) - 1;
  r.value = (uint8_t *)val;
  r.value_len = sizeof(val) - 1;
  a->st = murmur_kv_commit(a->db, &r, 1, &a->sqlrc);
  return NULL;
}

typedef struct {
  sqlite3 *db;
  int base;
  int n;
  int fails;
} hammer_arg_t;

static void *conc_hammer_thread(void *v) {
  hammer_arg_t *a = (hammer_arg_t *)v;
  for (int i = 0; i < a->n; i++) {
    char kb[32];
    snprintf(kb, sizeof(kb), "conc/h%d/%d", a->base, i);
    murmur_kv_record_t r;
    memset(&r, 0, sizeof(r));
    r.key = (uint8_t *)kb;
    r.key_len = strlen(kb);
    static const uint8_t val[] = "v";
    r.value = (uint8_t *)val;
    r.value_len = 1;
    int sqlrc = 0;
    if (murmur_kv_commit(a->db, &r, 1, &sqlrc) != MURMUR_SYNC_OK) {
      a->fails++;
    }
  }
  return NULL;
}

/* Two threads sharing one handle must serialize write transactions: without
 * the writer guard the loser's BEGIN fails with "cannot start a transaction
 * within a transaction" (the log-boundedness snapshot stall). */
static void test_concurrent_txn(void) {
  sqlite3 *db = open_crr();
  if (!db) {
    return;
  }
  pthread_barrier_t bar;
  pthread_barrier_init(&bar, NULL, 2);
  conc_arg_t a;
  memset(&a, 0, sizeof(a));
  a.db = db;
  a.bar = &bar;
  a.st = MURMUR_SYNC_OVERLOADED;
  murmur_db_writer_lock();
  CHECK(sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, NULL) == SQLITE_OK,
        "raw begin");
  pthread_t t;
  pthread_create(&t, NULL, conc_commit_thread, &a);
  pthread_barrier_wait(&bar);
  struct timespec ts;
  ts.tv_sec = 0;
  ts.tv_nsec = 200 * 1000 * 1000;
  nanosleep(&ts, NULL);
  CHECK(sqlite3_exec(db, "COMMIT", NULL, NULL, NULL) == SQLITE_OK,
        "raw commit");
  murmur_db_writer_unlock();
  pthread_join(t, NULL);
  pthread_barrier_destroy(&bar);
  CHECK(a.st == MURMUR_SYNC_OK, "concurrent kv_commit st=%d sqlrc=%d",
        (int)a.st, a.sqlrc);
  uint8_t *got = NULL;
  size_t got_len = 0;
  int found = 0, sqlrc = 0;
  static const uint8_t kk[] = "conc/k";
  CHECK(murmur_kv_get(db, kk, sizeof(kk) - 1, &got, &got_len, &found,
                      &sqlrc) == MURMUR_SYNC_OK &&
            found && got_len == 1 && got[0] == 'v',
        "concurrent value landed");
  free(got);
  hammer_arg_t ha[4];
  pthread_t ht[4];
  for (int i = 0; i < 4; i++) {
    ha[i].db = db;
    ha[i].base = i;
    ha[i].n = 50;
    ha[i].fails = 0;
    pthread_create(&ht[i], NULL, conc_hammer_thread, &ha[i]);
  }
  int fails = 0;
  for (int i = 0; i < 4; i++) {
    pthread_join(ht[i], NULL);
    fails += ha[i].fails;
  }
  CHECK(fails == 0, "hammer fails=%d", fails);
  sqlite3_close(db);
}

int main(void) {
  test_export_roundtrip();
  test_export_paginates();
  test_export_validation();
  test_export_optout();
  test_export_overloaded();
  test_stage_apply();
  test_apply_guards();
  test_progress_misc();
  test_retain_params();
  test_gc_stage();
  test_gc_tombstones();
  test_reap_orphans();
  test_config_validate();
  test_config_setting();
  test_schema_discovery();
  test_schema_checks();
  test_schema_diff();
  test_schema_apply();
  test_txcodec();
  test_kv_backend();
  test_txtransfer();
  test_txretain();
  test_txsnap();
  test_snapbuild();
  test_retainpass();
  test_schemaadopt();
  test_serve_frames();
  test_serve_handshake();
  test_serve_pull();
  test_serve_snapshot();
  test_serve_request();
  test_serve_schema();
  test_concurrent_txn();
  test_serve_pull_multibatch();
  if (failures == 0) {
    printf("SYNC-OK (34 suites)\n");
    return 0;
  }
  printf("SYNC-FAIL (%d)\n", failures);
  return 1;
}
