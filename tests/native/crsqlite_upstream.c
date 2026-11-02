#include "sqlite3.h"
#include "sqlite_murmur_crsqlite.h"
#include "msgcodec.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "failed: %s line %d\n", #x, __LINE__); exit(1); } } while (0)
static void sql(sqlite3 *db, const char *text) {
  char *err = NULL; int rc = sqlite3_exec(db, text, NULL, NULL, &err);
  if (rc != SQLITE_OK) fprintf(stderr, "%s: %s\n", text, err ? err : sqlite3_errmsg(db));
  sqlite3_free(err); CHECK(rc == SQLITE_OK);
}
static void init(sqlite3 **db) {
  CHECK(sqlite3_open(":memory:", db) == SQLITE_OK);
  char *err = NULL; int rc = sqlite3_crsqlite_init(*db, &err, NULL);
  if (rc) fprintf(stderr, "crsql init: %s\n", err ? err : sqlite3_errmsg(*db));
  sqlite3_free(err); CHECK(rc == SQLITE_OK);
  sql(*db, "CREATE TABLE t(id TEXT PRIMARY KEY NOT NULL,v BLOB); SELECT crsql_as_crr('t')");
}
static int apply(sqlite3 *db, const void *data, int size) {
  sqlite3_stmt *st = NULL;
  CHECK(sqlite3_prepare_v2(db, "SELECT crsql_ingest_blob(?)", -1, &st, NULL) == SQLITE_OK);
  CHECK(sqlite3_bind_blob(st, 1, data, size, SQLITE_STATIC) == SQLITE_OK);
  int rc = sqlite3_step(st);
  if (rc != SQLITE_ROW) fprintf(stderr, "ingest: %s\n", sqlite3_errmsg(db));
  sqlite3_finalize(st); return rc;
}
int main(void) {
  sqlite3 *a, *b, *c; init(&a); init(&b); init(&c);
  sql(a, "INSERT INTO t VALUES('row',x'000a1aff')");
  sqlite3_stmt *st = NULL;
  CHECK(sqlite3_prepare_v2(a, "SELECT \"table\",pk,cid,val,col_version,db_version,site_id,cl,seq FROM crsql_changes", -1, &st, NULL) == SQLITE_OK);
  CHECK(sqlite3_step(st) == SQLITE_ROW);
  murmur_cell_t cell = {0};
  cell.table = sqlite3_column_text(st, 0); cell.table_len = sqlite3_column_bytes(st, 0);
  cell.pk = sqlite3_column_blob(st, 1); cell.pk_len = sqlite3_column_bytes(st, 1);
  cell.cid = sqlite3_column_text(st, 2); cell.cid_len = sqlite3_column_bytes(st, 2);
  cell.val_tag = 4; cell.val_blob = sqlite3_column_blob(st, 3); cell.val_blob_len = sqlite3_column_bytes(st, 3);
  cell.col_version = sqlite3_column_int64(st, 4); cell.db_version = sqlite3_column_int64(st, 5);
  cell.site = sqlite3_column_blob(st, 6); cell.site_len = sqlite3_column_bytes(st, 6);
  cell.cl = sqlite3_column_int64(st, 7); cell.seq = sqlite3_column_int64(st, 8);
  unsigned char blob[2048]; size_t length = murmur_cells_encode(&cell, 1, blob, sizeof(blob));
  CHECK(length > 0);
  murmur_cell_t invalid[2] = {cell, cell};
  invalid[1].table = (const uint8_t *)"missing"; invalid[1].table_len = 7;
  unsigned char bad[4096]; size_t bad_len = murmur_cells_encode(invalid, 2, bad, sizeof(bad));
  CHECK(bad_len > 0); sqlite3_finalize(st);
  CHECK(apply(c, bad, (int)bad_len) != SQLITE_ROW);
  CHECK(sqlite3_prepare_v2(c, "SELECT count(*) FROM t", -1, &st, NULL) == SQLITE_OK);
  CHECK(sqlite3_step(st) == SQLITE_ROW && sqlite3_column_int(st,0) == 0);
  sqlite3_finalize(st);
  CHECK(apply(b, blob, (int)length) == SQLITE_ROW);
  CHECK(apply(b, blob, (int)length) == SQLITE_ROW); /* idempotence */
  CHECK(sqlite3_prepare_v2(b, "SELECT v FROM t WHERE id='row'", -1, &st, NULL) == SQLITE_OK);
  CHECK(sqlite3_step(st) == SQLITE_ROW);
  const unsigned char expected[] = {0,10,26,255};
  CHECK(sqlite3_column_bytes(st,0) == sizeof(expected));
  CHECK(memcmp(sqlite3_column_blob(st,0), expected, sizeof(expected)) == 0);
  sqlite3_finalize(st);
  murmur_cell_t typed; size_t decoded = 0;
  CHECK(murmur_cells_decode(blob, length, &typed, 1, &decoded) == MURMUR_OK && decoded == 1);
  const char *types[] = {"null", "integer", "real", "text", "blob"};
  for (int tag = 0; tag <= 4; ++tag) {
    typed.val_tag = tag; typed.val_int = -9223372036854775807LL;
    typed.val_real = 1.25;
    typed.val_blob = (const uint8_t *)""; typed.val_blob_len = 0;
    ++typed.col_version; ++typed.db_version;
    unsigned char changed[2048]; size_t changed_len = murmur_cells_encode(&typed, 1, changed, sizeof(changed));
    CHECK(changed_len > 0 && apply(b, changed, (int)changed_len) == SQLITE_ROW);
    CHECK(sqlite3_prepare_v2(b, "SELECT typeof(v),v FROM t WHERE id='row'", -1, &st, NULL) == SQLITE_OK);
    CHECK(sqlite3_step(st) == SQLITE_ROW);
    if (strcmp((const char *)sqlite3_column_text(st,0), types[tag])) fprintf(stderr, "tag %d got %s expected %s\n", tag, sqlite3_column_text(st,0), types[tag]);
    CHECK(strcmp((const char *)sqlite3_column_text(st,0), types[tag]) == 0);
    if (tag == 1) CHECK(sqlite3_column_int64(st,1) == typed.val_int);
    if (tag == 2) CHECK(sqlite3_column_double(st,1) == typed.val_real);
    sqlite3_finalize(st);
  }
  sql(c, "BEGIN");
  CHECK(apply(c, blob, (int)length) == SQLITE_ROW);
  sql(c, "ROLLBACK");
  CHECK(sqlite3_prepare_v2(c, "SELECT count(*) FROM t", -1, &st, NULL) == SQLITE_OK);
  CHECK(sqlite3_step(st) == SQLITE_ROW && sqlite3_column_int(st,0) == 0);
  sqlite3_finalize(st);
  CHECK(apply(b, blob, (int)length-1) != SQLITE_ROW);
  const unsigned char empty[] = {'C','R','S','B',1,0,0,0,0,0,0,0};
  CHECK(apply(b, empty, sizeof(empty)) == SQLITE_ROW);
  sql(a, "SELECT crsql_finalize()"); sql(b, "SELECT crsql_finalize()");
  sql(c, "SELECT crsql_finalize()"); CHECK(sqlite3_close(c) == SQLITE_OK);
  CHECK(sqlite3_close(a) == SQLITE_OK); CHECK(sqlite3_close(b) == SQLITE_OK);
  puts("CRSQLITE-UPSTREAM-OK"); return 0;
}
