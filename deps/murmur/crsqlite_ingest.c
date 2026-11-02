/* Murmur's CRSB envelope adapter over upstream cr-sqlite's public changes vtab. */
#include "msgcodec.h"
#include "sqlite3.h"
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static void ingest(sqlite3_context *ctx, int argc, sqlite3_value **argv) {
  (void)argc;
  const uint8_t *blob = sqlite3_value_blob(argv[0]);
  int length = sqlite3_value_bytes(argv[0]);
  if (sqlite3_value_type(argv[0]) != SQLITE_BLOB || length < 12 ||
      !blob || memcmp(blob, "CRSB\1\0\0\0", 8)) {
    sqlite3_result_error(ctx, "invalid CRSB v1 envelope", -1); return;
  }
  uint32_t count = (uint32_t)blob[8] | ((uint32_t)blob[9] << 8) |
                   ((uint32_t)blob[10] << 16) | ((uint32_t)blob[11] << 24);
  if (count > (uint32_t)(length - 12)
#if SIZE_MAX <= UINT32_MAX
      || count > SIZE_MAX / sizeof(murmur_cell_t)
#endif
      ) {
    sqlite3_result_error(ctx, "invalid CRSB cell count", -1); return;
  }
  murmur_cell_t *cells = count ? sqlite3_malloc64((sqlite3_uint64)count * sizeof(*cells)) : NULL;
  if (count && !cells) { sqlite3_result_error_nomem(ctx); return; }
  size_t n = 0;
  if (murmur_cells_decode(blob, (size_t)length, cells, count, &n) != MURMUR_OK) {
    sqlite3_free(cells); sqlite3_result_error(ctx, "invalid CRSB cells", -1); return;
  }
  sqlite3 *db = sqlite3_context_db_handle(ctx);
  sqlite3_stmt *st = NULL;
  int rc = sqlite3_exec(db, "SAVEPOINT murmur_crsql_ingest", NULL, NULL, NULL);
  int savepoint = rc == SQLITE_OK;
  if (rc == SQLITE_OK) rc = sqlite3_prepare_v2(db,
      "INSERT INTO crsql_changes(\"table\",pk,cid,val,col_version,db_version,site_id,cl,seq)"
      " VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)", -1, &st, NULL);
  for (size_t i = 0; rc == SQLITE_OK && i < n; ++i) {
    const murmur_cell_t *c = &cells[i];
    rc = sqlite3_bind_text(st, 1, (const char *)c->table, (int)c->table_len, SQLITE_STATIC);
    if (rc == SQLITE_OK) rc = sqlite3_bind_blob(st, 2, c->pk, (int)c->pk_len, SQLITE_STATIC);
    if (rc == SQLITE_OK) rc = sqlite3_bind_text(st, 3, (const char *)c->cid, (int)c->cid_len, SQLITE_STATIC);
    if (rc == SQLITE_OK) switch (c->val_tag) {
      case 0: rc = sqlite3_bind_null(st, 4); break;
      case 1: rc = sqlite3_bind_int64(st, 4, c->val_int); break;
      case 2: rc = sqlite3_bind_double(st, 4, c->val_real); break;
      case 3: rc = sqlite3_bind_text(st, 4, c->val_blob ? (const char *)c->val_blob : "", (int)c->val_blob_len, SQLITE_STATIC); break;
      case 4: rc = sqlite3_bind_blob(st, 4, c->val_blob ? c->val_blob : (const uint8_t *)"", (int)c->val_blob_len, SQLITE_STATIC); break;
      default: rc = SQLITE_MISMATCH;
    }
    if (rc == SQLITE_OK) rc = sqlite3_bind_int64(st, 5, c->col_version);
    if (rc == SQLITE_OK) rc = sqlite3_bind_int64(st, 6, c->db_version);
    if (rc == SQLITE_OK) rc = sqlite3_bind_blob(st, 7, c->site, (int)c->site_len, SQLITE_STATIC);
    if (rc == SQLITE_OK) rc = sqlite3_bind_int64(st, 8, c->cl);
    if (rc == SQLITE_OK) rc = sqlite3_bind_int64(st, 9, c->seq);
    if (rc == SQLITE_OK) {
      rc = sqlite3_step(st);
      if (rc == SQLITE_DONE) rc = SQLITE_OK;
    }
    int reset = sqlite3_reset(st);
    if (rc == SQLITE_OK) rc = reset;
    sqlite3_clear_bindings(st);
  }
  sqlite3_finalize(st); sqlite3_free(cells);
  char *message = rc == SQLITE_OK ? NULL : sqlite3_mprintf("%s", sqlite3_errmsg(db));
  if (savepoint) {
    if (rc != SQLITE_OK) sqlite3_exec(db, "ROLLBACK TO murmur_crsql_ingest", NULL, NULL, NULL);
    int release = sqlite3_exec(db, "RELEASE murmur_crsql_ingest", NULL, NULL, NULL);
    if (rc == SQLITE_OK) rc = release;
  }
  if (rc != SQLITE_OK) {
    sqlite3_result_error(ctx, message ? message : sqlite3_errmsg(db), -1);
    sqlite3_result_error_code(ctx, rc);
  } else sqlite3_result_int64(ctx, (sqlite3_int64)n);
  sqlite3_free(message);
}
int murmur_crsqlite_ingest_register(sqlite3 *db) {
  return sqlite3_create_function_v2(db, "crsql_ingest_blob", 1,
      SQLITE_UTF8 | SQLITE_DIRECTONLY, NULL, ingest, NULL, NULL, NULL);
}
