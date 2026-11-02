/* cr-sqlite C wrapper, single translation unit.
 *
 * The three wrapper sources share extension state
 * (SQLITE_EXTENSION_INIT1 in crsqlite.c, referenced from the other two
 * via SQLITE_EXTENSION_INIT3). They must be compiled as one TU so all
 * three see the same instance; separate objects segfault at init.
 */
#define sqlite3_crsqlite_init crsql_upstream_init
#include "src/crsqlite.c"
#include "src/changes-vtab.c"
#include "src/ext-data.c"

#undef sqlite3_crsqlite_init
extern int murmur_crsqlite_ingest_register(sqlite3 *db);
int sqlite3_crsqlite_init(sqlite3 *db, char **error, const sqlite3_api_routines *api) {
  int rc = crsql_upstream_init(db, error, api);
  return rc == SQLITE_OK ? murmur_crsqlite_ingest_register(db) : rc;
}
