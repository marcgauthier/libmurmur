#include <stddef.h>
#include "sqlite3ext.h"
SQLITE_EXTENSION_INIT1

static void loaded(sqlite3_context *ctx, int argc, sqlite3_value **argv) {
  (void)argc; (void)argv;
  sqlite3_result_text(ctx, "murmur-extension-ok", -1, SQLITE_STATIC);
}

int sqlite3_extension_init(sqlite3 *db, char **err, const sqlite3_api_routines *api) {
  (void)err;
  SQLITE_EXTENSION_INIT2(api);
  return sqlite3_create_function(db, "murmur_extension_check", 0,
                                 SQLITE_UTF8, NULL, loaded, NULL, NULL);
}
