/* Interoperability fixture: ordinary libmurmur client, no CLI adapter. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "libmurmur.h"
#include "sqlite3.h"

static int row(void *unused, int count, char **values, char **names) {
  (void)unused; (void)names;
  for (int i = 0; i < count; ++i) printf("%s%s", i ? "|" : "", values[i] ? values[i] : "NULL");
  putchar('\n');
  return 0;
}

int main(int argc, char **argv) {
  if (argc != 4 || strlen(argv[2]) != 64) return 2;
  uint8_t key[32];
  for (int i = 0; i < 32; ++i) {
    char hex[3] = {argv[2][2*i], argv[2][2*i+1], 0};
    char *end;
    key[i] = (uint8_t)strtoul(hex, &end, 16);
    if (*end) return 2;
  }
  if (murmur_init() || murmur_vfs_register(0, 0)) return 1;
  sqlite3 *db = NULL;
  int rc = sqlite3_open_v2(argv[1], &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, "sqlite-murmur");
  if (!rc) rc = murmur_db_key(db, key);
  if (!rc) rc = sqlite3_exec(db, argv[3], row, NULL, NULL);
  if (rc) fprintf(stderr, "native-check: %d %s\n", rc, db ? sqlite3_errmsg(db) : "open failed");
  int close_rc = sqlite3_close(db);
  murmur_shutdown();
  return rc || close_rc ? 1 : 0;
}
