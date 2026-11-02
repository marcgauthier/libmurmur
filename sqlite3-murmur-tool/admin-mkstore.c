/* mkstore: fixture builder for admincheck. Creates a keyed murmur
 * store with replication identity and a few tables. Usage:
 *   mkstore DIR KEYHEX NODEHEX GROUPHEX
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libmurmur.h"
#include "murmur/open.h"
#include "murmur/sync.h"
#include "sqlite3.h"

static int hexval(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

static int hexdec(const char *s, uint8_t *out, size_t n) {
  if (strlen(s) != n * 2) return -1;
  for (size_t i = 0; i < n; i++) {
    int hi = hexval(s[2 * i]), lo = hexval(s[2 * i + 1]);
    if (hi < 0 || lo < 0) return -1;
    out[i] = (uint8_t)((hi << 4) | lo);
  }
  return 0;
}

static int exec(sqlite3 *db, const char *sql) {
  char *e = NULL;
  int rc = sqlite3_exec(db, sql, NULL, NULL, &e);
  if (rc != SQLITE_OK) {
    fprintf(stderr, "mkstore: %s: %s\n", sql, e ? e : "?");
  }
  sqlite3_free(e);
  return rc;
}

int main(int argc, char **argv) {
  if (argc != 5 && argc != 6) {
    fprintf(stderr, "usage: %s DIR KEYHEX NODEHEX GROUPHEX [seal]\n", argv[0]);
    return 2;
  }
  uint8_t key[32], node[16];
  if (hexdec(argv[2], key, 32) != 0 || hexdec(argv[3], node, 16) != 0 ||
      strlen(argv[4]) != 32) {
    fprintf(stderr, "mkstore: bad hex args\n");
    return 2;
  }
  uint8_t group[16];
  if (hexdec(argv[4], group, 16) != 0) {
    fprintf(stderr, "mkstore: bad group\n");
    return 2;
  }
  if (murmur_init() != 0 || murmur_vfs_register(0, 0) != 0) {
    fprintf(stderr, "mkstore: init failed\n");
    return 1;
  }
  sqlite3 *db = NULL;
  if (sqlite3_open_v2(argv[1], &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE,
                      "sqlite-murmur") != SQLITE_OK) {
    fprintf(stderr, "mkstore: open: %s\n", sqlite3_errmsg(db));
    return 1;
  }
  if (murmur_db_key(db, key) != 0) {
    fprintf(stderr, "mkstore: key failed\n");
    return 1;
  }
  int sqlrc = 0;
  if (murmur_sync_ensure_schema(db, &sqlrc) != MURMUR_SYNC_OK) {
    fprintf(stderr, "mkstore: schema: %d\n", sqlrc);
    return 1;
  }
  char sql[256];
  snprintf(sql, sizeof(sql), "UPDATE murmur_identity SET node=x'%s' WHERE id=1;",
           argv[3]);
  if (exec(db, sql) != SQLITE_OK) return 1;
  snprintf(sql, sizeof(sql),
           "INSERT INTO murmur_config(name,value) VALUES('group_id','%s') "
           "ON CONFLICT(name) DO UPDATE SET value=excluded.value;",
           argv[4]);
  if (exec(db, sql) != SQLITE_OK) return 1;
  if (exec(db, "CREATE TABLE docs(id INTEGER PRIMARY KEY, body TEXT);") != 0)
    return 1;
  if (exec(db, "INSERT INTO docs VALUES(1,'hello world'),(2,'goodbye'),"
               "(3,'hello again');") != 0)
    return 1;
  if (exec(db, "CREATE TABLE kv(k TEXT PRIMARY KEY, v BLOB);") != 0) return 1;
  if (exec(db, "INSERT INTO kv VALUES('a',x'0102'),('b',x'03');") != 0)
    return 1;
  sqlite3_close(db);
  db = NULL;
  if (argc == 6 && strcmp(argv[5], "seal") == 0) {
    /* Seal under a direct-HKDF keyring via a shell reference. */
    uint64_t h = 0;
    void *xdb = NULL, *store = NULL;
    if (nvOpenStoreRef(argv[1], 0, 0, &h, &xdb, &store) != 0) {
      fprintf(stderr, "mkstore: shell open failed\n");
      return 1;
    }
    if (nvStoreKey(h, key) != 0) {
      fprintf(stderr, "mkstore: shell key failed\n");
      return 1;
    }
    if (nvStoreSetParam(h, NV_CTL_PARAM_KDF, 0, key) != 0) {
      fprintf(stderr, "mkstore: seal failed\n");
      return 1;
    }
    nvCloseStoreRef(h);
  }
  printf("mkstore: %s ready\n", argv[1]);
  return 0;
}
