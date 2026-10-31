/* Cross-implementation format check. Built twice: once against the
 * Rust libsqlite_murmur.a, once against the Go shared library. The
 * tools/format_xcheck.sh matrix proves databases written by either
 * implementation open in the other (pages, keyrings, rekeys).
 *
 * Usage: xcheck <write|append|read|rekey|readnew> <dir> [cipher]
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sqlite3.h"
#include "sqlite_murmur.h"

static void master(unsigned char out[32], unsigned base) {
  for (int i = 0; i < 32; i++) out[i] = (unsigned char)(base + i);
}

static int fails = 0;
#define EXPECT(cond, what) do { \
    if (!(cond)) { printf("FAIL %s\n", (what)); fails++; } \
  } while (0)

static void exec_all(sqlite3 *db, const char *sql, const char *what) {
  char *err = 0;
  int rc = sqlite3_exec(db, sql, 0, 0, &err);
  if (rc != SQLITE_OK) {
    printf("FAIL %s: %d %s\n", what, rc, err ? err : "");
    fails++;
  }
  sqlite3_free(err);
}

static void query_print(sqlite3 *db, const char *sql, const char *tag) {
  sqlite3_stmt *st = 0;
  if (sqlite3_prepare_v2(db, sql, -1, &st, 0) != SQLITE_OK) {
    printf("FAIL prepare %s\n", tag);
    fails++;
    return;
  }
  printf("%s:", tag);
  while (sqlite3_step(st) == SQLITE_ROW) {
    const char *v = (const char *) sqlite3_column_text(st, 0);
    printf(" %s", v ? v : "<null>");
  }
  printf("\n");
  sqlite3_finalize(st);
}

static int do_register(unsigned base) {
  unsigned char key[32];
  master(key, base);
  sqlite_murmur_config cfg;
  memset(&cfg, 0, sizeof cfg);
  cfg.key = key;
  int rc = sqlite_murmur_register(&cfg);
  memset(key, 0, 32);
  return rc;
}

static sqlite3 *do_open(const char *dir, const char *cipher) {
  sqlite3 *db = 0;
  sqlite_murmur_open_options opts;
  memset(&opts, 0, sizeof opts);
  opts.cipher = cipher;
  opts.compression = "zstd6";
  int rw = SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE;
  int rc = sqlite_murmur_open_v2(dir, &db, rw, &opts);
  if (rc != SQLITE_OK) {
    printf("FAIL open: %d\n", rc);
    fails++;
    return 0;
  }
  return db;
}

static int do_write(const char *dir, const char *cipher) {
  if (do_register(0xA0) != SQLITE_OK) { printf("FAIL register\n"); return 1; }
  sqlite3 *db = do_open(dir, cipher);
  if (!db) return 1;
  exec_all(db, "CREATE TABLE t(a INTEGER PRIMARY KEY, b TEXT);"
               "INSERT INTO t(b) VALUES('alpha'),('beta'),('gamma');",
           "seed rows");
  /* Seal after seeding: legacy pages plus keyed pages. */
  sqlite_murmur_keyring_args ka;
  memset(&ka, 0, sizeof ka);
  ka.op = SQLITE_MURMUR_KEYRING_SET;
  ka.param = SQLITE_MURMUR_KEYRING_PARAM_KDF;
  ka.value = 0;
  if (sqlite3_file_control(db, "main", SQLITE_MURMUR_FCNTL_KEYRING, &ka) != SQLITE_OK) {
    printf("FAIL seal\n");
    fails++;
  }
  exec_all(db, "INSERT INTO t(b) VALUES('delta');", "keyed row");
  memset(&ka, 0, sizeof ka);
  ka.op = SQLITE_MURMUR_KEYRING_ROTATE;
  if (sqlite3_file_control(db, "main", SQLITE_MURMUR_FCNTL_KEYRING, &ka) != SQLITE_OK) {
    printf("FAIL rotate\n");
    fails++;
  }
  exec_all(db, "INSERT INTO t(b) VALUES('epsilon');", "rotated row");
  if (sqlite_murmur_flush(dir) != SQLITE_OK) { printf("FAIL flush\n"); fails++; }
  if (sqlite_murmur_close(db) != SQLITE_OK) { printf("FAIL close\n"); fails++; }
  if (sqlite_murmur_unregister() != SQLITE_OK) { printf("FAIL unregister\n"); fails++; }
  if (!fails) printf("WRITE-OK %s\n", cipher);
  return fails != 0;
}

static int do_append(const char *dir) {
  if (do_register(0xA0) != SQLITE_OK) { printf("FAIL register\n"); return 1; }
  sqlite3 *db = do_open(dir, 0);
  if (!db) return 1;
  exec_all(db, "INSERT INTO t(b) VALUES('zeta');", "append row");
  if (sqlite_murmur_close(db) != SQLITE_OK) { printf("FAIL close\n"); fails++; }
  if (sqlite_murmur_unregister() != SQLITE_OK) { printf("FAIL unregister\n"); fails++; }
  if (!fails) printf("APPEND-OK\n");
  return fails != 0;
}

static int do_read(const char *dir, unsigned base, const char *tag) {
  if (do_register(base) != SQLITE_OK) { printf("FAIL register\n"); return 1; }
  sqlite3 *db = do_open(dir, 0);
  if (!db) return 1;
  query_print(db, "SELECT b FROM t ORDER BY a", "ROWS");
  query_print(db, "PRAGMA cipher", "CIPHER");
  query_print(db, "PRAGMA compression", "COMPRESSION");
  /* Inventory through the keyring FCTL. */
  sqlite_murmur_keyring_args ka;
  memset(&ka, 0, sizeof ka);
  ka.op = SQLITE_MURMUR_KEYRING_INVENTORY;
  if (sqlite3_file_control(db, "main", SQLITE_MURMUR_FCNTL_KEYRING, &ka) != SQLITE_OK || !ka.json) {
    printf("FAIL inventory\n");
    fails++;
  } else {
    printf("INV: %s\n", ka.json);
    sqlite3_free(ka.json);
  }
  if (sqlite_murmur_close(db) != SQLITE_OK) { printf("FAIL close\n"); fails++; }
  if (sqlite_murmur_unregister() != SQLITE_OK) { printf("FAIL unregister\n"); fails++; }
  if (!fails) printf("READ-OK %s\n", tag);
  return fails != 0;
}

static int do_rekey(const char *dir) {
  unsigned char oldm[32], newm[32];
  master(oldm, 0xA0);
  master(newm, 0xC0);
  if (do_register(0xA0) != SQLITE_OK) { printf("FAIL register\n"); return 1; }
  int rc = sqlite_murmur_rekey(dir, oldm, newm, 0);
  memset(oldm, 0, 32);
  memset(newm, 0, 32);
  if (rc != SQLITE_OK) { printf("FAIL rekey: %d\n", rc); return 1; }
  if (sqlite_murmur_unregister() != SQLITE_OK) { printf("FAIL unregister\n"); return 1; }
  printf("REKEY-OK\n");
  return 0;
}

int main(int argc, char **argv) {
  if (argc < 3) {
    printf("usage: xcheck <write|append|read|rekey|readnew> <dir> [cipher]\n");
    return 2;
  }
  const char *mode = argv[1];
  const char *dir = argv[2];
  const char *cipher = argc > 3 ? argv[3] : "aes256gcm";
  if (!strcmp(mode, "write")) return do_write(dir, cipher);
  if (!strcmp(mode, "append")) return do_append(dir);
  if (!strcmp(mode, "read")) return do_read(dir, 0xA0, "old");
  if (!strcmp(mode, "rekey")) return do_rekey(dir);
  if (!strcmp(mode, "readnew")) return do_read(dir, 0xC0, "new");
  printf("unknown mode %s\n", mode);
  return 2;
}
