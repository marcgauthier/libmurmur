/* murmur demo - the proving C client: open a Murmur store through
 * the public API, provision its key, configure replication, and
 * sync against a peer. No Go involved.
 *
 * Usage:
 *   demo DB BIND NODE CERT KEY CA GROUP [SEED] [ROUNDS]
 * Nodes A/B share GROUP; exactly one side passes SEED (the other's
 * BIND) to bootstrap dialing. The seedless side writes a row every
 * 2s; both sides log peers/rows every 5s. ROUNDS>0 exits after that
 * many 5s reports (0 runs until SIGINT).
 */
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "config.h"
#include "driver.h"
#include "engine.h"
#include "libmurmur.h"
#include "sqlite3.h"
#include "sync.h"

static volatile int stop = 0;

static void on_sigint(int sig) {
  (void)sig;
  stop = 1;
}

static void sleep_ms(long ms) {
  struct timespec ts;
  ts.tv_sec = ms / 1000;
  ts.tv_nsec = (ms % 1000) * 1000 * 1000;
  nanosleep(&ts, NULL);
}

static int64_t count_rows(sqlite3 *db) {
  sqlite3_stmt *st = NULL;
  if (sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM t", -1, &st, NULL) !=
      SQLITE_OK) {
    return -1;
  }
  int rc = sqlite3_step(st);
  int64_t n = rc == SQLITE_ROW ? sqlite3_column_int64(st, 0) : -1;
  sqlite3_finalize(st);
  return n;
}

static int set_setting(sqlite3 *db, const char *name, const char *value) {
  int sqlrc = 0;
  if (murmur_cfg_set_setting(db, name, (const uint8_t *)value, strlen(value),
                             &sqlrc) != MURMUR_SYNC_OK) {
    fprintf(stderr, "setting %s failed: %d\n", name, sqlrc);
    return 0;
  }
  return 1;
}

int main(int argc, char **argv) {
  if (argc < 8) {
    fprintf(stderr,
            "usage: %s DB BIND NODE CERT KEY CA GROUP [SEED] [ROUNDS]\n",
            argv[0]);
    return 2;
  }
  const char *dbpath = argv[1];
  const char *bind = argv[2];
  const char *node = argv[3];
  const char *cert = argv[4];
  const char *key = argv[5];
  const char *ca = argv[6];
  const char *group = argv[7];
  const char *seed = argc > 8 && argv[8][0] ? argv[8] : NULL;
  int rounds = argc > 9 ? atoi(argv[9]) : 0;

  if (murmur_init() != 0) {
    fprintf(stderr, "murmur_init failed\n");
    return 1;
  }
  if (murmur_vfs_register(0, 0) != 0) {
    fprintf(stderr, "vfs register failed\n");
    return 1;
  }
  sqlite3 *db = NULL;
  if (sqlite3_open_v2(dbpath, &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE,
                      "sqlite-murmur") != SQLITE_OK) {
    fprintf(stderr, "open failed: %s\n", sqlite3_errmsg(db));
    return 1;
  }
  /* Demo key (insecure by design; real clients seal one). */
  uint8_t demo_key[32];
  for (int i = 0; i < 32; i++) {
    demo_key[i] = (uint8_t)(0xD0 + i);
  }
  int krc = murmur_db_key(db, demo_key);
  if (krc != 0) {
    fprintf(stderr, "db key failed: %d\n", krc);
    return 1;
  }
  int sqlrc = 0;
  if (murmur_sync_ensure_schema(db, &sqlrc) != MURMUR_SYNC_OK) {
    fprintf(stderr, "schema failed: %d\n", sqlrc);
    return 1;
  }
  char sql[256];
  snprintf(sql, sizeof(sql),
           "UPDATE murmur_identity SET node=x'%s' WHERE id=1;", node);
  char *err = NULL;
  if (sqlite3_exec(db, sql, NULL, NULL, &err) != SQLITE_OK) {
    fprintf(stderr, "identity failed: %s\n", err ? err : "?");
    return 1;
  }
  if (!set_setting(db, "group_id", group) ||
      !set_setting(db, "bind", bind) || !set_setting(db, "advertise", bind) ||
      !set_setting(db, "certificate", cert) ||
      !set_setting(db, "private_key", key) || !set_setting(db, "ca", ca)) {
    return 1;
  }
  if (seed) {
    char boot[128];
    snprintf(boot, sizeof(boot), "[\"%s\"]", seed);
    if (!set_setting(db, "bootstrap", boot)) {
      return 1;
    }
  }
  murmur_engine_t eng;
  murmur_driver_t drv;
  murmur_engine_init(&eng, db);
  murmur_driver_init(&drv, &eng);
  char *detail = NULL;
  if (murmur_driver_start(&drv, &detail, &sqlrc) != MURMUR_SYNC_OK) {
    fprintf(stderr, "driver start failed: %s\n", detail ? detail : "?");
    return 1;
  }
  free(detail);
  if (sqlite3_exec(db, "CREATE TABLE IF NOT EXISTS t(a INTEGER PRIMARY KEY "
                       "NOT NULL, b TEXT);",
                   NULL, NULL, &err) != SQLITE_OK) {
    fprintf(stderr, "create failed: %s\n", err ? err : "?");
    return 1;
  }
  if (sqlite3_exec(db, "SELECT crsql_as_crr('main',\"t\")", NULL, NULL,
                   &err) != SQLITE_OK) {
    fprintf(stderr, "crr failed: %s\n", err ? err : "?");
    return 1;
  }
  signal(SIGINT, on_sigint);
  signal(SIGTERM, on_sigint);
  printf("demo up: db=%s bind=%s seed=%s\n", dbpath, bind,
         seed ? seed : "(writer)");
  fflush(stdout);
  int elapsed = 0, reports = 0;
  long counter = 0;
  while (!stop && (rounds <= 0 || reports < rounds)) {
    sleep_ms(1000);
    if (stop) {
      break;
    }
    elapsed++;
    /* The seedless side writes. */
    if (!seed && elapsed % 2 == 0) {
      counter++;
      snprintf(sql, sizeof(sql), "INSERT INTO t VALUES(%ld,'n%ld');", counter,
               counter);
      if (sqlite3_exec(db, sql, NULL, NULL, &err) != SQLITE_OK) {
        fprintf(stderr, "insert failed: %s\n", err ? err : "?");
        sqlite3_free(err);
        err = NULL;
      }
    }
    if (elapsed % 5 != 0) {
      continue;
    }
    reports++;
    murmur_node_t peers[8];
    size_t n = murmur_engine_conn_peers(&eng, peers, 8);
    printf("demo report: peers=%zu rows=%lld\n", n,
           (long long)count_rows(db));
    fflush(stdout);
  }
  murmur_driver_stop(&drv, NULL);
  murmur_driver_destroy(&drv);
  murmur_engine_destroy(&eng);
  sqlite3_close(db);
  murmur_shutdown();
  printf("demo down\n");
  return 0;
}
