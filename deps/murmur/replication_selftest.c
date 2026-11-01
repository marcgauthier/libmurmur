/* replicatest - extended node-to-node replication over real QUIC.
 *
 * Two live drivers (testdata mTLS certs) prove bidirectional pull,
 * multi-batch convergence, same-key conflict resolution, stop/restart
 * healing, and snapshot-to-empty-joiner, plus status/membership and
 * retention building blocks while replicating.
 *
 * Usage: ./build/replicatest [testdata-dir] [base-port]
 */
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "config.h"
#include "driver.h"
#include "engine.h"
#include "serve.h"
#include "sqlite3.h"
#include "sync.h"

static int failures = 0;
static int suites = 0;

#define CHECK(cond, ...)                                                 \
  do {                                                                   \
    if (!(cond)) {                                                       \
      printf("FAIL %s:%d: ", __func__, __LINE__);                        \
      printf(__VA_ARGS__);                                               \
      printf("\n");                                                      \
      failures++;                                                        \
    }                                                                    \
  } while (0)

static void sleep_ms(long ms) {
  struct timespec ts;
  ts.tv_sec = ms / 1000;
  ts.tv_nsec = (ms % 1000) * 1000 * 1000;
  nanosleep(&ts, NULL);
}

static int64_t query_int(sqlite3 *db, const char *query) {
  sqlite3_stmt *st = NULL;
  if (sqlite3_prepare_v2(db, query, -1, &st, NULL) != SQLITE_OK) {
    return -1;
  }
  int rc = sqlite3_step(st);
  int64_t n = rc == SQLITE_ROW ? sqlite3_column_int64(st, 0) : -1;
  sqlite3_finalize(st);
  return n;
}

/* Owned text of a single-row single-column query (NULL on empty). */
static char *query_text(sqlite3 *db, const char *query) {
  sqlite3_stmt *st = NULL;
  if (sqlite3_prepare_v2(db, query, -1, &st, NULL) != SQLITE_OK) {
    return NULL;
  }
  char *out = NULL;
  if (sqlite3_step(st) == SQLITE_ROW &&
      sqlite3_column_type(st, 0) != SQLITE_NULL) {
    const unsigned char *t = sqlite3_column_text(st, 0);
    if (t) {
      out = strdup((const char *)t);
    }
  }
  sqlite3_finalize(st);
  return out;
}

static int exec_ok(sqlite3 *db, const char *sql) {
  char *err = NULL;
  int rc = sqlite3_exec(db, sql, NULL, NULL, &err);
  if (rc != SQLITE_OK) {
    printf("FAIL sql %.60s: %s\n", sql, err ? err : "?");
    failures++;
  }
  sqlite3_free(err);
  return rc == SQLITE_OK;
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

typedef struct {
  sqlite3 *db;
  murmur_engine_t eng;
  murmur_driver_t drv;
  const char *tag;
} node_t;

static int node_boot(node_t *n, const char *tag, const char *node_hex,
                     const char *group_hex, const char *td, int port,
                     const char *seed) {
  n->tag = tag;
  if (sqlite3_open(":memory:", &n->db) != SQLITE_OK) {
    printf("FAIL %s open\n", tag);
    failures++;
    return 0;
  }
  int sqlrc = 0;
  if (murmur_sync_ensure_schema(n->db, &sqlrc) != MURMUR_SYNC_OK) {
    printf("FAIL %s schema %d\n", tag, sqlrc);
    failures++;
    return 0;
  }
  char sql[256];
  snprintf(sql, sizeof(sql),
           "UPDATE murmur_identity SET node=x'%s' WHERE id=1;", node_hex);
  if (!exec_ok(n->db, sql)) {
    return 0;
  }
  char path[512];
  if (!set_setting(n->db, "group_id", group_hex)) {
    return 0;
  }
  snprintf(path, sizeof(path), "127.0.0.1:%d", port);
  if (!set_setting(n->db, "bind", path)) {
    return 0;
  }
  if (!set_setting(n->db, "advertise", path)) {
    return 0;
  }
  const char *which = node_hex[0] == 'a' ? "a" : "b";
  snprintf(path, sizeof(path), "%s/node-%s.pem", td, which);
  if (!set_setting(n->db, "certificate", path)) {
    return 0;
  }
  snprintf(path, sizeof(path), "%s/node-%s-key.pem", td, which);
  if (!set_setting(n->db, "private_key", path)) {
    return 0;
  }
  snprintf(path, sizeof(path), "%s/ca.pem", td);
  if (!set_setting(n->db, "ca", path)) {
    return 0;
  }
  if (seed) {
    snprintf(path, sizeof(path), "[\"%s\"]", seed);
    if (!set_setting(n->db, "bootstrap", path)) {
      return 0;
    }
  }
  char trust[128];
  snprintf(trust, sizeof(trust), "[\"%s\"]",
           node_hex[0] == 'a' ? "b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0"
                              : "a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0");
  if (!set_setting(n->db, "snapshot_trusted_sources", trust)) {
    return 0;
  }
  /* Minimum batch forces multi-batch pulls for the large suite. */
  if (!set_setting(n->db, "batch_bytes", "65536")) {
    return 0;
  }
  murmur_engine_init(&n->eng, n->db);
  murmur_driver_init(&n->drv, &n->eng);
  return 1;
}

static void node_down(node_t *n) {
  murmur_driver_stop(&n->drv, NULL);
  murmur_driver_destroy(&n->drv);
  murmur_engine_destroy(&n->eng);
  sqlite3_exec(n->db, "SELECT crsql_finalize()", NULL, NULL, NULL);
  sqlite3_close(n->db);
}

static int wait_count(node_t *n, const char *query, int64_t want, int secs) {
  for (int i = 0; i < secs * 10; i++) {
    if (query_int(n->db, query) == want) {
      return 1;
    }
    sleep_ms(100);
  }
  return 0;
}

static int wait_conns(node_t *n, int secs) {
  murmur_node_t peers[8];
  for (int i = 0; i < secs * 10; i++) {
    if (murmur_engine_conn_peers(&n->eng, peers, 8) > 0) {
      return 1;
    }
    sleep_ms(100);
  }
  return 0;
}

static int wait_status_idle(murmur_engine_t *e, int secs) {
  for (int i = 0; i < secs * 10; i++) {
    pthread_mutex_lock(&e->mu);
    const char *s = e->snapshot_status;
    int running = s && strcmp(s, "running") == 0;
    pthread_mutex_unlock(&e->mu);
    if (!running) {
      return 1;
    }
    sleep_ms(100);
  }
  return 0;
}

static void engine_counters(murmur_engine_t *e, uint64_t *sent,
                            uint64_t *applied, uint64_t *gossip) {
  pthread_mutex_lock(&e->mu);
  if (sent) {
    *sent = e->sent;
  }
  if (applied) {
    *applied = e->applied;
  }
  if (gossip) {
    *gossip = e->gossip_rounds;
  }
  pthread_mutex_unlock(&e->mu);
}

/* Inserts rows [lo,hi] with a ~200-byte payload in multi-row batches. */
static int insert_range(sqlite3 *db, int lo, int hi, const char *prefix) {
  char pad[192];
  memset(pad, 'x', sizeof(pad) - 1);
  pad[sizeof(pad) - 1] = 0;
  for (int base = lo; base <= hi;) {
    char sql[32768];
    size_t off = 0;
    off += snprintf(sql + off, sizeof(sql) - off, "INSERT INTO t VALUES");
    int top = base + 49 < hi ? base + 49 : hi;
    for (int a = base; a <= top; a++) {
      off += snprintf(sql + off, sizeof(sql) - off, "%s(%d,'%s-%d-%s')",
                      a == base ? "" : ",", a, prefix, a, pad);
      if (off + 512 >= sizeof(sql)) {
        break;
      }
    }
    sql[sizeof(sql) - 1] = 0;
    if (!exec_ok(db, sql)) {
      return 0;
    }
    base = top + 1;
  }
  return 1;
}

int main(int argc, char **argv) {
  const char *td = argc > 1 ? argv[1] : "deps/murmur/testdata";
  int base = argc > 2 ? atoi(argv[2]) : 18443;
  const char *group = "07070707070707070707070707070707";
  const char *hexa = "a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0";
  const char *hexb = "b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0";
  node_t a, b;
  memset(&a, 0, sizeof(a));
  memset(&b, 0, sizeof(b));
  char seed[64];
  snprintf(seed, sizeof(seed), "127.0.0.1:%d", base);
  if (!node_boot(&a, "A", hexa, group, td, base, NULL)) {
    return 1;
  }
  if (!node_boot(&b, "B", hexb, group, td, base + 1, seed)) {
    node_down(&a);
    return 1;
  }
  char *detail = NULL;
  int sqlrc = 0;
  CHECK(murmur_driver_start(&a.drv, &detail, &sqlrc) == MURMUR_SYNC_OK,
        "start A %s", detail ? detail : "");
  free(detail);
  detail = NULL;
  CHECK(murmur_driver_start(&b.drv, &detail, &sqlrc) == MURMUR_SYNC_OK,
        "start B %s", detail ? detail : "");
  free(detail);
  detail = NULL;
  exec_ok(a.db, "CREATE TABLE t(a INTEGER PRIMARY KEY NOT NULL, b TEXT);");
  exec_ok(a.db, "SELECT crsql_as_crr('main',\"t\")");
  exec_ok(b.db, "CREATE TABLE t(a INTEGER PRIMARY KEY NOT NULL, b TEXT);");
  exec_ok(b.db, "SELECT crsql_as_crr('main',\"t\")");
  CHECK(wait_conns(&a, 30), "A connected");
  CHECK(wait_conns(&b, 30), "B connected");

  /* Suite 1: bidirectional replication converges both ways. */
  suites++;
  CHECK(insert_range(a.db, 1, 50, "a"), "insert A 1..50");
  CHECK(insert_range(b.db, 51, 100, "b"), "insert B 51..100");
  CHECK(wait_count(&a, "SELECT COUNT(*) FROM t", 100, 60), "A sees 100");
  CHECK(wait_count(&b, "SELECT COUNT(*) FROM t", 100, 60), "B sees 100");
  CHECK(query_int(a.db, "SELECT SUM(a) FROM t") == 5050, "A sum 5050");
  CHECK(query_int(b.db, "SELECT SUM(a) FROM t") == 5050, "B sum 5050");
  {
    uint64_t as = 0, aa = 0, bs = 0, ba = 0;
    int counted = 0;
    for (int i = 0; i < 100; i++) {
      engine_counters(&a.eng, &as, &aa, NULL);
      engine_counters(&b.eng, &bs, &ba, NULL);
      if (as > 0 && aa > 0 && bs > 0 && ba > 0) {
        counted = 1;
        break;
      }
      sleep_ms(100);
    }
    CHECK(counted, "both sent+applied (A %llu/%llu B %llu/%llu)",
          (unsigned long long)as, (unsigned long long)aa,
          (unsigned long long)bs, (unsigned long long)ba);
  }

  /* Suite 2: multi-batch pull of 2000 wide rows at 64 KiB batches. */
  suites++;
  {
    uint64_t before = 0;
    engine_counters(&b.eng, NULL, &before, NULL);
    CHECK(insert_range(a.db, 101, 2100, "bulk"), "insert A 101..2100");
    CHECK(wait_count(&b, "SELECT COUNT(*) FROM t", 2100, 180),
          "B sees 2100");
    CHECK(wait_count(&a, "SELECT COUNT(*) FROM t", 2100, 30),
          "A keeps 2100");
    int64_t want_sum = (int64_t)2100 * 2101 / 2;
    CHECK(query_int(a.db, "SELECT SUM(a) FROM t") == want_sum, "A bulk sum");
    CHECK(query_int(b.db, "SELECT SUM(a) FROM t") == want_sum, "B bulk sum");
    for (int probe = 0; probe < 3; probe++) {
      int idv = probe == 0 ? 101 : probe == 1 ? 1000 : 2100;
      char q[128];
      snprintf(q, sizeof(q), "SELECT b FROM t WHERE a=%d", idv);
      char *va = query_text(a.db, q);
      char *vb = query_text(b.db, q);
      CHECK(va && vb && strcmp(va, vb) == 0, "payload %d exact", idv);
      free(va);
      free(vb);
    }
    uint64_t after = 0;
    engine_counters(&b.eng, NULL, &after, NULL);
    CHECK(after > before, "B applied advanced");
  }

  /* Suite 3: same-key writes on both sides resolve to one value. */
  suites++;
  exec_ok(a.db, "INSERT OR REPLACE INTO t VALUES(900001,'from-a');");
  exec_ok(b.db, "INSERT OR REPLACE INTO t VALUES(900001,'from-b');");
  {
    int converged = 0;
    for (int i = 0; i < 600 && !converged; i++) {
      int64_t ca =
          query_int(a.db, "SELECT COUNT(*) FROM t WHERE a=900001");
      int64_t cb =
          query_int(b.db, "SELECT COUNT(*) FROM t WHERE a=900001");
      if (ca == 1 && cb == 1) {
        char *va = query_text(a.db, "SELECT b FROM t WHERE a=900001");
        char *vb = query_text(b.db, "SELECT b FROM t WHERE a=900001");
        if (va && vb && strcmp(va, vb) == 0) {
          converged = 1;
        }
        free(va);
        free(vb);
      }
      if (!converged) {
        sleep_ms(100);
      }
    }
    CHECK(converged, "conflict converged");
    CHECK(wait_count(&a, "SELECT COUNT(*) FROM t", 2101, 30), "A 2101");
    CHECK(wait_count(&b, "SELECT COUNT(*) FROM t", 2101, 30), "B 2101");
  }

  /* Suite 4: control surface, membership, and retention while live. */
  suites++;
  {
    char *sta = murmur_engine_status(&a.eng);
    char *hea = murmur_engine_health(&a.eng);
    char *pro = murmur_engine_progress(&a.eng);
    char *pa = murmur_engine_peers(&a.eng);
    char *pb = murmur_engine_peers(&b.eng);
    CHECK(sta && sta[0] != 0, "status JSON");
    CHECK(hea && hea[0] != 0, "health JSON");
    CHECK(pro && pro[0] != 0, "progress JSON");
    CHECK(pa && strstr(pa, hexb), "A peers see B");
    CHECK(pb && strstr(pb, hexa), "B peers see A");
    free(sta);
    free(hea);
    free(pro);
    free(pa);
    free(pb);
    uint64_t ga = 0, gb = 0;
    engine_counters(&a.eng, NULL, NULL, &ga);
    engine_counters(&b.eng, NULL, NULL, &gb);
    CHECK(ga > 0 && gb > 0, "gossip rounds advance");
    uint64_t moved = 0, pruned = 0;
    CHECK(murmur_driver_retention_collect(&a.drv, &moved, &pruned, &sqlrc) ==
              MURMUR_SYNC_OK,
          "retention collect");
  }

  /* Suite 5: B stops, A writes, B restarts and catches up. */
  suites++;
  CHECK(murmur_driver_stop(&b.drv, &sqlrc) == MURMUR_SYNC_OK, "stop B");
  CHECK(insert_range(a.db, 300001, 300100, "gap"), "insert A gap");
  sleep_ms(2000);
  CHECK(query_int(b.db, "SELECT COUNT(*) FROM t") == 2101, "B frozen");
  CHECK(murmur_driver_start(&b.drv, &detail, &sqlrc) == MURMUR_SYNC_OK,
        "restart B %s", detail ? detail : "");
  free(detail);
  detail = NULL;
  CHECK(wait_conns(&b, 30), "B reconnected");
  CHECK(wait_conns(&a, 30), "A reconnected");
  CHECK(wait_count(&b, "SELECT COUNT(*) FROM t", 2201, 90), "B caught up");
  {
    int64_t sa = query_int(a.db, "SELECT SUM(a) FROM t");
    int64_t sb = query_int(b.db, "SELECT SUM(a) FROM t");
    CHECK(sa > 0 && sa == sb, "gap sums match");
  }

  /* Suite 6: a fresh joiner with the same identity takes a snapshot. */
  suites++;
  CHECK(murmur_driver_stop(&b.drv, &sqlrc) == MURMUR_SYNC_OK, "stop B again");
  sleep_ms(3000);
  node_t j;
  memset(&j, 0, sizeof(j));
  int join_ok = 0;
  if (node_boot(&j, "J", hexb, group, td, base + 1, seed)) {
    if (murmur_driver_start(&j.drv, &detail, &sqlrc) == MURMUR_SYNC_OK) {
      free(detail);
      detail = NULL;
      exec_ok(j.db, "CREATE TABLE t(a INTEGER PRIMARY KEY NOT NULL, b TEXT);");
      exec_ok(j.db, "SELECT crsql_as_crr('main',\"t\")");
      CHECK(wait_conns(&j, 30), "J connected");
      murmur_node_t na;
      memset(&na, 0, sizeof(na));
      memset(na.b, 0xA0, sizeof(na.b));
      CHECK(murmur_serve_request_snapshot(&j.eng, &na, &sqlrc) ==
                MURMUR_SYNC_OK,
            "snapshot queued");
      CHECK(wait_status_idle(&j.eng, 90), "snapshot done");
      pthread_mutex_lock(&j.eng.mu);
      int okfmt = j.eng.snapshot_status &&
                  strncmp(j.eng.snapshot_status, "ok ", 3) == 0;
      pthread_mutex_unlock(&j.eng.mu);
      CHECK(okfmt, "snapshot status");
      int64_t want = query_int(a.db, "SELECT COUNT(*) FROM t");
      CHECK(wait_count(&j, "SELECT COUNT(*) FROM t", want, 90),
            "joiner rows %lld", (long long)want);
      {
        int64_t sa = query_int(a.db, "SELECT SUM(a) FROM t");
        int64_t sj = query_int(j.db, "SELECT SUM(a) FROM t");
        CHECK(sa > 0 && sa == sj, "joiner sum exact");
      }
      join_ok = 1;
    } else {
      printf("FAIL start J %s\n", detail ? detail : "");
      failures++;
      free(detail);
      detail = NULL;
    }
    node_down(&j);
  }
  CHECK(join_ok, "joiner suite ran");

  node_down(&a);
  node_down(&b);
  if (failures == 0) {
    printf("REPLICATE-OK (%d suites)\n", suites);
    return 0;
  }
  printf("REPLICATE-FAIL (%d)\n", failures);
  return 1;
}
