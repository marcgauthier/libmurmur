/* drivertest - two live drivers replicate over real QUIC
 * loopback with mutual TLS (testdata certs). Usage:
 *   ./build/drivertest [testdata-dir] [base-port]
 * Or: make drivertest
 */
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "config.h"
#include "driver.h"
#include "driver_internal.h"
#include "engine.h"
#include "serve.h"
#include "sqlite3.h"
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

static void sleep_ms(long ms) {
  struct timespec ts;
  ts.tv_sec = ms / 1000;
  ts.tv_nsec = (ms % 1000) * 1000 * 1000;
  nanosleep(&ts, NULL);
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

static int exec_ok(sqlite3 *db, const char *sql) {
  char *err = NULL;
  int rc = sqlite3_exec(db, sql, NULL, NULL, &err);
  if (rc != SQLITE_OK) {
    printf("FAIL sql %s: %s\n", sql, err ? err : "?");
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

static int node_boot_ip(node_t *n, const char *tag, const char *node_hex,
                        const char *group_hex, const char *td, const char *ip,
                        int port, const char *seed) {
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
  snprintf(path, sizeof(path), "%s:%d", ip, port);
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
  murmur_engine_init(&n->eng, n->db);
  murmur_driver_init(&n->drv, &n->eng);
  return 1;
}

static int node_boot(node_t *n, const char *tag, const char *node_hex,
                     const char *group_hex, const char *td, int port,
                     const char *seed) {
  return node_boot_ip(n, tag, node_hex, group_hex, td, "127.0.0.1", port,
                      seed);
}

static void node_down(node_t *n) {
  murmur_driver_stop(&n->drv, NULL);
  murmur_driver_destroy(&n->drv);
  murmur_engine_destroy(&n->eng);
  sqlite3_exec(n->db, "SELECT crsql_finalize()", NULL, NULL, NULL);
  sqlite3_close(n->db);
}

static int wait_rows(node_t *n, int want, int secs) {
  for (int i = 0; i < secs * 10; i++) {
    if (count_rows(n->db, "SELECT COUNT(*) FROM t") == want) {
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

typedef struct {
  const uint8_t *p;
  size_t n;
  size_t off;
} freader_t;

static int fmem_read(void *ctx, uint8_t *buf, size_t cap, size_t *n_out,
                     int *eof_out) {
  freader_t *r = ctx;
  size_t take = r->n - r->off;
  if (take > cap) {
    take = cap;
  }
  memcpy(buf, r->p + r->off, take);
  r->off += take;
  *n_out = take;
  *eof_out = (r->off == r->n);
  return 0;
}

typedef struct {
  uint8_t *p;
  size_t n;
  size_t cap;
} fwriter_t;

static int fmem_write(void *ctx, const uint8_t *buf, size_t n) {
  fwriter_t *w = ctx;
  if (w->n + n > w->cap) {
    size_t ncap = w->cap ? w->cap * 2 : 4096;
    while (ncap < w->n + n) {
      ncap *= 2;
    }
    uint8_t *np = realloc(w->p, ncap);
    if (!np) {
      return -1;
    }
    w->p = np;
    w->cap = ncap;
  }
  memcpy(w->p + w->n, buf, n);
  w->n += n;
  return 0;
}

/* Suite 0: dial_backoff_ms pure-function unit tests (no network, no
 * live drivers needed). Covers the exponential-backoff behavior
 * added to guard against hammering an unreachable peer. */
static void test_dial_backoff(void) {
  /* fail_count==0 is the "just succeeded / no history" base window:
   * always exactly 5000ms, no jitter applied. */
  CHECK(dial_backoff_ms(0, 0) == 5000, "fail_count=0 base is exactly 5000ms");
  CHECK(dial_backoff_ms(0, 123456789) == 5000,
        "fail_count=0 base ignores seed");

  /* Monotonic growth: the un-jittered center value should double per
   * failure. We can't read the center directly, but repeated seeds
   * sampled across a wide range should keep the *average* envelope
   * growing; more directly, verify every value stays within the
   * expected [center*0.75, center*1.25] band for several seeds. */
  uint64_t centers[] = {5000, 10000, 20000, 40000, 80000,
                        160000, 300000 /* capped from 320000 */,
                        300000 /* capped from 640000 */};
  for (uint32_t fc = 1; fc <= 8; fc++) {
    uint64_t center = centers[fc - 1];
    uint64_t lo = center - center / 4;
    uint64_t hi = center + center / 4;
    if (hi > 300000) {
      hi = 300000; /* jitter never exceeds the documented hard cap */
    }
    for (uint64_t seed = 0; seed < 5; seed++) {
      uint64_t v = dial_backoff_ms(fc, seed * 0x1111111111ULL + fc);
      CHECK(v >= lo && v <= hi,
            "fail_count=%u seed=%llu value %llu within [%llu,%llu]", fc,
            (unsigned long long)seed, (unsigned long long)v,
            (unsigned long long)lo, (unsigned long long)hi);
    }
  }

  /* Cap: large fail counts must never exceed 300000ms (5min), even
   * with jitter, and must never go negative/underflow. */
  for (uint32_t fc = 9; fc <= 1000; fc += 97) {
    uint64_t v = dial_backoff_ms(fc, fc * 0x9E3779B1ULL);
    CHECK(v <= 300000, "fail_count=%u capped value %llu <= 300000", fc,
          (unsigned long long)v);
  }

  /* Jitter actually varies across seeds for a fixed fail_count (not
   * a no-op), which is what prevents synchronized thundering-herd
   * redials. */
  uint64_t v1 = dial_backoff_ms(4, 1);
  uint64_t v2 = dial_backoff_ms(4, 2);
  uint64_t v3 = dial_backoff_ms(4, 3);
  CHECK(!(v1 == v2 && v2 == v3),
        "jitter varies across seeds (got %llu,%llu,%llu)",
        (unsigned long long)v1, (unsigned long long)v2,
        (unsigned long long)v3);

  /* Determinism: same (fail_count, seed) always yields the same
   * delay, so the function is safe to call without locking. */
  CHECK(dial_backoff_ms(4, 42) == dial_backoff_ms(4, 42),
        "pure function is deterministic for a fixed (fail_count, seed)");

  /* dial_backoff_seed: different addresses or different times should
   * (almost always) produce different seeds, and is itself pure. */
  uint64_t s1 = dial_backoff_seed("127.0.0.1:9001", 1000);
  uint64_t s2 = dial_backoff_seed("127.0.0.1:9002", 1000);
  uint64_t s3 = dial_backoff_seed("127.0.0.1:9001", 2000);
  CHECK(s1 != s2, "different addresses yield different seeds");
  CHECK(s1 != s3, "different timestamps yield different seeds");
  CHECK(dial_backoff_seed("127.0.0.1:9001", 1000) == s1,
        "dial_backoff_seed is deterministic");
}

int main(int argc, char **argv) {
  test_dial_backoff();
  const char *td = argc > 1 ? argv[1] : "deps/murmur/testdata";
  int base = argc > 2 ? atoi(argv[2]) : 17443;
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
  /* Suite 4 (search) stages before start: one FTS index on A. */
  {
    const char *scols[] = {"body"};
    murmur_search_def_t sdef;
    memset(&sdef, 0, sizeof(sdef));
    sdef.tag = MURMUR_SEARCH_FTS5;
    sdef.name = "sft";
    sdef.source_table = "sdocs";
    sdef.columns = scols;
    sdef.n_columns = 1;
    murmur_driver_search_config_t scfg;
    memset(&scfg, 0, sizeof(scfg));
    scfg.defs = &sdef;
    scfg.n_defs = 1;
    scfg.interval_ms = 100;
    char *sdetail = NULL;
    int ssqlrc = 0;
    if (murmur_driver_search_open(&a.drv, &scfg, &sdetail, &ssqlrc) !=
        MURMUR_SYNC_OK) {
      printf("FAIL search stage A: %s\n", sdetail ? sdetail : "?");
      free(sdetail);
      node_down(&a);
      node_down(&b);
      return 1;
    }
    free(sdetail);
  }
  /* Suite 1: bring-up plus pull replication. */
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
  if (!exec_ok(a.db, "INSERT INTO t VALUES(1,'x'),(2,'y');")) {
    node_down(&a);
    node_down(&b);
    return 1;
  }
  CHECK(wait_conns(&a, 30), "A connected");
  CHECK(wait_conns(&b, 30), "B connected");
  CHECK(wait_rows(&b, 2, 30), "rows replicated");
  /* Counters land just after row visibility; poll past the race. */
  int counted = 0;
  for (int i = 0; i < 100; i++) {
    pthread_mutex_lock(&a.eng.mu);
    uint64_t sent = a.eng.sent;
    pthread_mutex_unlock(&a.eng.mu);
    pthread_mutex_lock(&b.eng.mu);
    uint64_t applied = b.eng.applied;
    pthread_mutex_unlock(&b.eng.mu);
    if (applied > 0 && sent > 0) {
      counted = 1;
      break;
    }
    sleep_ms(100);
  }
  CHECK(counted, "B applied / A sent");
  /* Suite 2: snapshot over the live session. */
  murmur_node_t na;
  memset(&na, 0, sizeof(na));
  for (int i = 0; i < 16; i++) {
    na.b[i] = 0xA0;
  }
  CHECK(murmur_serve_request_snapshot(&b.eng, &na, &sqlrc) ==
            MURMUR_SYNC_OK,
        "snapshot queued");
  CHECK(wait_status_idle(&b.eng, 60), "snapshot done");
  pthread_mutex_lock(&b.eng.mu);
  int okfmt = b.eng.snapshot_status &&
              strncmp(b.eng.snapshot_status, "ok ", 3) == 0;
  pthread_mutex_unlock(&b.eng.mu);
  CHECK(okfmt, "snapshot status");
  CHECK(count_rows(b.db, "SELECT COUNT(*) FROM t") == 2, "snapshot rows");
  /* Suite 3: gossip membership converges over datagrams. */
  char *pa = NULL, *pb = NULL;
  int seen_ab = 0, seen_ba = 0;
  for (int i = 0; i < 300 && (!seen_ab || !seen_ba); i++) {
    free(pa);
    free(pb);
    pa = murmur_engine_peers(&a.eng);
    pb = murmur_engine_peers(&b.eng);
    if (pa && strstr(pa, hexb)) {
      seen_ab = 1;
    }
    if (pb && strstr(pb, hexa)) {
      seen_ba = 1;
    }
    if (!seen_ab || !seen_ba) {
      sleep_ms(200);
    }
  }
  CHECK(seen_ab, "A sees B");
  CHECK(seen_ba, "B sees A");
  free(pa);
  free(pb);
  /* Suite 4: search maintenance on the live driver tick. The source
   * appears after start, so resync installs it; the hook + tick then
   * index the rows with no manual refresh. */
  exec_ok(a.db, "CREATE TABLE sdocs(id INTEGER PRIMARY KEY, body TEXT);");
  CHECK(murmur_driver_search_sync(&a.drv, 1, &detail, &sqlrc) ==
            MURMUR_SYNC_OK,
        "search resync %s", detail ? detail : "");
  free(detail);
  detail = NULL;
  exec_ok(a.db, "INSERT INTO sdocs VALUES(1,'the quick brown fox'),"
                "(2,'lazy dog naps'),(3,'quick dog runs');");
  {
    int ready = 0;
    for (int i = 0; i < 300 && !ready; i++) {
      int r = 0;
      if (murmur_search_guard_ready(murmur_driver_search(&a.drv), "sft",
                                    &r) &&
          r) {
        ready = 1;
        break;
      }
      sleep_ms(200);
    }
    CHECK(ready, "search guard ready");
  }
  CHECK(count_rows(a.db, "SELECT COUNT(*) FROM temp.sft WHERE sft MATCH 'quick'") ==
            2,
        "search live query");
  CHECK(murmur_driver_search(&b.drv) == NULL, "B search unstaged");
  /* Suite 5: end-to-end files over two live drivers. C uploads;
   * metadata replicates through the mesh; D's file tick fetches
   * the container over QUIC. Distinct loopback IPs share one
   * uniform fetch port. */
  node_t c, d;
  memset(&c, 0, sizeof(c));
  memset(&d, 0, sizeof(d));
  char seed2[64];
  snprintf(seed2, sizeof(seed2), "127.0.0.1:%d", base + 20);
  int files_ok = 0;
  if (node_boot_ip(&c, "C", hexa, group, td, "127.0.0.1", base + 20, NULL) &&
      node_boot_ip(&d, "D", hexb, group, td, "127.0.0.2", base + 21, seed2)) {
    char cdir[] = "/tmp/murmur-drvfiles-c-XXXXXX";
    char ddir[] = "/tmp/murmur-drvfiles-d-XXXXXX";
    if (mkdtemp(cdir) && mkdtemp(ddir)) {
      uint8_t fkey[32];
      memset(fkey, 0x2a, 32);
      murmur_driver_files_config_t fcc, fcd;
      memset(&fcc, 0, sizeof(fcc));
      memset(&fcd, 0, sizeof(fcd));
      fcc.directory = cdir;
      memcpy(fcc.key, fkey, 32);
      fcc.fetch_bind_ip = "127.0.0.1";
      fcc.fetch_port = (uint16_t)(base + 30);
      fcc.fetch_interval_ms = 1000;
      fcd.directory = ddir;
      memcpy(fcd.key, fkey, 32);
      fcd.fetch_bind_ip = "127.0.0.2";
      fcd.fetch_port = (uint16_t)(base + 30);
      fcd.fetch_interval_ms = 1000;
      if (murmur_driver_files_open(&c.drv, &fcc, &detail, &sqlrc) ==
              MURMUR_SYNC_OK &&
          murmur_driver_files_open(&d.drv, &fcd, &detail, &sqlrc) ==
              MURMUR_SYNC_OK) {
        free(detail);
        detail = NULL;
        if (murmur_driver_start(&c.drv, &detail, &sqlrc) ==
                MURMUR_SYNC_OK &&
            murmur_driver_start(&d.drv, &detail, &sqlrc) ==
                MURMUR_SYNC_OK) {
          free(detail);
          detail = NULL;
          exec_ok(c.db, "CREATE TABLE t(a INTEGER PRIMARY KEY NOT NULL, b "
                        "TEXT);");
          exec_ok(c.db, "SELECT crsql_as_crr('main',\"t\")");
          exec_ok(d.db, "CREATE TABLE t(a INTEGER PRIMARY KEY NOT NULL, b "
                        "TEXT);");
          exec_ok(d.db, "SELECT crsql_as_crr('main',\"t\")");
          CHECK(wait_conns(&c, 30), "C connected");
          CHECK(wait_conns(&d, 30), "D connected");
          /* Upload on C. */
          size_t paylen = 80000;
          uint8_t *pay = malloc(paylen);
          unsigned x = 0x12345678u + 51;
          for (size_t i = 0; i < paylen; i++) {
            x = x * 1103515245u + 12345u;
            pay[i] = (uint8_t)(x >> 16);
          }
          freader_t fr;
          memset(&fr, 0, sizeof(fr));
          fr.p = pay;
          fr.n = paylen;
          murmur_files_meta_t fm;
          memset(&fm, 0, sizeof(fm));
          char *fdetail = NULL;
          murmur_files_status_t fst = murmur_files_upload_one(
              murmur_driver_files(&c.drv), "e2e", fmem_read, &fr, &fm,
              &fdetail, &sqlrc);
          CHECK(fst == MURMUR_FILES_OK, "C upload %s",
                fdetail ? fdetail : "");
          free(fdetail);
          murmur_files_meta_free(&fm);
          /* Metadata crosses the mesh first. */
          int meta_seen = 0;
          for (int i = 0; i < 300 && !meta_seen; i++) {
            murmur_files_meta_t dm;
            memset(&dm, 0, sizeof(dm));
            int found = 0;
            if (murmur_files_metadata(murmur_driver_files(&d.drv),
                                      "e2e", &dm, &found, NULL,
                                      NULL) == MURMUR_FILES_OK &&
                found) {
              meta_seen = 1;
            }
            murmur_files_meta_free(&dm);
            if (!meta_seen) {
              sleep_ms(200);
            }
          }
          CHECK(meta_seen, "metadata replicated");
          /* Then D's tick fetches the container. */
          int fetched = 0;
          for (int i = 0; i < 300 && !fetched; i++) {
            int avail = 0;
            if (murmur_files_available(murmur_driver_files(&d.drv),
                                       "e2e", &avail, NULL,
                                       NULL) == MURMUR_FILES_OK &&
                avail) {
              fetched = 1;
              break;
            }
            sleep_ms(200);
          }
          CHECK(fetched, "container fetched");
          if (fetched) {
            fwriter_t fw;
            memset(&fw, 0, sizeof(fw));
            fst = murmur_files_read(murmur_driver_files(&d.drv), "e2e",
                                    fmem_write, &fw, NULL, &fdetail, &sqlrc);
            CHECK(fst == MURMUR_FILES_OK, "D read %s",
                  fdetail ? fdetail : "");
            free(fdetail);
            CHECK(fw.n == paylen && memcmp(fw.p, pay, paylen) == 0,
                  "fetched bytes exact");
            free(fw.p);
          }
          free(pay);
          files_ok = 1;
        } else {
          free(detail);
          detail = NULL;
        }
      } else {
        free(detail);
        detail = NULL;
      }
    }
  }
  CHECK(files_ok, "files e2e ran");
  node_down(&c);
  node_down(&d);
  /* Suite 6: clean stop. */
  node_down(&a);
  node_down(&b);
  if (failures == 0) {
    printf("DRIVER-OK (7 suites)\n");
    return 0;
  }
  printf("DRIVER-FAIL (%d)\n", failures);
  return 1;
}
