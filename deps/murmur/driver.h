/* murmur driver - the replication runtime: QUIC endpoint,
 * accept/dial, per-session stream and datagram pumps, the pull
 * scheduler, and the gossip/probe/retention ticks over
 * murmur_engine_t. No Go reference exists (clients/go only
 * libraries the engine and transport); this is the native
 * integrator the transport and membership headers describe.
 *
 * Wire conventions (driver policy, documented here):
 * - The first stream on every connection is the session
 *   handshake (incoming side validates, then replies); later
 *   streams dispatch through ServeStream. Dial/auth failures
 *   close the connection.
 * - Sync workers pull to drain, adopt once on schema mismatch
 *   when accept_remote_schema is set, then master-push; they
 *   re-run every 5s and on the engine sync kick.
 * - Ticks: gossip and probe every 1s, retention every 60s,
 *   dial/sync sweep every 500ms.
 *
 * Threading: start spawns joinable accept/scheduler/tick
 * threads; session pumps and sync/dial workers are detached.
 * Session handles stay valid until driver stop (dead sessions
 * drop their QUIC state eagerly; the small handle frees at
 * stop), so engine session copies never dangle.
 */
#ifndef MURMUR_DRIVER_H
#define MURMUR_DRIVER_H

#include <pthread.h>
#include <stddef.h>
#include <stdint.h>

#include "engine.h"
#include "fetch.h"
#include "files.h"
#include "search.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct murmur_quic murmur_quic_t;
typedef struct murmur_session murmur_session_t;
typedef struct murmur_stream murmur_stream_t;

typedef struct murmur_driver murmur_driver_t;

/* One live connection (driver-owned; valid until driver stop). */
typedef struct {
  murmur_node_t peer;
  murmur_session_t *qs; /* NULL once dead */
  int dead;
  int syncing;
  uint64_t gen;
  char err[256];
  struct murmur_driver *drv;
} murmur_driver_sess_t;

/* File store + fetch configuration (public C API; keys and paths
 * travel here, never through SQL text). Zero fields take defaults
 * except fetch_port, which is required: every node binds its fetch
 * service on this uniform cluster port. */
typedef struct {
  const char *directory;
  uint8_t key[32];
  const uint8_t (*previous_key)[32]; /* nullable */
  uint64_t generation;
  uint64_t max_file_bytes;    /* 0 = 4 GiB */
  uint64_t max_staging_bytes; /* 0 = 1 GiB */
  int concurrent_fetches;     /* 0 = 2 */
  uint64_t fetch_interval_ms; /* 0 = 30000 */
  const char *fetch_bind_ip;  /* NULL = 127.0.0.1 */
  uint16_t fetch_port;        /* required */
} murmur_driver_files_config_t;

struct murmur_driver {
  pthread_mutex_t mu;
  pthread_cond_t detach_cond;
  int detached;
  murmur_engine_t *eng; /* borrowed */
  murmur_quic_t *quic;  /* owned while running */
  int running;
  uint16_t local_port;
  uint32_t sessions;
  pthread_t accept_th, sched_th, tick_th;
  murmur_driver_sess_t **sess; /* individually boxed: stable addresses */
  size_t n_sess, cap_sess;
  uint64_t gen_next;
  char dialing[16][72];
  size_t n_dialing;
  char dial_cool[16][72];
  uint64_t dial_cool_until[16];
  uint32_t dial_fail_count[16];
  size_t n_cool;
  murmur_files_t *files; /* owned when files_on */
  murmur_fetch_t *fetch; /* owned while running && files_on */
  murmur_driver_files_config_t files_cfg; /* owned copy */
  int files_on;
  uint64_t file_tick;
  murmur_search_manager_t *search; /* owned when search_on */
  uint64_t search_interval_ms;     /* 0 = 100 */
  int search_on;
  uint64_t search_tick_n;
};

/* Search index configuration (public C API). Definitions are
 * validated and copied at open; zero queue/batch take the Go
 * defaults (8 MiB / 256 rows); zero interval means 100 ms. */
typedef struct {
  const murmur_search_def_t *defs; /* borrowed, copied at open */
  size_t n_defs;
  size_t queue_bytes;   /* 0 = 8 MiB */
  size_t batch_rows;    /* 0 = 256 */
  uint64_t interval_ms; /* 0 = 100 */
} murmur_driver_search_config_t;

/* Stages the file store (call before start; stages only — the
 * store opens at start, once the engine identity exists). */
murmur_sync_status_t murmur_driver_files_open(murmur_driver_t *d,
                                              const murmur_driver_files_config_t *c,
                                              char **detail_out, int *sqlrc);
/* Borrowed store handle (NULL unless files opened). */
murmur_files_t *murmur_driver_files(murmur_driver_t *d);

/* Stages the search manager (call before start; validates and copies
 * the definitions). Maintenance runs on the tick thread. */
murmur_sync_status_t murmur_driver_search_open(
    murmur_driver_t *d, const murmur_driver_search_config_t *c,
    char **detail_out, int *sqlrc);
/* Borrowed manager handle (NULL unless search opened). */
murmur_search_manager_t *murmur_driver_search(murmur_driver_t *d);
/* Re-runs schema sync on demand (sources created late, DDL churn). */
murmur_sync_status_t murmur_driver_search_sync(murmur_driver_t *d,
                                               int allow_missing,
                                               char **detail_out, int *sqlrc);

void murmur_driver_init(murmur_driver_t *d, murmur_engine_t *e);
void murmur_driver_destroy(murmur_driver_t *d);

/* Brings up replication: transport setting, engine start, QUIC
 * endpoint from the TLS settings, then threads. detail_out
 * (nullable) receives the owned failure detail. */
murmur_sync_status_t murmur_driver_start(murmur_driver_t *d,
                                         char **detail_out, int *sqlrc);
/* Stops threads, drops sessions, frees the endpoint, stops the
 * engine. Idempotent. */
murmur_sync_status_t murmur_driver_stop(murmur_driver_t *d, int *sqlrc);
int murmur_driver_running(murmur_driver_t *d);
/* Runs one retention collection pass now (reference RETENTION COLLECT
 * parity); moved/pruned (nullable) receive floor advance and tombstone
 * deletes. Safe to call while running. */
murmur_sync_status_t murmur_driver_retention_collect(murmur_driver_t *d,
                                                     uint64_t *moved,
                                                     uint64_t *pruned,
                                                     int *sqlrc);

#ifdef __cplusplus
}
#endif

#endif /* MURMUR_DRIVER_H */
