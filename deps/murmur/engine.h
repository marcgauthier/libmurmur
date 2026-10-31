/* murmur engine - native replication engine: lifecycle, control
 * surface, retention, membership wiring, and SQL verbs over one
 * database. Ports pkgs/replication/engine.go, the Engine methods of
 * membership.go/retention.go/snapshot.go/schema_serve.go/serve.go,
 * sql.go, and wait.go. Stream handlers live in serve.c against this
 * state.
 *
 * Like Go, the engine is passive: dial/accept/pull/gossip loops are
 * driven externally (the C demo and the picoquic transport in N7d);
 * only the vetted-fetch and snapshot-request workers run detached
 * threads. Sessions are an abstract interface so tests drive two
 * engines over loopback streams with no sockets.
 *
 * Error recording mirrors errors.go: extended 0x53xx codes, kind
 * strings, and "Kind: detail" messages surface through Status and
 * Health exactly like the Go verbs.
 */
#ifndef MURMUR_ENGINE_H
#define MURMUR_ENGINE_H

#include <pthread.h>
#include <stddef.h>
#include <stdint.h>

#include "member.h"
#include "sync.h"

typedef struct sqlite3 sqlite3;
typedef struct sqlite3_context sqlite3_context;
typedef struct sqlite3_value sqlite3_value;

#ifdef __cplusplus
extern "C" {
#endif

/* One reliable bidirectional byte stream. read_full blocks for
 * exactly n bytes; all return 0 on success. error_text (nullable)
 * reports the last failure for protocol details; NULL means a
 * fixed "stream error". */
typedef struct {
  int (*write)(void *ctx, const uint8_t *b, size_t n);
  int (*read_full)(void *ctx, uint8_t *b, size_t n);
  int (*close)(void *ctx);
  const char *(*error_text)(void *ctx);
  void *ctx;
} murmur_stream_io_t;

/* One authenticated peer session (QUIC in production, loopback in
 * tests). The engine opens streams, datagrams membership packets,
 * and closes; dial/accept/recv belong to the driver. */
typedef struct {
  int (*open_stream)(void *ctx, murmur_stream_io_t *out);
  int (*send_datagram)(void *ctx, const uint8_t *b, size_t n);
  int (*close)(void *ctx);
  /* Last open failure text (nullable); NULL means no text. */
  const char *(*error_text)(void *ctx);
  void *ctx;
} murmur_session_if_t;

/* Extended result codes (facility 0x53xx, SQLite primary low). */
#define MURMUR_CODE_INVALID 0x530101
#define MURMUR_CODE_PROTOCOL 0x530B0F
#define MURMUR_CODE_AUTH 0x530C17
#define MURMUR_CODE_UNAVAILABLE 0x530D0E
#define MURMUR_CODE_OVERLOADED 0x530E05
#define MURMUR_CODE_STORAGE 0x53080A

typedef struct {
  murmur_node_t peer;
  murmur_session_if_t sess;
} murmur_engine_conn_t;

typedef struct {
  murmur_node_t peer;
  uint8_t digest[32];
  int verdict;
} murmur_vetted_ent_t;

typedef struct {
  murmur_node_t peer;
  uint8_t digest[32];
  uint64_t sequence;
} murmur_schema_sent_t;

typedef struct murmur_engine {
  pthread_mutex_t mu;
  /* Guards mship; order mship_mu -> mu (mship io callbacks take mu). */
  pthread_mutex_t mship_mu;
  pthread_cond_t sync_cond;
  pthread_cond_t serving_cond, receiving_cond;
  pthread_cond_t worker_cond;
  int workers; /* detached serve workers (vet/snapshot) in flight */
  sqlite3 *db; /* borrowed */
  int running;
  uint64_t started_wall_ms;
  murmur_node_t node, site, group;
  int has_transport;
  char *bind_addr; /* owned, NULL when unset */
  uint64_t incarnation;
  murmur_addr_t advertise;
  size_t serve_in_use, serve_cap;
  uint64_t serving_max, serving_in_use;
  uint64_t receiving_max, receiving_in_use;
  uint64_t applied, sent;
  murmur_mship_t *mship;
  uint64_t persisted_incarnation;
  int sync_pending;
  int gossip_fanout;
  uint64_t serve_ok, serve_reject, serve_error;
  int has_last_err;
  int32_t last_err_code;
  char *last_err_kind;
  char *last_err_msg;
  char *last_error_text; /* owned, NULL when empty */
  char *snapshot_status; /* owned, NULL when empty */
  murmur_vetted_ent_t *vetted;
  size_t n_vetted, cap_vetted;
  uint64_t vet_ok, vet_no, vet_fail, schema_adoptions;
  murmur_schema_sent_t *schema_sent;
  size_t n_schema_sent, cap_schema_sent;
  murmur_engine_conn_t *conns;
  size_t n_conns, cap_conns;
  /* Seed buffer (72-byte slots): pre-Start adds plus bootstrap
   * replay, mirroring Go's map across restarts. */
  char *seeds;
  size_t n_seeds, cap_seeds;
} murmur_engine_t;

/* Binds an engine to db (borrowed). */
void murmur_engine_init(murmur_engine_t *e, sqlite3 *db);
void murmur_engine_destroy(murmur_engine_t *e);

/* Transport presence plus its local address (NULL unsets). Start
 * fails without a transport, like Go's nil check. */
void murmur_engine_set_transport(murmur_engine_t *e, const char *local_addr);

/* Lifecycle. Start loads config, claims identity, and serves until
 * Stop; double-Start is OVERLOADED ("replication already running").
 * detail_out (nullable) receives the owned failure detail (the Msg
 * half of Go's "Kind: Msg"); SQLITE failures report the SQLite
 * message instead. */
murmur_sync_status_t murmur_engine_start(murmur_engine_t *e, char **detail_out,
                                         int *sqlrc);
murmur_sync_status_t murmur_engine_stop(murmur_engine_t *e, int *sqlrc);
int murmur_engine_running(murmur_engine_t *e);

/* Control surfaces (owned JSON, Go key order and escaping). */
char *murmur_engine_status(murmur_engine_t *e);
char *murmur_engine_health(murmur_engine_t *e);
char *murmur_engine_progress(murmur_engine_t *e);
char *murmur_engine_peers(murmur_engine_t *e);

/* Sessions (driver-owned handles, engine drops on remove/stop). */
murmur_sync_status_t murmur_engine_add_conn(murmur_engine_t *e,
                                            const murmur_node_t *peer,
                                            const murmur_session_if_t *sess,
                                            int *sqlrc);
void murmur_engine_remove_conn(murmur_engine_t *e, const murmur_node_t *peer);
int murmur_engine_get_conn(murmur_engine_t *e, const murmur_node_t *peer,
                           murmur_session_if_t *out);

/* Membership ticks and packets (now_ms wall). */
void murmur_engine_gossip(murmur_engine_t *e);
void murmur_engine_probe(murmur_engine_t *e, uint64_t now_ms);
murmur_sync_status_t murmur_engine_handle_packet(murmur_engine_t *e,
                                                 const murmur_node_t *peer,
                                                 const uint8_t *datagram,
                                                 size_t len, uint64_t now_ms,
                                                 int *sqlrc);
murmur_sync_status_t murmur_engine_add_seed(murmur_engine_t *e, const char *addr,
                                            int *sqlrc);
void murmur_engine_remove_node(murmur_engine_t *e, const murmur_node_t *node);
size_t murmur_engine_fetch_sources(murmur_engine_t *e, uint16_t port,
                                   murmur_fetch_source_t *out, size_t cap);
/* Dial-target seeds: mship seeds plus buffered pre-start adds
 * (cap x 72-byte slots). */
size_t murmur_engine_seeds(murmur_engine_t *e, char *out, size_t cap);
/* Connected peer ids (for the sync scheduler). */
size_t murmur_engine_conn_peers(murmur_engine_t *e, murmur_node_t *out,
                                size_t cap);

/* Retention. moved counts origins; pruned counts tombstones. */
murmur_sync_status_t murmur_engine_retention_pass(murmur_engine_t *e,
                                                  uint64_t *moved,
                                                  uint64_t *pruned,
                                                  int *sqlrc);

/* Sync flag (murmur_sync / seed notify). Non-blocking take. */
void murmur_engine_kick_sync(murmur_engine_t *e);
int murmur_engine_take_sync(murmur_engine_t *e);

/* Waits (100ms poll; zero timeout polls once). */
murmur_sync_status_t murmur_engine_wait_applied(murmur_engine_t *e,
                                                const murmur_node_t *origin,
                                                uint64_t seq,
                                                uint64_t timeout_ms, int *ok,
                                                int *sqlrc);
murmur_sync_status_t murmur_engine_wait_lag(murmur_engine_t *e, uint64_t bound,
                                            uint64_t timeout_ms, int *ok,
                                            int *sqlrc);

/* SQL verbs (RegisterSQL surface). */
murmur_sync_status_t murmur_engine_register_sql(murmur_engine_t *e, int *sqlrc);

/* Recorded-error helpers for verbs and handlers. */
void murmur_engine_fail(murmur_engine_t *e, int32_t code, const char *kind,
                        const char *message);
void murmur_engine_record(murmur_engine_t *e, const char *text);

/* Detached serve-worker accounting (serve.c—or the driver—pairs
 * add/release around each worker; wait blocks until none). */
void murmur_engine_worker_add(murmur_engine_t *e);
void murmur_engine_worker_release(murmur_engine_t *e);
void murmur_engine_worker_wait(murmur_engine_t *e);

/* Shared bits for serve.c: wall clock, node hex, ParseID. */
uint64_t murmur_engine_wall_ms(void);
void murmur_engine_node_format(const murmur_node_t *id, char out[33]);
murmur_sync_status_t murmur_engine_node_parse(const char *s, murmur_node_t *id,
                                              int *sqlrc);

#ifdef __cplusplus
}
#endif

#endif /* MURMUR_ENGINE_H */
