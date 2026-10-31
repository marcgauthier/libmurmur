/* murmur kv - native murmur_kv store plus the CrrBackend surface:
 * ordered reads, prefix scans, atomic commits, hybrid-clock
 * observe, per-origin progress, snapshot capture, and schema
 * accept. Ports kvGet/kvPut/kvGetMany/kvKeys/kvKeysPage/kvCommit/
 * kvApply/clockObserve/txProgress and the CrrBackend methods from
 * pkgs/replication/backend.go. SQL text is verbatim; txErr kind
 * mapping collapses (C has the one status enum, consumed directly).
 * Go's map-ordered txProgress comes out deterministic (scan order);
 * every consumer is order-free.
 */
#ifndef MURMUR_KV_H
#define MURMUR_KV_H

#include <stddef.h>
#include <stdint.h>

#include "member.h"
#include "sync.h"
#include "txcodec.h"

typedef struct sqlite3 sqlite3;

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
  uint8_t *key;
  size_t key_len;
  uint8_t *value; /* NULL when is_delete */
  size_t value_len;
  int is_delete;
} murmur_kv_record_t;

void murmur_kv_record_free(murmur_kv_record_t *r);

/* One value; *found false on missing (**val NULL then). */
murmur_sync_status_t murmur_kv_get(sqlite3 *db, const uint8_t *key,
                                   size_t key_len, uint8_t **val,
                                   size_t *val_len, int *found, int *sqlrc);
murmur_sync_status_t murmur_kv_put(sqlite3 *db, const uint8_t *key,
                                   size_t key_len, const uint8_t *val,
                                   size_t val_len, int *sqlrc);

/* Ordered read; vals[i] is NULL with present[i]==0 on missing. */
murmur_sync_status_t murmur_kv_get_many(sqlite3 *db, const uint8_t **keys,
                                        const size_t *key_lens, size_t n,
                                        uint8_t ***vals, size_t **val_lens,
                                        int **present, int *sqlrc);
void murmur_kv_get_many_free(uint8_t **vals, size_t *val_lens, int *present,
                             size_t n);

/* Ordered prefix read within a byte budget (missing consumes none;
 * one oversized first value allowed). Returns the kept prefix. */
murmur_sync_status_t murmur_kv_get_many_bounded(
    sqlite3 *db, const uint8_t **keys, const size_t *key_lens, size_t n,
    int64_t max_bytes, uint8_t ***vals, size_t **val_lens, int **present,
    size_t *kept, int *sqlrc);

/* Prefix scans in key order (malloc'd key set). */
murmur_sync_status_t murmur_kv_keys(sqlite3 *db, const uint8_t *prefix,
                                    size_t prefix_len, uint8_t ***keys,
                                    size_t **key_lens, size_t *n, int *sqlrc);
murmur_sync_status_t murmur_kv_keys_page(sqlite3 *db, const uint8_t *prefix,
                                         size_t prefix_len, const uint8_t *after,
                                         size_t after_len, int has_after,
                                         int64_t limit, uint8_t ***keys,
                                         size_t **key_lens, size_t *n,
                                         int *sqlrc);
void murmur_kv_keys_free(uint8_t **keys, size_t *key_lens, size_t n);

/* Exclusive BLOB range end (*unbounded when the prefix is all-0xff). */
int murmur_kv_prefix_end(const uint8_t *prefix, size_t prefix_len,
                         uint8_t **out, size_t *out_len, int *unbounded);

/* In-caller-tx apply; BEGIN/COMMIT-wrapped commit. */
murmur_sync_status_t murmur_kv_apply(sqlite3 *db,
                                     const murmur_kv_record_t *records,
                                     size_t n, int *sqlrc);
murmur_sync_status_t murmur_kv_commit(sqlite3 *db,
                                      const murmur_kv_record_t *records,
                                      size_t n, int *sqlrc);

/* Hybrid clock max-merge; returns the stored clock. */
murmur_sync_status_t murmur_clock_observe(sqlite3 *db, uint64_t millis,
                                          uint32_t logical, uint64_t *clock,
                                          uint32_t *clock_logical, int *sqlrc);

/* Durable per-origin progress (Applied clamped over Observed). */
murmur_sync_status_t murmur_tx_progress(sqlite3 *db, murmur_tx_progress_t **ps,
                                        size_t *n, int *sqlrc);
void murmur_tx_progress_free(murmur_tx_progress_t *ps, size_t n);

/* Serving budgets (loadServeParams: 7 settings + the loader
 * invariant batch <= max <= min(queue, staging, 64MiB)). */
typedef struct {
  int64_t sessions;
  int64_t queue_bytes;
  int64_t batch_bytes;
  int64_t max_batch_bytes;
  int64_t staging_bytes;
  int64_t gossip_fanout;
  int64_t staging_timeout_ms;
} murmur_serve_params_t;

/* detail_out (nullable) receives the owned "invalid <name>" /
 * invariant message on INVALID. */
murmur_sync_status_t murmur_serve_params(sqlite3 *db, murmur_serve_params_t *p,
                                         char **detail_out, int *sqlrc);

/* Backend: progress with the live local head merged in. */
murmur_sync_status_t murmur_backend_progress(sqlite3 *db,
                                             const murmur_node_t *node,
                                             murmur_tx_progress_t **ps,
                                             size_t *n, int *sqlrc);

/* Backend: BEGIN IMMEDIATE + ingest payloads + apply records + COMMIT. */
murmur_sync_status_t murmur_backend_apply(sqlite3 *db, const uint8_t **payloads,
                                          const size_t *payload_lens, size_t np,
                                          const murmur_kv_record_t *records,
                                          size_t nr, int *sqlrc);

/* Backend: replicated-subset schema bytes. */
murmur_sync_status_t murmur_backend_schema(sqlite3 *db, uint8_t **blob,
                                           size_t *len, int *sqlrc);

/* Backend: re-decide and adopt additive remote schema. */
murmur_sync_status_t murmur_backend_accept_schema(sqlite3 *db,
                                                  const uint8_t *schema,
                                                  size_t schema_len,
                                                  int *accepted, int *sqlrc);

/* Backend: full CRSB export image (+ heads). Offline reports
 * OVERLOADED ("replication is stopped" is transient). */
murmur_sync_status_t murmur_backend_snapshot(sqlite3 *db, int online,
                                             uint8_t **blob, size_t *len,
                                             int *sqlrc);
murmur_sync_status_t murmur_backend_snapshot_with_progress(
    sqlite3 *db, int online, uint8_t **blob, size_t *len,
    murmur_tx_progress_t **ps, size_t *n, int *sqlrc);

#ifdef __cplusplus
}
#endif

#endif /* MURMUR_KV_H */
