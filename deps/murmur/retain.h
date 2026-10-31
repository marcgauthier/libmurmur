/* murmur retain - native retention helpers: floor parameters,
 * snapshot parameters, staging sweep, tombstone GC, watermark, and
 * orphan clock reaping over a sqlite3 connection.
 *
 * Port of the pure-SQL half of retention.go plus SnapshotParamsFrom:
 * SQL text, defaults, parsing rules, and error kinds match Go. The
 * tx-backend floor collectors (CollectFloors, MyStreamFloor), the
 * snapshot state machine, and RetentionPass itself need the native
 * kv backend and land with store-attached replication (N7).
 */
#ifndef MURMUR_RETAIN_H
#define MURMUR_RETAIN_H

#include <stddef.h>
#include <stdint.h>

#include "sync.h"

typedef struct sqlite3 sqlite3;

#ifdef __cplusplus
extern "C" {
#endif

#define MURMUR_STARTUP_GRACE_MILLIS 60000u

typedef struct {
  uint64_t min_retained;
  uint64_t max_offline_ms;
  int bootstrap_nonempty;
} murmur_retain_params_t;

murmur_sync_status_t murmur_retain_params_from(sqlite3 *db,
                                              murmur_retain_params_t *out,
                                              int *sqlrc);

typedef struct {
  int64_t snapshot_bytes;
  int64_t snapshot_staging_bytes;
  uint64_t transfer_lifetime_ms;
  int64_t staging_transfers;
  int64_t max_transaction_bytes;
  int64_t batch_bytes;
  murmur_node_t *trusted; /* malloc'd set; free with _free */
  size_t n_trusted;
} murmur_snap_params_t;

void murmur_snap_params_free(murmur_snap_params_t *p);

murmur_sync_status_t murmur_snap_params_from(sqlite3 *db,
                                            murmur_snap_params_t *out,
                                            int *sqlrc);

/* Drops expired staging rows; reports rows removed. */
murmur_sync_status_t murmur_gc_stage(sqlite3 *db, int64_t *removed,
                                     int *sqlrc);

/* Drops tombstone clocks at or below floor; advances gc_watermark. */
murmur_sync_status_t murmur_gc_tombstones(sqlite3 *db, uint64_t floor,
                                          uint64_t *deleted, int *sqlrc);

/* Highest pruned local db_version (0 fresh). */
murmur_sync_status_t murmur_gc_watermark(sqlite3 *db, uint64_t *mark,
                                         int *sqlrc);

/* Drops side tables whose base tables are gone, pinning their peak
 * db_version first. */
murmur_sync_status_t murmur_reap_orphan_clocks(sqlite3 *db, uint64_t *reaped,
                                               int *sqlrc);

#ifdef __cplusplus
}
#endif

#endif /* MURMUR_RETAIN_H */
