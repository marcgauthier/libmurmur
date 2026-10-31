/* murmur txsnap - native durable snapshot transfers: staged chunk
 * receive, validation, missing scans, pin-gated prune limits, and
 * the maintain/reap sweepers. Ports pkgs/tx/snapshot.go. Kv records
 * are the only authoritative state; int64 wraparounds in stream
 * bounds replicate Go's 64-bit wrapping explicitly. errUnavailable
 * maps to OVERLOADED (transient), auth failures to AUTH.
 */
#ifndef MURMUR_TXSNAP_H
#define MURMUR_TXSNAP_H

#include <stddef.h>
#include <stdint.h>

#include "member.h"
#include "sync.h"
#include "txcodec.h"

typedef struct sqlite3 sqlite3;

#ifdef __cplusplus
extern "C" {
#endif

#define MURMUR_TX_OUT "07/replication/snapshot-v1/out/"
#define MURMUR_TX_IN "07/replication/snapshot-v1/in/"
#define MURMUR_TX_RECEIPTS "07/replication/snapshot-v1/receipts/"
#define MURMUR_TX_PINS "07/replication/snapshot-v1/pins/"
#define MURMUR_TX_STREAM_MAGIC "MURMUR-SNAPSHOT\x00\x02"
#define MURMUR_TX_STREAM_MAGIC_LEN 17

/* Validated byte-range reassembly of the staged payload. */
murmur_sync_status_t murmur_tx_stream_read(sqlite3 *db,
                                           const murmur_tx_manifest_t *m,
                                           uint64_t offset, int64_t length,
                                           uint8_t **out, size_t *out_len,
                                           int *sqlrc);

/* First staged recipient-side transfer (*found false when none). */
murmur_sync_status_t murmur_tx_load_incoming(sqlite3 *db,
                                             murmur_tx_incoming_t *r,
                                             int *found, int *sqlrc);

/* Stages one validated chunk (idempotent on equal bytes). */
murmur_sync_status_t murmur_tx_receive(sqlite3 *db, const murmur_node_t *source,
                                       const murmur_node_t *transfer,
                                       uint32_t index, const uint8_t *data,
                                       size_t data_len, uint64_t now,
                                       int *sqlrc);

/* Chunk identity, length, and hash check (pure). */
murmur_sync_status_t murmur_tx_validate_chunk(const murmur_tx_manifest_t *m,
                                              const murmur_node_t *source,
                                              uint32_t index,
                                              const uint8_t *data,
                                              size_t data_len, int *sqlrc);

/* Up to 128 absent chunk indexes, in index order. */
murmur_sync_status_t murmur_tx_missing(sqlite3 *db,
                                       const murmur_tx_incoming_t *state,
                                       uint32_t **indexes, size_t *n,
                                       int *sqlrc);

/* Minimum pruning boundary across live pins (max u64 when none). */
murmur_sync_status_t murmur_tx_prune_limit(sqlite3 *db,
                                           const murmur_node_t *origin,
                                           uint64_t now, uint64_t *limit,
                                           int *sqlrc);

/* Sweeps expired pins/headers/orphans/receipts plus v8 leftovers
 * (256 records per commit, Go's exact cap semantics). */
murmur_sync_status_t murmur_tx_maintain(sqlite3 *db, uint64_t now, int *sqlrc);

/* Drops pins of retired/fogotten/fulfilled recipients. */
murmur_sync_status_t murmur_tx_reap_forgotten_pins(sqlite3 *db, uint64_t now,
                                                  uint64_t max_offline_ms,
                                                  const murmur_node_t *online,
                                                  size_t n_online, int *sqlrc);

#ifdef __cplusplus
}
#endif

#endif /* MURMUR_TXSNAP_H */
