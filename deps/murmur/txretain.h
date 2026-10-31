/* murmur txretain - native peer-liveness subset: records, merge,
 * touch, retire, and collector status. Ports pkgs/tx/retention.go.
 * Encode order for ack maps is byte-sorted (txcodec); lookups scan
 * from the end for Go map last-wins. Wall clock is realtime
 * milliseconds like Go UnixMilli.
 */
#ifndef MURMUR_TXRETAIN_H
#define MURMUR_TXRETAIN_H

#include <stddef.h>
#include <stdint.h>

#include "member.h"
#include "sync.h"
#include "txcodec.h"

typedef struct sqlite3 sqlite3;

#ifdef __cplusplus
extern "C" {
#endif

uint64_t murmur_tx_now_millis(void);

typedef struct {
  murmur_tx_peer_t *peers;
  size_t n_peers;
  uint64_t collected_transactions;
  uint64_t last_collection_millis;
} murmur_tx_retention_status_t;

void murmur_tx_retention_status_free(murmur_tx_retention_status_t *st);

/* Peer liveness plus collector counters. */
murmur_sync_status_t murmur_tx_status(sqlite3 *db,
                                      murmur_tx_retention_status_t *st,
                                      int *sqlrc);

/* One liveness record (*found false when absent). */
murmur_sync_status_t murmur_tx_peer(sqlite3 *db, const murmur_node_t *node,
                                    murmur_tx_peer_t *peer, int *found,
                                    int *sqlrc);

/* Records contact, max-merges progress; skips quiet writes; retired
 * peers fail AUTH; >4096 acks fail OVERLOADED. */
murmur_sync_status_t murmur_tx_touch(sqlite3 *db, const murmur_node_t *node,
                                     const murmur_tx_progress_t *progress,
                                     size_t n_progress, int *sqlrc);

/* Marks retired and writes the exclusion tombstone. */
murmur_sync_status_t murmur_tx_retire(sqlite3 *db, const murmur_node_t *node,
                                      int *sqlrc);

#ifdef __cplusplus
}
#endif

#endif /* MURMUR_TXRETAIN_H */
