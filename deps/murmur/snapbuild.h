/* murmur snapbuild - native snapshot join over CRR state: the
 * downstream adapter over the tx snapshot chunk/pin/receipt state
 * machine. Ports the non-Engine functions of
 * pkgs/replication/snapshot.go: transport verification (mutual TLS
 * binds donor identity; signatures stay empty), streaming donor
 * builds, recipient accept, multi-call install, and the
 * prefix-consistent full-export build.
 *
 * Backend identity arrives as explicit (database, donor/recipient)
 * ids; Go's snapshotTxErr collapses onto the one status enum, and
 * errClosed (build in progress, another staged, schema mismatch)
 * maps to OVERLOADED like the other transient failures.
 */
#ifndef MURMUR_SNAPBUILD_H
#define MURMUR_SNAPBUILD_H

#include <stddef.h>
#include <stdint.h>

#include "kv.h"
#include "member.h"
#include "retain.h"
#include "sync.h"

typedef struct sqlite3 sqlite3;

#ifdef __cplusplus
extern "C" {
#endif

/* Transfer lifetime bound (saturating). */
uint64_t murmur_snap_deadline(const murmur_snap_params_t *p, uint64_t now);

/* Manifest::verify minus Ed25519: identity/trust/expiry are AUTH,
 * budgets are OVERLOADED, progress shape is PROTOCOL. */
murmur_sync_status_t murmur_snap_verify(
    const murmur_tx_manifest_t *m, const murmur_node_t *database,
    const murmur_node_t *recipient, const murmur_node_t *source,
    const murmur_snap_params_t *params, uint64_t now, int *sqlrc);

/* Persists one build group synchronously (n may be 0 on the final
 * call, mirroring Go's trailing emit(nil)). */
typedef murmur_sync_status_t (*murmur_snap_emit_fn)(
    void *ctx, const murmur_kv_record_t *records, size_t n, int *sqlrc);

/* Streams CRSB pages into OUT chunks without materializing the
 * payload; only the final group publishes the manifest and pin.
 * The output manifest deep-copies progress and chunks (free with
 * murmur_tx_manifest_free). */
murmur_sync_status_t murmur_snap_build_streaming(
    const murmur_node_t *database, const murmur_node_t *donor,
    const murmur_node_t *recipient, const uint8_t **pages,
    const size_t *page_lens, size_t n_pages,
    const murmur_tx_progress_t *progress, size_t n_progress,
    const uint8_t schema[32], const murmur_snap_params_t *params,
    uint64_t now, murmur_snap_emit_fn emit, void *emit_ctx,
    murmur_tx_manifest_t *out, int *sqlrc);

/* Stages a verified manifest for install. */
murmur_sync_status_t murmur_snap_accept(sqlite3 *db,
                                        const murmur_node_t *database,
                                        const murmur_node_t *recipient,
                                        const murmur_snap_params_t *params,
                                        const murmur_node_t *source,
                                        const murmur_tx_manifest_t *m,
                                        uint64_t now, int *sqlrc);

/* Installs staged chunks; *done once the receipt is durable (big
 * streams take several calls). */
murmur_sync_status_t murmur_snap_finish(sqlite3 *db,
                                        const murmur_node_t *database,
                                        const murmur_node_t *recipient,
                                        const murmur_snap_params_t *params,
                                        const murmur_node_t *source,
                                        const murmur_node_t *transfer,
                                        uint64_t now, int *done, int *sqlrc);

/* Builds for recipient over a prefix-consistent full export. Chunks
 * land in the local kv; the manifest must fit one frame. */
murmur_sync_status_t murmur_snap_build_for(
    sqlite3 *db, const murmur_node_t *database, const murmur_node_t *donor,
    const murmur_snap_params_t *params, int64_t batch_bytes,
    int64_t max_batch_bytes, const murmur_node_t *recipient, uint64_t now,
    murmur_tx_manifest_t *out, int *sqlrc);

#ifdef __cplusplus
}
#endif

#endif /* MURMUR_SNAPBUILD_H */
