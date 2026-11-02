#ifndef MURMUR_BRIDGE_FERRY_H
#define MURMUR_BRIDGE_FERRY_H
#include "bridge_rows.h"
#include "files.h"
#ifdef __cplusplus
extern "C" {
#endif
/* Each receiver pins one exporter node and source stream. Overlap up to eight
 * Ed25519 public keys during signer rotation. All buffers/strings are copied.
 * Directories must already exist and be owned by the operator. */
typedef struct {
  uint8_t source[16], exporter[16], receiver[32];
  uint8_t signers[8][32];
  size_t signer_count;
  const char *stream, *directory;
  /* Optional private quarantine directory: rejected bounded ciphertext is
   * copied, never removed from the shared ferry. At most 64 MiB / 1024 files.
   * Nonregular or oversized artifacts are rejected without copying. */
  const char *quarantine_directory;
  uint64_t staging_bytes;
} murmur_bridge_receiver_config_t;
typedef struct murmur_bridge_receiver murmur_bridge_receiver_t;
typedef struct {
  uint64_t scanned, applied, duplicate, deferred, rejected, files_completed;
  int last_result;
} murmur_bridge_ferry_status_t;
/* Receiver does not own db. Stop/free BEFORE closing db, detaching capture or
 * changing its table registration. Lifecycle calls must not hold the native
 * writer guard; stop joins a thread that may be waiting for that guard. */
int murmur_bridge_receiver_new(sqlite3 *,
                               const murmur_bridge_receiver_config_t *,
                               murmur_bridge_receiver_t **);
/* Bounded directory scan. Preserves every artifact for other High receivers.
 * Only the next contiguous sequence is staged, so gaps cannot fill the inbox.
 * max_entries 1..256; more work continues from the native directory cursor. */
int murmur_bridge_receiver_poll(murmur_bridge_receiver_t *, size_t max_entries);
/* Optional borrowed file store, configured while stopped. Staged plaintext
 * parts live only in the encrypted SQL store. Finished objects are streamed
 * through the file store and encrypted using the High-side object key.
 * Close/free the receiver before the borrowed file store. */
int murmur_bridge_receiver_files(murmur_bridge_receiver_t *, murmur_files_t *);
/* Optional native polling thread. Interval 10..60000 milliseconds. Poll must
 * not be called manually while started. Stop is idempotent and joins it. */
int murmur_bridge_receiver_start(murmur_bridge_receiver_t *,
                                 unsigned interval_ms);
void murmur_bridge_receiver_stop(murmur_bridge_receiver_t *);
void murmur_bridge_receiver_status(murmur_bridge_receiver_t *,
                                   murmur_bridge_ferry_status_t *);
void murmur_bridge_receiver_free(murmur_bridge_receiver_t *);
#ifdef __cplusplus
}
#endif
#endif
