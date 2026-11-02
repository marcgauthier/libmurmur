#ifndef MURMUR_BRIDGE_SENDER_H
#define MURMUR_BRIDGE_SENDER_H
#include "bridge_publish.h"
#include "files.h"
#ifdef __cplusplus
extern "C" {
#endif
typedef struct murmur_bridge_sender murmur_bridge_sender_t;
typedef struct {
  uint64_t published, baseline_rows, file_parts;
  int baseline_complete, last_result;
} murmur_bridge_sender_status_t;
/* Source capture must already be attached as Low. The sender optionally
 * prepares its existing rows in resumable batches, draining queued artifacts
 * before preparing another batch. Configured source/stream must match capture.
 * Directory must exist. All parameters are copied; db is borrowed until free.
 * Do not detach capture, change registered tables or close db before free. */
int murmur_bridge_sender_new(sqlite3 *, const uint8_t source[16],
                             const char *stream, const char *directory,
                             int prepare_baseline, murmur_bridge_sender_t **);
/* Drain up to max_artifacts (1..256). Prepare at most 256 rows only after
 * draining the outbox. Backpressure/errors leave durable work retryable. */
int murmur_bridge_sender_poll(murmur_bridge_sender_t *, size_t max_artifacts);
/* Optional borrowed file store, configured while stopped. Must use the same
 * SQL handle. Free the sender BEFORE closing its file store. File data is
 * streamed through bounded signed/encrypted parts in the same source lane. */
int murmur_bridge_sender_files(murmur_bridge_sender_t *, murmur_files_t *);
/* Lifecycle calls must not hold native writer admission; stop joins. */
int murmur_bridge_sender_start(murmur_bridge_sender_t *, unsigned interval_ms);
void murmur_bridge_sender_stop(murmur_bridge_sender_t *);
void murmur_bridge_sender_status(murmur_bridge_sender_t *,
                                 murmur_bridge_sender_status_t *);
void murmur_bridge_sender_free(murmur_bridge_sender_t *);
#ifdef __cplusplus
}
#endif
#endif
