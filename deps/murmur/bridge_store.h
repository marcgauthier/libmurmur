#ifndef MURMUR_BRIDGE_STORE_H
#define MURMUR_BRIDGE_STORE_H
#include "bridge_codec.h"
typedef struct sqlite3 sqlite3;
#ifdef __cplusplus
extern "C" {
#endif
/* These low-level operations borrow db synchronously. The caller must reserve
 * its connection for the entire operation, including any outer transaction. */
int murmur_bridge_store_init(sqlite3 *db);
/* staging_bytes limits one (source,stream,kind) lane. All lanes additionally
 * share a hard 1 GiB cap per kind on this database connection. */
/* Queue must run inside the source write transaction. Allocates a contiguous
 * stream sequence and seals the payload under a savepoint; failure rolls back
 * allocation and enqueue together. The caller commits and flushes its write. */
int murmur_bridge_store_queue(sqlite3 *db, murmur_bridge_header_t *header,
                              const uint8_t signer[32],
                              const uint8_t recipient[32], const void *payload,
                              size_t len, size_t max_bundle, size_t max_payload,
                              uint64_t staging_bytes);
/* Fetch a queued artifact. NOTFOUND means no work. Bytes stay queued until
 * ack is called after durable filesystem publication. */
int murmur_bridge_store_next(sqlite3 *db, const uint8_t database[16],
                             const char *stream, uint64_t *sequence,
                             murmur_bridge_bytes_t *bundle);
int murmur_bridge_store_ack(sqlite3 *db, const uint8_t database[16],
                            const char *stream, uint64_t sequence);
/* Authenticate then stage a receiver artifact. Duplicate identical envelopes
 * are idempotent; reuse of a sequence with different bytes is AUTH. */
int murmur_bridge_store_stage(sqlite3 *db, const void *bundle, size_t len,
                              const uint8_t source[16], const char *stream,
                              const uint8_t signer[32],
                              const uint8_t receiver[32], size_t max_bundle,
                              size_t max_payload, uint64_t staging_bytes);
typedef int (*murmur_bridge_apply_fn)(sqlite3 *, const murmur_bridge_header_t *,
                                      const void *, size_t, void *);
/* Applies only the next contiguous sequence. The callback and progress receipt
 * commit atomically. It must not change transaction state or retain pointers.
 * NOTFOUND means no contiguous work. SCHEMA holds an incompatible bundle.
 * A post-COMMIT flush error is an uncertain outcome; retry is idempotent. */
int murmur_bridge_store_apply(sqlite3 *db, const uint8_t source[16],
                              const char *stream, const uint8_t signer[32],
                              const uint8_t receiver[32],
                              const uint8_t schema[32], size_t max_bundle,
                              size_t max_payload, murmur_bridge_apply_fn,
                              void *);
#ifdef __cplusplus
}
#endif
#endif
