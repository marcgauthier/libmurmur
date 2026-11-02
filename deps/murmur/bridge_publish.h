#ifndef MURMUR_BRIDGE_PUBLISH_H
#define MURMUR_BRIDGE_PUBLISH_H
#include "bridge_store.h"
#ifdef __cplusplus
extern "C" {
#endif
/* Durably publishes one queued artifact, then acknowledges it. Directory must
 * already exist and be owned by the operator. Uses an immutable SHA-256 name,
 * exclusive temporary file, file sync, atomic publication and directory sync.
 * A failure leaves the queue retryable; an already published identical file
 * is accepted. The caller serializes access to its SQLite connection.
 * SQLITE_NOTFOUND means the outbox has no work. */
int murmur_bridge_publish(sqlite3 *, const uint8_t source[16],
                          const char *stream, const char *directory);
#ifdef __cplusplus
}
#endif
#endif
