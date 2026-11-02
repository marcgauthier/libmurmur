#ifndef MURMUR_BRIDGE_CAPTURE_H
#define MURMUR_BRIDGE_CAPTURE_H
#include "bridge_rows.h"
#ifdef __cplusplus
extern "C" {
#endif
typedef enum {
  MURMUR_BRIDGE_LOW = 1,
  MURMUR_BRIDGE_HIGH = 2
} murmur_bridge_role_t;
typedef struct {
  murmur_bridge_role_t role;
  uint8_t database[16], node[16], signer[32], recipient[32];
  char stream[65];
  uint64_t staging_bytes;
} murmur_bridge_capture_options_t;
/* Attach to an exclusive borrowed connection after registering tables.
 * Private keys remain in native memory, not SQL. Temporary triggers journal
 * only transactions executed through bridge_write. Reattach after reopening.
 * Caller joins operations before detach/connection close. */
int murmur_bridge_capture_attach(sqlite3 *,
                                 const murmur_bridge_capture_options_t *);
int murmur_bridge_capture_detach(sqlite3 *);
typedef int (*murmur_bridge_write_fn)(sqlite3 *, void *);
/* Synchronous native transaction and writer admission. Low changes enqueue one
 * atomic typed bundle; High edits claim only changed fields and deletes claim
 * the row. Callback errors roll back data, capture, ownership, clock and queue.
 * Callback must not change transaction state, throw, or retain the handle.
 * COMMIT followed by sync failure is an uncertain committed outcome. */
int murmur_bridge_write(sqlite3 *, murmur_bridge_write_fn, void *);
/* Split transaction entry points for SQL-driver integration. The caller must
 * retain the connection AND native writer guard on the same OS thread from
 * begin until commit/rollback. Commit rolls back on pre-commit failures and
 * always leaves capture inactive. Prefer bridge_write for synchronous clients.
 */
int murmur_bridge_capture_attached(sqlite3 *);
int murmur_bridge_capture_begin(sqlite3 *);
int murmur_bridge_capture_commit(sqlite3 *);
int murmur_bridge_capture_rollback(sqlite3 *);
/* Standalone High release with a native logical-clock stamp. NULL column
 * releases a row-delete claim; a named column releases its field claim.
 * NOTFOUND is an idempotent no-op. Projection, release and clock commit
 * together. Requires autocommit and attached High capture. */
int murmur_bridge_capture_release(sqlite3 *, const char *table,
                                  const murmur_value_t *key, size_t key_len,
                                  const char *column);
/* Same release using canonical encoded Vec<Value> primary-key bytes. */
int murmur_bridge_capture_release_encoded(sqlite3 *, const char *table,
                                          const void *key, size_t key_len,
                                          const char *column);
/* Export existing Low rows in resumable batches (1..1024 rows). A completed
 * schema gets a durable marker, so subsequent opens do not rescan tables.
 * Source rows are never rewritten. NOTFOUND means baseline preparation is
 * complete; successful batches return the number captured. */
int murmur_bridge_capture_prepare(sqlite3 *, size_t max_rows, size_t *captured);
#ifdef __cplusplus
}
#endif
#endif
