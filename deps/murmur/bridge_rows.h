#ifndef MURMUR_BRIDGE_ROWS_H
#define MURMUR_BRIDGE_ROWS_H
#include "bridge_store.h"
#include "managed.h"
#ifdef __cplusplus
extern "C" {
#endif
typedef struct {
  uint64_t millis;
  uint32_t logical;
  uint8_t origin[16];
} murmur_bridge_version_t;
/* Explicit allowlist. Names and column IDs are deterministically bound to the
 * local SQL declaration. Virtual/internal tables and tables without a primary
 * key are rejected. Re-register after an intentional local schema migration.
 * This does not enable CRR or install automatic capture triggers. */
int murmur_bridge_rows_register(sqlite3 *, const char *table,
                                uint8_t table_id[16]);
int murmur_bridge_rows_schema(sqlite3 *, uint8_t digest[32]);
/* Snapshot a changed row into a canonical native LWW record. Requires the
 * source write transaction and its writer guard. Existing row generations
 * and unchanged cell versions are retained. Deleted keys must use their
 * actual stored SQL types. The capture state commits with the source write. */
int murmur_bridge_rows_capture(sqlite3 *, const uint8_t table_id[16],
                               const murmur_value_t *key, size_t key_len,
                               int deleted, const murmur_bridge_version_t *,
                               murmur_bridge_bytes_t *record);
/* Package up to 1024 canonical row records. Duplicate rows are rejected. */
int murmur_bridge_rows_pack(const murmur_bridge_bytes_t *records, size_t count,
                            murmur_bridge_bytes_t *payload);
/* Authenticated, contiguous import using the local registered schema digest.
 * Projection, shadows, and receipts commit atomically. Only registered LWW
 * table/column IDs are admitted; incoming DDL is never executed. */
int murmur_bridge_rows_apply(sqlite3 *, const uint8_t source[16],
                             const char *stream, const uint8_t signer[32],
                             const uint8_t receiver[32], size_t max_bundle,
                             size_t max_payload);
/* Claim/release follow a successful local High write in the SAME transaction.
 * column==NULL denotes a row-delete claim/release. Claim reads the current
 * field value; row claims require the row already be deleted. Release
 * reprojects the latest retained Low state immediately. Returns NOTFOUND
 * when there is no active claim. Automatic trigger integration is separate. */
int murmur_bridge_rows_claim(sqlite3 *, const uint8_t table_id[16],
                             const murmur_value_t *key, size_t key_len,
                             const char *column,
                             const murmur_bridge_version_t *);
int murmur_bridge_rows_release(sqlite3 *, const uint8_t table_id[16],
                               const murmur_value_t *key, size_t key_len,
                               const char *column,
                               const murmur_bridge_version_t *);
#ifdef __cplusplus
}
#endif
#endif
