/* murmur sync - native sync plane: export / stage / apply /
 * progress / reset / observed-max over a sqlite3 connection.
 *
 * Port of the sync.go Storage sync methods: SQL text, cursor rules,
 * budget accounting, error kinds, and wire bytes match the Go (and
 * Rust) implementation. Export reads the crsql_changes vtab and
 * Apply ingests through crsql_ingest_blob; the table_replication
 * filter parses through SQLite JSON1 with Go encoding/json
 * semantics for the {"table":bool} shape (last duplicate wins,
 * non-boolean values rejected).
 *
 * Status model: INVALID/PROTOCOL/OVERLOADED/AUTH mirror the Go
 * Error kinds; SQLITE reports a native SQLite failure with the
 * failing primary result code in *sqlrc (when non-NULL), mirroring
 * Go's "Native" passthrough. Durability matches Go: Apply commits;
 * the COMMIT barrier plus the caller's flush is the barrier.
 */
#ifndef MURMUR_SYNC_H
#define MURMUR_SYNC_H

#include <stddef.h>
#include <stdint.h>

#include "msgcodec.h"

typedef struct sqlite3 sqlite3;

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
  MURMUR_SYNC_OK = 0,
  MURMUR_SYNC_INVALID = 1,
  MURMUR_SYNC_PROTOCOL = 2,
  MURMUR_SYNC_OVERLOADED = 3,
  MURMUR_SYNC_AUTH = 4,
  MURMUR_SYNC_SQLITE = 5,
} murmur_sync_status_t;

const char *murmur_sync_status_str(murmur_sync_status_t st);

/* Installs the murmur_* metadata tables (SchemaDDL verbatim). */
murmur_sync_status_t murmur_sync_ensure_schema(sqlite3 *db, int *sqlrc);

/* Stored cursor: cursor borrows owned (free with _free). */
typedef struct {
  murmur_cursor_t cursor;
  uint8_t *owned;
} murmur_stored_cursor_t;

void murmur_sync_cursor_free(murmur_stored_cursor_t *c);

/* Export result: CRSB blob plus resume cursor (free with _free). */
typedef struct {
  uint8_t *blob;
  size_t blob_len;
  murmur_stored_cursor_t next;
} murmur_export_t;

void murmur_sync_export_free(murmur_export_t *e);

/* Reads clock rows after cursor (up to batch_bytes estimated,
 * max_batch_bytes encoded, 1024 cells) into a CRSB blob with a
 * resume cursor. */
murmur_sync_status_t murmur_sync_export(sqlite3 *db,
                                        const murmur_cursor_t *cursor,
                                        int64_t batch_bytes,
                                        int64_t max_batch_bytes,
                                        murmur_export_t *out, int *sqlrc);

/* Reassembles staged chunks for node, verifies length and digest,
 * drops opted-out tables, ingests, and advances progress plus the
 * applied/observed heads atomically. Stored progress must equal
 * previous. */
murmur_sync_status_t murmur_sync_apply(
    sqlite3 *db, const murmur_node_t *node, const murmur_node_t *site,
    const murmur_cursor_t *previous, const murmur_cursor_t *next,
    uint64_t length, const uint8_t digest[32], int *sqlrc);

/* Clears staged chunks for a peer plus expired rows. */
murmur_sync_status_t murmur_sync_stage_begin(sqlite3 *db,
                                             const murmur_node_t *node,
                                             int64_t timeout_ms, int *sqlrc);

/* Appends one chunk for a peer under the staging budget. */
murmur_sync_status_t murmur_sync_stage(sqlite3 *db, const murmur_node_t *node,
                                       uint32_t idx, const uint8_t *data,
                                       size_t len, int64_t budget, int *sqlrc);

/* Loads the stored (site, cursor) for an origin. A missing row
 * yields has_site 0 and the default cursor. */
murmur_sync_status_t murmur_sync_progress(sqlite3 *db,
                                          const murmur_node_t *node,
                                          murmur_node_t *site, int *has_site,
                                          murmur_stored_cursor_t *cur,
                                          int *sqlrc);

/* Restores the default cursor for an origin with a new site. */
murmur_sync_status_t murmur_sync_reset(sqlite3 *db, const murmur_node_t *node,
                                       const murmur_node_t *site, int *sqlrc);

/* Max-merges an observed version for an origin. */
murmur_sync_status_t murmur_sync_observed_max(sqlite3 *db,
                                              const murmur_node_t *origin,
                                              uint64_t seq, int *sqlrc);

/* Local cr-sqlite site id and db version. */
murmur_sync_status_t murmur_sync_site_id(sqlite3 *db, murmur_node_t *site,
                                         int *sqlrc);
murmur_sync_status_t murmur_sync_db_version(sqlite3 *db, int64_t *ver,
                                            int *sqlrc);

/* Merges one CRSB batch through cr-sqlite. The caller owns the
 * transaction. */
murmur_sync_status_t murmur_sync_ingest_blob(sqlite3 *db,
                                             const uint8_t *blob, size_t len,
                                             int *sqlrc);

#ifdef __cplusplus
}
#endif

#endif /* MURMUR_SYNC_H */
