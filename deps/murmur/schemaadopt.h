/* murmur schemaadopt - native schema adoption: monotonic manifest
 * cursors, transport verification, per-signer accepted sequences,
 * and manifest vetting. Ports the manifest half of
 * pkgs/replication/schema_adopt.go (diffs, validation, and
 * application already live in schema.c). Identity arrives
 * explicitly; tx errors pass through the one status enum.
 */
#ifndef MURMUR_SCHEMAADOPT_H
#define MURMUR_SCHEMAADOPT_H

#include <stddef.h>
#include <stdint.h>

#include "member.h"
#include "schema.h"
#include "sync.h"
#include "txcodec.h"

typedef struct sqlite3 sqlite3;

#ifdef __cplusplus
extern "C" {
#endif

/* Vet verdicts, matching Go's SchemaDecision order. */
typedef enum {
  MURMUR_SCHEMA_CURRENT = 0,
  MURMUR_SCHEMA_ADOPT = 1,
  MURMUR_SCHEMA_STALE = 2,
  MURMUR_SCHEMA_RECORD = 3,
} murmur_schema_decision_t;

/* Monotonic manifest for schema bytes (owned; free the schema with
 * murmur_signed_schema_free). */
murmur_sync_status_t murmur_schema_build_manifest(
    sqlite3 *db, const murmur_schema_params_t *params,
    const murmur_node_t *own, const murmur_node_t *database,
    const uint8_t *schema, size_t schema_len, murmur_signed_schema_t *out,
    int *sqlrc);

/* Transport auth: database/signer identity plus size (AUTH). */
murmur_sync_status_t murmur_schema_verify_transport(
    const murmur_signed_schema_t *s, const murmur_node_t *database,
    const murmur_node_t *source, const murmur_schema_params_t *params,
    int *sqlrc);

/* Stores the highest accepted sequence per signer. */
murmur_sync_status_t murmur_schema_record_accepted(
    sqlite3 *db, const murmur_signed_schema_t *s, int *sqlrc);

/* Vets one manifest against filtered local bytes. *decision is
 * RECORD on every error return, matching Go. */
murmur_sync_status_t murmur_schema_check_manifest(
    sqlite3 *db, const murmur_schema_params_t *params,
    const murmur_node_t *own, const uint8_t *local_schema,
    size_t local_len, const murmur_signed_schema_t *s,
    const murmur_node_t *database, const murmur_node_t *source,
    murmur_schema_decision_t *decision, int *sqlrc);

#ifdef __cplusplus
}
#endif

#endif /* MURMUR_SCHEMAADOPT_H */
