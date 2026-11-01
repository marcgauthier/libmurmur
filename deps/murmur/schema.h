/* murmur schema - native schema management: CRR discovery,
 * canonical bytes and digest, DDL validation, additive diffs and
 * compatibility, adoption parameters, and additive application.
 *
 * Port of SchemaPairs/SchemaBytes/ManifestSchemaBytes/Schema,
 * IsCRR/MakeCRR, SchemaParamsFrom, and the schema_adopt.go pure
 * core (CheckCreateTable, CheckAddColumn, SchemaDiff,
 * PullerCompatible, ApplySchemaAdditive). SQL text and error kinds
 * match Go. The DDL lexers replicate Go rune semantics byte for
 * byte, including low-byte quote comparison and replacement-char
 * re-encoding of invalid UTF-8; only case mapping of unquoted
 * non-ASCII text is ASCII-only (DDL keywords are ASCII, and names
 * are ASCII-validated before any comparison).
 *
 * Manifest sequencing and vetting (BuildSchemaManifest,
 * CheckSchemaManifest, RecordSchemaAccepted) need the tx backend
 * and land with store-attached replication (N7).
 */
#ifndef MURMUR_SCHEMA_H
#define MURMUR_SCHEMA_H

#include <stddef.h>
#include <stdint.h>

#include "sync.h"

typedef struct sqlite3 sqlite3;

#ifdef __cplusplus
extern "C" {
#endif

/* Owned (table, DDL) pair. Named entry because msgcodec owns
 * murmur_schema_pair_t (borrowed views for the wire form). */
typedef struct {
  char *table;
  char *ddl;
} murmur_schema_entry_t;

void murmur_schema_pairs_free(murmur_schema_entry_t *pairs, size_t n);

/* CRR tables ordered by name; murmur_* CRRs and the empty set fail. */
murmur_sync_status_t murmur_schema_pairs(sqlite3 *db,
                                         murmur_schema_entry_t **pairs,
                                         size_t *n, int *sqlrc);

/* Canonical pair bytes (malloc'd) and their SHA-256 digest. */
murmur_sync_status_t murmur_schema_bytes(sqlite3 *db, uint8_t **blob,
                                         size_t *len, int *sqlrc);
murmur_sync_status_t murmur_schema_digest(sqlite3 *db, uint8_t digest[32],
                                          int *sqlrc);

/* Canonical bytes minus opted-out tables (empty set allowed). */
murmur_sync_status_t murmur_manifest_schema_bytes(sqlite3 *db, uint8_t **blob,
                                                 size_t *len, int *sqlrc);

/* Clock-table presence; enabling replication on a table. */
murmur_sync_status_t murmur_schema_is_crr(sqlite3 *db, const uint8_t *table,
                                          size_t table_len, int *is_crr,
                                          int *sqlrc);
murmur_sync_status_t murmur_schema_make_crr(sqlite3 *db, const uint8_t *table,
                                            size_t table_len, int *sqlrc);

/* Additive delta: new tables and columns as owned (table, DDL)
 * pairs; incompatible carries the reason (owned, NULL when
 * additive). */
typedef struct {
  char *table;
  char *def;
} murmur_schema_delta_ent_t;

typedef struct {
  int additive;
  murmur_schema_delta_ent_t *new_tables;
  size_t n_tables;
  murmur_schema_delta_ent_t *add_columns;
  size_t n_columns;
  char *incompatible;
} murmur_schema_diff_t;

void murmur_schema_diff_free(murmur_schema_diff_t *d);

/* Diffs canonical pair bytes. Like Go, incompatibility is data:
 * OK with additive=0 and incompatible set ("unparseable local/remote
 * DDL: T", "table constraint change: T", "column redefined:
 * T.col"); only undecodable bytes fail INVALID. Local-extra tables
 * and columns are kept, not conflicts, so divergent additive
 * branches merge through mutual adoption. */
murmur_sync_status_t murmur_schema_diff(const uint8_t *local, size_t local_len,
                                        const uint8_t *remote,
                                        size_t remote_len,
                                        murmur_schema_diff_t *out, int *sqlrc);

/* Donor-side check: every local table exists on the puller with the
 * same column set (order-insensitive) and equal constraints. */
murmur_sync_status_t murmur_puller_compatible(const uint8_t *local,
                                              size_t local_len,
                                              const uint8_t *puller,
                                              size_t puller_len,
                                              int *compatible, int *sqlrc);

/* Validates remote DDL before execution. */
murmur_sync_status_t murmur_check_create_table(const uint8_t *table,
                                               size_t table_len,
                                               const uint8_t *ddl,
                                               size_t ddl_len, int *sqlrc);
murmur_sync_status_t murmur_check_add_column(const uint8_t *coldef,
                                             size_t coldef_len, char **name,
                                             int *sqlrc);

/* Applies an additive delta: creates adopted tables (CRR-ified) and
 * appends adopted columns, validating every statement. Re-applying
 * converged state is a no-op; divergence fails closed. */
murmur_sync_status_t murmur_apply_additive(
    sqlite3 *db, const murmur_schema_delta_ent_t *tables, size_t n_tables,
    const murmur_schema_delta_ent_t *columns, size_t n_columns, int *sqlrc);

typedef struct {
  int accept_remote;
  int has_master;
  murmur_node_t master;
  int master_enabled;
  int64_t max_schema_bytes;
} murmur_schema_params_t;

murmur_sync_status_t murmur_schema_params_from(sqlite3 *db,
                                              murmur_schema_params_t *out,
                                              int *sqlrc);

#ifdef __cplusplus
}
#endif

#endif /* MURMUR_SCHEMA_H */
