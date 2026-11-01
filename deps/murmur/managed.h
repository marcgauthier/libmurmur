/* Managed transaction foundation. This API is opt-in; it does not upgrade
 * the legacy replication protocol. Close only after all callers join. */
#ifndef MURMUR_MANAGED_H
#define MURMUR_MANAGED_H
#include "scheduler.h"
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
typedef struct murmur_managed murmur_managed_t;
typedef struct murmur_transaction murmur_transaction_t;
typedef enum { MURMUR_NULL, MURMUR_INTEGER, MURMUR_REAL,
               MURMUR_TEXT, MURMUR_BLOB } murmur_value_type_t;
typedef struct {
  murmur_value_type_t type;
  int64_t integer;
  double real;
  const void *data;
  size_t bytes;
} murmur_value_t;
/* Row values are borrowed until the callback returns. Nonzero aborts SQL. */
typedef int (*murmur_row_fn)(void *, int, const murmur_value_t *);
typedef int (*murmur_transaction_fn)(murmur_transaction_t *, void *);
/* Uses sqlite-murmur VFS and initializes cr-sqlite; key is never SQL text.
 * Handles for the same canonical path share admission. No raw writer handle
 * is exposed. Callbacks and row data must not escape their documented scope. */
int murmur_managed_open(const char *path, const uint8_t key[32], murmur_managed_t **);
void murmur_managed_close(murmur_managed_t *);
int murmur_managed_transaction(murmur_managed_t *, murmur_writer_class_t,
    int64_t timeout_ms, murmur_cancel_fn, void *cancel_ctx,
    murmur_transaction_fn, void *);
/* Exactly one statement; explicit transaction control, DDL, and reserved
 * metadata access are denied. Statements finalize before this call returns. */
int murmur_transaction_execute(murmur_transaction_t *, const char *sql,
    const murmur_value_t *, size_t, murmur_row_fn, void *);
typedef enum {
  MURMUR_POLICY_LWW, MURMUR_POLICY_COUNTER, MURMUR_POLICY_SET,
  MURMUR_POLICY_MIN, MURMUR_POLICY_MAX, MURMUR_POLICY_JSON, MURMUR_POLICY_LIST
} murmur_merge_policy_t;
typedef enum {
  MURMUR_OP_COUNTER_ADD, MURMUR_OP_SET_ADD, MURMUR_OP_SET_REMOVE,
  MURMUR_OP_MIN, MURMUR_OP_MAX, MURMUR_OP_JSON_SET,
  MURMUR_OP_JSON_REMOVE, MURMUR_OP_LIST_APPEND, MURMUR_OP_LIST_REMOVE
} murmur_policy_op_t;
typedef struct {
  murmur_policy_op_t kind;
  int64_t delta; /* counter only */
  murmur_value_t value;
  const char *path; /* nonempty flat JSON key, JSON operations only */
} murmur_policy_operation_t;
/* Non-LWW policy columns require explicit primary keys and cannot themselves
 * be primary keys. Once established, changing their policy is rejected.
 * Set baselines are NULL or postcard Vec<Value> BLOBs; JSON/list baselines
 * are NULL or flat scalar object/array TEXT. Counters require INTEGER.
 * Initial INSERT values establish the baseline. Direct UPDATEs of policy
 * columns and primary keys of policy tables are denied. */
int murmur_managed_set_policy(murmur_managed_t *,const char *table,
                              const char *column,murmur_merge_policy_t);
int murmur_transaction_policy(murmur_transaction_t *,const char *table,
    const murmur_value_t *key,size_t key_len,const char *column,
    const murmur_policy_operation_t *);
/* SQL equivalents: murmur_counter_add, murmur_set_add/remove, murmur_min/max,
 * murmur_json_set/remove, murmur_list_append/remove. Arguments are table,
 * key, column, operand (JSON set takes path,value; JSON remove takes path).
 * Keys accept scalar JSON arrays, or canonical key BLOBs from
 * murmur_policy_key(pk1,...). BLOB primary keys use the latter form.
 * These functions run only inside a managed transaction and return 1.
 * Enable signed replication separately with set_replication; operations on
 * enabled tables then capture their causal state with the signed commit. */
/* Rows: table, column, policy enum. */
int murmur_managed_policy_status(murmur_managed_t *,murmur_row_fn,void *);
/* DDL-only atomic migration; generation advances only on success.
 * Use explicit mappings to retain identities across renames.
 * In the signed profile, the schema authority also publishes a signed
 * artifact atomically. Replicated migrations allow additive changes and
 * explicit renames; dropping/redefining existing columns is rejected. */
int murmur_managed_migrate(murmur_managed_t *, const char *sql);
typedef struct {
  const char *table; /* pre-migration name */
  const char *new_table; /* NULL keeps table name */
  const char *column; /* NULL maps table only */
  const char *new_column;
} murmur_rename_t;
int murmur_managed_migrate_mapped(murmur_managed_t *, const char *sql,
                                 const murmur_rename_t *, size_t);
/* Persist and validate declarations, then rebuild disposable temp indexes.
 * dimensions=0 disables vectors (otherwise 1..8192); distance is 0=L2,
 * 1=cosine, 2=L1. A 256-row maintenance turn runs every 100ms when admitted.
 * FTS requires TEXT, vectors BLOB; sources need one INTEGER PRIMARY KEY. */
int murmur_managed_set_search(murmur_managed_t *, const char *table,
                              const char *column, int fts, int dimensions,
                              int distance);
/* Rows: table name, table ID, column name, column ID, fts, dimensions,
 * distance, schema generation. IDs are immutable 16-byte blobs. */
int murmur_managed_schema(murmur_managed_t *, murmur_row_fn, void *);
/* Explicitly drain pending work. Build errors leave declarations intact. */
int murmur_managed_refresh_indexes(murmur_managed_t *);
/* Rows: temp index name, ready, rebuilding, pending keys, queued bytes,
 * nullable error. Index names derive from stable IDs and survive renames.
 * Queries of unpublished/stale indexes fail authorization; source queries
 * remain available to repair invalid data. */
int murmur_managed_search_status(murmur_managed_t *, murmur_row_fn, void *);
void murmur_managed_scheduler_stats(murmur_managed_t *, murmur_scheduler_stats_t *);
#ifdef __cplusplus
}
#endif
#endif
