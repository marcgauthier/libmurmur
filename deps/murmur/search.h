/* Native search manager: node-local disposable FTS5 and vec0
 * indexes over source tables. Port of search.go/search_types.go.
 *
 * Definitions are explicit (Options.SearchIndexes). Schema-derived
 * definitions (SchemaSearchDefinitions over StoredSchema FTS/vector
 * column flags) have no substrate in this port: StoredSchema/model
 * codec was never ported, so SyncSearchSchema reconciles the explicit
 * set only.
 *
 * Change feed: Go decodes SQLite changesets (EnqueueSearch) plus local
 * row states (SearchRows). Native local and replicated writes land on
 * the same SQLite connection, so one sqlite3_update_hook observes both
 * and records (table, rowid) hits directly; there is no changeset
 * queue. WITHOUT ROWID sources never fire the hook, so any
 * connection-wide write activity tripwires their indexes into a
 * rebuild instead of tracking keys.
 *
 * Threading: the manager owns a mutex; the update hook only touches
 * manager memory (never SQLite). Guard readiness has its own lock. */
#ifndef MURMUR_SEARCH_H
#define MURMUR_SEARCH_H

#include <stddef.h>
#include <stdint.h>

#include "sqlite3.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
  MURMUR_SEARCH_OK = 0,
  MURMUR_SEARCH_INVALID = 1,
  MURMUR_SEARCH_SQLITE = 2,
  MURMUR_SEARCH_NOMEM = 3,
  MURMUR_SEARCH_MISMATCH = 4
} murmur_search_status_t;

const char *murmur_search_status_str(murmur_search_status_t st);

typedef enum {
  MURMUR_SEARCH_FTS5 = 0,
  MURMUR_SEARCH_VECTOR = 1
} murmur_search_tag_t;

typedef enum {
  MURMUR_DIST_L2 = 0,
  MURMUR_DIST_COSINE = 1,
  MURMUR_DIST_L1 = 2
} murmur_distance_t;

/* One index declaration. Borrowed strings; the manager copies. */
typedef struct {
  murmur_search_tag_t tag;
  /* FTS5: */
  const char *name;
  const char *source_table;
  const char **columns;
  size_t n_columns;
  const char *tokenizer; /* NULL = unicode61 */
  /* Vector: */
  const char *vector_column;
  int dimensions;
  murmur_distance_t distance;
} murmur_search_def_t;

typedef struct murmur_search_manager murmur_search_manager_t;

/* Builds a manager from explicit definitions. queue_bytes in
 * (0,128<<20], batch_rows in (0,65536]. */
murmur_search_status_t murmur_search_open(const murmur_search_def_t *defs,
                                          size_t n_defs, size_t queue_bytes,
                                          size_t batch_rows,
                                          murmur_search_manager_t **out,
                                          char **detail_out);
void murmur_search_close(murmur_search_manager_t *m);

/* Deep copy (CloneSearchManager). Shares no state except nothing:
 * the guard map is copied too. */
murmur_search_manager_t *murmur_search_clone(const murmur_search_manager_t *m);

/* Registers search prerequisites on a connection: temp_store=MEMORY
 * when definitions exist, plus the vec0 module. Idempotent. */
murmur_search_status_t murmur_search_register(sqlite3 *db,
                                              const murmur_search_manager_t *m,
                                              char **detail_out, int *sqlrc);

/* Reconciles installed temp tables with the explicit set and the
 * live schema. allow_missing skips sources that do not exist yet
 * (unless already installed). */
murmur_search_status_t murmur_search_sync_schema(murmur_search_manager_t *m,
                                                 sqlite3 *db, int allow_missing,
                                                 char **detail_out, int *sqlrc);
murmur_search_status_t murmur_search_drop(murmur_search_manager_t *m,
                                          sqlite3 *db, char **detail_out,
                                          int *sqlrc);

/* True when any index is rebuilding or holds pending keys. */
int murmur_search_pending(murmur_search_manager_t *m);

/* One bounded maintenance turn. published_out gains the names ready
 * this turn (owned array of owned strings). */
murmur_search_status_t murmur_search_tick(murmur_search_manager_t *m,
                                          sqlite3 *db, char ***published_out,
                                          size_t *n_published,
                                          char **detail_out, int *sqlrc);
/* Drains all pending work; returns sorted published names. */
murmur_search_status_t murmur_search_refresh(murmur_search_manager_t *m,
                                             sqlite3 *db, char ***published_out,
                                             size_t *n_published,
                                             char **detail_out, int *sqlrc);
void murmur_search_published_free(char **names, size_t n);

typedef struct {
  char *name;
  int ready;
  int rebuilding;
  size_t pending_keys;
  size_t queued_bytes;
  char *error; /* nullable owned */
} murmur_search_index_status_t;

murmur_search_status_t murmur_search_status(murmur_search_manager_t *m,
                                            murmur_search_index_status_t **out,
                                            size_t *n_out);
void murmur_search_status_free(murmur_search_index_status_t *st, size_t n);

/* Drains publication names (sorted). */
murmur_search_status_t murmur_search_take_publications(
    murmur_search_manager_t *m, char ***out, size_t *n_out);

/* Guard: owned temp-table name (case-insensitive) -> readiness. */
int murmur_search_guard_ready(murmur_search_manager_t *m, const char *name,
                              int *ready_out);

/* Installs/removes the update-hook feed on db. Only one manager per
 * connection; attach replaces any previous hook. The attached
 * connection is borrowed for the WITHOUT ROWID pending tripwire;
 * clones start detached. */
void murmur_search_attach(murmur_search_manager_t *m, sqlite3 *db);
void murmur_search_detach(murmur_search_manager_t *m, sqlite3 *db);

/* Notes out-of-band table churn (DDL-adjacent events callers detect);
 * invalidates installed indexes on table at next maintenance. */
void murmur_search_note_table(murmur_search_manager_t *m, const char *table);

#ifdef __cplusplus
}
#endif

#endif
