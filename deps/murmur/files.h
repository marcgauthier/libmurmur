/* murmur files - native FileObjects store (replication/files.go).
 *
 * Immutable authenticated file objects: bounded encrypted upload,
 * SPFO0001 containers (AES-256-GCM, per-object HKDF-SHA256 key,
 * per-chunk nonces), metadata in the kv backend, generation-keyed
 * rotation, garbage collection, and staging protection. The fetch
 * service (N8c) consumes Download/ProtectStaging/PublishFetched.
 *
 * Status taxonomy mirrors Go exactly: INVALID/AUTH/IO/UNAVAILABLE/
 * OVERLOADED plus SQLITE (kv backend failure, sqlrc set). Every
 * fallible call takes a nullable detail_out receiving an owned
 * message (free with free()).
 */
#ifndef MURMUR_FILES_H
#define MURMUR_FILES_H

#include <stddef.h>
#include <stdint.h>

#include "engine.h"
#include "filecodec.h"
#include "member.h"
#include "sync.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
  MURMUR_FILES_OK = 0,
  MURMUR_FILES_INVALID = 1,
  MURMUR_FILES_AUTH = 2,
  MURMUR_FILES_IO = 3,
  MURMUR_FILES_UNAVAILABLE = 4,
  MURMUR_FILES_OVERLOADED = 5,
  MURMUR_FILES_SQLITE = 6,
  MURMUR_FILES_PROTOCOL = 7,
} murmur_files_status_t;

const char *murmur_files_status_str(murmur_files_status_t st);

/* Owned file metadata (filecodec's borrows; this owns the name). */
typedef struct {
  char *name;
  uint8_t digest[32];
  uint64_t bytes;
  uint64_t generation;
  uint64_t millis;
  murmur_node_t node;
  int deleted;
} murmur_files_meta_t;

void murmur_files_meta_free(murmur_files_meta_t *m);
void murmur_files_meta_list_free(murmur_files_meta_t *ms, size_t n);

typedef struct {
  const char *directory;
  uint8_t key[32];
  const uint8_t (*previous_key)[32]; /* nullable */
  uint64_t generation;
  uint64_t max_file_bytes;    /* default 4 GiB */
  uint64_t max_staging_bytes; /* default 1 GiB */
  uint64_t fetch_interval_ms; /* validated, unused until N8c */
  int concurrent_fetches;     /* validated, unused until N8c */
} murmur_files_config_t;

void murmur_files_config_default(murmur_files_config_t *c,
                                 const char *directory,
                                 const uint8_t key[32]);

typedef struct murmur_files_t murmur_files_t;
typedef struct murmur_file_upload_t murmur_file_upload_t;
typedef struct murmur_file_download_t murmur_file_download_t;
typedef struct murmur_staging_reservation_t murmur_staging_reservation_t;
typedef struct murmur_staged_transfer_t murmur_staged_transfer_t;

/* Opens the store: validates config, refuses old-generation
 * metadata without a previous key, creates the directory (0700),
 * reconciles staging. db is the borrowed kv backend; self is the
 * local node identity. sqlrc set on SQLITE. */
murmur_files_status_t murmur_files_open(const murmur_files_config_t *config,
                                        sqlite3 *db, const murmur_node_t *self,
                                        murmur_files_t **out, char **detail_out,
                                        int *sqlrc);
void murmur_files_close(murmur_files_t *o);

/* Borrowed SQL connection; file resources must be closed before this handle. */
sqlite3 *murmur_files_database(const murmur_files_t *);
/* Store directory (borrowed; for the fetch staging paths). */
const char *murmur_files_directory(const murmur_files_t *o);

/* Object path for a digest+generation (owned; free with free()). */
char *murmur_files_object_path(murmur_files_t *o, const uint8_t digest[32],
                               uint64_t generation);

/* Streaming sinks/sources. Return 0, or nonzero to abort (the
 * callback's error propagates). */
typedef int (*murmur_files_read_fn)(void *ctx, uint8_t *buf, size_t cap,
                                    size_t *n_out, int *eof_out);
typedef int (*murmur_files_write_fn)(void *ctx, const uint8_t *buf, size_t n);

/* UploadOne: stores one object from a reader. */
murmur_files_status_t murmur_files_upload_one(
    murmur_files_t *o, const char *name, murmur_files_read_fn read, void *ctx,
    murmur_files_meta_t *meta_out, char **detail_out, int *sqlrc);

/* Bounded multi-part upload. Finish publishes metadata. */
murmur_files_status_t murmur_files_begin_upload(murmur_files_t *o,
                                                const char *name,
                                                murmur_file_upload_t **out,
                                                char **detail_out, int *sqlrc);
murmur_files_status_t murmur_files_upload_append(murmur_file_upload_t *u,
                                                 const uint8_t *p, size_t n,
                                                 char **detail_out);
murmur_files_status_t murmur_files_finish_upload(
    murmur_files_t *o, murmur_file_upload_t *u, murmur_files_meta_t *meta_out,
    char **detail_out, int *sqlrc);
/* Finish with a synchronous callback in the SAME transaction as metadata.
 * The encrypted object is synced first. Callback failure rolls back metadata
 * and its SQL effects. The upload is consumed on success or failure.
 * Call outside writer admission and SQL transactions: file gate precedes
 * writer admission. Callback must not call file APIs or change transaction
 * state. A post-COMMIT durability error is an uncertain committed outcome. */
typedef int (*murmur_files_commit_fn)(sqlite3 *,const murmur_files_meta_t *,void *);
murmur_files_status_t murmur_files_finish_upload_atomic(
    murmur_files_t *,murmur_file_upload_t *,murmur_files_commit_fn,void *,
    murmur_files_meta_t *,char **detail_out,int *sqlrc);
void murmur_files_upload_abort(murmur_file_upload_t *u);

/* Shared disk staging capacity. Release is idempotent. */
murmur_files_status_t murmur_files_reserve_staging(
    murmur_files_t *o, uint64_t n, murmur_staging_reservation_t **out);
void murmur_files_staging_release(murmur_staging_reservation_t *r);

/* Verify authenticates one container, streaming plaintext to
 * output (nullable). */
murmur_files_status_t murmur_files_verify(murmur_files_t *o, const char *path,
                                           const murmur_files_meta_t *meta,
                                           murmur_files_write_fn output,
                                           void *ctx, char **detail_out,
                                           int *sqlrc);

/* Download pins and authenticates one object; Next returns up to
 * limit plaintext bytes (limit in [1, 1 MiB]). Close is idempotent. */
murmur_files_status_t murmur_files_download(murmur_files_t *o,
                                             const char *name,
                                             murmur_file_download_t **out,
                                             char **detail_out, int *sqlrc);
murmur_files_status_t murmur_files_download_next(
    murmur_file_download_t *d, size_t limit, uint64_t *start_out,
    uint8_t *out_buf, size_t *n_out, int *done_out, char **detail_out);
/* Borrowed pinned metadata, valid until download_close. */
const murmur_files_meta_t *murmur_files_download_metadata(const murmur_file_download_t *);
uint64_t murmur_files_download_bytes(const murmur_file_download_t *d);
void murmur_files_download_close(murmur_file_download_t *d);

/* Metadata reads one file's metadata (*found false when absent). */
murmur_files_status_t murmur_files_metadata(murmur_files_t *o,
                                             const char *name,
                                             murmur_files_meta_t *meta_out,
                                             int *found, char **detail_out,
                                             int *sqlrc);
murmur_files_status_t murmur_files_list(murmur_files_t *o,
                                        murmur_files_meta_t **out, size_t *n,
                                        char **detail_out, int *sqlrc);
murmur_files_status_t murmur_files_list_bounded(murmur_files_t *o,
                                                size_t max_bytes,
                                                murmur_files_meta_t **out,
                                                size_t *n, char **detail_out,
                                                int *sqlrc);
murmur_files_status_t murmur_files_available(murmur_files_t *o,
                                             const char *name, int *avail,
                                             char **detail_out, int *sqlrc);
murmur_files_status_t murmur_files_availability(murmur_files_t *o,
                                                const char *name,
                                                murmur_file_avail_t *avail_out,
                                                char **detail_out, int *sqlrc);
murmur_files_status_t murmur_files_delete(murmur_files_t *o, const char *name,
                                           char **detail_out, int *sqlrc);
murmur_files_status_t murmur_files_read(murmur_files_t *o, const char *name,
                                        murmur_files_write_fn output, void *ctx,
                                        murmur_files_meta_t *meta_out,
                                        char **detail_out, int *sqlrc);

/* StreamPlainChunks verifies and streams plaintext in bounded
 * chunks, omitting a resumed prefix. A non-OK emit status aborts
 * the stream and propagates to the caller (detail_out optional). */
typedef murmur_files_status_t (*murmur_files_emit_fn)(
    void *ctx, uint64_t offset, const uint8_t *buf, size_t n,
    char **detail_out);
murmur_files_status_t murmur_files_stream_plain_chunks(
    murmur_files_t *o, const char *name, uint64_t skip, size_t chunk_size,
    murmur_files_emit_fn emit, void *ctx, murmur_files_meta_t *meta_out,
    uint64_t *total_out, char **detail_out, int *sqlrc);

/* PublishFetched publishes only a fully authenticated staged
 * container. */
murmur_files_status_t murmur_files_publish_fetched(
    murmur_files_t *o, const char *staged, const murmur_files_meta_t *meta,
    char **detail_out, int *sqlrc);

/* RotateKeys re-encrypts up to limit old-generation objects. */
murmur_files_status_t murmur_files_rotate_keys(murmur_files_t *o, size_t limit,
                                                size_t *rotated,
                                                char **detail_out, int *sqlrc);
murmur_files_status_t murmur_files_key_rotation_status(
    murmur_files_t *o, murmur_file_keyrot_t *out, char **detail_out,
    int *sqlrc);

/* Collect removes unreferenced objects and abandoned staging
 * after grace_ms. */
murmur_files_status_t murmur_files_collect(murmur_files_t *o,
                                            uint64_t grace_ms, size_t *removed,
                                            char **detail_out, int *sqlrc);

/* Staging protection pins a path plus its identity sidecar until
 * released (idempotent). */
murmur_staged_transfer_t *murmur_files_protect_staging(murmur_files_t *o,
                                                       const char *path);
void murmur_files_staged_release(murmur_staged_transfer_t *s);

/* Fetch error latch (set by the N8c fetcher). */
void murmur_files_fetch_error(murmur_files_t *o, const char *msg);
char *murmur_files_last_fetch_error(murmur_files_t *o); /* owned, nullable */

/* Sweep unprotected staging residue (runs on the N8c fetch tick). */
murmur_files_status_t murmur_files_reap_staging_orphans(murmur_files_t *o,
                                                         char **detail_out);

/* Exposed for the fetcher (N8c): record a peer's availability. */
murmur_files_status_t murmur_files_record_peer(
    murmur_files_t *o, const uint8_t digest[32], uint64_t generation,
    const murmur_node_t *node, int available, char **detail_out, int *sqlrc);

#ifdef __cplusplus
}
#endif

#endif /* MURMUR_FILES_H */
