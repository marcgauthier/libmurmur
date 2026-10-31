/* murmur filecodec - file frame, metadata, availability, and key
 * rotation codecs over postcard, plus the 12-byte file frame
 * transport ("FF" + u16be version 1 + 4 reserved zero bytes +
 * u32be length, 128 KiB cap). Byte-exact with
 * replication/filefetch.go and replication/files.go.
 *
 * Decode borrows the input (data/name/remote slices point into
 * it); the availability remote list is the exception (owned,
 * freed with _free).
 */
#ifndef MURMUR_FILECODEC_H
#define MURMUR_FILECODEC_H

#include <stddef.h>
#include <stdint.h>

#include "engine.h"
#include "postcard.h"
#include "sync.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MURMUR_FILE_FRAME_BYTES (128u << 10)
#define MURMUR_FILE_CHUNK (64u << 10)

typedef enum {
  MURMUR_FILE_REQUEST = 0,
  MURMUR_FILE_HEADER = 1,
  MURMUR_FILE_CHUNK_FRAME = 2,
  MURMUR_FILE_DONE = 3,
  MURMUR_FILE_MISSING = 4,
} murmur_file_frame_kind_t;

typedef struct {
  murmur_file_frame_kind_t kind;
  murmur_node_t database;
  uint8_t digest[32];
  uint64_t generation;
  uint64_t offset;
  uint64_t bytes;
  uint8_t identity[32];
  const uint8_t *data;
  size_t data_len;
} murmur_file_frame_t;

void murmur_file_frame_encode(murmur_pc_enc_t *e,
                              const murmur_file_frame_t *f);
murmur_pc_status_t murmur_file_frame_decode(const uint8_t *b, size_t n,
                                            murmur_file_frame_t *f);

typedef struct {
  const uint8_t *name;
  size_t name_len;
  uint8_t digest[32];
  uint64_t bytes;
  uint64_t generation;
  uint64_t millis;
  murmur_node_t node;
  int deleted;
} murmur_file_meta_t;

void murmur_file_meta_encode(murmur_pc_enc_t *e, const murmur_file_meta_t *m);
murmur_pc_status_t murmur_file_meta_decode(const uint8_t *b, size_t n,
                                           murmur_file_meta_t *m);

typedef enum {
  MURMUR_FILE_LOCAL = 0,
  MURMUR_FILE_REMOTE = 1,
  MURMUR_FILE_UNAVAILABLE = 2,
} murmur_file_avail_kind_t;

typedef struct {
  murmur_file_avail_kind_t kind;
  murmur_node_t *remote; /* owned iff kind == REMOTE */
  size_t n_remote;
} murmur_file_avail_t;

void murmur_file_avail_free(murmur_file_avail_t *a);
void murmur_file_avail_encode(murmur_pc_enc_t *e,
                              const murmur_file_avail_t *a);
murmur_pc_status_t murmur_file_avail_decode(const uint8_t *b, size_t n,
                                            murmur_file_avail_t *a);

typedef struct {
  uint64_t current_generation;
  uint64_t old_generation_objects;
  uint64_t old_generation_metadata_missing_locally;
  uint64_t staged_transfers;
  int previous_key_unused_locally;
} murmur_file_keyrot_t;

void murmur_file_keyrot_encode(murmur_pc_enc_t *e,
                               const murmur_file_keyrot_t *s);
murmur_pc_status_t murmur_file_keyrot_decode(const uint8_t *b, size_t n,
                                             murmur_file_keyrot_t *s);

/* Frame IO over a byte stream. Write fails OVERLOADED past the
 * frame cap, else PROTOCOL on stream errors. Read fails PROTOCOL
 * ("file frame" for bad magic/version/length, the stream error
 * text otherwise) or INVALID on undecodable payloads.
 * owned_out is required (the frame borrows it; free after use). */
murmur_sync_status_t murmur_file_write_frame(murmur_stream_io_t *io,
                                             const murmur_file_frame_t *f,
                                             char **detail_out, int *sqlrc);
murmur_sync_status_t murmur_file_read_frame(murmur_stream_io_t *io,
                                            murmur_file_frame_t *f,
                                            uint8_t **owned_out,
                                            char **detail_out, int *sqlrc);

#ifdef __cplusplus
}
#endif

#endif /* MURMUR_FILECODEC_H */
