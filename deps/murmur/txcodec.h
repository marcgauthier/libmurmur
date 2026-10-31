/* murmur txcodec - native tx-protocol codecs: head counters,
 * progress watermarks, kv key builders, signed schemas, zigzag
 * integers, and the CrrSnapshot image. Ports pkgs/tx/tx.go,
 * pkgs/tx/protocol.go, and Encode/DecodeCrrSnapshot from
 * pkgs/replication/backend.go. Codecs are hand-written postcard
 * (uvarint integers, raw arrays, uvarint-length vecs), matching the
 * golden-tested conventions; decode failures are PROTOCOL, trailing
 * bytes fail closed. sqlite3 fwd-declared for backend key helpers.
 */
#ifndef MURMUR_TXCODEC_H
#define MURMUR_TXCODEC_H

#include <stddef.h>
#include <stdint.h>

#include "member.h"
#include "sync.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Uvarint put/get primitives (postcard/LEB128). Encode returns bytes
 * or 0 when cap is short; decode advances *pos, 0 on ok. */
size_t murmur_tx_uvarint_encode(uint64_t v, uint8_t *out, size_t cap);
int murmur_tx_uvarint_decode(const uint8_t *b, size_t n, size_t *pos,
                             uint64_t *v);

/* Head counters (malloc'd encode; strict trailing check). */
uint8_t *murmur_tx_encode_u64(uint64_t v, size_t *len);
murmur_sync_status_t murmur_tx_decode_u64(const uint8_t *b, size_t n,
                                          uint64_t *v, int *sqlrc);

typedef struct {
  murmur_node_t origin;
  uint64_t applied;
  uint64_t observed;
  uint64_t retained_from;
  uint64_t retained_through;
} murmur_tx_progress_t;

uint8_t *murmur_tx_progress_encode(const murmur_tx_progress_t *p, size_t *len);
murmur_sync_status_t murmur_tx_progress_decode(const uint8_t *b, size_t n,
                                               murmur_tx_progress_t *p,
                                               int *sqlrc);

/* Key builders (malloc'd, explicit length, no NUL). */
uint8_t *murmur_tx_progress_key(const murmur_node_t *origin, size_t *len);
uint8_t *murmur_tx_observed_key(const murmur_node_t *origin, size_t *len);
uint8_t *murmur_tx_retained_key(const murmur_node_t *origin, size_t *len);
uint8_t *murmur_tx_floor_key(const murmur_node_t *origin, size_t *len);
uint8_t *murmur_tx_schema_manifest_key(size_t *len);
uint8_t *murmur_tx_schema_accepted_key(const murmur_node_t *signer,
                                       size_t *len);
uint8_t *murmur_tx_chunk_prefix(const murmur_node_t *origin, uint64_t seq,
                                size_t *len);

/* Zigzag i64 (replication protocol.go). */
uint64_t murmur_tx_zig_encode(int64_t v);
int64_t murmur_tx_zig_decode(uint64_t v);

typedef struct {
  murmur_node_t database;
  murmur_node_t signer;
  uint64_t sequence;
  uint8_t *schema;
  size_t schema_len;
  uint8_t *signature;
  size_t signature_len;
} murmur_signed_schema_t;

void murmur_signed_schema_free(murmur_signed_schema_t *s);
uint8_t *murmur_signed_schema_encode(const murmur_signed_schema_t *s,
                                     size_t *len);
murmur_sync_status_t murmur_signed_schema_decode(const uint8_t *b, size_t n,
                                                 murmur_signed_schema_t *s,
                                                 int *sqlrc);
/* Domain-separated signature preimage (malloc'd). */
uint8_t *murmur_signed_schema_bytes(const murmur_signed_schema_t *s,
                                    size_t *len);

typedef struct {
  uint8_t schema[32];
  int64_t version;
  uint8_t **segments;
  size_t *segment_lens;
  size_t n_segments;
} murmur_crr_snapshot_t;

void murmur_crr_snapshot_free(murmur_crr_snapshot_t *s);
uint8_t *murmur_crr_snapshot_encode(const murmur_crr_snapshot_t *s,
                                    size_t *len);
/* Segment count past 1<<20 fails PROTOCOL. */
murmur_sync_status_t murmur_crr_snapshot_decode(const uint8_t *b, size_t n,
                                                murmur_crr_snapshot_t *s,
                                                int *sqlrc);

/* ---- Transfer codecs (tx/snapshot.go, tx/retention.go) ---- */

#define MURMUR_TX_CHUNK_BYTES (64u << 10)
#define MURMUR_TX_BUILD_GRACE_MILLIS 3600000u
#define MURMUR_TX_BUILD_STALE_MILLIS 300000u
#define MURMUR_TX_BUILD_FRESH_MARGIN_MILLIS \
  (MURMUR_TX_BUILD_GRACE_MILLIS - MURMUR_TX_BUILD_STALE_MILLIS)

typedef struct {
  murmur_node_t origin;
  uint64_t seq;
} murmur_tx_ack_t;

/* Sorted boundary maps; decode caps at 4096 entries. */
uint8_t *murmur_tx_boundary_encode(const murmur_tx_ack_t *acks, size_t n,
                                   size_t *len);
murmur_sync_status_t murmur_tx_boundary_decode(const uint8_t *b, size_t n,
                                               size_t *pos,
                                               murmur_tx_ack_t **acks,
                                               size_t *count, int *sqlrc);
void murmur_tx_acks_free(murmur_tx_ack_t *acks, size_t n);

/* Progress vectors; decode caps at 4096 entries. */
uint8_t *murmur_tx_progress_vec_encode(const murmur_tx_progress_t *ps, size_t n,
                                       size_t *len);
murmur_sync_status_t murmur_tx_progress_vec_decode(const uint8_t *b, size_t n,
                                                   size_t *pos,
                                                   murmur_tx_progress_t **ps,
                                                   size_t *count, int *sqlrc);

typedef struct {
  murmur_node_t node;
  uint64_t last_seen_millis;
  int retired;
  murmur_tx_ack_t *acks;
  size_t n_acks;
} murmur_tx_peer_t;

void murmur_tx_peer_free(murmur_tx_peer_t *p);
uint8_t *murmur_tx_peer_encode(const murmur_tx_peer_t *p, size_t *len);
murmur_sync_status_t murmur_tx_peer_decode(const uint8_t *b, size_t n,
                                           murmur_tx_peer_t *p, int *sqlrc);

uint8_t *murmur_tx_peer_key(const murmur_node_t *node, size_t *len);
uint8_t *murmur_tx_excluded_key(const murmur_node_t *node, size_t *len);

typedef struct {
  murmur_node_t database;
  murmur_node_t donor;
  murmur_node_t recipient;
  murmur_node_t transfer;
  uint64_t expires;
  uint64_t bytes;
  uint8_t digest[32];
  uint8_t schema[32];
  murmur_tx_progress_t *progress;
  size_t n_progress;
  uint8_t (*chunks)[32];
  size_t n_chunks;
  uint8_t *signature;
  size_t signature_len;
} murmur_tx_manifest_t;

void murmur_tx_manifest_free(murmur_tx_manifest_t *m);
uint8_t *murmur_tx_manifest_encode(const murmur_tx_manifest_t *m, size_t *len);
/* Chunk list past 1<<24 fails PROTOCOL. */
murmur_sync_status_t murmur_tx_manifest_decode(const uint8_t *b, size_t n,
                                               murmur_tx_manifest_t *m,
                                               int *sqlrc);

typedef struct {
  murmur_tx_manifest_t manifest;
  uint64_t deadline;
} murmur_tx_incoming_t;

void murmur_tx_incoming_free(murmur_tx_incoming_t *r);
uint8_t *murmur_tx_incoming_encode(const murmur_tx_incoming_t *r, size_t *len);
murmur_sync_status_t murmur_tx_incoming_decode(const uint8_t *b, size_t n,
                                               murmur_tx_incoming_t *r,
                                               int *sqlrc);

typedef struct {
  murmur_node_t recipient;
  murmur_tx_ack_t *boundary;
  size_t n_boundary;
  murmur_tx_ack_t *target; /* valid only when has_target */
  size_t n_target;
  int has_target;
  uint64_t expires;
  uint8_t digest[32];
} murmur_tx_pin_t;

void murmur_tx_pin_free(murmur_tx_pin_t *p);
uint8_t *murmur_tx_pin_encode(const murmur_tx_pin_t *p, size_t *len);
murmur_sync_status_t murmur_tx_pin_decode(const uint8_t *b, size_t n,
                                          murmur_tx_pin_t *p, int *sqlrc);

/* Transfer key builders (prefix selects IN/OUT staging). */
uint8_t *murmur_tx_header_key(const char *prefix, const murmur_node_t *transfer,
                              size_t *len);
uint8_t *murmur_tx_chunk_key(const char *prefix, const murmur_node_t *transfer,
                             uint32_t index, size_t *len);
uint8_t *murmur_tx_pin_key(const murmur_node_t *transfer, size_t *len);
uint8_t *murmur_tx_receipt_key(const murmur_node_t *transfer, size_t *len);
uint8_t *murmur_tx_install_key(const murmur_node_t *transfer, size_t *len);

#ifdef __cplusplus
}
#endif

#endif /* MURMUR_TXCODEC_H */
