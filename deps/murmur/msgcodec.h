/* murmur msgcodec - sync wire codec (postcard layout).
 *
 * Native port of the protocol.go codec: change-stream Key/Cursor,
 * the 14 Message variants, length-prefixed frames, CRSB change
 * cells, kv u64 heads, and the progress/observed key formats.
 * Integers are unsigned LEB128 varints (Go binary.Uvarint semantics,
 * including overflow rejection); signed values zigzag first; byte
 * strings carry a varint length; options are a 0x00/0x01 byte;
 * enums are varint variant indices; structs go in declaration
 * order. testdata/{key*,cursor*,msg_*,crsb_cells,u64_*,*_key.txt}
 * are the goldens.
 *
 * Ownership: encodes read caller structs; decodes borrow variable
 * fields (table names, keys, blobs, manifests, text) from the input
 * buffer, which must outlive use. Fixed fields (nodes, digests,
 * cursors, addresses) are copied into the output struct.
 *
 * Encode returns bytes written, or 0 when out is short or the value
 * is invalid (no valid encoding is empty, so 0 is unambiguous).
 * Decode returns a murmur_mship_status_t: PROTOCOL for malformed
 * input (truncation, trailing bytes, unknown tags, bad options,
 * invalid UTF-8, range overflow), OVERLOADED when a caller array is
 * short for the decoded count.
 */
#ifndef MURMUR_MSGCODEC_H
#define MURMUR_MSGCODEC_H

#include <stddef.h>
#include <stdint.h>

#include "member.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MURMUR_FRAME_BYTES (128u << 10)
#define MURMUR_CHUNK_BYTES (64u << 10)

/* Strict UTF-8 validation, mirroring Go utf8.Valid. */
int murmur_utf8_valid(const uint8_t *s, size_t n);

/* Change-cell stream position. Table/cid/pk borrow the input on decode. */
typedef struct {
  int64_t version;
  int64_t seq;
  const uint8_t *table;
  size_t table_len;
  const uint8_t *pk;
  size_t pk_len;
  const uint8_t *cid;
  size_t cid_len;
} murmur_key_t;

typedef struct {
  int64_t from;
  int has_through;
  int64_t through;
  int has_after;
  murmur_key_t after;
} murmur_cursor_t;

typedef enum {
  MURMUR_MSG_HELLO = 0,
  MURMUR_MSG_PULL = 1,
  MURMUR_MSG_RESET = 2,
  MURMUR_MSG_IDLE = 3,
  MURMUR_MSG_BATCH = 4,
  MURMUR_MSG_CHUNK = 5,
  MURMUR_MSG_SNAPSHOT_REQUEST = 6,
  MURMUR_MSG_SNAPSHOT_MANIFEST = 7,
  MURMUR_MSG_SCHEMA_REQUEST = 8,
  MURMUR_MSG_SCHEMA_MANIFEST = 9,
  MURMUR_MSG_SCHEMA_ACK = 10,
  MURMUR_MSG_END = 11,
  MURMUR_MSG_ACK = 12,
  MURMUR_MSG_ERROR = 13,
} murmur_msg_tag_t;

typedef struct {
  murmur_msg_tag_t tag;
  murmur_node_t group;   /* hello, pull, snapshot-request */
  murmur_node_t node;    /* hello, pull, snapshot-request */
  murmur_node_t site;    /* hello, pull, reset, batch, snapshot-request */
  uint8_t schema[32];    /* hello, pull, snapshot-request */
  uint64_t incarnation;  /* hello */
  murmur_addr_t addr;    /* hello */
  int has_expected;      /* pull */
  murmur_node_t expected; /* pull */
  murmur_cursor_t cursor; /* pull, batch */
  uint64_t bytes;        /* batch */
  uint8_t digest[32];    /* batch, schema-ack, ack */
  uint32_t index;        /* chunk */
  const uint8_t *data;   /* chunk data, manifests, error text (borrowed) */
  size_t data_len;
  uint64_t sequence; /* schema-ack */
} murmur_msg_t;

/* Decoded CRSB change cell. Table/cid/pk/blob/site borrow the input. */
typedef struct {
  const uint8_t *table;
  size_t table_len;
  const uint8_t *pk;
  size_t pk_len;
  const uint8_t *cid;
  size_t cid_len;
  uint8_t val_tag; /* 0 null, 1 int, 2 real, 3 text, 4 blob */
  int64_t val_int;
  double val_real;
  const uint8_t *val_blob;
  size_t val_blob_len;
  int64_t col_version;
  int64_t db_version;
  const uint8_t *site;
  size_t site_len;
  int64_t cl;
  int64_t seq;
} murmur_cell_t;

size_t murmur_key_encode(const murmur_key_t *k, uint8_t *out, size_t cap);
murmur_mship_status_t murmur_key_decode(const uint8_t *buf, size_t len,
                                        murmur_key_t *out);

size_t murmur_cursor_encode(const murmur_cursor_t *c, uint8_t *out,
                            size_t cap);
murmur_mship_status_t murmur_cursor_decode(const uint8_t *buf, size_t len,
                                           murmur_cursor_t *out);

size_t murmur_msg_encode(const murmur_msg_t *m, uint8_t *out, size_t cap);
murmur_mship_status_t murmur_msg_decode(const uint8_t *buf, size_t len,
                                        murmur_msg_t *out);

/* Length-prefixed frame: 4-byte big-endian length plus payload.
 * Payloads past 128 KiB (or short out) encode to 0; empty and
 * oversized lengths decode to PROTOCOL. */
size_t murmur_frame_encode(const murmur_msg_t *m, uint8_t *out, size_t cap);
murmur_mship_status_t murmur_frame_decode(const uint8_t *buf, size_t len,
                                          murmur_msg_t *out);

size_t murmur_cells_encode(const murmur_cell_t *cells, size_t n,
                           uint8_t *out, size_t cap);
/* Encodes one cell record (Export's per-row budget accounting). */
size_t murmur_cell_encode(const murmur_cell_t *c, uint8_t *out,
                          size_t cap);
murmur_mship_status_t murmur_cells_decode(const uint8_t *buf, size_t len,
                                          murmur_cell_t *out, size_t cap,
                                          size_t *n);

size_t murmur_u64_encode(uint64_t v, uint8_t *out, size_t cap);
murmur_mship_status_t murmur_u64_decode(const uint8_t *buf, size_t len,
                                        uint64_t *v);

/* Formats the head keys ("07/replication/applied/<hex>" and
 * "07/replication/observed/<hex>") into out[0,cap). Returns bytes
 * written (no NUL), or 0 when cap is short. */
size_t murmur_progress_key(const murmur_node_t *origin, char *out,
                           size_t cap);
size_t murmur_observed_key(const murmur_node_t *origin, char *out,
                           size_t cap);

/* Ordered (table, DDL) schema pair. Fields borrow the input on decode. */
typedef struct {
  const uint8_t *table;
  size_t table_len;
  const uint8_t *ddl;
  size_t ddl_len;
} murmur_schema_pair_t;

/* Postcard Vec<(String, String)> layout: varint count, then
 * varint-prefixed table and DDL bytes each. Decode failures report
 * INVALID (mirroring Go errInvalid, not errProtocol); a short array
 * reports OVERLOADED. */
size_t murmur_schema_pairs_encode(const murmur_schema_pair_t *pairs,
                                 size_t n, uint8_t *out, size_t cap);
murmur_mship_status_t murmur_schema_pairs_decode(
    const uint8_t *buf, size_t len, murmur_schema_pair_t *out, size_t cap,
    size_t *n);

#ifdef __cplusplus
}
#endif

#endif /* MURMUR_MSGCODEC_H */
