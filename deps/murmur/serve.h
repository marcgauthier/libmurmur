/* murmur serve - native stream handlers: handshake, pull, serve,
 * snapshot fetch/serve, vetting, and schema push/adopt over
 * abstract streams. Ports the session half of
 * pkgs/replication/serve.go, snapshot.go, and schema_serve.go
 * against murmur_engine_t state. Bytes on the wire match Go
 * exactly (frame codec in msgcodec); handler order, gauge and
 * semaphore accounting, counters, and MsgError/record texts match
 * Go message for message.
 *
 * Conventions: detail_out (nullable) receives the owned Msg half
 * of Go's "Kind: Msg" on failure (NULL when the failure carries
 * no composed text); SQLITE failures report sqlite3_errmsg.
 * Frame IO failures are PROTOCOL with Go's fixed texts (write
 * failures wrap io->error_text, defaulting to "stream error").
 * Message-decode failures are INVALID/PROTOCOL with a fixed
 * "invalid message" detail: Go's per-construct decode texts are
 * not reproduced, only the status and the reject behavior.
 * SQLITE detail texts come from sqlite3_errmsg and may differ
 * from Go's driver wrapping; codes match.
 */
#ifndef MURMUR_SERVE_H
#define MURMUR_SERVE_H

#include <stddef.h>
#include <stdint.h>

#include "engine.h"
#include "msgcodec.h"
#include "sync.h"
#include "txcodec.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Empty CRSB framing length (sync.go emptyCRSBLen) and the chunk
 * split (protocol.go ChunkBytes). */
#define MURMUR_EMPTY_CRSB_LEN 12
#define MURMUR_CHUNK_BYTES (64u << 10)

/* One read frame: msg borrows owned (free with _free). */
typedef struct {
  murmur_msg_t msg;
  uint8_t *owned;
} murmur_serve_msg_t;

void murmur_serve_msg_free(murmur_serve_msg_t *m);

/* Frame IO. write_msg fails OVERLOADED ("frame too large") past
 * the frame cap, else PROTOCOL on stream errors. read_msg fails
 * PROTOCOL ("truncated frame header" / "invalid frame length" /
 * "truncated frame") or the decode status. */
murmur_sync_status_t murmur_serve_write_msg(murmur_stream_io_t *io,
                                            const murmur_msg_t *m,
                                            char **detail_out, int *sqlrc);
murmur_sync_status_t murmur_serve_read_msg(murmur_stream_io_t *io,
                                           murmur_serve_msg_t *out,
                                           char **detail_out, int *sqlrc);

/* Handshake: exchange hellos (caller opens the stream). outgoing
 * writes first; incoming reads first, validates, then replies.
 * Returns the peer incarnation and address. */
murmur_sync_status_t murmur_serve_handshake(
    murmur_engine_t *e, const murmur_node_t *peer, murmur_stream_io_t *io,
    int outgoing, uint64_t *incarnation_out, murmur_addr_t *addr_out,
    char **detail_out, int *sqlrc);

/* PullOnce: pull from the peer over an open stream (caller opens
 * it, post-handshake). more=1 means another round may have data.
 * Does not record or reply on failure (caller surfaces it). */
murmur_sync_status_t murmur_serve_pull_once(murmur_engine_t *e,
                                            const murmur_node_t *peer,
                                            murmur_stream_io_t *io, int *more,
                                            char **detail_out, int *sqlrc);

/* ServePull: serve one pull request (req is the already-read Pull
 * message). Updates sent progress and the sent counter. */
murmur_sync_status_t murmur_serve_pull(murmur_engine_t *e,
                                       const murmur_node_t *peer,
                                       murmur_stream_io_t *io,
                                       const murmur_msg_t *req,
                                       char **detail_out, int *sqlrc);

/* ServeStream: serve one inbound stream by its first message,
 * replying Error on failure like the session loop. Counts
 * serve_ok/serve_reject/serve_error for pulls. */
murmur_sync_status_t murmur_serve_stream(murmur_engine_t *e,
                                         const murmur_node_t *peer,
                                         murmur_stream_io_t *io,
                                         char **detail_out, int *sqlrc);

/* Snapshot worker entry points. fetch runs CALLER-side over one
 * stream opened on sess (which must stay usable for the call) and
 * returns the installed transfer id; serve runs DONOR-side;
 * request queues fetch on a detached worker and returns
 * immediately (the worker re-resolves the session from the engine,
 * so a disconnect lands in the snapshot status instead of a UAF).
 * fetch fails OVERLOADED ("snapshot peer is not connected" /
 * "snapshot install did not complete") where Go fails Closed. */
murmur_sync_status_t murmur_serve_fetch_snapshot(
    murmur_engine_t *e, const murmur_node_t *peer, murmur_session_if_t *sess,
    murmur_node_t *transfer_out, char **detail_out, int *sqlrc);
murmur_sync_status_t murmur_serve_snapshot(murmur_engine_t *e,
                                                 const murmur_node_t *peer,
                                                 murmur_stream_io_t *io,
                                                 const murmur_msg_t *req,
                                                 char **detail_out, int *sqlrc);
murmur_sync_status_t murmur_serve_request_snapshot(murmur_engine_t *e,
                                                   const murmur_node_t *peer,
                                                   int *sqlrc);

/* Schema vetting and propagation. vet_fetch runs one vet round
 * trip: verdict is set only when ok=1 (transport failures yield
 * ok=0 for a re-vet on the next pull). push_schema is
 * best-effort and silent like Go. */
void murmur_serve_vet_fetch(murmur_engine_t *e, const murmur_node_t *peer,
                            murmur_session_if_t *sess, int *verdict, int *ok);
murmur_sync_status_t murmur_serve_schema_request(murmur_engine_t *e,
                                                 murmur_stream_io_t *io,
                                                 char **detail_out, int *sqlrc);
murmur_sync_status_t murmur_serve_ingest_manifest(
    murmur_engine_t *e, const murmur_node_t *peer, const uint8_t *payload,
    size_t payload_len, uint8_t digest_out[32], uint64_t *sequence_out,
    char **detail_out, int *sqlrc);
murmur_sync_status_t murmur_serve_receive_schema_push(murmur_engine_t *e,
                                                      const murmur_node_t *peer,
                                                      murmur_stream_io_t *io,
                                                      const uint8_t *payload,
                                                      size_t payload_len,
                                                      char **detail_out,
                                                      int *sqlrc);
murmur_sync_status_t murmur_serve_adopt_from_peer(
    murmur_engine_t *e, const murmur_node_t *peer, murmur_session_if_t *sess,
    char **detail_out, int *sqlrc);
void murmur_serve_push_schema(murmur_engine_t *e, const murmur_node_t *peer,
                              murmur_session_if_t *sess);

/* Records peer contact and max-merges progress. Best-effort like
 * Go: failures are ignored. */
void murmur_serve_touch_peer(murmur_engine_t *e, const murmur_node_t *peer,
                             const murmur_tx_progress_t *ps, size_t n_ps);

#ifdef __cplusplus
}
#endif

#endif /* MURMUR_SERVE_H */
