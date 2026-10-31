/* murmur membership - bounded SWIM state, gossip, and probing.
 *
 * Native port of clients/go/pkgs/replication/membership.go below the
 * packet codec (the codec itself lives in framing.c, proven against
 * testdata/vec_pkt_*.bin). Packet STRUCTS are defined here so the codec
 * and the state machine share one layout; encode/decode function
 * signatures are declared in framing.h.
 *
 * Seams (function pointers, no transport/DB linkage):
 *  - randomness: murmur_word_fn (crypto words; tests inject fakes),
 *  - clock: callers pass now_ms (no time calls inside),
 *  - IO: murmur_send_fn carries packet structs to the integrator, which
 *    encodes (framing.c) and datagrams them (transport). The integrator's
 *    send MUST drop packets encoding to more than 1000 bytes, mirroring
 *    the Go sendPacket/broadcast guards.
 *  - persist/notify/close callbacks for incarnation, seed, conn events.
 *
 * Error codes mirror Go errKind strings: "Auth", "Protocol",
 * "Overloaded", "Invalid".
 */
#ifndef MURMUR_MEMBER_H
#define MURMUR_MEMBER_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MURMUR_MAX_VIEW_MEMBERS 4096
#define MURMUR_MAX_DATAGRAM_BYTES 1000
#define MURMUR_SEED_STRLEN 72
#define MURMUR_MAX_ENVELOPE_MEMBERS 4
#define MURMUR_GOSSIP_FANOUT_DEFAULT 3

typedef enum {
  MURMUR_OK = 0,
  MURMUR_MSHIP_AUTH = 1,
  MURMUR_MSHIP_PROTOCOL = 2,
  MURMUR_MSHIP_OVERLOADED = 3,
  MURMUR_MSHIP_INVALID = 4,
} murmur_mship_status_t;

const char *murmur_mship_status_str(murmur_mship_status_t st);

typedef enum {
  MURMUR_ALIVE = 0,
  MURMUR_SUSPECT = 1,
  MURMUR_DEAD = 2,
  MURMUR_LEFT = 3,
} murmur_state_t;

typedef struct {
  uint8_t b[16];
} murmur_node_t;

int murmur_node_eq(const murmur_node_t *a, const murmur_node_t *b);

/* Socket address. IPv4 uses ip[0..4], IPv6 all 16 bytes. */
typedef struct {
  uint8_t ip[16];
  uint16_t port;
  uint8_t is6;
} murmur_addr_t;

/* Parses "1.2.3.4:5678" / "[::1]:5678". Formats back canonically. */
int murmur_addr_parse(murmur_addr_t *out, const char *s);
void murmur_addr_format(const murmur_addr_t *a, char *out, size_t cap);

typedef struct {
  murmur_node_t node;
  murmur_addr_t addr;
  uint64_t incarnation;
  murmur_state_t state;
} murmur_member_t;

typedef enum {
  MURMUR_PKT_GOSSIP = 0,
  MURMUR_PKT_INDIRECT_ACK = 1,
  MURMUR_PKT_PING = 2,
  MURMUR_PKT_ACK = 3,
  MURMUR_PKT_PINGREQ = 4,
} murmur_pkt_tag_t;

/* Decoded packet. members points to caller-owned storage. */
typedef struct {
  murmur_pkt_tag_t tag;
  murmur_node_t database;
  murmur_node_t sender;
  murmur_node_t target; /* indirect-ack / ping-request only */
  uint64_t nonce;       /* ping / ack / indirect-ack / ping-request */
  murmur_member_t *members;
  size_t n_members; /* gossip / ping / ack only */
} murmur_pkt_t;

/* Crypto word source. Returns 0 on success. */
typedef int (*murmur_word_fn)(void *ctx, uint64_t *word);

/* Uniform [0, upper). Mirrors Go belowWith incl. rejection sampling. */
int murmur_below(murmur_word_fn wf, void *wctx, uint64_t upper,
                 uint64_t *out);
/* Reservoir-sample up to amount of n indices into out_idx. */
int murmur_sample_idx(murmur_word_fn wf, void *wctx, size_t n, size_t amount,
                      size_t *out_idx, size_t *out_n);

/* Production word source (getentropy//dev/urandom). */
int murmur_word_crypto(void *ctx, uint64_t *word);

typedef struct murmur_view murmur_view_t;

murmur_view_t *murmur_view_new(const murmur_member_t *local);
void murmur_view_free(murmur_view_t *v);

/* Membership merge. Newer incarnations win; ties go to higher rank. */
void murmur_view_merge(murmur_view_t *v, const murmur_member_t *m);
/* Local member plus up to 3 random members. Returns count. */
size_t murmur_view_gossip(murmur_view_t *v, murmur_member_t *out, size_t cap,
                          murmur_word_fn wf, void *wctx);
void murmur_view_ack(murmur_view_t *v, const murmur_node_t *node,
                     uint64_t nonce);

typedef struct {
  murmur_node_t target;
  uint64_t nonce;
} murmur_probe_req_t;

/* Expire probe timers at now_ms. Returns indirect-repair count. */
size_t murmur_view_expire(murmur_view_t *v, uint64_t now_ms,
                          murmur_probe_req_t *reqs, size_t cap);

/* Test/diagnostic accessors (linear scans; not for the hot path). */
size_t murmur_view_size(const murmur_view_t *v);
/* Copies up to cap members in table order; returns total count. */
size_t murmur_view_members(const murmur_view_t *v, murmur_member_t *out,
                           size_t cap);
size_t murmur_view_pending(const murmur_view_t *v);
const murmur_member_t *murmur_view_lookup(const murmur_view_t *v,
                                          const murmur_node_t *node);
const murmur_member_t *murmur_view_local(const murmur_view_t *v);
uint32_t murmur_view_awareness(const murmur_view_t *v);
/* Test hook: rewind one pending probe's timestamp. */
int murmur_view_rewind_pending(murmur_view_t *v, const murmur_node_t *node,
                               uint64_t at_ms);
/* Test hook: insert a pending probe. */
int murmur_view_add_pending(murmur_view_t *v, const murmur_node_t *node,
                            uint64_t at_ms, uint64_t nonce);

/* Packet send. The integrator encodes (framing.c), enforces the 1000B
 * cap, and datagrams to the peer session. */
typedef int (*murmur_send_fn)(void *ctx, const murmur_node_t *peer,
                              const murmur_pkt_t *pkt);
typedef int (*murmur_persist_fn)(void *ctx, uint64_t incarnation);
typedef void (*murmur_notify_fn)(void *ctx);
typedef void (*murmur_close_fn)(void *ctx, const murmur_node_t *peer);

typedef struct murmur_mship murmur_mship_t;

murmur_mship_t *murmur_mship_new(const murmur_node_t *group,
                                 const murmur_node_t *node,
                                 const murmur_member_t *local);
void murmur_mship_free(murmur_mship_t *m);

void murmur_mship_set_io(murmur_mship_t *m, murmur_send_fn send, void *send_ctx,
                         murmur_persist_fn persist, void *persist_ctx,
                         murmur_notify_fn notify, void *notify_ctx,
                         murmur_close_fn close_fn, void *close_ctx);
void murmur_mship_set_fanout(murmur_mship_t *m, int fanout);

/* Connection table (driven by the transport integrator). */
int murmur_mship_add_conn(murmur_mship_t *m, const murmur_node_t *peer);
int murmur_mship_has_conn(const murmur_mship_t *m, const murmur_node_t *peer);

/* gossip / probe ticks. now_ms is injected; wf supplies nonces. */
void murmur_mship_gossip(murmur_mship_t *m, murmur_word_fn wf, void *wctx);
void murmur_mship_probe(murmur_mship_t *m, uint64_t now_ms, murmur_word_fn wf,
                        void *wctx);
/* One datagram from the session peer (already decoded). */
murmur_mship_status_t murmur_mship_on_packet(murmur_mship_t *m,
                                             const murmur_node_t *peer,
                                             const murmur_pkt_t *pkt,
                                             uint64_t now_ms);

murmur_mship_status_t murmur_mship_add_seed(murmur_mship_t *m, const char *addr);
/* Raw insert for Start's bootstrap seeding (no validation, cap, or
 * notify, like Go's direct map assignment; over-long entries
 * truncate to the seed slot). */
void murmur_mship_add_seed_raw(murmur_mship_t *m, const char *addr);
/* Copies up to cap seed addresses (cap x MURMUR_SEED_STRLEN slots). */
size_t murmur_mship_seeds(const murmur_mship_t *m, char *out, size_t cap);
void murmur_mship_remove_node(murmur_mship_t *m, const murmur_node_t *node);
int murmur_mship_has_seed(const murmur_mship_t *m, const char *addr);

typedef struct {
  murmur_node_t node;
  murmur_addr_t addr;
} murmur_fetch_source_t;

/* Dial targets: uniform-port derivation over alive+suspect members. */
size_t murmur_mship_fetch_sources(murmur_mship_t *m, uint16_t port,
                                 murmur_fetch_source_t *out, size_t cap);

murmur_view_t *murmur_mship_view(murmur_mship_t *m);

#ifdef __cplusplus
}
#endif

#endif /* MURMUR_MEMBER_H */
