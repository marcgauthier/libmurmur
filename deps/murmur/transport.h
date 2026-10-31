/* Murmur native QUIC transport (picoquic + picotls + mbedTLS).
 *
 * Replaces the Go quic-go transport (pkgs/replication/transport_quic.go)
 * with identical wire behavior: mutual TLS 1.3, ALPN "murmur-crsqlite/1",
 * node identity from the leaf URI SAN "replicateddb://node/<hex>".
 *
 * Threading: one pump thread per endpoint owns the UDP socket and makes
 * every picoquic call. Client threads talk to it through commands and
 * blocking waits with timeouts; picoquic callbacks push inbound events
 * into per-session queues. No callbacks into Go, ever.
 *
 * Credentials are DER in memory (Go parses PEM via stdlib on the cold
 * path). Trust anchor install uses the mbedtls verifier assembler with
 * an f_vrfy hook that captures the leaf at depth 0 and correlates it to
 * the connection via picoquic_get_cnx_in_progress (proven by probe).
 *
 * Error model: 0 = OK, negative = -MURMUR_* (mirrors Go error kinds).
 */
#ifndef MURMUR_QUIC_TRANSPORT_H
#define MURMUR_QUIC_TRANSPORT_H

#include <stddef.h>
#include <stdint.h>

#include "member.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MURMUR_QUIC_ALPN "murmur-crsqlite/1"
#define MURMUR_QUIC_SAN_PREFIX "replicateddb://node/"

/* Node ids reuse member.h's murmur_node_t so engine code can include
 * both headers. Status enumerators carry the QUIC prefix for the
 * same reason (member.h owns MURMUR_OK). Values mirror
 * pkgs/replication/errors.go. */
typedef enum {
    MURMUR_QUIC_OK = 0,
    MURMUR_QUIC_INVALID = 1,
    MURMUR_QUIC_BUSY = 2,
    MURMUR_QUIC_CLOSED = 3,
    MURMUR_QUIC_PROTOCOL = 4,
    MURMUR_QUIC_OVERLOADED = 5,
    MURMUR_QUIC_AUTH = 6,
    MURMUR_QUIC_TIMEOUT = 7,
    MURMUR_QUIC_CANCELLED = 8
} murmur_status_t;

typedef struct murmur_quic murmur_quic_t;       /* endpoint */
typedef struct murmur_session murmur_session_t; /* one connection */
typedef struct murmur_stream murmur_stream_t;   /* one bidi stream */

/* --- endpoint --- */
/* chain_der/ca_der: DER certs (leaf first for chain). key_pem: PEM bytes
 * ("PRIVATE KEY" PKCS8 for EC/RSA, or "RSA PRIVATE KEY"); EC keys must
 * be PKCS8, never SEC1. Go converts on the cold path. */
int murmur_quic_create(murmur_quic_t** out, const char* bind_ip,
    uint16_t bind_port, const uint8_t** chain_der, const size_t* chain_lens,
    size_t chain_n, const uint8_t* key_pem, size_t key_len,
    const uint8_t** ca_der, const size_t* ca_lens, size_t ca_n,
    const murmur_node_t* self, const murmur_node_t* allowed, size_t n_allowed,
    const char** allow_cidrs, size_t n_cidrs, uint32_t max_conns,
    uint32_t sessions);
/* create with an explicit ALPN (the file service uses
 * MURMUR_FETCH_ALPN); create() defaults to MURMUR_QUIC_ALPN. */
int murmur_quic_create_alpn(murmur_quic_t** out, const char* bind_ip,
    uint16_t bind_port, const uint8_t** chain_der, const size_t* chain_lens,
    size_t chain_n, const uint8_t* key_pem, size_t key_len,
    const uint8_t** ca_der, const size_t* ca_lens, size_t ca_n,
    const murmur_node_t* self, const murmur_node_t* allowed, size_t n_allowed,
    const char** allow_cidrs, size_t n_cidrs, uint32_t max_conns,
    uint32_t sessions, const char* alpn);
int murmur_quic_local_addr(
    murmur_quic_t* q, char* buf, size_t buflen); /* "ip:port" */
int murmur_quic_accept(
    murmur_quic_t* q, murmur_session_t** out, int timeout_ms);
int murmur_quic_dial(murmur_quic_t* q, const char* ip, uint16_t port,
    const char* sni, murmur_session_t** out, int timeout_ms);
int murmur_quic_close(murmur_quic_t* q); /* stop listen + all sessions */
void murmur_quic_free(murmur_quic_t* q);
int murmur_last_error(murmur_quic_t* q, char* buf, size_t buflen);

/* --- session --- */
int murmur_session_peer(murmur_session_t* s, murmur_node_t* out);
int murmur_session_open_stream(murmur_session_t* s, murmur_stream_t** out);
int murmur_session_accept_stream(
    murmur_session_t* s, murmur_stream_t** out, int timeout_ms);
int murmur_session_send_datagram(
    murmur_session_t* s, const uint8_t* data, size_t len);
int murmur_session_recv_datagram(murmur_session_t* s, uint8_t* buf, size_t cap,
    size_t* out_len, int timeout_ms);
int murmur_session_close(murmur_session_t* s); /* ordered close, code 0 */
int murmur_session_close_code(
    murmur_session_t* s, uint64_t code); /* ordered close, given code */
void murmur_session_release(murmur_session_t* s); /* drop handle ref */
/* Peer's "ip:port" (pump-thread read, race-free). 0, or negative. */
int murmur_session_remote_addr(
    murmur_session_t* s, char* buf, size_t buflen);
/* Waits for the close event; 0 closed, -TIMEOUT on expiry. */
int murmur_session_wait_closed(murmur_session_t* s, int timeout_ms);

/* --- stream --- */
int murmur_stream_write(murmur_stream_t* s, const uint8_t* data, size_t len);
int murmur_stream_read(
    murmur_stream_t* s, uint8_t* buf, size_t cap, size_t* out_len);
/* Bounded read; -TIMEOUT on expiry (partial bytes kept queued). */
int murmur_stream_read_timeout(murmur_stream_t* s, uint8_t* buf, size_t cap,
    size_t* out_len, int timeout_ms);
int murmur_stream_close(murmur_stream_t* s); /* FIN */
void murmur_stream_release(murmur_stream_t* s);

#ifdef __cplusplus
}
#endif

#endif /* MURMUR_QUIC_TRANSPORT_H */
