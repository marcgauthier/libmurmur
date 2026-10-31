// Murmur native QUIC transport manager. See transport.h for the contract.
//
// Credential loading notes (mbedtls provider gaps, all verified in source):
//  - picoquic_set_tls_key is declared but has NO implementation: the
//    manager loads the private key from DER with murmur_load_key_der,
//    which replicates ptls_mbedtls_load_private_key (file) using its
//    non-static helpers. EC keys must be PKCS8 (the SEC1 helper is
//    static); Go converts via x509.MarshalPKCS8 on the cold path.
//  - The mbedtls provider never registers set_tls_root_certificates_fn,
//    so trust anchors are installed with the (non-static, undeclared)
//    ptls_mbedssl_init_verify_certificate_complete assembler plus an
//    f_vrfy hook. The hook captures the leaf at depth 0 and correlates
//    it with picoquic_get_cnx_in_progress (proven non-NULL by probe).
//  - Chain install uses picoquic_set_tls_certificate_chain (direct,
//    provider-independent).

#include "transport.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <deque>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "picotls.h"
#include "picoquic.h"
#include "picoquic_crypto_provider_api.h"
#include "picoquic_internal.h"
#include "ptls_mbedtls.h"
#include "tls_api.h"
#include "mbedtls/pem.h"
#include "mbedtls/pk.h"
#include "mbedtls/x509.h"
#include "mbedtls/x509_crt.h"
#include "psa/crypto.h"

// Non-static mbedtls-backend helpers without header declarations.
// Signatures copied from picoquic_mbedtls/ptls_mbedtls_sign.c; a vendor
// update that changes them fails loudly at link time.
extern "C" {
extern ptls_mbedtls_verify_certificate_t*
ptls_mbedssl_init_verify_certificate_complete(mbedtls_x509_crt* trust_ca,
    mbedtls_x509_crl* trust_crl,
    int (*f_vrfy)(void*, mbedtls_x509_crt*, int, uint32_t*), void* p_vrfy);
extern int ptls_mbedtls_get_der_key(mbedtls_pem_context* pem,
    mbedtls_pk_type_t* pk_type, const unsigned char* key, size_t keylen,
    const unsigned char* pwd, size_t pwdlen,
    int (*f_rng)(void*, unsigned char*, size_t), void* p_rng);
extern int ptls_mbedtls_set_available_schemes(
    ptls_mbedtls_sign_certificate_t* signer);
extern void ptls_mbedtls_set_rsa_key_attributes(
    ptls_mbedtls_sign_certificate_t* signer, const unsigned char* key_value,
    size_t key_length);
extern int ptls_mbedtls_set_ec_key_attributes(
    ptls_mbedtls_sign_certificate_t* signer, size_t key_length);
extern int ptls_mbedtls_parse_ec_private_key(const unsigned char* pem_buf,
    size_t pem_len, size_t* key_index, size_t* key_length);
extern int ptls_parse_private_key_field(const unsigned char* pem_buf,
    size_t pem_len, size_t* oid_index, size_t* oid_length, size_t* key_index,
    size_t* key_length);
} // extern "C"

namespace {

const uint64_t kKeepAliveUs = 10 * 1000000; // 10 s, like Go transport
const uint64_t kIdleTimeoutMs = 30000;      // 30 s, like Go transport
const size_t kMaxDatagram = 1000;           // Murmur membership cap
const uint64_t kMaxDataDefault = 16 << 20;  // conn flow-control window
const uint64_t kMaxStreamDataDefault = 4 << 20; // stream window (64 KiB chunks)

// Standard key OIDs (copies; upstream keeps them static).
const uint8_t kOidEcKey[] = { 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01 };
const uint8_t kOidRsaKey[] = { 0x2a, 0x86, 0x48, 0x86, 0xf7,
    0x0d, 0x01, 0x01, 0x01 };

bool node_is_zero(const murmur_node_t& n)
{
    for (size_t i = 0; i < sizeof(n.b); i++) {
        if (n.b[i] != 0)
            return false;
    }
    return true;
}

bool node_equal(const murmur_node_t& a, const murmur_node_t& b)
{
    return memcmp(a.b, b.b, sizeof(a.b)) == 0;
}

int hex_val(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

// Parse a URI SAN value into a node id. Mirrors Go nodeIDFromCert:
// -1 = not a Murmur URI (skip), 0 = Murmur prefix but malformed
// (reject), 1 = valid id in out.
int parse_node_san(const char* uri, size_t len, murmur_node_t* out)
{
    const char* prefix = MURMUR_QUIC_SAN_PREFIX;
    size_t plen = strlen(prefix);
    if (len < plen || memcmp(uri, prefix, plen) != 0)
        return -1;
    const char* p = uri + plen;
    size_t left = len - plen;
    uint8_t id[16];
    size_t nibbles = 0;
    for (size_t i = 0; i < left; i++) {
        if (p[i] == '-')
            continue;
        int v = hex_val(p[i]);
        if (v < 0 || nibbles >= 32)
            return 0;
        if ((nibbles & 1) == 0)
            id[nibbles / 2] = (uint8_t)(v << 4);
        else
            id[nibbles / 2] |= (uint8_t)v;
        nibbles++;
    }
    if (nibbles != 32)
        return 0;
    memcpy(out->b, id, sizeof(out->b));
    return node_is_zero(*out) ? 0 : 1;
}

// Extract the single Murmur node id from a leaf cert. Returns true with
// exactly one valid URI SAN, false otherwise (zero/duplicate/missing).
// Walk mirrors mbedtls x509_crt_check_san_uri (library/x509_crt.c).
bool leaf_node_id(mbedtls_x509_crt* leaf, murmur_node_t* out)
{
    // NOTE: no ext_types pre-check (that field is MBEDTLS_PRIVATE); an
    // absent extension leaves a zeroed sequence whose tag never matches.
    bool found = false;
    for (const mbedtls_x509_sequence* cur = &leaf->subject_alt_names;
        cur != NULL; cur = cur->next) {
        const unsigned char san_type =
            (unsigned char)cur->buf.tag & MBEDTLS_ASN1_TAG_VALUE_MASK;
        if (san_type != MBEDTLS_X509_SAN_UNIFORM_RESOURCE_IDENTIFIER)
            continue;
        murmur_node_t cand;
        int pr = parse_node_san(
            (const char*)cur->buf.p, cur->buf.len, &cand);
        if (pr < 0)
            continue; // non-Murmur URI: ignore, like Go
        if (pr == 0 || found)
            return false; // malformed, zero, or duplicate: reject
        *out = cand;
        found = true;
    }
    return found;
}

struct Endpoint;
struct Session;
struct Stream;

// One-shot result delivered from the pump thread to a waiting client.
template <typename T> struct Future {
    std::mutex mu;
    std::condition_variable cv;
    bool done = false;
    int status = -MURMUR_QUIC_CLOSED;
    T value{};
    void set(int st, T v = T{})
    {
        std::lock_guard<std::mutex> lk(mu);
        if (done)
            return;
        status = st;
        value = std::move(v);
        done = true;
        cv.notify_all();
    }
    // timeout_ms < 0 waits forever. Returns status or -MURMUR_QUIC_TIMEOUT.
    int wait(int timeout_ms, T* out)
    {
        std::unique_lock<std::mutex> lk(mu);
        if (!done) {
            if (timeout_ms < 0) {
                cv.wait(lk, [&] { return done; });
            } else if (!cv.wait_for(lk,
                           std::chrono::milliseconds(timeout_ms),
                           [&] { return done; })) {
                return -MURMUR_QUIC_TIMEOUT;
            }
        }
        if (out)
            *out = value;
        return status;
    }
};

struct Stream : std::enable_shared_from_this<Stream> {
    std::shared_ptr<Session> session;
    uint64_t id = 0;
    bool local = false; // created by murmur_session_open_stream
    std::mutex mu;
    std::condition_variable cv;
    std::deque<uint8_t> rx; // received bytes not yet read
    bool fin = false;       // peer FIN seen (after rx drains)
    bool reset = false;     // peer reset / conn dead
    bool closed = false;    // local close (FIN sent)
    bool enqueued = false;  // already in session accept queue
};

struct Session : std::enable_shared_from_this<Session> {
    Endpoint* ep = nullptr;
    picoquic_cnx_t* cnx = NULL;
    bool client = false;
    murmur_node_t peer{};
    bool peer_known = false; // leaf captured + gates passed
    std::mutex mu;
    std::condition_variable cv;
    bool closed = false; // close event or local close
    std::map<uint64_t, std::shared_ptr<Stream>> streams;
    std::deque<std::shared_ptr<Stream>> accept_q; // streams with data/FIN
    std::deque<std::vector<uint8_t>> dgrams;      // bounded below
};

struct PendingDial {
    std::shared_ptr<Future<std::shared_ptr<Session>>> future;
    uint64_t id = 0;
};

struct Endpoint {
    picoquic_quic_t* quic = NULL;
    int sock = -1;
    int wake_pipe[2] = { -1, -1 };
    std::thread pump;
    std::atomic<bool> stop{ false };
    std::mutex mu; // guards cmd_q, sessions, pending, accept_q, err
    std::condition_variable accept_cv;
    std::deque<std::function<void()>> cmd_q;
    std::map<picoquic_cnx_t*, std::shared_ptr<Session>> sessions;
    std::map<picoquic_cnx_t*, std::shared_ptr<PendingDial>> pending_dials;
    std::deque<std::shared_ptr<Session>> accept_q;
    bool closing = false; // set by the close command; wakes acceptors
    uint64_t next_dial_id = 1;
    murmur_node_t self{};
    std::vector<murmur_node_t> allowed; // empty = all
    struct Cidr {
        uint8_t addr[16] = {}; // v4-mapped or v6
        unsigned bits = 0;
    };
    std::vector<Cidr> cidrs; // empty = all
    std::string last_error;
    uint32_t max_streams = 0;
    std::string alpn; // negotiated protocol; default MURMUR_QUIC_ALPN
};

// Parse "1.2.3.4/24" or bare IP (host route). v4 collapses to v4-mapped,
// like Go (peerID order: network gate first, empty = open).
bool parse_cidr(const char* s, Endpoint::Cidr* out)
{
    std::string str(s);
    std::string ip = str;
    unsigned bits = 0;
    bool has_bits = false;
    size_t slash = str.find('/');
    if (slash != std::string::npos) {
        ip = str.substr(0, slash);
        bits = (unsigned)atoi(str.substr(slash + 1).c_str());
        has_bits = true;
    }
    struct in_addr v4;
    struct in6_addr v6;
    memset(out->addr, 0, sizeof(out->addr));
    if (inet_pton(AF_INET, ip.c_str(), &v4) == 1) {
        if (!has_bits)
            bits = 32;
        if (bits > 32)
            return false;
        out->addr[10] = 0xff;
        out->addr[11] = 0xff;
        memcpy(out->addr + 12, &v4, 4);
        out->bits = 96 + bits;
        return true;
    }
    if (inet_pton(AF_INET6, ip.c_str(), &v6) == 1) {
        if (!has_bits)
            bits = 128;
        if (bits > 128)
            return false;
        memcpy(out->addr, &v6, 16);
        out->bits = bits;
        return true;
    }
    return false;
}

void sockaddr_to_key(const struct sockaddr* sa, uint8_t key[16])
{
    memset(key, 0, 16);
    if (sa->sa_family == AF_INET) {
        const struct sockaddr_in* v4 = (const struct sockaddr_in*)sa;
        key[10] = 0xff;
        key[11] = 0xff;
        memcpy(key + 12, &v4->sin_addr, 4);
    } else if (sa->sa_family == AF_INET6) {
        const struct sockaddr_in6* v6 = (const struct sockaddr_in6*)sa;
        memcpy(key, &v6->sin6_addr, 16);
        // Collapse v4-mapped to the same form (already is); nothing to do.
    }
}

bool cidr_match(const Endpoint::Cidr& c, const uint8_t key[16])
{
    for (unsigned i = 0; i < c.bits; i++) {
        unsigned a = (c.addr[i / 8] >> (7 - (i % 8))) & 1;
        unsigned b = (key[i / 8] >> (7 - (i % 8))) & 1;
        if (a != b)
            return false;
    }
    return true;
}

void set_error_locked(Endpoint* ep, const std::string& msg)
{
    ep->last_error = msg;
}

void set_error(Endpoint* ep, const std::string& msg)
{
    std::lock_guard<std::mutex> lk(ep->mu);
    set_error_locked(ep, msg);
}

// Post-chain gates, Go peerID order: network, SAN identity (already
// extracted), node allowlist. Empty string = pass, else reason.
// Caller must hold ep->mu.
std::string gate_peer(Endpoint* ep, picoquic_cnx_t* cnx)
{
    struct sockaddr* peer = NULL;
    picoquic_get_peer_addr(cnx, &peer);
    if (peer != NULL && !ep->cidrs.empty()) {
        uint8_t key[16];
        sockaddr_to_key(peer, key);
        bool ok = false;
        for (const auto& c : ep->cidrs) {
            if (cidr_match(c, key)) {
                ok = true;
                break;
            }
        }
        if (!ok)
            return "remote network denied";
    }
    auto it = ep->sessions.find(cnx);
    if (it == ep->sessions.end() || !it->second->peer_known)
        return "missing peer certificate";
    if (!ep->allowed.empty()) {
        bool ok = false;
        for (const auto& a : ep->allowed) {
            if (node_equal(a, it->second->peer)) {
                ok = true;
                break;
            }
        }
        if (!ok)
            return "remote node denied";
    }
    return "";
}

// Pump-thread only. Ensure a Session exists for cnx (server side sees
// verify before any stream callback).
std::shared_ptr<Session> ensure_session(Endpoint* ep, picoquic_cnx_t* cnx)
{
    auto it = ep->sessions.find(cnx);
    if (it != ep->sessions.end())
        return it->second;
    auto s = std::make_shared<Session>();
    s->ep = ep;
    s->cnx = cnx;
    s->client = picoquic_is_client(cnx) != 0;
    ep->sessions[cnx] = s;
    return s;
}

// mbedtls verify hook: runs per chain cert, depth 0 = leaf, on the pump
// thread during handshake processing. Captures the peer node id and, on
// the client side only, enforces SAN + allowlist (handshake fails, like
// Go VerifyPeerCertificate). Server side captures only; gates run at
// ready and refuse with an ordered close, like Go's accept loop.
int murmur_f_vrfy(
    void* p, mbedtls_x509_crt* crt, int depth, uint32_t* flags)
{
    // No DNS/CN name check: node identity is the URI SAN, not a DNS
    // name. Mirrors Go (InsecureSkipVerify + VerifyOptions without
    // DNSName). Only this flag is ever cleared; all other chain
    // failures still fail the handshake.
    *flags &= (uint32_t)~MBEDTLS_X509_BADCERT_CN_MISMATCH;
    if (depth != 0)
        return 0;
    Endpoint* ep = (Endpoint*)p;
    picoquic_cnx_t* cnx = picoquic_get_cnx_in_progress(ep->quic);
    if (cnx == NULL)
        return MBEDTLS_ERR_X509_CERT_VERIFY_FAILED; // fail closed
    std::lock_guard<std::mutex> lk(ep->mu);
    std::shared_ptr<Session> s = ensure_session(ep, cnx);
    murmur_node_t id;
    if (!leaf_node_id(crt, &id)) {
        set_error_locked(ep, "peer leaf has no valid node URI SAN");
        if (s->client)
            return MBEDTLS_ERR_X509_CERT_VERIFY_FAILED;
        return 0; // server: refuse later at ready with close code 0
    }
    {
        std::lock_guard<std::mutex> slk(s->mu);
        s->peer = id;
        s->peer_known = true;
    }
    if (s->client && !ep->allowed.empty()) {
        bool ok = false;
        for (const auto& a : ep->allowed) {
            if (node_equal(a, id)) {
                ok = true;
                break;
            }
        }
        if (!ok) {
            set_error_locked(ep, "peer identity denied");
            return MBEDTLS_ERR_X509_CERT_VERIFY_FAILED;
        }
    }
    return 0;
}

// Load a private key from PEM bytes into the master TLS context.
// Replicates ptls_mbedtls_load_private_key with a memory buffer;
// EC keys must be PKCS8 (the SEC1 helper is static upstream).
int murmur_load_key_pem(
    ptls_context_t* master, const uint8_t* pem_bytes, size_t pem_len)
{
    mbedtls_pem_context pem;
    mbedtls_pk_type_t pk_type = MBEDTLS_PK_NONE;
    size_t key_length = 0;
    size_t key_index = 0;
    ptls_mbedtls_sign_certificate_t* signer =
        (ptls_mbedtls_sign_certificate_t*)malloc(
            sizeof(ptls_mbedtls_sign_certificate_t));
    if (signer == NULL)
        return PTLS_ERROR_NO_MEMORY;
    memset(signer, 0, sizeof(ptls_mbedtls_sign_certificate_t));
    signer->attributes = psa_key_attributes_init();

    // get_der_key reads one past the end for NUL: copy with terminator.
    std::vector<unsigned char> buf(pem_len + 1, 0);
    memcpy(buf.data(), pem_bytes, pem_len);
    int ret = ptls_mbedtls_get_der_key(
        &pem, &pk_type, buf.data(), pem_len, NULL, 0, NULL, NULL);
    // Wipe the copy immediately; upstream does the same for files.
    memset(buf.data(), 0, pem_len);

    if (ret == 0) {
        if (pk_type == MBEDTLS_PK_RSA) {
            key_length = pem.private_buflen;
            ptls_mbedtls_set_rsa_key_attributes(
                signer, pem.private_buf, key_length);
        } else if (pk_type == MBEDTLS_PK_ECKEY) {
            ret = PTLS_ERROR_NOT_AVAILABLE; // SEC1: Go must send PKCS8
        } else if (pk_type == MBEDTLS_PK_NONE) {
            size_t oid_index = 0;
            size_t oid_length = 0;
            psa_set_key_usage_flags(
                &signer->attributes, PSA_KEY_USAGE_SIGN_HASH);
            ret = ptls_parse_private_key_field(pem.private_buf,
                pem.private_buflen, &oid_index, &oid_length, &key_index,
                &key_length);
            if (ret == 0) {
                if (oid_length == sizeof(kOidEcKey) &&
                    memcmp(pem.private_buf + oid_index, kOidEcKey,
                        sizeof(kOidEcKey)) == 0) {
                    ret = ptls_mbedtls_parse_ec_private_key(pem.private_buf,
                        pem.private_buflen, &key_index, &key_length);
                    if (ret == 0) {
                        ret = ptls_mbedtls_set_ec_key_attributes(
                            signer, key_length);
                    }
                } else if (oid_length == sizeof(kOidRsaKey) &&
                    memcmp(pem.private_buf + oid_index, kOidRsaKey,
                        sizeof(kOidRsaKey)) == 0) {
                    ptls_mbedtls_set_rsa_key_attributes(signer,
                        pem.private_buf + key_index, key_length);
                } else {
                    ret = PTLS_ERROR_NOT_AVAILABLE;
                }
            }
        } else {
            ret = -1;
        }
        if (ret == 0) {
            psa_status_t status = psa_import_key(&signer->attributes,
                pem.private_buf + key_index, key_length, &signer->key_id);
            if (status != PSA_SUCCESS) {
                ret = -1;
            } else {
                ret = ptls_mbedtls_set_available_schemes(signer);
            }
        }
        mbedtls_pem_free(&pem);
    }
    if (ret == 0) {
        signer->super.cb = ptls_mbedtls_sign_certificate;
        master->sign_certificate = &signer->super;
    } else {
        ptls_mbedtls_dispose_sign_certificate(&signer->super);
    }
    return ret;
}

// Pump thread. Tear down a session: wake every waiter, fail a pending
// dial, drop the map ref. Idempotent.
void kill_session_locked(Endpoint* ep, std::shared_ptr<Session> s, int status)
{
    bool first = false;
    {
        std::lock_guard<std::mutex> slk(s->mu);
        if (!s->closed) {
            s->closed = true;
            first = true;
        }
    }
    if (!first)
        return;
    for (const auto& kv : s->streams) {
        std::lock_guard<std::mutex> tlk(kv.second->mu);
        kv.second->reset = true;
        kv.second->cv.notify_all();
    }
    s->cv.notify_all();
    auto pd = ep->pending_dials.find(s->cnx);
    if (pd != ep->pending_dials.end()) {
        pd->second->future->set(status, nullptr);
        ep->pending_dials.erase(pd);
    }
    ep->sessions.erase(s->cnx);
    ep->accept_cv.notify_all();
}

// The single picoquic callback for every connection. Pump thread only.
// Lock order: ep->mu -> session->mu -> stream->mu.
int murmur_quic_cb(picoquic_cnx_t* cnx, uint64_t stream_id, uint8_t* bytes,
    size_t length, picoquic_call_back_event_t ev, void* cb_ctx,
    void* stream_ctx)
{
    (void)stream_ctx;
    Endpoint* ep = (Endpoint*)cb_ctx;
    if (ev == picoquic_callback_close ||
        ev == picoquic_callback_application_close) {
        std::lock_guard<std::mutex> lk(ep->mu);
        auto it = ep->sessions.find(cnx);
        if (it != ep->sessions.end())
            kill_session_locked(ep, it->second, -MURMUR_QUIC_CLOSED);
        return 0;
    }
    if (ev == picoquic_callback_ready ||
        ev == picoquic_callback_almost_ready) {
        // Decide under lock; any close runs after unlock (reentrant
        // callbacks take ep->mu). Kill-before-close fails waiters fast;
        // the later close event is then a no-op via the map erase.
        std::string doom_reason;
        {
            std::lock_guard<std::mutex> lk(ep->mu);
            std::shared_ptr<Session> s = ensure_session(ep, cnx);
            if (s->client) {
                auto pd = ep->pending_dials.find(cnx);
                if (pd == ep->pending_dials.end())
                    return 0; // dial already completed/aborted
                std::shared_ptr<Session> sess = s;
                bool known;
                {
                    std::lock_guard<std::mutex> slk(s->mu);
                    known = s->peer_known;
                }
                if (!known) {
                    kill_session_locked(ep, s, -MURMUR_QUIC_AUTH);
                    return 0;
                }
                // Dial-side peerID (Go runs it post-handshake too).
                std::string reason = gate_peer(ep, cnx);
                if (!reason.empty()) {
                    set_error_locked(ep, reason);
                    kill_session_locked(ep, s, -MURMUR_QUIC_AUTH);
                    doom_reason = reason;
                } else {
                    picoquic_enable_keep_alive(cnx, kKeepAliveUs);
                    pd->second->future->set(0, sess);
                    ep->pending_dials.erase(pd);
                }
            } else {
                std::string reason;
                {
                    std::lock_guard<std::mutex> slk(s->mu);
                    if (!s->peer_known)
                        reason = "missing peer certificate";
                    else
                        reason = gate_peer(ep, cnx);
                }
                if (!reason.empty()) {
                    // Refused: ordered close code 0, like Go's accept.
                    set_error_locked(ep, reason);
                    kill_session_locked(ep, s, -MURMUR_QUIC_AUTH);
                    doom_reason = reason;
                } else {
                    picoquic_enable_keep_alive(cnx, kKeepAliveUs);
                    ep->accept_q.push_back(s);
                    ep->accept_cv.notify_one();
                }
            }
        }
        if (!doom_reason.empty())
            picoquic_close_ex(cnx, 0, doom_reason.c_str());
        return 0;
    }
    if (ev == picoquic_callback_stream_data ||
        ev == picoquic_callback_stream_fin) {
        std::lock_guard<std::mutex> lk(ep->mu);
        auto it = ep->sessions.find(cnx);
        if (it == ep->sessions.end())
            return 0;
        std::shared_ptr<Session> s = it->second;
        std::lock_guard<std::mutex> slk(s->mu);
        if (s->closed)
            return 0;
        auto st = s->streams.find(stream_id);
        std::shared_ptr<Stream> t;
        if (st == s->streams.end()) {
            // Peer-initiated bidi only; ignore uni/reset races.
            if (!PICOQUIC_IS_BIDIR_STREAM_ID(stream_id))
                return 0;
            t = std::make_shared<Stream>();
            t->session = s;
            t->id = stream_id;
            s->streams[stream_id] = t;
        } else {
            t = st->second;
        }
        {
            std::lock_guard<std::mutex> tlk(t->mu);
            t->rx.insert(t->rx.end(), bytes, bytes + length);
            if (ev == picoquic_callback_stream_fin)
                t->fin = true;
            t->cv.notify_all();
        }
        if (!t->enqueued && !t->local) {
            // Materialize peer-initiated streams for accept only once
            // data/FIN arrived (quic-go). Replies on locally-initiated
            // streams only wake their owner's reads, never accept.
            t->enqueued = true;
            s->accept_q.push_back(t);
            s->cv.notify_all();
        }
        return 0;
    }
    if (ev == picoquic_callback_stream_reset ||
        ev == picoquic_callback_stop_sending) {
        std::lock_guard<std::mutex> lk(ep->mu);
        auto it = ep->sessions.find(cnx);
        if (it == ep->sessions.end())
            return 0;
        std::lock_guard<std::mutex> slk(it->second->mu);
        auto st = it->second->streams.find(stream_id);
        if (st == it->second->streams.end())
            return 0;
        std::lock_guard<std::mutex> tlk(st->second->mu);
        st->second->reset = true;
        st->second->cv.notify_all();
        it->second->cv.notify_all();
        return 0;
    }
    if (ev == picoquic_callback_datagram) {
        std::lock_guard<std::mutex> lk(ep->mu);
        auto it = ep->sessions.find(cnx);
        if (it == ep->sessions.end())
            return 0;
        std::shared_ptr<Session> s = it->second;
        std::lock_guard<std::mutex> slk(s->mu);
        if (s->closed || length > kMaxDatagram)
            return 0;
        if (s->dgrams.size() >= 256)
            s->dgrams.pop_front(); // drop oldest; membership tolerates loss
        s->dgrams.emplace_back(bytes, bytes + length);
        s->cv.notify_all();
        return 0;
    }
    return 0;
}

void enqueue(Endpoint* ep, std::function<void()> fn)
{
    {
        std::lock_guard<std::mutex> lk(ep->mu);
        ep->cmd_q.push_back(std::move(fn));
    }
    uint8_t b = 1;
    ssize_t w = write(ep->wake_pipe[1], &b, 1); // non-blocking; best effort
    (void)w;
}

void pump_send(Endpoint* ep)
{
    uint8_t buf[PICOQUIC_MAX_PACKET_SIZE];
    for (;;) {
        size_t len = 0;
        struct sockaddr_storage to, from;
        int if_index = 0;
        picoquic_connection_id_t log_cid;
        picoquic_cnx_t* last_cnx = NULL;
        int ret = picoquic_prepare_next_packet(ep->quic,
            picoquic_current_time(), buf, sizeof(buf), &len, &to, &from,
            &if_index, &log_cid, &last_cnx);
        if (ret != 0 || len == 0)
            break;
        socklen_t sl = (to.ss_family == AF_INET6)
            ? sizeof(struct sockaddr_in6)
            : sizeof(struct sockaddr_in);
        (void)sendto(ep->sock, buf, len, 0, (struct sockaddr*)&to, sl);
    }
}

void pump_recv(Endpoint* ep, const struct sockaddr* local, socklen_t local_len)
{
    (void)local_len;
    uint8_t buf[PICOQUIC_MAX_PACKET_SIZE];
    for (;;) {
        struct sockaddr_storage from;
        socklen_t sl = sizeof(from);
        ssize_t n = recvfrom(
            ep->sock, buf, sizeof(buf), MSG_DONTWAIT, (struct sockaddr*)&from, &sl);
        if (n <= 0)
            break;
        picoquic_incoming_packet(ep->quic, buf, (size_t)n,
            (struct sockaddr*)&from, (struct sockaddr*)local, 0, 0,
            picoquic_current_time());
    }
}

void pump_loop(Endpoint* ep)
{
    struct sockaddr_storage local;
    socklen_t local_len = sizeof(local);
    if (getsockname(ep->sock, (struct sockaddr*)&local, &local_len) != 0)
        memset(&local, 0, sizeof(local));
    while (!ep->stop.load()) {
        // 1. commands (run without ep->mu: they call into picoquic).
        for (;;) {
            std::function<void()> fn;
            {
                std::lock_guard<std::mutex> lk(ep->mu);
                if (ep->cmd_q.empty())
                    break;
                fn = std::move(ep->cmd_q.front());
                ep->cmd_q.pop_front();
            }
            fn();
        }
        // 2. flush outbound.
        pump_send(ep);
        // 3. wait for net input, wake pipe, or next timer.
        int64_t delay_us = picoquic_get_next_wake_delay(
            ep->quic, picoquic_current_time(), 50 * 1000);
        int timeout_ms = delay_us < 0 ? 1
            : delay_us > 50 * 1000      ? 50
                                        : (int)(delay_us / 1000);
        struct pollfd pf[2];
        pf[0].fd = ep->sock;
        pf[0].events = POLLIN;
        pf[1].fd = ep->wake_pipe[0];
        pf[1].events = POLLIN;
        if (poll(pf, 2, timeout_ms) > 0) {
            if (pf[1].revents & POLLIN) {
                uint8_t drain[64];
                while (read(ep->wake_pipe[0], drain, sizeof(drain)) > 0) {
                }
            }
            if (pf[0].revents & POLLIN)
                pump_recv(ep, (struct sockaddr*)&local, local_len);
        }
    }
}

// ALPN strictness: the endpoint offers/proposes only its configured
// ALPN (MURMUR_QUIC_ALPN by default, the file protocol for the fetch
// service). A foreign peer fails chain verification before ALPN could
// matter, so no select callback is needed (it only fires without a
// default).

int murmur_install_chain(Endpoint* ep, const uint8_t** chain_der,
    const size_t* chain_lens, size_t chain_n, murmur_node_t* leaf_id)
{
    // Self check first: leaf SAN must equal the configured node id,
    // like Go ("certificate is not for this node").
    mbedtls_x509_crt leaf;
    mbedtls_x509_crt_init(&leaf);
    if (mbedtls_x509_crt_parse_der(&leaf, chain_der[0], chain_lens[0]) != 0) {
        set_error(ep, "leaf certificate does not parse");
        return -MURMUR_QUIC_INVALID;
    }
    bool ok = leaf_node_id(&leaf, leaf_id);
    mbedtls_x509_crt_free(&leaf);
    if (!ok) {
        set_error(ep, "leaf certificate has no valid node URI SAN");
        return -MURMUR_QUIC_AUTH;
    }
    if (!node_equal(*leaf_id, ep->self)) {
        set_error(ep, "certificate is not for this node");
        return -MURMUR_QUIC_AUTH;
    }
    // Install: picoquic takes ownership of malloc'd copies (it frees
    // both the array and every base; never point into caller memory).
    ptls_iovec_t* certs =
        (ptls_iovec_t*)malloc(chain_n * sizeof(ptls_iovec_t));
    if (certs == NULL)
        return -MURMUR_QUIC_BUSY;
    for (size_t i = 0; i < chain_n; i++) {
        certs[i].base = (uint8_t*)malloc(chain_lens[i]);
        if (certs[i].base == NULL) {
            for (size_t j = 0; j < i; j++)
                free(certs[j].base);
            free(certs);
            return -MURMUR_QUIC_BUSY;
        }
        memcpy(certs[i].base, chain_der[i], chain_lens[i]);
        certs[i].len = chain_lens[i];
    }
    picoquic_set_tls_certificate_chain(ep->quic, certs, chain_n);
    return 0;
}

int murmur_install_trust(Endpoint* ep, const uint8_t** ca_der,
    const size_t* ca_lens, size_t ca_n)
{
    mbedtls_x509_crt* ca =
        (mbedtls_x509_crt*)malloc(sizeof(mbedtls_x509_crt));
    if (ca == NULL)
        return -MURMUR_QUIC_BUSY;
    mbedtls_x509_crt_init(ca);
    for (size_t i = 0; i < ca_n; i++) {
        if (mbedtls_x509_crt_parse_der(ca, ca_der[i], ca_lens[i]) != 0) {
            mbedtls_x509_crt_free(ca);
            free(ca);
            set_error(ep, "CA certificate does not parse");
            return -MURMUR_QUIC_INVALID;
        }
    }
    ptls_mbedtls_verify_certificate_t* v =
        ptls_mbedssl_init_verify_certificate_complete(
            ca, NULL, murmur_f_vrfy, ep);
    if (v == NULL) {
        mbedtls_x509_crt_free(ca);
        free(ca);
        return -MURMUR_QUIC_BUSY;
    }
    picoquic_set_verify_certificate_callback(ep->quic, &v->super,
        ptls_mbedtls_dispose_verify_certificate);
    ep->quic->is_cert_store_not_empty = 1;
    picoquic_set_client_cert_verification_policy(ep->quic, 1); // strict
    return 0;
}

void murmur_endpoint_destroy(Endpoint* ep)
{
    if (ep->pump.joinable()) {
        ep->stop.store(true);
        uint8_t b = 1;
        ssize_t w = write(ep->wake_pipe[1], &b, 1);
        (void)w;
        ep->pump.join();
    }
    if (ep->quic != NULL) {
        picoquic_free(ep->quic);
        ep->quic = NULL;
    }
    if (ep->sock >= 0) {
        close(ep->sock);
        ep->sock = -1;
    }
    if (ep->wake_pipe[0] >= 0)
        close(ep->wake_pipe[0]);
    if (ep->wake_pipe[1] >= 0)
        close(ep->wake_pipe[1]);
    delete ep;
}

} // namespace

extern "C" {

int murmur_quic_create(murmur_quic_t** out, const char* bind_ip,
    uint16_t bind_port, const uint8_t** chain_der, const size_t* chain_lens,
    size_t chain_n, const uint8_t* key_pem, size_t key_len,
    const uint8_t** ca_der, const size_t* ca_lens, size_t ca_n,
    const murmur_node_t* self, const murmur_node_t* allowed, size_t n_allowed,
    const char** allow_cidrs, size_t n_cidrs, uint32_t max_conns,
    uint32_t sessions)
{
    return murmur_quic_create_alpn(out, bind_ip, bind_port, chain_der,
        chain_lens, chain_n, key_pem, key_len, ca_der, ca_lens, ca_n, self,
        allowed, n_allowed, allow_cidrs, n_cidrs, max_conns, sessions,
        MURMUR_QUIC_ALPN);
}

int murmur_quic_create_alpn(murmur_quic_t** out, const char* bind_ip,
    uint16_t bind_port, const uint8_t** chain_der, const size_t* chain_lens,
    size_t chain_n, const uint8_t* key_pem, size_t key_len,
    const uint8_t** ca_der, const size_t* ca_lens, size_t ca_n,
    const murmur_node_t* self, const murmur_node_t* allowed, size_t n_allowed,
    const char** allow_cidrs, size_t n_cidrs, uint32_t max_conns,
    uint32_t sessions, const char* alpn)
{
    if (alpn == NULL || *alpn == '\0')
        return -MURMUR_QUIC_INVALID;
    if (out == NULL || chain_n == 0 || chain_der == NULL ||
        chain_lens == NULL || key_pem == NULL || key_len == 0 ||
        ca_n == 0 || ca_der == NULL || ca_lens == NULL || self == NULL)
        return -MURMUR_QUIC_INVALID;
    *out = NULL;
    // Provider init once per process (reset disturbs live endpoints).
    static std::once_flag provider_once;
    std::call_once(provider_once, [] {
        picoquic_tls_api_reset(TLS_API_INIT_FLAGS_NO_MINICRYPTO);
    });

    std::unique_ptr<Endpoint> ep(new Endpoint());
    auto fail = [&](int code) -> int {
        murmur_endpoint_destroy(ep.release());
        return code;
    };
    ep->self = *self;
    ep->alpn = alpn;
    for (size_t i = 0; i < n_allowed; i++)
        ep->allowed.push_back(allowed[i]);
    for (size_t i = 0; i < n_cidrs; i++) {
        Endpoint::Cidr c;
        if (!parse_cidr(allow_cidrs[i], &c)) {
            set_error(ep.get(), "bad allowlist CIDR");
            return fail(-MURMUR_QUIC_INVALID);
        }
        ep->cidrs.push_back(c);
    }
    ep->max_streams = (sessions == 0 ? 32 : sessions) + 8;

    // UDP socket.
    bool want_v6 = bind_ip != NULL && strchr(bind_ip, ':') != NULL;
    ep->sock = socket(want_v6 ? AF_INET6 : AF_INET, SOCK_DGRAM, 0);
    if (ep->sock < 0)
        return fail(-MURMUR_QUIC_BUSY);
    int one = 1;
    setsockopt(ep->sock, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    fcntl(ep->sock, F_SETFL, O_NONBLOCK);
    if (want_v6) {
        struct sockaddr_in6 a;
        memset(&a, 0, sizeof(a));
        a.sin6_family = AF_INET6;
        a.sin6_port = htons(bind_port);
        if (bind_ip == NULL || *bind_ip == '\0')
            a.sin6_addr = in6addr_any;
        else if (inet_pton(AF_INET6, bind_ip, &a.sin6_addr) != 1)
            return fail(-MURMUR_QUIC_INVALID);
        if (bind(ep->sock, (struct sockaddr*)&a, sizeof(a)) != 0)
            return fail(-MURMUR_QUIC_BUSY);
    } else {
        struct sockaddr_in a;
        memset(&a, 0, sizeof(a));
        a.sin_family = AF_INET;
        a.sin_port = htons(bind_port);
        if (bind_ip == NULL || *bind_ip == '\0' ||
            strcmp(bind_ip, "0.0.0.0") == 0) {
            a.sin_addr.s_addr = htonl(INADDR_ANY);
        } else if (inet_pton(AF_INET, bind_ip, &a.sin_addr) != 1) {
            return fail(-MURMUR_QUIC_INVALID);
        }
        if (bind(ep->sock, (struct sockaddr*)&a, sizeof(a)) != 0)
            return fail(-MURMUR_QUIC_BUSY);
    }

    ep->quic = picoquic_create(max_conns == 0 ? 32 : max_conns, NULL, NULL,
        NULL, ep->alpn.c_str(), murmur_quic_cb, ep.get(), NULL, NULL, NULL,
        picoquic_current_time(), NULL, NULL, NULL, 0);
    if (ep->quic == NULL)
        return fail(-MURMUR_QUIC_BUSY);

    // Transport parameters from current defaults, Murmur knobs applied.
    picoquic_tp_t tp = *picoquic_get_default_tp(ep->quic);
    tp.initial_max_stream_id_bidir = ep->max_streams;
    tp.initial_max_stream_id_unidir = 0; // uni streams disabled, like Go
    tp.initial_max_data = kMaxDataDefault;
    tp.initial_max_stream_data_bidi_local = kMaxStreamDataDefault;
    tp.initial_max_stream_data_bidi_remote = kMaxStreamDataDefault;
    tp.max_idle_timeout = kIdleTimeoutMs;
    tp.max_datagram_frame_size = 1280;
    picoquic_set_default_tp(ep->quic, &tp);

    murmur_node_t leaf_id;
    int rc = murmur_install_chain(ep.get(), chain_der, chain_lens, chain_n,
        &leaf_id);
    if (rc != 0) {
        murmur_endpoint_destroy(ep.release());
        return rc;
    }
    ptls_context_t* master = (ptls_context_t*)ep->quic->tls_master_ctx;
    if (murmur_load_key_pem(master, key_pem, key_len) != 0) {
        set_error(ep.get(), "private key does not parse");
        murmur_endpoint_destroy(ep.release());
        return -MURMUR_QUIC_INVALID;
    }
    rc = murmur_install_trust(ep.get(), ca_der, ca_lens, ca_n);
    if (rc != 0) {
        murmur_endpoint_destroy(ep.release());
        return rc;
    }
    picoquic_set_client_authentication(ep->quic, 1); // mutual TLS
    // Memory-installed credentials don't clear the client-only flag
    // (picoquic_create sets it when cert/key files are NULL); this
    // endpoint accepts inbound connections, like any peer.
    picoquic_enforce_client_only(ep->quic, 0);

    if (pipe(ep->wake_pipe) != 0) {
        murmur_endpoint_destroy(ep.release());
        return -MURMUR_QUIC_BUSY;
    }
    // Both ends non-blocking: the pump drains the read end in a loop
    // that must terminate (a blocking read wedges the pump forever).
    fcntl(ep->wake_pipe[0], F_SETFL, O_NONBLOCK);
    fcntl(ep->wake_pipe[1], F_SETFL, O_NONBLOCK);
    ep->pump = std::thread(pump_loop, ep.get());
    *out = (murmur_quic_t*)ep.release();
    return 0;
}

int murmur_quic_local_addr(murmur_quic_t* q, char* buf, size_t buflen)
{
    if (q == NULL || buf == NULL || buflen == 0)
        return -MURMUR_QUIC_INVALID;
    Endpoint* ep = (Endpoint*)q;
    struct sockaddr_storage a;
    socklen_t sl = sizeof(a);
    if (getsockname(ep->sock, (struct sockaddr*)&a, &sl) != 0)
        return -MURMUR_QUIC_BUSY;
    char ip[64];
    uint16_t port = 0;
    if (a.ss_family == AF_INET) {
        struct sockaddr_in* v4 = (struct sockaddr_in*)&a;
        inet_ntop(AF_INET, &v4->sin_addr, ip, sizeof(ip));
        port = ntohs(v4->sin_port);
    } else if (a.ss_family == AF_INET6) {
        struct sockaddr_in6* v6 = (struct sockaddr_in6*)&a;
        inet_ntop(AF_INET6, &v6->sin6_addr, ip, sizeof(ip));
        port = ntohs(v6->sin6_port);
    } else {
        return -MURMUR_QUIC_BUSY;
    }
    snprintf(buf, buflen, "%s:%u", ip, port);
    return 0;
}

int murmur_last_error(murmur_quic_t* q, char* buf, size_t buflen)
{
    if (q == NULL || buf == NULL || buflen == 0)
        return -MURMUR_QUIC_INVALID;
    Endpoint* ep = (Endpoint*)q;
    std::lock_guard<std::mutex> lk(ep->mu);
    snprintf(buf, buflen, "%s", ep->last_error.c_str());
    return 0;
}

int murmur_quic_close(murmur_quic_t* q)
{
    if (q == NULL)
        return 0;
    Endpoint* ep = (Endpoint*)q;
    auto done = std::make_shared<Future<int>>();
    enqueue(ep, [ep, done] {
        // Snapshot under lock; close without it (picoquic calls may
        // reenter via callbacks, which take ep->mu; the pump is
        // single-threaded so no session can vanish mid-command).
        std::vector<picoquic_cnx_t*> all;
        {
            std::lock_guard<std::mutex> lk(ep->mu);
            ep->closing = true;
            for (const auto& kv : ep->sessions)
                all.push_back(kv.first);
        }
        for (auto cnx : all)
            picoquic_close(cnx, 0); // ordered; never delete in callback
        {
            std::lock_guard<std::mutex> lk(ep->mu);
            std::vector<std::shared_ptr<Session>> ss;
            for (const auto& kv : ep->sessions)
                ss.push_back(kv.second);
            for (const auto& s : ss)
                kill_session_locked(ep, s, -MURMUR_QUIC_CLOSED);
            for (const auto& kv : ep->pending_dials)
                kv.second->future->set(-MURMUR_QUIC_CLOSED, nullptr);
            ep->pending_dials.clear();
            ep->accept_cv.notify_all();
            done->set(0, 0);
        }
    });
    int ignored = 0;
    return done->wait(10000, &ignored);
}

void murmur_quic_free(murmur_quic_t* q)
{
    if (q == NULL)
        return;
    Endpoint* ep = (Endpoint*)q;
    murmur_quic_close(q);
    murmur_endpoint_destroy(ep);
}

struct murmur_session {
    std::shared_ptr<Session> ref;
};

struct murmur_stream {
    std::shared_ptr<Stream> ref;
};

int murmur_quic_dial(murmur_quic_t* q, const char* ip, uint16_t port,
    const char* sni, murmur_session_t** out, int timeout_ms)
{
    if (q == NULL || ip == NULL || out == NULL)
        return -MURMUR_QUIC_INVALID;
    *out = NULL;
    Endpoint* ep = (Endpoint*)q;
    struct sockaddr_storage addr;
    memset(&addr, 0, sizeof(addr));
    if (strchr(ip, ':') != NULL) {
        struct sockaddr_in6* v6 = (struct sockaddr_in6*)&addr;
        v6->sin6_family = AF_INET6;
        v6->sin6_port = htons(port);
        if (inet_pton(AF_INET6, ip, &v6->sin6_addr) != 1)
            return -MURMUR_QUIC_INVALID;
    } else {
        struct sockaddr_in* v4 = (struct sockaddr_in*)&addr;
        v4->sin_family = AF_INET;
        v4->sin_port = htons(port);
        if (inet_pton(AF_INET, ip, &v4->sin_addr) != 1)
            return -MURMUR_QUIC_INVALID;
    }
    std::string sni_str = (sni && *sni) ? sni : ip;
    auto fut = std::make_shared<Future<std::shared_ptr<Session>>>();
    enqueue(ep, [ep, addr, sni_str, fut] {
        picoquic_cnx_t* cnx = picoquic_create_client_cnx(ep->quic,
            (struct sockaddr*)&addr, picoquic_current_time(),
            PICOQUIC_V1_VERSION, sni_str.c_str(), ep->alpn.c_str(),
            murmur_quic_cb, ep);
        std::lock_guard<std::mutex> lk(ep->mu);
        if (cnx == NULL) {
            fut->set(-MURMUR_QUIC_BUSY, nullptr);
            return;
        }
        std::shared_ptr<Session> s = ensure_session(ep, cnx);
        s->client = true;
        auto pd = std::make_shared<PendingDial>();
        pd->future = fut;
        pd->id = ep->next_dial_id++;
        ep->pending_dials[cnx] = pd;
        // NOTE: create_client_cnx already starts the handshake.
    });
    std::shared_ptr<Session> sess;
    int rc = fut->wait(timeout_ms, &sess);
    if (rc != 0) {
        // Abort a still-pending handshake (black-hole peer); a dial
        // that completed in the race stays until idle timeout reaps it.
        // Close without ep->mu: reentrant callbacks take it.
        enqueue(ep, [ep, fut] {
            picoquic_cnx_t* doomed = NULL;
            {
                std::lock_guard<std::mutex> lk(ep->mu);
                for (const auto& kv : ep->pending_dials) {
                    if (kv.second->future == fut) {
                        doomed = kv.first;
                        break;
                    }
                }
            }
            if (doomed == NULL)
                return;
            picoquic_close_ex(doomed, 0, "dial timeout");
            std::lock_guard<std::mutex> lk(ep->mu);
            auto st = ep->sessions.find(doomed);
            if (st != ep->sessions.end())
                kill_session_locked(ep, st->second, -MURMUR_QUIC_TIMEOUT);
            else
                ep->pending_dials.erase(doomed);
        });
        return rc;
    }
    murmur_session* h = new murmur_session();
    h->ref = sess;
    *out = h;
    return 0;
}

int murmur_quic_accept(
    murmur_quic_t* q, murmur_session_t** out, int timeout_ms)
{
    if (q == NULL || out == NULL)
        return -MURMUR_QUIC_INVALID;
    *out = NULL;
    Endpoint* ep = (Endpoint*)q;
    std::unique_lock<std::mutex> lk(ep->mu);
    auto ready = [&] {
        while (!ep->accept_q.empty()) {
            std::shared_ptr<Session> s = ep->accept_q.front();
            std::lock_guard<std::mutex> slk(s->mu);
            if (!s->closed)
                return true;
            ep->accept_q.pop_front();
        }
        return false;
    };
    auto awake = [&] { return ready() || ep->closing; };
    if (!awake()) {
        if (timeout_ms < 0) {
            ep->accept_cv.wait(lk, awake);
        } else if (!ep->accept_cv.wait_for(lk,
                       std::chrono::milliseconds(timeout_ms), awake)) {
            return -MURMUR_QUIC_TIMEOUT;
        }
    }
    if (ep->closing && !ready())
        return -MURMUR_QUIC_CLOSED;
    murmur_session* h = new murmur_session();
    h->ref = ep->accept_q.front();
    ep->accept_q.pop_front();
    *out = h;
    return 0;
}

int murmur_session_peer(murmur_session_t* s, murmur_node_t* out)
{
    if (s == NULL || out == NULL)
        return -MURMUR_QUIC_INVALID;
    std::lock_guard<std::mutex> lk(s->ref->mu);
    if (!s->ref->peer_known)
        return -MURMUR_QUIC_AUTH;
    *out = s->ref->peer;
    return 0;
}

int murmur_session_open_stream(murmur_session_t* s, murmur_stream_t** out)
{
    if (s == NULL || out == NULL)
        return -MURMUR_QUIC_INVALID;
    *out = NULL;
    std::shared_ptr<Session> sess = s->ref;
    Endpoint* ep = sess->ep;
    auto fut = std::make_shared<Future<std::shared_ptr<Stream>>>();
    enqueue(ep, [ep, sess, fut] {
        std::lock_guard<std::mutex> lk(ep->mu);
        std::lock_guard<std::mutex> slk(sess->mu);
        if (sess->closed) {
            fut->set(-MURMUR_QUIC_CLOSED, nullptr);
            return;
        }
        uint64_t id = picoquic_get_next_local_stream_id(sess->cnx, 0);
        std::shared_ptr<Stream> t = std::make_shared<Stream>();
        t->session = sess;
        t->id = id;
        t->local = true;
        sess->streams[id] = t;
        fut->set(0, t);
    });
    std::shared_ptr<Stream> t;
    int rc = fut->wait(-1, &t);
    if (rc != 0)
        return rc;
    murmur_stream* h = new murmur_stream();
    h->ref = t;
    *out = h;
    return 0;
}

int murmur_session_accept_stream(
    murmur_session_t* s, murmur_stream_t** out, int timeout_ms)
{
    if (s == NULL || out == NULL)
        return -MURMUR_QUIC_INVALID;
    *out = NULL;
    std::shared_ptr<Session> sess = s->ref;
    std::unique_lock<std::mutex> lk(sess->mu);
    auto ready = [&] { return !sess->accept_q.empty() || sess->closed; };
    if (!ready()) {
        if (timeout_ms < 0) {
            sess->cv.wait(lk, ready);
        } else if (!sess->cv.wait_for(lk,
                       std::chrono::milliseconds(timeout_ms), ready)) {
            return -MURMUR_QUIC_TIMEOUT;
        }
    }
    if (sess->accept_q.empty())
        return -MURMUR_QUIC_CLOSED;
    murmur_stream* h = new murmur_stream();
    h->ref = sess->accept_q.front();
    sess->accept_q.pop_front();
    *out = h;
    return 0;
}

int murmur_session_send_datagram(
    murmur_session_t* s, const uint8_t* data, size_t len)
{
    if (s == NULL || (data == NULL && len > 0))
        return -MURMUR_QUIC_INVALID;
    if (len > kMaxDatagram)
        return -MURMUR_QUIC_OVERLOADED;
    std::shared_ptr<Session> sess = s->ref;
    {
        std::lock_guard<std::mutex> lk(sess->mu);
        if (sess->closed)
            return -MURMUR_QUIC_CLOSED;
    }
    std::vector<uint8_t> copy(data, data + len);
    enqueue(sess->ep, [sess, copy] {
        picoquic_cnx_t* cnx;
        {
            std::lock_guard<std::mutex> lk(sess->ep->mu);
            std::lock_guard<std::mutex> slk(sess->mu);
            if (sess->closed)
                return;
            cnx = sess->cnx;
        }
        // Best effort: oversize-vs-MTU drops at send, like Go's
        // ignored SendDatagram errors.
        picoquic_queue_datagram_frame(cnx, copy.size(), copy.data());
    });
    return 0;
}

int murmur_session_recv_datagram(murmur_session_t* s, uint8_t* buf, size_t cap,
    size_t* out_len, int timeout_ms)
{
    if (s == NULL || buf == NULL || out_len == NULL)
        return -MURMUR_QUIC_INVALID;
    *out_len = 0;
    std::shared_ptr<Session> sess = s->ref;
    std::unique_lock<std::mutex> lk(sess->mu);
    auto ready = [&] { return !sess->dgrams.empty() || sess->closed; };
    if (!ready()) {
        if (timeout_ms < 0) {
            sess->cv.wait(lk, ready);
        } else if (!sess->cv.wait_for(lk,
                       std::chrono::milliseconds(timeout_ms), ready)) {
            return -MURMUR_QUIC_TIMEOUT;
        }
    }
    if (sess->dgrams.empty())
        return -MURMUR_QUIC_CLOSED;
    if (sess->dgrams.front().size() > cap)
        return -MURMUR_QUIC_OVERLOADED; // keep queued for a bigger buffer
    *out_len = sess->dgrams.front().size();
    memcpy(buf, sess->dgrams.front().data(), *out_len);
    sess->dgrams.pop_front();
    return 0;
}

int murmur_session_close(murmur_session_t* s)
{
    return murmur_session_close_code(s, 0);
}

int murmur_session_close_code(murmur_session_t* s, uint64_t code)
{
    if (s == NULL)
        return 0;
    std::shared_ptr<Session> sess = s->ref;
    Endpoint* ep = sess->ep;
    auto done = std::make_shared<Future<int>>();
    enqueue(ep, [ep, sess, done, code] {
        // Only touch picoquic if the cnx is still registered (it is
        // deleted after the close event; the map erase marks that).
        // Close without ep->mu: reentrant callbacks take it.
        bool registered;
        {
            std::lock_guard<std::mutex> lk(ep->mu);
            registered =
                ep->sessions.find(sess->cnx) != ep->sessions.end();
        }
        if (registered)
            picoquic_close(sess->cnx, code);
        {
            std::lock_guard<std::mutex> lk(ep->mu);
            kill_session_locked(ep, sess, -MURMUR_QUIC_CLOSED);
            done->set(0, 0);
        }
    });
    int ignored = 0;
    return done->wait(-1, &ignored);
}

int murmur_session_remote_addr(
    murmur_session_t* s, char* buf, size_t buflen)
{
    if (s == NULL || buf == NULL || buflen == 0)
        return -MURMUR_QUIC_INVALID;
    buf[0] = '\0';
    std::shared_ptr<Session> sess = s->ref;
    Endpoint* ep = sess->ep;
    auto fut = std::make_shared<Future<std::string>>();
    enqueue(ep, [ep, sess, fut] {
        picoquic_cnx_t* cnx = NULL;
        {
            std::lock_guard<std::mutex> lk(ep->mu);
            if (ep->sessions.find(sess->cnx) != ep->sessions.end())
                cnx = sess->cnx;
        }
        if (cnx == NULL) {
            fut->set(-MURMUR_QUIC_CLOSED, std::string());
            return;
        }
        struct sockaddr* peer = NULL;
        picoquic_get_peer_addr(cnx, &peer);
        if (peer == NULL) {
            fut->set(-MURMUR_QUIC_PROTOCOL, std::string());
            return;
        }
        char host[INET6_ADDRSTRLEN];
        uint16_t port = 0;
        if (peer->sa_family == AF_INET) {
            const struct sockaddr_in* v4 = (const struct sockaddr_in*)peer;
            inet_ntop(AF_INET, &v4->sin_addr, host, sizeof(host));
            port = ntohs(v4->sin_port);
        } else if (peer->sa_family == AF_INET6) {
            const struct sockaddr_in6* v6 = (const struct sockaddr_in6*)peer;
            inet_ntop(AF_INET6, &v6->sin6_addr, host, sizeof(host));
            port = ntohs(v6->sin6_port);
        } else {
            fut->set(-MURMUR_QUIC_PROTOCOL, std::string());
            return;
        }
        char text[INET6_ADDRSTRLEN + 8];
        snprintf(text, sizeof(text), "%s:%u", host, port);
        fut->set(0, std::string(text));
    });
    std::string out;
    int rc = fut->wait(-1, &out);
    if (rc != 0)
        return rc;
    if (out.size() + 1 > buflen)
        return -MURMUR_QUIC_OVERLOADED;
    memcpy(buf, out.c_str(), out.size() + 1);
    return 0;
}

int murmur_session_wait_closed(murmur_session_t* s, int timeout_ms)
{
    if (s == NULL)
        return -MURMUR_QUIC_INVALID;
    std::shared_ptr<Session> sess = s->ref;
    std::unique_lock<std::mutex> lk(sess->mu);
    if (sess->closed)
        return 0;
    if (timeout_ms < 0) {
        sess->cv.wait(lk, [&] { return sess->closed; });
        return 0;
    }
    if (!sess->cv.wait_for(lk, std::chrono::milliseconds(timeout_ms),
            [&] { return sess->closed; }))
        return -MURMUR_QUIC_TIMEOUT;
    return 0;
}

void murmur_session_release(murmur_session_t* s)
{
    delete s;
}

int murmur_stream_write(murmur_stream_t* s, const uint8_t* data, size_t len)
{
    if (s == NULL || (data == NULL && len > 0))
        return -MURMUR_QUIC_INVALID;
    std::shared_ptr<Stream> t = s->ref;
    std::shared_ptr<Session> sess = t->session;
    {
        std::lock_guard<std::mutex> lk(t->mu);
        if (t->closed || t->reset)
            return -MURMUR_QUIC_CLOSED;
    }
    std::vector<uint8_t> copy(data, data + len);
    auto fut = std::make_shared<Future<int>>();
    enqueue(sess->ep, [sess, t, copy, fut] {
        picoquic_cnx_t* cnx;
        uint64_t id;
        {
            std::lock_guard<std::mutex> lk(sess->ep->mu);
            std::lock_guard<std::mutex> slk(sess->mu);
            std::lock_guard<std::mutex> tlk(t->mu);
            if (sess->closed || t->closed || t->reset) {
                fut->set(-MURMUR_QUIC_CLOSED, 0);
                return;
            }
            cnx = sess->cnx;
            id = t->id;
        }
        if (picoquic_add_to_stream(cnx, id, copy.data(), copy.size(), 0) != 0)
            fut->set(-MURMUR_QUIC_CLOSED, 0);
        else
            fut->set(0, 0);
    });
    int ignored = 0;
    return fut->wait(-1, &ignored);
}

int murmur_stream_read(
    murmur_stream_t* s, uint8_t* buf, size_t cap, size_t* out_len)
{
    return murmur_stream_read_timeout(s, buf, cap, out_len, -1);
}

int murmur_stream_read_timeout(murmur_stream_t* s, uint8_t* buf, size_t cap,
    size_t* out_len, int timeout_ms)
{
    if (s == NULL || buf == NULL || out_len == NULL)
        return -MURMUR_QUIC_INVALID;
    *out_len = 0;
    if (cap == 0)
        return -MURMUR_QUIC_INVALID;
    std::shared_ptr<Stream> t = s->ref;
    std::unique_lock<std::mutex> lk(t->mu);
    auto ready = [&] {
        return !t->rx.empty() || t->fin || t->reset;
    };
    if (timeout_ms < 0) {
        t->cv.wait(lk, ready);
    } else if (!t->cv.wait_for(lk, std::chrono::milliseconds(timeout_ms),
                   ready)) {
        return -MURMUR_QUIC_TIMEOUT;
    }
    if (!t->rx.empty()) {
        size_t n = cap < t->rx.size() ? cap : t->rx.size();
        for (size_t i = 0; i < n; i++) {
            buf[i] = t->rx.front();
            t->rx.pop_front();
        }
        *out_len = n;
        return 0;
    }
    if (t->reset) {
        // Lock order is session -> stream: release t->mu first.
        lk.unlock();
        std::lock_guard<std::mutex> slk(t->session->mu);
        return t->session->closed ? -MURMUR_QUIC_CLOSED : -MURMUR_QUIC_PROTOCOL;
    }
    return 0; // FIN with empty rx: *out_len == 0
}

int murmur_stream_close(murmur_stream_t* s)
{
    if (s == NULL)
        return 0;
    std::shared_ptr<Stream> t = s->ref;
    {
        std::lock_guard<std::mutex> lk(t->mu);
        if (t->closed)
            return 0;
        t->closed = true;
    }
    std::shared_ptr<Session> sess = t->session;
    auto fut = std::make_shared<Future<int>>();
    enqueue(sess->ep, [sess, t, fut] {
        picoquic_cnx_t* cnx = NULL;
        {
            std::lock_guard<std::mutex> lk(sess->ep->mu);
            std::lock_guard<std::mutex> slk(sess->mu);
            if (!sess->closed)
                cnx = sess->cnx;
        }
        if (cnx != NULL) {
            picoquic_add_to_stream(cnx, t->id, NULL, 0, 1);
            // Send FIN even if the stream errored; ignore the result.
        }
        fut->set(0, 0);
    });
    int ignored = 0;
    return fut->wait(-1, &ignored);
}

void murmur_stream_release(murmur_stream_t* s)
{
    delete s;
}

} // extern "C"
