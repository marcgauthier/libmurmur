# C++ Transport Manager Design: picoquic+mbedTLS replacing Go quic-go

## 1. Go contract to replace (all in `clients/go/pkgs/replication/transport_quic.go`)

Wire identity: ALPN `murmur-crsqlite/1` (`transport_quic.go:31`); node = URI SAN `replicateddb://node/<32hex>` (`transport_quic.go:34`), exactly one, nonzero, dashes stripped, dup/zero/missing rejected (`transport_quic.go:48-80`). Knobs: idle 30s, keepalive 10s, bidi budget `sessions+8`, uni streams disabled (`-1`), datagrams on, dial timeout 10s, default bind `0.0.0.0:7443` (`transport_quic.go:37-43`, `transport_quic.go:363-369`, `transport_quic.go:392`).

Credentials: PEM chain + PKCS8/EC/RSA key (file bytes zeroed) + CA pool from `certificate`/`private_key`/`ca` settings (`transport_quic.go:84-140`, `transport_quic.go:155-173`); leaf SAN must equal local node or `certificate is not for this node` (`transport_quic.go:298-303`). Chain verify ignores DNS names, `ExtKeyUsageAny`, current time (`transport_quic.go:254-280`); client side adds SAN + `allowed_peers` gate inside `VerifyPeerCertificate` with `InsecureSkipVerify:true` (`transport_quic.go:326-344`); server side verifies chain at handshake, defers identity/network/node gates to `peerID` at accept (`transport_quic.go:347-361`); `ClientCAs=roots` so Acceptable-CA list goes on wire (`transport_quic.go:361`).

`peerID` order: network gate (empty=all; v4-mapped collapsed, `SplitHostPort`+`ParseIP`) → nonempty chain → SAN → `allowed_peers` nonempty-gated (`transport_quic.go:219-240`, `transport_quic.go:436-452`).

Semantics: `Dial` clones TLS config per dial (quic-go mutates `ServerName`; concurrent-dial race otherwise), 10s ctx timeout, all dial errors wrapped `Auth`, failed-gate conns closed with code 0 + reason (`transport_quic.go:391-406`). `Accept` loops forever: refused peers closed code 0, keep waiting; listener error → `Auth` (`transport_quic.go:411-424`). `Close` = `listener.Close()` stops listen+sessions, nil-safe (`transport_quic.go:427-432`). Session: `OpenStream/AcceptStream` (errors → `Auth`), `SendDatagram/RecvDatagram` blocking (errors → `Auth`), `Close`=code-0 close (`transport_quic.go:461-499`). Stream: `Write` loops to full buffer, returns raw err; `Read` single partial read passthrough; `Close`=FIN (`transport_quic.go:507-522`). Note: inbound stream only materializes after opener writes — engine always writes request first (`transport_quic_test.go:253-260`).

## 2. Engine seam + every caller

Seam (`engine.go:16-48`): `Transport{LocalAddr,Dial,Accept,Close}`, `Session{PeerID,OpenStream,AcceptStream,SendDatagram,RecvDatagram,Close}`, `Stream{Write,Read,Close}`. Engine owns `transport Transport`, nil OK offline, `Start` fails without one (`engine.go:62,98-119`); `Stop` closes all `conns` then transport, swaps map under mutex (`engine.go:210-227`); `Status` reads `LocalAddr` (`engine.go:244-246`).

Call sites (exhaustive, non-test): membership `sendPacket` best-effort `SendDatagram` ≤1000B (`membership.go:186,539-551`), `broadcast` fanout-sampled `SendDatagram` (`membership.go:554-569`), `probe` uses `sendPacket` only (`membership.go:582-618`); `RemoveNode` deletes conn + `Close` (`membership.go:782-789`); `vetFetchAsync` opens stream per vet round (`schema_serve.go:56-70`); `murmur_snapshot_request` opens stream per request (`sql.go:229-234`); `Handshake/PullOnce/ServePull/ServeStream/ServeSnapshot` operate only on `io.Reader/Writer` adapters (`streamWriter/streamReader`, `schema_serve.go:279-297`), never touch Transport directly — all frames via `WriteFrame/ReadFrame` (4B BE len, 1..`FrameBytes`=128KiB, `ChunkBytes`=64KiB) (`protocol.go:25-28,646-681`). No accept-loop/dial-loop exists in Go engine code today: `Accept/Dial/gossip/probe/handlePacket/PullOnce-serve` wiring (`serve.go:256-562`, `membership.go:572-746`) is called by tests/SQL only; `syncCh` wakeups exist (`membership.go:761-764`, `sql.go:169`) but no consumer loop was found — the C++ manager must own the accept/probe/pull loops or expose them. Error taxonomy: kinds Invalid/Busy/Closed/Protocol/Overloaded/Auth (`errors.go:22-27`), projected to `0x53xx` SQLite ext codes (`errors.go:35-85`).

## 3. Vendored picoquic API inventory (read, not grepped)

Lifecycle: `picoquic_create(max_conns, cert,key,root files, default_alpn, default_cb, cb_ctx, cnx_id_cb, reset_seed, time...)` (`picoquic.h:720-732`); `picoquic_free` (`picoquic.h:734`); client `picoquic_create_client_cnx(quic, addr, time, version, sni, alpn, cb, ctx)` + `picoquic_start_client_cnx` (`picoquic.h:1014-1019`); `picoquic_set_callback` per-cnx (`picoquic.h:1350-1351`), `picoquic_set_default_callback` for server (`picoquic.h:992`); states `..._ready/_disconnecting/_closing/_draining/_disconnected` via `picoquic_get_cnx_state` (`picoquic.h:188-208,1303`); close is 3-way: ordered `picoquic_close/cnx,code` (+`_ex` with reason string), abrupt `picoquic_close_immediate` (safe in callback, "a bit experimental"), `picoquic_delete_cnx` (UNSAFE in callback) (`picoquic.h:1021-1048`).

Pump model: app owns UDP sockets; `picoquic_incoming_packet[_ex]` feeds net→stack (`picoquic.h:1385-1404`); `picoquic_prepare_next_packet[_ex]` drains stack→net (`picoquic.h:1415-1424`); sleep bound from `picoquic_get_next_wake_delay/get_wake_delay/get_next_wake_time/get_earliest_cnx_to_wake` (`picoquic.h:1293-1301`); socket errors fed back via `picoquic_notify_destination_unreachable[_by_cnxid]` (`picoquic.h:1452-1455`); `picoquic_set_app_wake_time` for app timers (`picoquic.h:1051`). Alternative: threaded `picoquic_start_network_thread` (requires non-NULL loop cb), `picoquic_wake_up_network_thread` → `picoquic_packet_loop_wake_up` cb in net-thread ctx where picoquic APIs are concurrency-safe, `picoquic_delete_network_thread` (`picoquic_packet_loop.h:289-307,351-367`); loop cb/action enums (`picoquic_packet_loop.h:135-158,185`).

Streams: single cb typedef `(cnx, stream_id, bytes, length, event, callback_ctx, stream_ctx)` (`picoquic.h:530-533`); events `stream_data/stream_fin/stream_reset/stop_sending/close/application_close/prepare_to_send/almost_ready/ready/datagram/.../stream_released` (`picoquic.h:398-430`). Send path A (copy): `picoquic_add_to_stream[_with_ctx](cnx,id,data,len,set_fin[,app_ctx])` — clears active-mark and prior app ctx (`picoquic.h:1638-1653`); path B (zero-copy poll): `picoquic_mark_active_stream[_v2]` → `prepare_to_send` cb → `picoquic_provide_stream_data_buffer(ctx,nb,is_fin,is_still_active)` (`picoquic.h:1509-1523,1621-1636`). `picoquic_get_next_local_stream_id(cnx,is_unidir)` (`picoquic.h:1676`); `reset/stop_sending/discard/open_flow_control` (`picoquic.h:1662-1686`); bidi id macros (`picoquic.h:481-492`).

Datagrams: `picoquic_queue_datagram_frame(cnx,len,bytes)` — must fit path MTU, oversize dropped at send, checks use current MTU (`picoquic.h:1365-1376`); or poll path `picoquic_mark_datagram_ready` → `prepare_datagram` cb → `picoquic_provide_datagram_buffer[_ex]`; old API + no re-arm burns CPU hot loop, `_ex` with `is_active` required for correctness (`picoquic.h:1688-1768`); recv via `picoquic_callback_datagram`; ack/loss/spurious callbacks (`picoquic.h:410-418`); priority vs streams (`picoquic.h:1597-1619`).

Transport params: `picoquic_tp_t` (`picoquic.h:451-476`: bidi/uni stream-data, max_data, `initial_max_stream_id_bidir/unidir`, `max_idle_timeout`, `max_datagram_frame_size`, ...); set via `picoquic_set_default_tp[_value]` / per-cnx `picoquic_set_transport_parameters` (`picoquic.h:780-788`); TP ids (`picoquic.h:236-252`); idle `picoquic_set_default_idle_timeout` (`picoquic.h:932`); keepalive per-cnx `picoquic_enable/disable_keep_alive` (0→idle/2) (`picoquic.h:1791-1795`); `picoquic_get_peer_addr/get_local_addr` (`picoquic.h:1331-1332`); `picoquic_is_client` (`picoquic.h:1798`); ALPN select fns (`picoquic.h:541-544,984-987`); negotiated ALPN via `ptls_get_negotiated_protocol` in tls_api (`tls_api.c:1450`).

TLS/mTLS: DER in-memory creds `picoquic_set_tls_certificate_chain` (takes ownership), `picoquic_set_tls_root_certificates` (takes ownership, 0/-1/-2), `picoquic_set_tls_key` (caller retains) (`picoquic.h:790-814`); `picoquic_set_client_authentication(quic,int)` (`picoquic.h:821`); custom verifier `picoquic_set_verify_certificate_callback(quic,cb,free_fn)` → installs into ptls ctx, disposes old (`picoquic.h:817-818`, `tls_api.c:1534-1549`); `picoquic_enable_custom_verify_certificate_callback` (`tls_api.c:1493-1498`); fail-open default when no roots unless `picoquic_set_client_cert_verification_policy(quic,strict)` (`picoquic.h:806-811`); `picoquic_set_null_verifier` disables (`picoquic.h:804`). picotls verify cb = 2-phase: `cb(self,tls,server_name,&verify_sign,&verify_data,certs,num)` returns 0 + sets sign-verify fn (`picotls.h:808-816`).

mbedTLS provider: `ptls_mbedtls_verify_certificate_t{super, trust_ca, trust_crl, f_vrfy, p_vrfy}` (`ptls_mbedtls.h:71-78`); `mbedtls_verify_certificate` parses each `ptls_iovec_t` DER via `mbedtls_x509_crt_parse_der`, calls `mbedtls_x509_crt_verify(chain,trust_ca,crl,server_name,&flags,f_vrfy,p_vrfy)`, maps `VERIFY_FAILED→PTLS_ALERT_BAD_CERTIFICATE`, on success imports leaf `pk_raw` into PSA and sets `*verifier=mbedtls_verify_sign` (`ptls_mbedtls_sign.c:1321-1420`, design notes `ptls_mbedtls_sign.c:1085-1145`); `f_vrfy(void*,crt,depth,flags)` runs per-cert bottom-up and may clear/add flags (`ptls_mbedtls_sign.c:1132-1139`); init/dispose (`ptls_mbedtls_sign.c:1490-1563`); suites/hash/aead/keyex externs + `ptls_mbedtls_init/free/random_bytes` (`ptls_mbedtls.h:34-58`).

Minicrypto: stubbed deliberately — `TLS_API_INIT_FLAGS_NO_{OPENSSL,MINICRYPTO,FUSION,MBEDTLS}=1,2,4,8` (`picoquic_crypto_provider_api.h:30-33`); `picoquic_tls_api_init_providers` skips flagged providers, latest registration wins (`tls_api.c:187-221`); `picoquic_tls_api_reset(init_flags)` re-inits (`tls_api.c:283-296`); stubs carry id `0xFFFF`, `random_bytes→abort`, `load_private_key→-1` (`minicrypto_stub.c:1-51`). cflags already `-DPTLS_WITHOUT_OPENSSL -DPTLS_WITHOUT_FUSION -DPICOQUIC_WITH_MBEDTLS` (`clients/go/bindings/picoquic/picoquic.go:15`); package intent = own threads, narrow session/stream/datagram API, later C++-driven (`clients/go/bindings/picoquic/picoquic.go:1-12`).

mbedTLS X.509: leaf SANs in `crt->subject_alt_names` (`x509_crt.h:66`); parse each with `mbedtls_x509_parse_subject_alt_name` (`x509.h:449-461`); URI type `MBEDTLS_X509_SAN_UNIFORM_RESOURCE_IDENTIFIER=6` (`x509.h:133`); `mbedtls_x509_crt_verify(crt,trust_ca,crl,cn,&flags,f_vrfy,p_vrfy)` (`x509_crt.h:603-670`).

## 4. Proposed C API surface (`deps/murmur_quic/murmur_quic.h`, `extern "C"`)

Error model: `int` return, 0=OK; negative = `-MURMUR_*` mapped from Go kinds (`errors.go:22-27,35-51`): `MURMUR_OK,INVALID,BUSY,CLOSED,PROTOCOL,OVERLOADED,AUTH,TIMEOUT,CANCELLED`. Out-events use explicit queues (never callbacks into Go).

```c
typedef struct murmur_quic murmur_quic_t;       /* endpoint: quic ctx + pump thread + socket */
typedef struct murmur_session murmur_session_t; /* one cnx: id, stream/dgram queues */
typedef struct murmur_stream murmur_stream_t;   /* one bidi stream: rx ring + tx state */
typedef struct { uint8_t id[16]; } murmur_node_t; /* tx.NodeID [16]byte, clients/go/pkgs/tx/tx.go:20 */

/* --- endpoint --- */
int murmur_quic_create(murmur_quic_t **out, const char *bind_ip, uint16_t bind_port,
    const uint8_t *chain_der, size_t *chain_lens, size_t chain_n,   /* leaf first */
    const uint8_t *key_der, size_t key_len, int key_is_pkcs8,        /* Go accepts PKCS8/EC/RSA, transport_quic.go:120-134 */
    const uint8_t *ca_der, size_t *ca_lens, size_t ca_n,
    const murmur_node_t *self, const murmur_node_t *allowed, size_t n_allowed, /* empty=all */
    const char **allow_cidrs, size_t n_cidrs, uint32_t max_conns, uint32_t sessions);
int murmur_quic_local_addr(murmur_quic_t *q, char *buf, size_t buflen); /* cf LocalAddr transport_quic.go:383-388 */
int murmur_quic_accept(murmur_quic_t *q, murmur_session_t **out, int timeout_ms); /* <0 block, cf Accept loop transport_quic.go:411-424 */
int murmur_quic_dial(murmur_quic_t *q, const char *ip, uint16_t port, const char *sni,
    murmur_session_t **out, int timeout_ms); /* 10s default, transport_quic.go:42,391-406 */
int murmur_quic_close(murmur_quic_t *q);      /* stop listen+all sessions, transport_quic.go:427-432 */
void murmur_quic_free(murmur_quic_t *q);
/* --- session --- */
int murmur_session_peer(murmur_session_t *s, murmur_node_t *out);   /* PeerID transport_quic.go:461 */
int murmur_session_open_stream(murmur_session_t *s, murmur_stream_t **out); /* transport_quic.go:464-470 */
int murmur_session_accept_stream(murmur_session_t *s, murmur_stream_t **out, int timeout_ms); /* transport_quic.go:473-479 */
int murmur_session_send_datagram(murmur_session_t *s, const uint8_t *b, size_t n); /* <=1000B, membership.go:186 */
int murmur_session_recv_datagram(murmur_session_t *s, uint8_t *b, size_t cap, size_t *n, int timeout_ms);
int murmur_session_close(murmur_session_t *s);   /* ordered close code 0, transport_quic.go:499 */
void murmur_session_release(murmur_session_t *s);/* drop handle ref */
/* --- stream --- */
int murmur_stream_write(murmur_stream_t *s, const uint8_t *b, size_t n); /* full-buffer loop, transport_quic.go:507-516 */
int murmur_stream_read(murmur_stream_t *s, uint8_t *b, size_t n, size_t *got); /* partial OK, transport_quic.go:519 */
int murmur_stream_close(murmur_stream_t *s);      /* FIN, transport_quic.go:522 */
void murmur_stream_release(murmur_stream_t *s);
int murmur_last_error(murmur_quic_t *q, char *buf, size_t buflen); /* thread-local text */
```

Buffering rules (encode Go behavior): datagram send >1000B → `OVERLOADED`/drop to mirror `sendPacket/broadcast` silent-drop (`membership.go:541-543,555-557`); stream write ≤128KiB frames enforced by caller (`protocol.go:651-653`), manager need not re-check. `accept_stream` queues only streams that carried data/FIN (Go/quic-go behavior, `transport_quic_test.go:253-260`).

## 5. Thread model

One pump thread per endpoint (preferred: reuse `picoquic_start_network_thread` + `picoquic_wake_up_network_thread`, `picoquic_packet_loop.h:289-307,351-367` — wake-up cb runs in net-thread ctx where picoquic calls are concurrency-safe). All `picoquic_*` calls happen on pump thread only. Go/C++ client threads never call picoquic; they push commands into an MPSC (dial/open/write/send/close) and block on per-op completions/futures; pump-thread picoquic callbacks (`picoquic.h:530-533`) push inbound events (new-cnx-ready, stream-data/fin/reset, datagram, close) into per-session bounded queues + a global accept queue. Wakeups: client enqueue → `picoquic_wake_up_network_thread`; net I/O + timers handled inside loop; app timers via `picoquic_set_app_wake_time` (`picoquic.h:1051`) for dial timeouts (10s, `transport_quic.go:42,392`). UNVERIFIED: whether `picoquic_packet_loop_v3` binds the UDP socket itself from `bind_ip:port` including `:0` ephemeral + reports the bound addr — Go test requires `127.0.0.1:0` + `LocalAddr` roundtrip (`transport_quic_test.go:202-214`); if the loop can't report ephemeral port, manager must own the socket and use manual `incoming/prepare/wake-delay` pump (`picoquic.h:1293-1301,1385-1424`) instead. Either way keep socket ownership decision inside the manager, invisible to the C API above.

Flow control: per-session stream-rx rings bounded (suggest 2×`queue_bytes` default 64MiB, `config.go:131` — UNVERIFIED sizing); datagram rx ring bounded (drop-oldest, membership tolerates loss); tx backpressure: `murmur_stream_write` blocks until queued-or-error (mirrors blocking Go `Write`, `transport_quic.go:507-516`); `send_datagram` non-blocking best-effort (mirrors ignored `SendDatagram` errors, `membership.go:550,567`).

## 6. mTLS verify + URI SAN plan (mbedTLS only)

Init: `picoquic_tls_api_reset(TLS_API_INIT_FLAGS_NO_MINICRYPTO|NO_OPENSSL|NO_FUSION)` (`tls_api.c:283-296`, flags `picoquic_crypto_provider_api.h:30-33`), `ptls_mbedtls_init()` PSA (`ptls_mbedtls.h:56-58`). Load creds: parse PEM→DER in manager (mirror `pemCerts/pemKey`, `transport_quic.go:84-134`); install via `picoquic_set_tls_certificate_chain` + `picoquic_set_tls_key` + `picoquic_set_tls_root_certificates` (`picoquic.h:790-814`); `picoquic_set_client_authentication(quic,1)` (`picoquic.h:821`); `picoquic_set_client_cert_verification_policy(quic,1)` strict so missing roots fail closed (`picoquic.h:806-811`); ALPN `murmur-crsqlite/1` as default ALPN at `picoquic_create` (`picoquic.h:720-732`) + enforce `picoquic_alpn_select_fn_v2` exact-match (`picoquic.h:544,987`).

Chain verify: keep default mbedTLS verifier (`mbedtls_x509_crt_verify` inside `mbedtls_verify_certificate`, `ptls_mbedtls_sign.c:1361-1377`) with `server_name=NULL` (no DNS identity — Go sets `ExtKeyUsageAny` + skips name checks, `transport_quic.go:270-275`). UNVERIFIED: mbedTLS with NULL cn skips name checks but still enforces EKU/KeyUsage — confirm no EKU rejection for our P-256 test leaves (`transport_quic_test.go:38-50`); if rejected, supply `f_vrfy` clearing only `MBEDTLS_X509_BADCERT_BAD_KEY`-class flags — narrowly, never blanket-clear.

Identity extraction (post-handshake, both sides): in `picoquic_callback_ready/almost_ready` (`picoquic.h:408-409`) the manager must obtain the peer leaf DER. Gap: no public `picoquic_get_peer_certificate` found in `picoquic.h` (grep-verified absent). Two candidate routes: (a) custom `ptls_verify_certificate_t` wrapper installed via `picoquic_set_verify_certificate_callback` (`picoquic.h:817-818`, `tls_api.c:1534-1549`) that delegates to `mbedtls_verify_certificate` then copies `certs[0]` (first iovec = leaf, `ptls_mbedtls_sign.c:1113-1117,1351-1360`) into cnx-attached storage before returning — needs `picoquic_get_cnx_in_progress`/cb ctx correlation, UNVERIFIED plumbing; (b) `f_vrfy`/`p_vrfy` hook (`ptls_mbedtls.h:74-78`, invoked per-cert depth 0=leaf, `ptls_mbedtls_sign.c:1132-1139`) capturing depth-0 `mbedtls_x509_crt*` → walk `subject_alt_names` (`x509_crt.h:66`) with `mbedtls_x509_parse_subject_alt_name` filtering `type==6` URI (`x509.h:133,461`) at verify time. Prefer (b): no picotls-struct surgery. Then apply Go-exact SAN rule: strip `replicateddb://node/`, remove `-`, 32 hex, nonzero, exactly one (`transport_quic.go:56-79`) → 16B id; then network allowlist (`picoquic_get_peer_addr`, `picoquic.h:1331`, collapse v4-mapped, `transport_quic.go:219-240`) + `allowed_peers` gate. Gate failure post-handshake: `picoquic_close_ex(cnx,0,reason)` (ordered, mirrors code-0 + reason close, `transport_quic.go:402,419`, `picoquic.h:1044`) and never enqueue to accept queue / fail the dial (mirrors Go accept-loop `continue` and dial-side close, `transport_quic.go:411-424,400-405`). Rogue-CA dial must fail the handshake (`transport_quic_test.go:305-333`); wrong-node local leaf must fail `create` (`transport_quic.go:298-303`).

TP mirror: `initial_max_stream_id_bidir=sessions+8` (default sessions=32, range 1..256, `transport_quic.go:366`, `config.go:128,265-268`), `initial_max_stream_id_unidir=0` (Go `-1`=disable; picoquic 0 = none — UNVERIFIED equivalence), `max_datagram_frame_size≥1200` (1000B payload + overhead; Go `EnableDatagrams:true`, `transport_quic.go:368`), `max_idle_timeout=30000ms` (`picoquic.h:932`, `transport_quic.go:38`), per-cnx keepalive 10s (`picoquic_enable_keep_alive`, `picoquic.h:1793`, `transport_quic.go:39`).

## 7. Mapping table Go-seam-method → C-API-function

| Go (`engine.go:16-48`, `transport_quic.go`) | C API (§4) | Notes |
|---|---|---|
| `Transport.LocalAddr` (`engine.go:18`) | `murmur_quic_local_addr` | bound addr string |
| `Transport.Dial` (`engine.go:20`) | `murmur_quic_dial` | 10s timeout; Auth wrap |
| `Transport.Accept` (`engine.go:22`) | `murmur_quic_accept` | refuse-and-continue inside |
| `Transport.Close` (`engine.go:24`) | `murmur_quic_close`+`_free` | stop all, then free |
| `Session.PeerID` (`engine.go:30`) | `murmur_session_peer` | verified 16B id |
| `Session.OpenStream` (`engine.go:32`) | `murmur_session_open_stream` | `get_next_local_stream_id`+`add_to_stream` |
| `Session.AcceptStream` (`engine.go:34`) | `murmur_session_accept_stream` | data-triggered queue |
| `Session.SendDatagram` (`engine.go:36`) | `murmur_session_send_datagram` | best-effort ≤1000B |
| `Session.RecvDatagram` (`engine.go:38`) | `murmur_session_recv_datagram` | blocking + timeout |
| `Session.Close` (`engine.go:40`) | `murmur_session_close`+`_release` | ordered close, refcount |
| `Stream.Write` (`engine.go:45`) | `murmur_stream_write` | full-buffer, blocking |
| `Stream.Read` (`engine.go:46`) | `murmur_stream_read` | partial OK |
| `Stream.Close` (`engine.go:47`) | `murmur_stream_close`+`_release` | FIN |
| `ListenQuic` (`transport_quic.go:285`) | `murmur_quic_create` | DER creds + gates in |
| `nodeIDFromCert/peerID/verifyChain` (`transport_quic.go:48-80,254-280,436-452`) | internal `murmur_verify.c` | mbedTLS SAN walk |

## 8. Lifecycle / shutdown ordering

Create: `tls_api_reset(flags)` → `ptls_mbedtls_init` → `picoquic_create` → TP/idle/ALPN/creds/roots/client-auth/strict-policy → default cb → start net thread (`picoquic.h:720-734,780-821,932,992`; `picoquic_packet_loop.h:351`). Dial: alloc pending (id, deadline) → pump-thread `create_client_cnx`+`start_client_cnx` (`picoquic.h:1014-1019`) → `almost_ready/ready` → verify+gates → complete or `close_ex` (`picoquic.h:408-409,1044`). Accept: default cb stash pre-ready cnx → ready → verify+gates → enqueue or `close_ex`. Stream open: `picoquic_get_next_local_stream_id` (`picoquic.h:1676`); first `add_to_stream` creates it (`picoquic.h:1645-1646`) — matches Go write-first flow (`transport_quic_test.go:253-260`). Stream close: `add_to_stream(...,set_fin=1)` empty; abort via `reset_stream` (`picoquic.h:1662-1663`).

Shutdown (mirror `Stop`: conns first, then transport, `engine.go:210-227`): (1) mark endpoint closing, fail queued accept/dial/stream/dgram ops with `CLOSED`; (2) pump-thread `picoquic_close(cnx,0)` every cnx (ordered; never `delete_cnx` in callback, `picoquic.h:1037-1048`); (3) stop net thread (`picoquic_delete_network_thread`, `picoquic_packet_loop.h:367` — UNVERIFIED whether it drains closing packets; if not, pre-delay ~1s, UNVERIFIED duration); (4) `picoquic_free` (`picoquic.h:734`); (5) `ptls_mbedtls_free` (`ptls_mbedtls.h:57`); (6) zero key DER (`clearBytes` analog, `transport_quic.go:136-140`). Refcount sessions/streams: `close`≠`release`; callbacks use weak refs; `stream_released` (`picoquic.h:426-428`) retires stream ctx.

## 9. Risks

R1 Peer-cert access has no public API (absent from `picoquic.h`; only `ptls_get_negotiated_protocol` used internally, `tls_api.c:1450`) — route via `f_vrfy` depth-0 capture (`ptls_mbedtls_sign.c:1132-1139`) or custom verify wrapper (`tls_api.c:1534-1549`); prototype first. R2 mbedTLS NULL-cn verify semantics + EKU enforcement UNVERIFIED — test against P-256 PKI (`transport_quic_test.go:32-60`) before lock-in. R3 `initial_max_stream_id_unidir=0` vs Go `-1` disable UNVERIFIED — confirm no uni-stream TP advertisement. R4 Ephemeral-bind + `LocalAddr` reporting through packet-loop API UNVERIFIED — may force manual socket pump (`picoquic.h:1385-1424`). R5 `picoquic_close_immediate` "experimental" (`picoquic.h:1029-1035`) — use ordered `close_ex` everywhere except callback-context emergencies. R6 `add_to_stream` copies (`picoquic.h:1638-1641`) — 64MiB batches (`config.go:130`) fine functionally but copies; zero-copy `mark_active+provide` later. R7 `queue_datagram_frame` MTU-drop (`picoquic.h:1370-1373`) vs Go blocking `SendDatagram` (`transport_quic.go:482-487`) — acceptable: callers ignore errors (`membership.go:550,567`), 1000B cap (`membership.go:186`) fits any MTU. R8 No engine accept/dial loops exist in Go (`engine.go`, `serve.go`, `membership.go` grep-verified) — C++ manager scope must include them or the engine needs a driver. R9 TLS 1.3-only: Go pins `MinVersion:TLS13` (`transport_quic.go:328,350`); picotls is TLS1.3-only by design — UNVERIFIED no TLS1.2 fallback exists in vendored picotls; confirm.