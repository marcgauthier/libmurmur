# Murmur replication wire-protocol porting spec (Go → C++, QUIC native)

Source of truth: Go port in `clients/go/pkgs/replication/`, `clients/go/pkgs/tx/`, mirroring `murmur-replication/src/protocol.rs`, `engine.rs`, `transport.rs`, `membership.rs`, `storage.rs`, `snapshot.rs`, `murmur-tx` (`clients/go/pkgs/replication/protocol.go:15`, `clients/go/pkgs/replication/serve.go:3`, `clients/go/pkgs/replication/transport_quic.go:3`, `clients/go/pkgs/replication/membership.go:2`, `clients/go/pkgs/replication/sync.go:3`, `clients/go/pkgs/tx/tx.go:1`).

## 1. Postcard primitives (all Message/Packet/Manifest/Schema encodings)

- u64/u32/enum-tag/bool-as-varint: unsigned LEB128 (`binary.PutUvarint`), minimal form; truncated varint = Protocol error (`clients/go/pkgs/replication/protocol.go:34`,`40`, `clients/go/pkgs/tx/tx.go:74`,`80`).
- i64 (Key.version/seq, Cursor.from/through): zigzag `uint64((v<<1)^(v>>63))` then varint (`clients/go/pkgs/replication/protocol.go:48`,`50`).
- bytes/String: varint length + raw bytes; strings must be valid UTF-8 (`clients/go/pkgs/replication/protocol.go:52`,`57`,`68`).
- Option<T>: single byte `0x00`=None / `0x01`=Some, then T; any other byte = Protocol error (`clients/go/pkgs/replication/protocol.go:180`,`205`,`221`; `clients/go/pkgs/replication/protocol.go:399`,`525`).
- Enum discriminant: varint tag = Rust declaration order, then variant fields in declaration order (`clients/go/pkgs/replication/protocol.go:250`, `clients/go/pkgs/replication/membership.go:143`).
- Fixed arrays (NodeID 16 B, digests 32 B, IPv4 4 B, IPv6 16 B): raw bytes, no length (`clients/go/pkgs/replication/protocol.go:79`,`467`,`477`).
- Strictness everywhere: every top-level decode rejects trailing bytes (`DecodeMessage` `clients/go/pkgs/replication/protocol.go:461`; `DecodePacket` `clients/go/pkgs/replication/membership.go:379`; `DecodeCursor` `clients/go/pkgs/replication/protocol.go:244`; `DecodeCells` `clients/go/pkgs/replication/protocol.go:895`; `DecodeManifest`/`DecodeSignedSchema`/`DecodeProgress`/`DecodeU64` `clients/go/pkgs/tx/snapshot.go:221`,`clients/go/pkgs/tx/protocol.go:141`,`55`,`clients/go/pkgs/tx/tx.go:131`).

## 2. Stream framing (reliable bidi QUIC streams only, never datagrams)

- Frame = 4-byte big-endian u32 length N + N-byte `EncodeMessage` payload (`clients/go/pkgs/replication/protocol.go:654`).
- `0 < N <= FrameBytes` else Protocol error; `FrameBytes = 128<<10` (`clients/go/pkgs/replication/protocol.go:26`,`651`,`673`).
- `WriteFrame` pre-checks encoded length, returns Overloaded if oversized before touching stream (`clients/go/pkgs/replication/protocol.go:646`). `ReadFrame` uses `io.ReadFull` for header and body (`clients/go/pkgs/replication/protocol.go:669`,`677`).
- Protocol-level `ALPN = "murmur-crsqlite/1"` (`clients/go/pkgs/replication/protocol.go:24`); QUIC `NextProtos=["murmur-crsqlite/1"]` on both client and server TLS configs (`clients/go/pkgs/tx/protocol.go:10` is unrelated tx constant; QUIC: `clients/go/pkgs/replication/transport_quic.go:31`,`329`,`351`).
- Chunk payload cap `ChunkBytes = 64<<10`; tx snapshot chunking uses identical `tx.ChunkBytes = 64<<10` (`clients/go/pkgs/replication/protocol.go:28`, `clients/go/pkgs/tx/protocol.go:14`).

## 3. Identities

- `NodeID = [16]byte` (`clients/go/pkgs/tx/tx.go:20`), alias in replication pkg (`clients/go/pkgs/replication/config.go:21`). Wire: 16 raw bytes. Text: 32 lowercase hex, dashes ignored on parse; zero id rejected (`clients/go/pkgs/tx/tx.go:23`,`32`, `clients/go/pkgs/replication/config.go:24`).
- Group/Node/Site roles: group = database id shared by mesh; node = TLS identity; site = cr-sqlite site id pinned in `murmur_identity` (`clients/go/pkgs/replication/serve.go:154`,`184`).
- Schema digest: `SHA256(EncodeSchemaPairs(pairs))` where pairs = `ORDER BY name` (table, DDL) for every CRR app table; `murmur_*` CRR = Invalid; zero tables = Invalid (`clients/go/pkgs/replication/sync.go:758`,`786`,`816`).

## 4. QUIC/TLS transport (C++ must reproduce)

- Mutual TLS 1.3 over QUIC, `MinVersion: tls.VersionTLS13` both sides (`clients/go/pkgs/replication/transport_quic.go:328`,`350`).
- Endpoint knobs: idle 30 s, keepalive 10 s, `MaxIncomingStreams = sessions+8`, `MaxIncomingUniStreams = -1` (disabled), `EnableDatagrams = true`, dial timeout 10 s, default bind `0.0.0.0:7443` (`clients/go/pkgs/replication/transport_quic.go:37`,`363`).
- Peer identity = leaf-cert URI SAN `replicateddb://node/<32 hex>`: exactly one, nonzero, dashes allowed; 0 or ≥2 or zero = Auth error (`clients/go/pkgs/replication/transport_quic.go:34`,`48`). Chain verified against operator CA file with `ExtKeyUsageAny`, current time; DNS-name checks bypassed (`InsecureSkipVerify:true` + `VerifyPeerCertificate` doing full `verifyChain`) (`clients/go/pkgs/replication/transport_quic.go:254`,`326`,`345`).
- Client dial additionally gates `allowed_peers` at handshake; server gates at accept via `peerID()`: network allowlist → chain present → SAN identity → node allowlist (`clients/go/pkgs/replication/transport_quic.go:331`,`400`,`417`,`436`). Network match: empty = open; IPv4-mapped collapses to v4 (`clients/go/pkgs/replication/transport_quic.go:219`).
- Local leaf must equal configured node id or `certificate is not for this node` (`clients/go/pkgs/replication/transport_quic.go:298`). Refused inbound peers get `CloseWithError(0, msg)` and Accept keeps waiting (`clients/go/pkgs/replication/transport_quic.go:411`).
- Session/stream seam: `Session` = one conn: `PeerID()`, `OpenStream/AcceptStream` (bidi frame streams), `SendDatagram/RecvDatagram` (membership only), `Close` (`clients/go/pkgs/replication/engine.go:27`). `Stream` = reliable bidi byte stream with full-buffer `Write` (`clients/go/pkgs/replication/engine.go:43`, `clients/go/pkgs/replication/transport_quic.go:464`,`473`,`482`,`490`,`507`).

## 5. Stream messages (tag = varint, fields in wire order)

All in `clients/go/pkgs/replication/protocol.go:254` (encode `383`, decode `487`):

| Tag | Type | Wire fields in order | Purpose / stream |
|---|---|---|---|
| 0 | MsgHello | group[16], node[16], site[16], schema[32], incarnation varint u64, addr (Addr) | Session hello; handshake stream only (`clients/go/pkgs/replication/serve.go:259`) |
| 1 | MsgPull | group[16], node[16], site[16], schema[32], Option<NodeID16> expected_site, Cursor | Pull request; first frame of pull stream (`clients/go/pkgs/replication/serve.go:328`) |
| 2 | MsgReset | site[16] | Donor's current site; receiver resets progress for peer (`clients/go/pkgs/replication/serve.go:342`,`447`) |
| 3 | MsgIdle | (none) | No new data; pull reply (`clients/go/pkgs/replication/serve.go:340`,`470`) |
| 4 | MsgBatch | site[16], Cursor next, bytes varint u64, digest[32]=SHA256(CRSB blob) | Batch header; then chunks (`clients/go/pkgs/replication/serve.go:350`,`473`) |
| 5 | MsgChunk | index varint (u32 range, overflow rejected), bytes data | Payload chunk, sequential from 0 (`clients/go/pkgs/replication/protocol.go:568`, `clients/go/pkgs/replication/serve.go:381`) |
| 6 | MsgSnapshotRequest | group[16], node[16], site[16], schema[32] | First frame of snapshot stream (`clients/go/pkgs/replication/snapshot.go:637`) |
| 7 | MsgSnapshotManifest | bytes = `tx.EncodeManifest` | Snapshot manifest reply (`clients/go/pkgs/replication/snapshot.go:593`) |
| 8 | MsgSchemaRequest | (none) | "Send your signed schema"; vet/adopt streams (`clients/go/pkgs/replication/schema_serve.go:95`,`209`) |
| 9 | MsgSchemaManifest | bytes = `tx.EncodeSignedSchema` | Schema manifest reply / master push first frame (`clients/go/pkgs/replication/schema_serve.go:148`,`262`) |
| 10 | MsgSchemaAck | digest[32]=SHA256(schema bytes), sequence varint u64 | Schema ack (`clients/go/pkgs/replication/schema_serve.go:199`,`227`) |
| 11 | MsgEnd | (none) | Terminates chunk sequence (batch or snapshot) (`clients/go/pkgs/replication/serve.go:376`,`486`, `clients/go/pkgs/replication/snapshot.go:608`) |
| 12 | MsgAck | digest[32] (must echo MsgBatch.digest) | Batch applied ack (`clients/go/pkgs/replication/serve.go:402`,`493`) |
| 13 | MsgError | string text | Failure reply; `ServeStream` sends on any serve error (`clients/go/pkgs/replication/serve.go:531`,`559`) |

Sub-structures:
- Addr: varint family (0=v4+4 raw bytes, 1=v6+16 raw bytes) + varint port (≤65535); invalid family/port rejected; invalid local addr encodes as 0.0.0.0 preserving port (`clients/go/pkgs/replication/protocol.go:320`,`340`).
- Key: zigzag version, zigzag seq, String table, bytes PK, String CID (`clients/go/pkgs/replication/protocol.go:137`).
- Cursor: zigzag from, Option<zigzag> through, Option<Key> after (`clients/go/pkgs/replication/protocol.go:178`). `Through != nil` = more batches remain (`clients/go/pkgs/replication/serve.go:396`).

## 6. Stream choreography (one flow per fresh bidi stream)

- Handshake: dialer writes Hello first, reads peer Hello; acceptor reads first, writes second (`clients/go/pkgs/replication/serve.go:272`,`299`). Checks: `group` equal, `node ==` TLS-peer id, peer site ≠ self site and nonzero, else Auth; schema mismatch + `accept_remote_schema=0` → Protocol fast-fail, else proceed to manifest convergence (`clients/go/pkgs/replication/serve.go:285`,`290`). Returns (peer incarnation, peer addr). NOTE: no production session-accept loop wires Handshake/ServeStream/handlePacket in Go today — only tests and `murmur_snapshot_request` open streams (`clients/go/pkgs/replication/serve_test.go:63`, `clients/go/pkgs/replication/sql.go:228`); C++ must define the accept loop (UNVERIFIED against Rust: confirm Rust session-loop order — hello stream before/parallel with serve streams).
- Pull (`PullOnce` ↔ `ServePull`, `clients/go/pkgs/replication/serve.go:311`,`420`): puller `WriteFrame(MsgPull)`; donor replies exactly one of `MsgIdle | MsgReset | MsgBatch | MsgError`. Batch: header → `MsgChunk{0..k}` → `MsgEnd`; puller acks `MsgAck{digest}`; donor verifies digest echo (`clients/go/pkgs/replication/serve.go:350`,`369`,`402`,`474`,`489`).
- Pull/donor validation (all Protocol unless noted): donor checks `req.Group==group`, `req.Node==TLS peer`, `req.Site != self site` else Auth (`clients/go/pkgs/replication/serve.go:437`); schema equal or vet-cached else "CRR schema mismatch" (`clients/go/pkgs/replication/serve.go:444`); `ExpectedSite != donor site` → `MsgReset{site}` not error (`clients/go/pkgs/replication/serve.go:447`); cursor older than GC watermark → "cursor pruned; snapshot required" (`clients/go/pkgs/replication/serve.go:463`); empty export (cursor unchanged + 12-byte empty CRSB) → `MsgIdle` (`clients/go/pkgs/replication/serve.go:470`); puller checks batch site/`Bytes` bounds (`emptyCRSBLen=12 .. max_batch_bytes`), cursor monotonicity, chunk index sequence/contiguity (`len(data)` in `1..=ChunkBytes`, total == header Bytes), then `Apply` verifies SHA256 + length (`clients/go/pkgs/replication/serve.go:351`,`357`,`381`,`393`, `clients/go/pkgs/replication/sync.go:446`).
- Snapshot (`FetchSnapshot` ↔ `ServeSnapshot`, `clients/go/pkgs/replication/snapshot.go:557`,`620`): request `MsgSnapshotRequest` → `MsgSnapshotManifest` → `MsgChunk{0..n}` (tx-chunk-sized, index sequential, `1..=ChunkBytes` each) → `MsgEnd`. Same group/node/site + schema/vet gates as pull (`clients/go/pkgs/replication/snapshot.go:574`,`581`). Manifest must fit one frame (`len(EncodeManifest) <= FrameBytes`, `clients/go/pkgs/replication/snapshot.go:547`). No MsgAck on snapshot path. Receiver commits each chunk to IN-kv then requires zero missing before `FinishSnapshot` (`clients/go/pkgs/replication/snapshot.go:681`,`706`).
- Schema/vet (`clients/go/pkgs/replication/schema_serve.go`): `VetFetch`: `MsgSchemaRequest` → expect `MsgSchemaManifest`, verify `signer==peer && database==group`, one-sided `PullerCompatible` (`schema_serve.go:90`). `AdoptFromPeer`: same + ingest + `MsgSchemaAck{digest,seq}` (`schema_serve.go:204`). `PushSchema` (master only): unsolicited `MsgSchemaManifest` → expect matching `MsgSchemaAck` (`schema_serve.go:233`). Serve side: `ServeSchemaRequest` always answers with manifest; `ReceiveSchemaPush` ingests then acks (`schema_serve.go:130`,`194`).
- Inbound dispatch `ServeStream(peer, w, r)`: first frame selects `MsgPull→ServePull | MsgSnapshotRequest→ServeSnapshot | MsgSchemaRequest→ServeSchemaRequest | MsgSchemaManifest→ReceiveSchemaPush`; anything else → `MsgError("expected pull, snapshot, or schema request")`; any handler error also emits `MsgError{text}` (`clients/go/pkgs/replication/serve.go:527`). Pull outcomes counted serve_ok/serve_reject(mismatch)/serve_error (`clients/go/pkgs/replication/serve.go:538`).

## 7. Datagram packets (unreliable QUIC datagrams only; no length prefix)

Types/tags/fields (`clients/go/pkgs/replication/membership.go:147`, encode `251`, decode `288`): Member = node[16] + Addr + incarnation varint + state varint 0..3 (Alive/Suspect/Dead/Left; >3 rejected) (`membership.go:108`,`192`,`216`); member vec = varint count + items, count ≤4096 (`membership.go:223`,`231`).

| Tag | Packet | Fields | Sender → behavior |
|---|---|---|---|
| 0 | PktGossip | database[16], sender[16], members[] | Periodic fanout (`gossip_fanout` random sessions, `membership.go:553`,`572`); merge all (`membership.go:639`) |
| 1 | PktIndirectAck | database[16], sender[16], target[16], nonce varint | Relay → requester on ack of relayed ping (`membership.go:676`,`699`) |
| 2 | PktPing | database[16], sender[16], nonce varint, members[] | Direct probe (`membership.go:603`) or relay forward (`membership.go:725`); nonce 0 = merge only, no reply (`membership.go:649`) |
| 3 | PktAck | database[16], sender[16], nonce varint, members[] | Ping reply with own gossip slice; clears pending on nonce match (`membership.go:681`,`682`) |
| 4 | PktPingRequest | database[16], sender[16], target[16], nonce varint | Indirect repair via 3 random relays (`membership.go:605`,`708`) |

Datagram rules: raw `EncodePacket` bytes, cap `maxDatagramBytes=1000` both directions (encode-side drop, decode-side Protocol error) (`clients/go/pkgs/replication/membership.go:186`,`541`,`622`). Envelope auth: Gossip/Ping/Ack require `database==group && sender==session peer && len(members)<=4` else Auth; IndirectAck/PingRequest require `database==group && sender==peer` (`clients/go/pkgs/replication/membership.go:632`,`702`,`709`). Relay table: 5 s expiry, cap 4096 entries (`membership.go:713`). Probe cadence/timeouts (500 ms×(awareness+1) probe timeout, 5 s×(awareness+1) suspect expiry, awareness ≤8) (`clients/go/pkgs/replication/membership.go:478`,`507`).

## 8. Embedded payload codecs (inside MsgChunk / MsgSnapshotManifest / MsgSchemaManifest)

- CRSB cells (`EncodeCells`, `clients/go/pkgs/replication/protocol.go:720`): magic `CRSB` + LE u32 version=1 + LE u32 count; per cell: LE-u32-len table, LE-u32-len PK, LE-u32-len CID, tag byte (0 null; 1 + LE i64; 2 + LE f64 bits; 3 text + field; 4 blob + field — decoder rejects other tags), LE i64 col_version, LE i64 db_version, field site_id, LE i64 cl, LE i64 seq (`protocol.go:731`,`820`). Empty = 12 B (`clients/go/pkgs/replication/sync.go:33`). Export cap: 1024 cells/batch, batch_bytes estimate (64+Σ lens) vs max_batch_bytes exact (`clients/go/pkgs/replication/sync.go:36`,`319`,`359`).
- `tx.Manifest` (`clients/go/pkgs/tx/snapshot.go:198`): database[16], donor[16], recipient[16], transfer[16], expires varint ms, bytes varint, digest[32]=SHA256(whole payload stream), schema[32], progress vec (≤4096), chunk-hash vec (count varint ≤2^24 + raw 32 B each), bytes signature (empty in embedded engine — transport auth replaces it, `clients/go/pkgs/replication/snapshot.go:8`). Snapshot payload = `STREAM_MAGIC "MURMUR-SNAPSHOT\x00\x02"` + per-page BE-u32-len + CRSB page; chunked at `tx.ChunkBytes` with per-chunk SHA256 (`clients/go/pkgs/tx/snapshot.go:35`, `clients/go/pkgs/replication/snapshot.go:239`,`219`). `ValidateChunk`: source==donor, exact expected length (last short), hash match (`clients/go/pkgs/tx/snapshot.go:456`).
- `tx.SignedSchema` (`clients/go/pkgs/tx/protocol.go:108`): database[16], signer[16], sequence varint, bytes schema (canonical pairs minus opted-out tables, `clients/go/pkgs/replication/sync.go:797`), bytes signature (empty embedded). `Digest()=SHA256(schema)`; `SignedBytes` preimage = `murmur/sqlite-schema/v1` + db + signer + seq + len-prefixed SHA256(schema) (`clients/go/pkgs/tx/protocol.go:149`,`159`).
- `tx.Progress` (`clients/go/pkgs/tx/protocol.go:27`): origin[16], applied/observed/retained_from/retained_through varints. U64 = bare varint (`clients/go/pkgs/tx/tx.go:123`). KV keys are ASCII (`07/replication/applied|observed|.../<hex>`, `clients/go/pkgs/tx/protocol.go:62`) — local store, not wire, except in vectors below.

## 9. Compat / version negotiation

- NO protocol-version handshake on the replication wire: no version field in any Message/Packet; compat = (a) ALPN string match at TLS, (b) group-id equality, (c) CRR-schema-digest equality-or-vet, (d) CRSB version==1, (e) snapshot schema-digest equality at install (`clients/go/pkgs/replication/serve.go:285`,`290`,`444`, `clients/go/pkgs/replication/snapshot.go:384`, `clients/go/pkgs/replication/protocol.go:807`). `tx.Version uint16=13` exists but is never sent/compared in Go (`clients/go/pkgs/tx/protocol.go:10`, no refs) — UNVERIFIED whether Rust negotiates it elsewhere.
- Schema mismatch paths: handshake fast-fail only when `accept_remote_schema=0` (`clients/go/pkgs/replication/serve.go:290`); pull/snapshot serve reject + spawn one background `VetFetch` per (peer,digest), cached in `vetted` map (vet_ok/vet_no/vet_fail counters); puller retries after vet lands or `AdoptFromPeer` (`clients/go/pkgs/replication/schema_serve.go:43`,`55`).
- GC/cursor compat: donor rejects cursors below watermark with "cursor pruned; snapshot required" (`clients/go/pkgs/replication/serve.go:463`); site change (clone) surfaces as `MsgReset` / Auth "cloned" (`clients/go/pkgs/replication/serve.go:343`,`447`).

## 10. Golden vector inventory (`clients/go/pkgs/replication/testdata/`, asserted by `protocol_test.go`, `membership_test.go`)

Msg/Key/Cursor vectors — `TestGoldenKey` (`protocol_test.go:49`), `TestGoldenCursors` (`:74`), `TestGoldenMessages` (`:96`); fixtures: `vecNode(b)`=16 B `b..b+15`, schema=32×0xAA, digest=32×0xBB, key={42,7,"t",[1,2,3],"b"} (`protocol_test.go:21`):
- `key.bin` (10 B, `540e0174030102030162`) — Key full; `key_neg.bin` (5 B) — Key{-7,-1,"",[],""} zigzag negatives.
- `cursor_default.bin` (3 B `000000`) — Cursor{0,nil,nil}; `cursor_full.bin` (15 B) — {42, through=100, after=vecKey}; trailing-byte rejection asserted.
- `msg_hello.bin` (89 B) / `msg_hello_v6.bin` (101 B) — MsgHello tag 0, incarnation 9, 127.0.0.1:4401 vs [::1]:4401.
- `msg_pull.bin` (111 B) — MsgPull tag 1 with ExpectedSite=Some + Cursor{42, after}; `msg_batch.bin` (55 B) — MsgBatch{cursor From=100, bytes=12345, digest}; `msg_chunk.bin` (103 B) — MsgChunk{idx 3, 100 B 0..99}; `msg_ack.bin` (33 B) — MsgAck; `msg_idle.bin` (1 B `03`); `msg_end.bin` (1 B `0b`); `msg_reset.bin` (17 B); `msg_error.bin` (6 B, "boom"); `msg_snapshot_request.bin` (81 B). Round-trip + trailing-byte + unknown-tag(99) rejection asserted (`protocol_test.go:121`,`160`). Un-vectored (round-trip only): MsgSchemaRequest/Manifest, MsgSnapshotManifest, MsgSchemaAck, MsgPull w/o ExpectedSite (`protocol_test.go:140`).
- `crsb_cells.bin` (355 B) — 5 cells: null/int(-7)/real(1.5)/text("hi")/blob(0,1,2); cell1 t/b col=5 db=6 cl=7 seq=8; bad-magic/version/truncation/trailing rejected (`TestGoldenCells`, `protocol_test.go:168`).
- `u64_300.bin` (`ac02`), `u64_max.bin` (10 B), `progress_key.txt` (`07/replication/applied/0405…13`), `observed_key.txt` (`…/observed/…`) for `vecNode(4)` (`TestGoldenKV`, `protocol_test.go:215`).
- `TestFrameIO` (`protocol_test.go:233`): Idle+Chunk+Error frame round-trip; `FrameBytes`-payload write rejected; empty/invalid-length reads rejected (no .bin).
Packet vectors — `TestGoldenPackets` (`membership_test.go:210`): db=0xaa×16, n1=0x11×16, n2=0x22×16, m={0x33×16, 127.0.0.1:7443, inc 5, Suspect}, v6m={0x44×16, [::1]:7443, inc 300, Alive}:
- `vec_pkt_gossip.bin` (97 B) Gossip{m,v6m}; `vec_pkt_indirectack.bin` (50 B) nonce 9; `vec_pkt_ping.bin` (60 B) nonce 7 +{m}; `vec_pkt_ack.bin` (35 B) nonce 8, no members; `vec_pkt_pingreq.bin` (50 B) nonce 10. Encode-match + decode-stability asserted; trailing/unknown-tag(9)/truncated rejected (`membership_test.go:199`).
- `vec_schema_pairs.bin` (37 B) — `[{"a","b"},{"Sticky Notes!","CREATE TABLE t(x)"}]` postcard Vec<(String,String)> (`TestGoldenSchemaPairs`, `membership_test.go:249`; codec `sync.go:702`).
- (Adjacent, tx pkg, same conventions: `clients/go/pkgs/tx/testdata/vec_{signed_schema,pin_none,pin_some,manifest,progress,incoming}.bin` — asserted by tx tests; include if C++ ports snapshot/manifest codecs.)

## 11. Open questions / UNVERIFIED (do not guess)

1. Rust session-accept loop order (hello stream vs serve-stream spawning vs datagram pump) — Go has no production loop; tests drive each stream manually (see §6). Confirm against `engine.rs` before freezing C++ accept path.
2. Whether Rust enforces `tx.Version=13` anywhere on the wire (Go never sends/compares it).
3. `MsgSnapshotManifest`/`MsgSchemaManifest`/`MsgSchemaAck` have no golden vectors — generate from Rust before freezing C++ codecs.
4. QUIC stream shutdown semantics (FIN vs full close, half-close for request/response streams) — Go `quicStream.Close` maps to `st.Close()` (`transport_quic.go:522`); confirm Rust drop order for Ack/End flows.
5. `MsgError` vs silent `serveSem`-Overloaded: Go `ServePull/ServeSnapshot` return Overloaded without writing when sessions cap hit (`serve.go:429`, `snapshot.go:566`) — confirm Rust also stays silent (no Error frame) in that case.
6. Gossip/probe timers (`poll_ms`, `anti_entropy_ms` settings exist in defaults, `config.go:125`) have no Go driver; confirm Rust tick wiring for C++ scheduler.
