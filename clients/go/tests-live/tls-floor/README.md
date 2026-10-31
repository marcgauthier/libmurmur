# tls-floor

A 2-node cluster converges a marker over QUIC, then a TLS-1.2-only QUIC
client must be refused while a TLS 1.3 client completes a handshake and
opens a stream (RFC 9001 requires TLS 1.3 exclusively for QUIC); the
mesh still converges a post-probe marker afterwards.

Nodes are native replication drivers over VFS stores, driven in-process
through `goharness` (see `../PORTING.md`). Probes dial the node's QUIC
address with quic-go: a `MaxVersion`-TLS1.2 dial must fail while the
identical TLS 1.3 dial succeeds. Credentials come from the
harness-issued node TLS dir; chain verification mirrors the product
client (roots pinned, server name ignored, leaf URI SAN node id parsed)
against ALPN `murmur-crsqlite/1`.

Run from `clients/go`:

```sh
MURMUR_ENGINE_INTEGRATION=1 go test -count=1 -timeout 600s ./tests-live/tls-floor/
```

Pass criteria: marker converges on both nodes within 60 s; the
TLS-1.2-only dial fails within 10 s; the TLS 1.3 dial completes the
handshake plus a stream open within 10 s / 5 s; the post-probe marker
converges on both nodes.
