# QUIC connection pressure

Holds authenticated QUIC connections without sending the replication
Hello while spraying invalid UDP datagrams. Honest clients must
continue writing within ten seconds, remote application must progress
during the attack, incomplete connections must not become replication
peers, and all exact rows must converge after teardown and a
post-attack write.

Defaults: `MURMUR_DOS_CLIENT_ATTACK_SECONDS=60` and
`MURMUR_DOS_CLIENT_QUIC_HALFOPEN=24`. Both accept positive integers.
Expired QUIC half-opens are replaced throughout the window. This
bounded loopback pressure test checks protocol admission and continued
service; it does not claim internet-scale denial-of-service resistance.

## Deviations from the reference

- Native replication drivers over VFS stores, in-process through
  `goharness` (see `../PORTING.md`), instead of `murmur-server` children
  over pgwire.
- The attacker dials QUIC over ALPN `murmur-crsqlite/1` (the tls-floor
  technique) with a fresh CA-signed leaf for a foreign node id minted
  from the cluster CA: a dial presenting the target's own leaf is
  dropped immediately as loop protection, and a cloned live leaf is
  reaped by session replacement once replication flows, so only a
  foreign-but-authenticated identity holds half-open under load.
- The reference's SQL half-open legs (pre-startup TCP connections and
  partial SSLRequests) have no target on this stack: native nodes
  expose no SQL listener, SQL runs in-process. `TestSQLHalfOpenPressure`
  records that as a skip; QUIC pressure is the whole attack surface.
- cr-sqlite DDL: the `PRIMARY KEY` column carries explicit `NOT NULL`,
  and `body` carries a `DEFAULT`.

Run from `clients/go`:

```sh
MURMUR_ENGINE_INTEGRATION=1 go test -count=1 -timeout 600s ./tests-live/dos-client/
```
