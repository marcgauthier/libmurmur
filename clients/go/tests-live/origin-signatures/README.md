# origin-signatures

Three nodes share one database id. A commits a transaction, B
receives it, A stops, and C receives A's transaction exclusively
through B.

## Status: partial (harness gap after the portable legs)

`TestForwardedOriginSurvivesOfflineOriginAndHostileRelay` runs the
honest forwarding, C-restart durability, and B-rejoin idempotent
re-offer legs, then skips with:

- `harness: raw-QUIC relay attacker fixture and origin signing keys
  unavailable (no wire-protocol peer; served-origin capture and
  forgery legs cannot run)`

The blocked legs need a raw-QUIC peer speaking the replication wire
protocol (fetch A's batches from C over a `Need` session, serve
modified / unsigned / cross-DBID / fabricated / chunk-identity
forgeries, answer a chunk-availability probe, replay the signed
duplicate, serve an untrusted snapshot manifest) plus the origins'
signing seeds. No such fixture exists in `goharness`, and scenario
packages must not import engine internals to build one.

## What runs here

- A and B mesh peer-to-peer; A commits `from-A`; B converges while
  C stays peerless.
- A stops; B and C mesh; C converges on `from-A` while A is
  stopped; B's and C's row sets are equal.
- C's applied cursor quiesces after B shuts down (in-flight honest
  batches may still apply, then the cursor holds still and never
  moves backwards).
- C restarts with A and B stopped: the honest row is still present.
- B rejoins and re-offers: C's rows and applied cursor are
  unchanged (idempotent re-offer).

## Deviations from the reference

- Quiescence and stillness use the applied-transaction sum from the
  progress snapshot: this stack exposes no staged gauge, no
  `last_error` rejection latch, and no commit cursor.
- The C restart is a replication stop/start with the store open
  (in-process nodes); the fresh-process counter premise is
  re-baselined, not asserted at zero.
- The restart and rejoin legs run before the blocked relay legs
  instead of interleaved with them (their assertions do not depend
  on the attacks having run).
- No `MURMUR SHOW REPLICATION` text columns: peers come from
  `ShowPeers`, counters from the decoded `ShowReplication` snapshot.
