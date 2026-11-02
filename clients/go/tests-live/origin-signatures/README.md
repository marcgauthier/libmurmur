# origin-signatures

Three nodes share one database id. A commits a transaction, B
receives it, A stops, and C receives A's transaction exclusively
through B.

## Status: enforced legs run; reference hostile-relay legs still partial

`TestForwardedOriginSurvivesOfflineOriginAndHostileRelay` runs the
honest forwarding, C-restart durability, and B-rejoin idempotent
re-offer legs, then skips with:

- `harness: raw-QUIC relay attacker fixture and origin signing keys
  unavailable (no wire-protocol peer; served-origin capture and
  forgery legs cannot run)`

The blocked reference legs need a raw-QUIC peer speaking the
replication wire protocol (fetch A's batches from C over a `Need`
session, serve modified / unsigned / cross-DBID / fabricated /
chunk-identity forgeries, answer a chunk-availability probe, replay
the signed duplicate, serve an untrusted snapshot manifest). No
such fixture exists in `goharness`, and scenario packages must not
import engine internals to build one.

Origin signing keys DO exist now (`origin_key_file` +
`trusted_origins`, provisioned via `NodeConfig.OriginSeed` and
`Cluster.EnforceOrigins`), and `TestEnforcedMeshConvergesAndRefusesForgery`
covers the hostile-relay substance without a raw-QUIC peer: the
rogue-origin and tampered-forward legs below. Still uncovered:
cross-DBID / fabricated / chunk-identity forgeries and the
chunk-availability probe, which need wire-level message control.

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

`TestEnforcedMeshConvergesAndRefusesForgery` (origin enforcement):

- 3-node enforced mesh converges; the relay holds verified
  origin signatures in `murmur_cell_sigs` (v2 proof).
- Rogue origin: A's site pinned to a wrong key on B/C; A's new
  row never lands there; restoring the true pin converges.
- Honest forward with the origin offline: C converges on A's
  row exclusively through B.
- Tampered forward: B's stored signature for A's row is
  corrupted; C refuses the re-export (row stays absent) while
  peered, then converges once the clean origin returns.

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
