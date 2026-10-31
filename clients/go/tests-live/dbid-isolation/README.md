# dbid-isolation

Nodes from two different databases (distinct database ids) never peer
with each other, even when the TLS layer would admit them. Two
independent 2-node clusters with byte-identical schema share CA trust
(so TLS cannot be the refusal cause), then are cross-peered in both
directions: markers must never cross over the 10 s observation window
while both clusters stay internally healthy, and a session
group/identity mismatch must be observed (proving the cross dials
passed TLS and died on the database-id check).

## Pass criteria

- Clusters `dbid-iso-a` and `dbid-iso-b` (2 nodes each) boot with
  distinct database ids (asserted; the test is vacuous otherwise) and
  four distinct node ids (see below).
- CA trust is exchanged (peer CA appended to every `ca.pem`, then all
  nodes restart; `Start` re-reads the CA file).
- Positive controls: one marker per cluster converges internally.
- Cross `PeerAdd` runs in both directions (full bipartite). Over the
  10 s window (500 ms poll) each node holds only its own cluster's
  marker.
- Within a 15 s grace window a `last_error` containing `mismatch` is
  observed on at least one node (the latch holds only the last error
  per node, but every 5 s redial round ends with a mismatch latched on
  at least the last acceptor).

## Mapping

- The reference `SetConfig` bootstrap writes become runtime `PeerAdd`
  calls; there is no native config surface.
- The reference static-topology toggle has no native counterpart;
  internal edges persist from the bootstrap seeds.
- `NewCluster` cannot serve here: it assigns every cluster the same
  deterministic node ids, and cross-cluster id aliasing would let the
  accept path drop cross dials as self/duplicate sessions before the
  database-id check runs, making isolation vacuous. Both pairs boot
  through `goharness.BootNode` with explicit distinct ids, using only
  exported harness API (the reference Rust port fixes distinct ids for
  the same reason).
- Row polling is a local 60 s helper (the shared `AssertRows` needs a
  `*Cluster`); artifact handling (`PrepareRuntimeDir`,
  `DumpNodeForensics`, `FinishArtifacts`) matches the harness.
- The cr-sqlite DDL carries explicit `NOT NULL`/`DEFAULT` per the
  porting rules; see `../PORTING.md`.

Run from `clients/go`:

```sh
MURMUR_ENGINE_INTEGRATION=1 go test -count=1 -timeout 600s ./tests-live/dbid-isolation/
```
