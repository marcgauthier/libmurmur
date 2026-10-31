# tail-repair

A node partitioned mid-write-burst misses a contiguous range of its
peers' origin logs, then heals and must repair the missing tail from
peer logs WITHOUT the snapshot path: row counts and ordered digests
converge everywhere while the healed node's log-path counter proves
the range arrived as transactions, not as a snapshot.

## Pass criteria

- 3 meshed native nodes under `tests-live/runtime/tail-repair/`.
- Baseline of 10 rows on node 0 converges on all 3 nodes (counts +
  equal digests) within 30 s.
- After isolating node3 from both peers (both directions), node3
  reports 0 connected peers within 15 s.
- Isolation probe: one row on node 0 reaches node 1 within 15 s but,
  after a 2 s settle margin, node3 still holds exactly the 10 baseline
  rows with an unchanged digest (leak = fail).
- A burst of `MURMUR_TAIL_REPAIR_BURST_ROWS` rows (default 100),
  alternating nodes 0/1, converges on both survivors within 30 s while
  node3 stays frozen at the baseline (anti-vacuity: it must actually
  miss the contiguous `1 + burst` range).
- After healing, every node reports 2 connected peers within 30 s and
  all 3 converge on the full row set with equal digests within 60 s.
- No-snapshot proof: node3's cumulative applied-transactions counter
  advances by at least the missed count across the heal (values logged
  for diagnosis).
- A post-heal insert on the healed node reaches all 3 nodes (counts +
  equal digests) within 30 s.

## Env knobs

- `MURMUR_TAIL_REPAIR_BURST_ROWS` (default 100): burst rows written on
  the survivors while node3 is isolated. Same name and default as the
  reference.

## Deviations from the reference

- Nodes are native replication drivers over VFS stores, driven
  in-process through `goharness` (see `../PORTING.md`) instead of
  `murmur-server` children over pgwire. Plain SQL
  (`records(id INTEGER PRIMARY KEY, name TEXT)`) with the same marker
  ids (0-9 / 9000 / 10000+i / 20000); every node flags the table
  replicated before any writes.
- This stack has no runtime peer-removal switch, so isolation uses
  per-node `allowed_peers` identity allow-lists (the partition-suite
  pattern) applied with a replication restart: nodes 0 and 1 allow
  only each other, node3 allows only itself. Healing clears the
  lists, restarts, and remeshes.
- Connected-peer waits read `ShowPeers` instead of the `peers` column
  of `MURMUR SHOW REPLICATION`.
- The reference's generous retention overlay (300 s, 10000 batches)
  is not applied: the missed range (~101 transactions) stays
  comfortably inside the product default retention, so log repair is
  the only legitimate healing path either way.
- The no-snapshot proof is behavioral only: the harness always
  configures `snapshot_trusted_sources`, so the reference's
  structural "no snapshot could have been taken" argument does not
  transfer. The cumulative applied counter (summed over per-origin
  `applied` in the progress snapshot) still proves the range arrived
  as log transactions, since snapshot application bypasses it.
- The digest keeps the reference rendering (`%#v` of the sorted
  `(id, name)` pairs).

Run from `clients/go`:

```sh
MURMUR_ENGINE_INTEGRATION=1 go test -count=1 -timeout 600s ./tests-live/tail-repair/
```
