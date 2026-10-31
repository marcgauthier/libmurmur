# flap-partition

Three fully meshed nodes take continuous writes from all nodes while
node 3's links flap through split/heal cycles. A partition must never
fail a write to a live node (all commits are local), and after the
final heal every node must converge on the identical row set with equal
contents. The first split carries an isolation proof: a marker written
on node 1 must reach node 2 but never node 3.

## Pass criteria

- 3 meshed nodes under `tests-live/runtime/flap-partition/`.
- The `records` table is created on every node and flagged replicated
  on each one (row convergence needs the per-node flag).
- 6 baseline inserts on node 0 converge on all 3 nodes within 150 s
  (honest-path control).
- Continuous writers on every node (50 ms cadence each) run across
  `MURMUR_FLAP_CYCLES` split/heal cycles (split hold
  `MURMUR_FLAP_SPLIT_SECONDS`, heal settle
  `MURMUR_FLAP_HEAL_SECONDS`).
- On the first split, the isolation marker reaches node 2 within 10 s
  and never appears on node 3 (checked throughout the window plus a
  1 s post-proof leak watch).
- Zero failed writes to live nodes (node 3's store never closes, so
  its local commits must succeed too).
- After the final idempotent heal, all 3 nodes converge on exactly
  `6 + written` rows with equal ordered contents within 150 s.

## Env knobs

- `MURMUR_FLAP_CYCLES` (default 5): split/heal flap cycles.
- `MURMUR_FLAP_SPLIT_SECONDS` (default 3): split hold per cycle.
- `MURMUR_FLAP_HEAL_SECONDS` (default 2): heal settle per cycle.

## Deviations from the reference

- Native replication drivers over VFS stores, in-process through
  `goharness` (see `../PORTING.md`), instead of `murmur-server` children
  over pgwire.
- This stack has no runtime peer-removal verb, so splits and heals
  rewrite the per-node `allowed_peers` allow-lists and restart
  replication (the partition-port technique); the transport refuses
  cross-partition sessions in both directions. Topology changes use
  config rewrites and replication restarts; this does not emulate
  packet loss on an otherwise running connection.
- `SyncAll` maps to a durability flush on every node.
- cr-sqlite DDL: the `PRIMARY KEY` column carries explicit `NOT NULL`,
  and `name` carries a `DEFAULT`.

Run from `clients/go`:

```sh
MURMUR_ENGINE_INTEGRATION=1 go test -count=1 -timeout 600s ./tests-live/flap-partition/
```
