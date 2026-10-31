# graceful-shutdown

Phase A stops node 0 mid-write under concurrent client write load,
restarts it cleanly, loses zero acknowledged writes, and reconverges.
Phase B restarts node 2 stale (log ranges GC'd after the member
deadline expires, forcing snapshot-resync) and interrupts it
mid-transfer with a clean stop.

## Pass criteria

- 5-row baseline converges across all nodes.
- Phase A (`TestGracefulShutdownMidWriteUnderLoad`, running) stops
  node 0 with writes in flight under load; restarts cleanly; cluster
  converges within 60 s with every acknowledged write present.
- Phase B (`TestGracefulShutdownMidSnapshotDuringRejoin`, skipped):
  50 survivor rows + 8 fat (~64 KB) rows converge on both survivors
  while node 2 is offline; node 2's session drops; retention GC
  prunes its range; node 2 restarts, is interrupted mid-transfer,
  restarts again, and all nodes reconverge with all rows intact plus
  a `post-recovery-write`. Skipped: after retention GC prunes the
  stale range, the rejoining node restores its sessions but the
  pruned range never arrives (no snapshot delivery), so the
  reconvergence leg cannot pass (`harness: stale rejoin via snapshot
  resync does not converge after retention GC`).

## Deviations from the reference

- Nodes are native replication drivers over VFS stores, driven
  in-process through `goharness` (see `../PORTING.md`) instead of
  `murmur-server` children over pgwire. The `contention` table keeps
  its shape with cr-sqlite DDL rules (`TEXT` keys, `NOT NULL` +
  `DEFAULT` everywhere, booleans n/a).
- The reference SIGTERMs a server child; this stack exposes no child
  PID/signal surface, so shutdown is the graceful in-process driver
  stop (`StopNode`) and restart is `StartNode`. The reference's
  `trusted_snapshot_sources` config loop is unnecessary: the harness
  already trusts every peer.
- The reference replication YAML (`retention: 1s`,
  `minimum_retained: 10`, `maximum_offline: 5s`) maps to
  `murmur_config` bounds (`retention_min_kept=10`,
  `retention_max_offline_ms=5000`) applied with a replication restart
  before the baseline; there is no time-window retention key on this
  stack.
- There is no on-demand `MURMUR RETENTION COLLECT` verb here, so the
  collection proof awaits the driver's automatic retention pass
  (every 60 s) by polling the progress snapshot until both
  survivors' retained floors advance past baseline.
- Phase A writers run `Execute` on the shared harness nodes (the
  handle is mutex-guarded) instead of separate client connections.
- `MURMUR SHOW PEERS` session-drop checks read `ShowPeers` connected
  rows; row convergence keeps the reference shape (equal non-empty
  ordered names on all 3 nodes).

Run from `clients/go`:

```sh
MURMUR_ENGINE_INTEGRATION=1 go test -count=1 -timeout 600s ./tests-live/graceful-shutdown/
```
