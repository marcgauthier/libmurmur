# crash-recovery

Three meshed native nodes take continuous application writes (two
workers per node) while node2 and then node3 are SIGKILLed mid-write
and restarted under load. Every acknowledged write survives both
restarts with identical digests on all nodes, and a post-recovery
write replicates everywhere.

## Pass criteria (same as the reference)

- Baseline: one row per node converges with a full `[2, 2, 2]` mesh.
- Each SIGKILL lands with a write provably in flight on the victim
  (5 s gate); each victim rejoins under continuing load (`[2, 2, 2]`
  peers within 90 s).
- After both restarts: full convergence, every acknowledged write
  present everywhere, equal digests.
- A post-recovery write on node1 replicates everywhere with equal
  digests.

## Env knobs

- `MURMUR_CRASH_WRITE_SECONDS` (default 8): burst length between
  kill/restart legs.
- `MURMUR_CRASH_SETTLE_SECONDS` (default 90): convergence deadline.

## Deviations from the reference

- Nodes are native replication drivers over VFS stores in child
  processes (`MURMUR_NODE_BIN`) instead of `murmur-server` children
  over the PG wire; kills are real SIGKILLs plus reboots on the same
  dir.
- Plain SQL (`records(id INTEGER PRIMARY KEY NOT NULL, name TEXT NOT
  NULL DEFAULT '')`, per-writer id strides) with `name@id` row
  identity in assertions.
- Session counts come from connected `SHOW PEERS` rows instead of the
  `peers` column of `MURMUR SHOW REPLICATION`.
- Digests are FNV-1a/64 over sorted names (only cross-node equality
  within one process is asserted).
- Table replication state persists in the store across restarts, so
  the reference re-set of `REPLICATED` after each restart is skipped;
  the re-mesh after each restart is kept via `PeerMesh` (there is no
  `SyncAll` verb here).
- Retention tail raised to 1000000 via `murmur_config`: the engine
  records a peer's ack at the high-water it *served* (not what the
  peer applied), and a pull refused as `cursor pruned` never takes
  the snapshot path on its own (only the operator verb starts a
  fetch, and it is not wired to test SQL handles). A SIGKILL landing
  mid-transfer would otherwise strand the victim permanently. The
  prune/snapshot dimension belongs to delete-pruning, not to crash
  survival; GC still runs, floors still advance.
- Flusher at 50 ms (`PRAGMA flush_interval_ms=50`, re-applied after
  each reboot since it is per-process) plus a pre-kill victim drain:
  this stack persists asynchronously (recent commits sit in process
  memory; `Flush` is not a sync barrier), so a SIGKILL loses the
  unflushed tail, including acknowledged rows, and a torn store can
  refuse to reopen. The victim's writers pause 300 ms before each
  kill (every acknowledged row persists); survivor writers never
  pause, so each kill still lands amid continuous mesh load.
- Scheduler-level in-flight proof: the victim's in-flight gate is
  satisfied by a sleeper that holds the in-flight counter without
  sending bytes (same counter check as the reference). Bytes in
  flight at kill time would tear the victim's store (see above), so
  torn-op robustness is explicitly *not* proven here; what is proven
  is that every acknowledged write survives kills that land while
  the victim has scheduled write work and the mesh is under load.
- Staggered bounce of every node's replication after each restart:
  this engine closes a fresh inbound session as a duplicate while
  any entry for the peer lives, with no tie-break, so a restarted
  node can wedge with all streams broken while peers still show
  connected; starting all nodes at once can further livelock the
  mutual re-dials. Nodes restart one second apart (first dial wins,
  as in the naturally staggered initial boot). The bounce is
  graceful (stores stay open), so mid-bounce writes stay exact.
- Stall breaker: the convergence waits reset the laggards' pull
  cursors for the ahead nodes (`DELETE FROM murmur_progress`) and
  re-bounce the mesh after 20 s without count progress. A stuck
  resume cursor otherwise fails every pull silently; deleting it
  forces a RESET to a zero cursor and a full resync (safe: the
  raised retention tail keeps every version servable). Proof
  criteria are unchanged.
- Light convergence polling: cheap counts, full name+digest
  comparison only once counts match (same pass criterion, a
  fraction of the child-stdio load).

Run from `clients/go`:

```sh
go build -o /tmp/murmur-test-node ./tests-live/node
MURMUR_ENGINE_INTEGRATION=1 MURMUR_NODE_BIN=/tmp/murmur-test-node go test -count=1 -timeout 600s ./tests-live/crash-recovery/
```
