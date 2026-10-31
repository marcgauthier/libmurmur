# crash-loop

Node 3 is SIGKILLed and restarted N times
(`MURMUR_CRASH_LOOP_ROUNDS`, default 5) under continuous writes from
every node, with short uptimes between restarts
(`MURMUR_CRASH_LOOP_UPTIME_MS`, default 1000). Every write acknowledged
before each restart must survive; the looped node must converge to
identical contents; it must reach ready within 60 s after the final
restart (no wedge); and a post-loop write on it must replicate
everywhere.

## Pass criteria (same as the reference)

- Positive control: baseline + full mesh + convergence within 30 s.
- Every non-final restart lands with a write provably in flight on the
  victim (10 s gate); the final round bursts 30 rows on a survivor and
  restarts within 500 ms (mid-replication by construction).
- Final restart reaches ready in under 60 s; mesh reforms (`[2, 2, 2]`
  peers) within 90 s; convergence within 90 s; every acknowledged write
  present everywhere.
- A post-loop write on the looped node replicates everywhere (60 s).

## Env knobs

- `MURMUR_CRASH_LOOP_ROUNDS` (default 5).
- `MURMUR_CRASH_LOOP_UPTIME_MS` (default 1000).

## Deviations from the reference

- Nodes are native replication drivers over VFS stores in child
  processes (`MURMUR_NODE_BIN`) instead of `murmur-server` children
  over the PG wire; kills are real SIGKILLs plus reboots on the same
  dir.
- Plain SQL (`records(id INTEGER PRIMARY KEY NOT NULL, name TEXT NOT
  NULL DEFAULT '')`, per-node id strides). Row identity in assertions
  is `name@id`.
- Session counts come from connected `SHOW PEERS` rows instead of the
  `peers` column of `MURMUR SHOW REPLICATION`.
- Table replication state persists in the store across restarts, so
  the reference re-set of `REPLICATED` after each restart is skipped;
  the re-mesh after each restart is kept via `PeerMesh` (there is no
  `SyncAll` verb here).
- Same durability adaptations as crash-recovery (see that suite's
  README for the full mechanism notes): retention tail 1000000,
  flusher at 50 ms, pre-kill victim drain (250 ms here),
  scheduler-level in-flight sleeper, staggered bounce of every
  node's replication after each restart, stall-breaking cursor
  reset plus re-bounce in the convergence waits, and light
  convergence polling.
- Victim rows written after the first restart are load-only
  (unacked): the victim faces another kill in every round but the
  last, and kills lose the unflushed tail. Survivor rows are acked
  throughout (their stores are never killed), victim rows are acked
  until the first round's drain, and the post-loop marker is acked
  (no kills remain). Every acknowledged write must still survive
  every round.
- The final-round 500 ms burst window is kept: the 250 ms victim
  drain runs inside it (burst on a survivor, drain, sleeper gate,
  kill), so the kill still lands mid-replication by construction.

Run from `clients/go`:

```sh
go build -o /tmp/murmur-test-node ./tests-live/node
MURMUR_ENGINE_INTEGRATION=1 MURMUR_NODE_BIN=/tmp/murmur-test-node go test -count=1 -timeout 600s ./tests-live/crash-loop/
```
