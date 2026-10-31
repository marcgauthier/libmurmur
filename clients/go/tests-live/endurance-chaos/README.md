# endurance-chaos (native port)

Reference: `/home/marc/DEV/MURMUR-SQL/tests-live/endurance-chaos/`
(`endurance_chaos_test.go`: `TestEnduranceChaos`).

## What it proves

Combined-fault validation: a live multi-node mesh of child-process
nodes absorbs continuous writes while rolling restarts (alternating
real SIGKILL crash legs and graceful replication stop/start legs),
peer-edge flaps, and disk pressure all overlap for a configured chaos
window. The verdict is exact cross-node convergence (equal row counts
plus identical PK-ordered row contents) with at least one restart,
impairment cycle, and disk hold executed, a rejoined full mesh, and a
post-chaos write that converges everywhere.

Key rotation, snapshot offline windows with resync proof, and
counter-proven GC progress are degraded legs (see below); each has a
skipped companion test naming the harness gap.

## Env knobs

Same names and defaults as the reference:

- `MURMUR_ENDURANCE_NODES` (default 5): nodes in the mesh (clamped to 3..16).
- `MURMUR_ENDURANCE_DURATION_SECONDS` (default 600): chaos window.
- `MURMUR_ENDURANCE_SETTLE_SECONDS` (default 300): max convergence wait.
- `MURMUR_ENDURANCE_WRITE_INTERVAL_MS` (default 25): pacing per writer
  task (up to 8 writers).
- `MURMUR_ENDURANCE_MAX_ROWS` (default 10000): live-id ceiling; past it
  writers recycle via updates/deletes.
- `MURMUR_ENDURANCE_SEED` (default 1): RNG seed.
- `MURMUR_ENDURANCE_STATUS_SECONDS` (default 30): heartbeat interval.
- `MURMUR_ENDURANCE_RESTART_SECONDS` (default 90): mean rolling-restart
  interval; `MURMUR_ENDURANCE_RESTART_DOWN_SECONDS` (default 8): downtime
  per restart.
- `MURMUR_ENDURANCE_ROTATE_SECONDS` (default 180): parsed but the
  rotation leg is degraded away (no native rotation verb).
- `MURMUR_ENDURANCE_SNAPSHOT_SECONDS` (default 300) /
  `MURMUR_ENDURANCE_SNAPSHOT_OFFLINE_SECONDS` (default 75, minimum 60):
  parsed but snapshot windows are skipped in-run (stale rejoin via
  snapshot resync does not converge).
- `MURMUR_ENDURANCE_IMPAIR_ON_SECONDS` (default 60) /
  `MURMUR_ENDURANCE_IMPAIR_OFF_SECONDS` (default 20): impairment phase
  length and clear gap. `MURMUR_ENDURANCE_IMPAIR_LATENCY_MS` (default 150)
  and `MURMUR_ENDURANCE_IMPAIR_LOSS_PCT` (default 3) are parsed and logged
  but have no effect (flap-only; no tc privilege model for child
  processes).
- `MURMUR_ENDURANCE_DISK_SECONDS` (default 180) /
  `MURMUR_ENDURANCE_DISK_MB` (default 128) /
  `MURMUR_ENDURANCE_DISK_HOLD_SECONDS` (default 60): disk-pressure holds.
- `MURMUR_ENDURANCE_SKEW_SECONDS` (default 120): parsed and logged but the
  skew leg is degraded away (no daemon for libfaketime).

Child-process legs need the node binary built and pointed at:
`go build -o /tmp/murmur-test-node ./tests-live/node` and
`MURMUR_NODE_BIN=/tmp/murmur-test-node`.

Full-duration CI runs may need `MURMUR_ENDURANCE_SETTLE_SECONDS`
raised above the 300 default: verdict resync replays the whole chaos
window from the origin logs (observed ~160 s after a 120 s / 3-node
window) and scales with chaos volume.

Quick smoke (short chaos window proving the port; full-duration runs
are for CI):

```sh
cd clients/go
go build -o /tmp/murmur-test-node ./tests-live/node
MURMUR_ENGINE_INTEGRATION=1 MURMUR_NODE_BIN=/tmp/murmur-test-node \
MURMUR_ENDURANCE_NODES=3 MURMUR_ENDURANCE_DURATION_SECONDS=120 \
MURMUR_ENDURANCE_SETTLE_SECONDS=120 MURMUR_ENDURANCE_RESTART_SECONDS=30 \
MURMUR_ENDURANCE_IMPAIR_ON_SECONDS=15 MURMUR_ENDURANCE_IMPAIR_OFF_SECONDS=10 \
MURMUR_ENDURANCE_DISK_SECONDS=60 MURMUR_ENDURANCE_DISK_MB=16 \
MURMUR_ENDURANCE_DISK_HOLD_SECONDS=15 MURMUR_ENDURANCE_STATUS_SECONDS=15 \
  go test -count=1 -timeout 600s ./tests-live/endurance-chaos/
```

## Pass criteria

- The baseline row converges on every node before chaos starts.
- At least one write is acked during the run (anti-vacuous guard).
- After chaos stops, every node is reachable with equal row counts and
  identical PK-ordered row contents within settle.
- At least one restart, impairment cycle, and disk hold (unless
  degraded for space) executed.
- A full N-1 peer mesh is back, and a post-chaos write converges
  everywhere.

Transient write errors during chaos are counted, never fatal.

## Deviations from the reference

- Native replication drivers over VFS stores in child processes
  instead of `murmur-server` children over the PostgreSQL wire
  protocol (per design); crash legs are real SIGKILLs with a reboot
  on the same dir, graceful legs stop/start replication in place.
- Plain SQL (`contention(id TEXT PRIMARY KEY NOT NULL DEFAULT '',
  name TEXT NOT NULL DEFAULT '', phone TEXT NOT NULL DEFAULT '',
  score INTEGER NOT NULL DEFAULT 0)`) with cr-sqlite DDL rules
  (explicit `NOT NULL` on the PK, `DEFAULT` on every `NOT NULL`
  column); the table is flagged replicated on each node via
  `SetTableReplicated`. Writer row shapes keep the reference 32-hex-char
  ids (`%08x%024x` per writer/sequence) and `writer-<n>` names.
- Convergence compares exact sorted row vectors (which imply equal
  counts and digests); the logged digest is dependency-free FNV-1a.
- tc/netem impairment degrades to `allowed_peers` edge flaps in all
  runs (the flap-partition technique: no runtime peer-removal verb
  exists): both endpoints restart replication with all-except-peer
  allow-lists, cycling the latency -> loss -> both phase names, then
  clear the lists and re-mesh. Flap open/restore waits out restart
  downtime on either endpoint (a downed child cannot take the
  allow-list rewrite).
- Clock skew is always skipped and reported as degraded, as in the
  reference.
- Key rotation is always skipped and reported as degraded: the
  bindings expose no rotation verb (same gap as the rekey suite;
  `TestEnduranceKeyRotationLeg` names it).
- Snapshot offline windows are skipped in-run: a stale rejoin over
  the snapshot path does not converge after retention GC (same gap as
  the snapshot-resync suite; `TestEnduranceSnapshotResyncLeg` names
  it). `retention_min_kept` is raised to 1000000 so restart
  outages rejoin over the log path; snapshot trust is wired
  up front by the harness (every node trusts every node).
- The GC progress proof is skipped: no `SHOW RETENTION`/collected
  counter exists and `collected_transactions` never advances (same gap
  as the gc-balance suite; `TestEnduranceGCProgressLeg` names it).
  The status sampler still logs row spread, write/fault tallies, and
  minimum disk free space.
- `retention_min_kept` is raised to 1000000 up front (the
  crash-recovery technique): the verdict stall breaker resets pull
  cursors to 0, which must replay the full origin log instead of
  hitting prune (`cursor pruned; snapshot required` is unrecoverable
  here since snapshot resync does not converge). One million kept
  versions covers any chaos window.
- Disk filler lands in each child node dir with the same 1 GiB
  headroom guard; free space comes from a local statfs probe.
- Writers, the status sampler, and the disk cycler run as goroutines
  sharing the cluster through one mutex; the director runs on the
  test goroutine. Every cluster touch locks, and each write re-checks
  its target's alive flag under the same lock, so lifecycle
  (stop/kill/start) and reads never race.
- The verdict convergence loop carries the crash-recovery stall
  breaker: post-restart sessions intermittently wedge with pulls
  silently dying while peers show connected, so 20 s without
  row-count progress resets every node's pull cursors for every
  other node (`DELETE FROM murmur_progress ...`, forcing a RESET to
  a zero cursor and a full resync) and bounces the mesh (stop all,
  staggered start all, re-mesh). All pairs reset because deletes
  move counts both ways; fires are cooldown-gated at 60 s so a
  slow-but-healthy full replay is not torn down mid-transfer.
  Proof criteria are unchanged.
- The markdown report is written to `runtime/endurance-chaos/`
  (retained under `tests-live/failures/` on FAIL via
  `Cluster.Finish`) instead of next to the test, so passing runs
  leave the repo clean.
- One table, one bounded working set; no file traffic or schema
  migration during chaos, same as the reference.

## Compile check

```sh
cd clients/go && go vet ./tests-live/endurance-chaos/
```
