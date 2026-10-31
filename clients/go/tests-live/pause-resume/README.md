# pause-resume

Three nodes mesh while all take writes; node 2 is frozen for 15-30 s
while the survivors keep writing, then resumes with zero data loss and
converging contents. The freeze must be *detected* (alive-view dip,
suspect/dead state, or a dropped session), the frozen member must not
be evicted, and the catch-up path must be proven (log-path apply).

## Pass criteria (same as the reference)

- Full mesh (2 sessions + 2 alive members excl. self) within 60 s; 5-row
  baseline converges within 30 s.
- Freeze window honors `MURMUR_PAUSE_RESUME_STOP_SECONDS` (default 20,
  15 s floor) with writers flowing (25 ms tick) on the survivors.
- Detection proof: survivors' alive view dips below 2, the frozen peer
  leaves `alive` (suspect/dead), or its session drops during the freeze
  (else the freeze was undetected and the test fails); at least one
  write acks during the freeze.
- After resume: every acknowledged write present everywhere within
  180 s; sessions + membership re-admitted within 90 s; no eviction
  (2 connected alive peers on every node).
- Catch-up proven via the log path: the frozen node's cumulative
  remote-origin `applied` counter advances (snapshot application
  bypasses it and the paused writer keeps local commits out of the
  remote sum).
- A `post-resume` write converges within 60 s.
- Env-gated: SKIPs on Windows (no SIGSTOP/SIGCONT) and off linux (no
  /proc PID discovery).

## Deviations from the reference

- Nodes are native replication drivers over VFS stores instead of
  `murmur-server` children over pgwire; the frozen node runs as a child
  process (`ChildSet`) so the freeze stays a true process freeze:
  SIGSTOP/SIGCONT on the child, whose PID is discovered by scanning
  /proc for its `--dir` argv pair. Build it once with
  `go build -o /tmp/murmur-test-node ./tests-live/node` and set
  `MURMUR_NODE_BIN=/tmp/murmur-test-node`.
- Plain SQL replaces the typed-records API
  (`live_typed_records(name)` in cr-sqlite form); the table is
  explicitly flagged replicated on each node.
- Peer/member assertions use the decoded `SHOW PEERS` rows (per-peer
  `connected`/`state`, self row excluded) instead of pgwire
  `MURMUR SHOW` tables. The rows persist through the freeze and carry
  no last-seen stamp, so the alive-view dip plus suspect/dead state
  take the place of the reference's staleness leg.
- Writers are goroutines inside one `WaitGroup` with the freeze driver;
  the frozen node's writer pauses while it is suspended. Writers skip
  the per-write flush in the hot loop (committed state ships on the
  engine tick; the graceful-shutdown precedent) and flush at phase
  boundaries.
- Resume needs only SIGCONT plus an explicit re-mesh (no auto-redial);
  there is no `SyncAll` verb here (the crash-recovery precedent).
- With default retention the log still holds everything, so catch-up
  must arrive over the log path (a remote-origin `applied` delta on the
  frozen node; local commits move the own-origin row on this stack, so
  it is excluded from the sum).

## Verification

```sh
cd clients/go && go vet ./tests-live/pause-resume/ && \
  MURMUR_NODE_BIN=/tmp/murmur-test-node MURMUR_ENGINE_INTEGRATION=1 \
  go test -count=1 -timeout 600s ./tests-live/pause-resume/
```
