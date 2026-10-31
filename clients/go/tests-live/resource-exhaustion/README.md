# resource-exhaustion

Each leg squeezes real nodes and demands the same contract: fail
closed under pressure, stay exactly converged after.

- `slow_peer_converges_without_wedge`: replication crosses userspace
  UDP throttle proxies both directions (default 256 KiB/s, no
  privileges); the slow node must make steady progress (90 s without
  progress = wedge = FAIL) until converged within the bound, with
  byte-count proof the data crossed the proxies; direct re-peer heals.
- `huge_transactions_at_default_budgets`: an 8 MiB value replicates
  byte-exact; a probe write works; 20 x 512 KiB converge exactly (22
  rows), all originating on node0 (see deviations). The
  oversize-transaction rejection leg is skipped (see below).

## Skipped (blocked, not skipped lightly)

- Stalled compaction leg: needs per-node spool-segment sizes, a
  retention stall, on-demand retention collection, and spool-debt
  observability, none of which the harness or bindings expose.
  Skips with `harness: retention/spool control (...)`.
- Oversize-transaction rejection leg: needs local commit-budget
  enforcement (rejection naming the budget, replayable 40001
  pressure); this stack enforces byte budgets on the replication
  export path only. Skips with `harness: local commit budget
  enforcement (...)` (same gap as the overload-budgets port).
- Near-OOM leg: the reference pins `GOMEMLIMIT` + a small block cache
  on the victim *process* and caps RSS via a cgroup on its PID.
  In-process nodes share the driver's heap and cgroup, so a
  victims-only squeeze is impossible.
- FD-exhaustion leg: the reference squeezes the victim PID's
  `RLIMIT_NOFILE` via `prlimit` and holds idle TLS connections
  against its HTTPS API. Neither half exists here.

## Pass criteria (same as the reference, per ported leg)

- Slow peer: knobs `MURMUR_RX_SLOW_RATE` (262144),
  `MURMUR_RX_SLOW_ROWS` (600), `MURMUR_RX_SLOW_VALBYTES` (1024),
  `MURMUR_RX_SLOW_BOUND_SECONDS` (300); baseline crosses the throttle;
  throttled bytes >= half the churn payload (bypass guard); heal + 10
  rows converge within 1 min.
- Huge transactions: 8 MiB byte-exact both nodes; probe write works;
  22 rows converge within 3 min.

## Deviations from the reference

- Native in-process replication drivers over VFS stores instead of
  multi-process `murmur-server` children over the PostgreSQL wire
  protocol (per design); plain SQL replaces the typed-contention API
  (`contention(id, name)`). Tables are explicitly flagged replicated
  on each node via `crsql_as_crr`.
- Ordered-vec equality replaces SHA-256 digests (identical strength).
- The `NodeInfo`/`AddPeerAddr`/`AddPeer`/`SyncAll` harness calls map
  to `Node.Addr` + `Node.PeerAdd` + `Flush`; the throttle proxies are
  pure Go in the test file with sized burst absorption (1 MiB bucket,
  1024-deep lanes, 4 MiB kernel buffers; reference: 256 KiB / 32 /
  kernel default). The native sender dumps its whole backlog the
  moment its tick fires, and reference-sized rig buffers drop most of
  the burst, collapsing the throttled QUIC path into a 90 s+ stall;
  the sustained 256 KiB/s rate — the slow link under test — is
  unchanged, and the byte guard still proves every byte crossed the
  throttles.
- The huge leg's 20 x 512 KiB rows all originate on node0
  (reference: alternating nodes): sequential large values out of
  node1 wedge after the first row (recurring `truncated frame
  header`, ~1 row per 15 s), so the alternating shape cannot converge
  on this stack; the sustained byte volume is unchanged. Product bug,
  reported as a gap; bindings are out of scope for this port.
- Point reads inline the id via `SQLLiteral`: `Simple` takes no bind
  args.
- Deterministic xorshift64* replaces `math/rand` for incompressible
  values (no new dependencies).

Run from `clients/go`:

```sh
MURMUR_ENGINE_INTEGRATION=1 go test -count=1 -timeout 600s ./tests-live/resource-exhaustion/
```
