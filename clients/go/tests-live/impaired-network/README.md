# impaired-network

A 3-node mesh keeps converging while tc/netem impairs ONLY the
replication ports: (a) +150 ms latency, (b) 3% packet loss, (c) a
1 Mbit cap during a stale-node snapshot resync under sustained
writes. Membership must stay stable (no false evictions) and
per-row visibility latencies are recorded with relaxed p95 bounds.

## Status: partial (harness gap before phase (c))

`TestImpairedNetworkConverges` runs the baseline plus the latency
and loss phases, then skips with:

- `harness: retention tuning + on-demand retention collect +
  snapshot delivery for the capped stale-rejoin leg (no
  replication knobs, no SHOW RETENTION binding, stale rejoin never
  converges)`

Phase (c) needs all three at once: aggressive retention tuning to
force the snapshot path (the harness exposes no replication
knobs), an on-demand retention pass (no `RETENTION COLLECT`
binding), and snapshot delivery for the stale rejoin (stale rejoin
never converges on this stack: the snapshot-resync gap, verified
first-hand by sibling suites).

## Env knobs

- `MURMUR_IMPAIRED_NETWORK_FORCE=1` runs the workload with no
  impairment (logic verification only, with loud disclaimers).
- `MURMUR_IMPAIRED_NETWORK_ROWS` overrides the per-phase row count
  (default 8).
- Without tc/netem + CAP_NET_ADMIN on lo (and without FORCE), the
  test skips like the reference; qdisc 77: is always removed, on
  success and on failure.

## What runs here

- Baseline converges unimpaired within 150 s (honest-path control).
- Latency phase: timed rows, 30 s per-row visibility, p95 within 15 s.
- Loss phase: timed rows, 45 s per-row visibility, p95 within 30 s.
- Every timed row samples stable membership (2 connected peers) on
  all nodes.

## What the reference proves beyond this port

- Capped phase: 5 stale rows, node3 stops; 60 survivor rows;
  retention pin lapses + one GC pass; restart into the 1 Mbit cap
  with 20 sustained writes; convergence within 180 s with the
  snapshot path proven via flat log-path counters; membership
  restored within 60 s.

## Deviations from the reference

- Membership is the connected-peer count from `ShowPeers` (the
  progress snapshot has no member view); the alive-count check has
  no equivalent (evictions still fail the member view).
- The mesh is explicit all-to-all `PeerAdd`: native nodes never
  dial beyond their seeds, so seed bootstrap alone stays
  hub-and-spoke (established partial-mesh finding).
- Ordered-vec equality replaces the digest (as in the reference port).
- `contention(id TEXT, name TEXT)` gains the cr-sqlite `NOT NULL` /
  `DEFAULT` qualifiers.
- The tc probe runs `tc -V`: the reference's `tc --version` is
  rejected by iproute2 (exit 255), which would wrongly report "tc
  binary not found" even where tc works.
