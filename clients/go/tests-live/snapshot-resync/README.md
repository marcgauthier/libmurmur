# snapshot-resync

Stale nodes rejoin via snapshot after their log ranges are pruned
past retention.

## Status: passing

All three legs pass (~65-75 s each; the legs wait out the 60 s
automatic collection tick since there is no RETENTION COLLECT verb).

This suite used to skip with `harness: stale rejoin via snapshot
resync does not converge after retention GC`. Two engine fixes closed
it: the pull loop now requests a snapshot automatically on a pruned
cursor (trust-gated, sweep-paced; `maybe_request_snapshot` in
`deps/murmur/driver.c`), and `murmur_session_open_stream` reserves
each QUIC stream id at open time (concurrent opens used to mint the
same id twice and cross both streams' bytes, starving one reader).
A third fix makes the prune proof observable:
`murmur_collect_floors` now advances the cumulative
`collected_transactions` counter it previously never bumped.

## What the reference proves

- 3 nodes mesh; node3 writes 5 `stale-*` rows; all converge.
- Node3 stops; node1 writes 60 `fresh-*` rows; survivors converge
  on 65 rows.
- After the member-deadline wait, each survivor prunes >= 40
  transactions and no longer pins node3.
- Node3 restarts with the same durable directory; all converge on
  65 rows with equal digests while node3's applied-log growth stays
  within the retained tail and far below the gap; the 5 pre-stop
  rows survive the merge.
- Dual leg: two stale nodes rejoin back-to-back onto one survivor
  with overlapping snapshot requests.
- Multi-source leg: 4 nodes; the victim stops while a survivor
  writes 6,000 rows; the victim rejoins under three concurrent
  sources and converges on 6,005 rows.

## Notes for a future port

- Retention is configurable via `murmur_config`
  (`retention_min_kept`, `retention_max_offline_ms`); collection
  runs on the driver's automatic pass (there is no `MURMUR
  RETENTION COLLECT` verb), so the collection proof must poll the
  progress snapshot's `retained_from` floors (the graceful-shutdown
  pattern), and the member-deadline wait is longer than the
  reference's.
- Retention pins and prune totals have no `SHOW RETENTION`
  equivalent; `collected_transactions` in the health snapshot never
  advances (floors are the prune signal).
- The snapshot-path proof (applied-log growth within the retained
  tail) maps to the per-origin `applied` counters of
  `ShowReplication`, excluding each node's own origin (local
  commits move the own-origin row here).
