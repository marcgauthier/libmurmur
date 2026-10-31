# delete-pruning

Three nodes hold the same key range through concurrent deletes,
resurrections, and updates (converging after every phase); then
retention collection prunes the delete batches while a post-prune
write still replicates everywhere.

## Pass criteria (same as the reference, adapted mechanics)

- Seed converges (300 rows everywhere).
- Phase 1 (node 1 deletes third 1, node 2 updates third 2, node 3
  deletes third 3) converges on 100 rows; phase 2 (resurrect third
  1) on 200; phase 3 (delete third 2) on 100.
- Collection: pre-collection tombstones >= 100 (non-vacuity), then
  the replicated tombstone count drops and the summed
  `retained_from` floors advance past baseline.
- Post-prune write on node 2 replicates everywhere with exact names.

## Env knobs

- `MURMUR_PRUNE_KEYS` (default 300, must stay a multiple of 3).
- `MURMUR_PRUNE_TIMEOUT_S` (default 25): convergence deadline.
- `MURMUR_PRUNE_COLLECT_TIMEOUT_S` (default 150): collection
  deadline (reference: 120 s with an explicitly driven collector;
  here collection rides the engine's automatic 60 s retention pass,
  so 150 s covers a just-missed tick plus margin).

## Deviations from the reference

- Nodes are native replication drivers over VFS stores (in-process;
  no kills in this suite) instead of `murmur-server` children over
  the PG wire.
- Plain SQL (`rows(id TEXT PRIMARY KEY NOT NULL DEFAULT '', name
  TEXT NOT NULL DEFAULT '')`).
- Aggressive retention is set through `murmur_config`
  (`retention_min_kept=10`, matching the reference's aggressive
  floor). There is no per-test collection-interval knob: the pass
  runs on the engine's automatic 60 s tick.
- Collection is observed, not driven: there is no `RETENTION
  COLLECT` verb or `SHOW RETENTION` counter binding, so the test
  awaits the automatic pass and proves collection two ways — the
  `crsql_changes` tombstone count drops (300 -> ~10) and the
  summed `retained_from` floors advance (as in graceful-shutdown).
- Table replication state persists in the store, so no `REPLICATED`
  re-set is needed.

Run from `clients/go`:

```sh
MURMUR_ENGINE_INTEGRATION=1 go test -count=1 -timeout 600s ./tests-live/delete-pruning/
```
