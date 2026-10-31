# gc-balance

Three nodes mesh with aggressive log retention (minimum retained 10,
maximum offline 20 s) while node 0 updates a fixed 200-key
`contention` set with eight parallel updaters over disjoint ranges at
140 ms per op.

`TestGCChurnConvergesLosslessly` runs the portable legs: 200 seed rows
converge everywhere, the churn phase (`MURMUR_GC_BALANCE_CHURN_SECONDS`,
default 30 s) completes with zero update errors and at least 5 full
sweeps per updater, a follower observes a churned value end to end, and
the suite ends with exact row counts and identical contents on all
nodes (no loss).

`TestLogGCKeepsUpWithChurn` is the reference's core proof -- after a
20 s warmup, a 40 s window (stretched to a 150 s cap until a 2000-commit
floor is met) must show GC collecting at least 90% of the origin-log
batches the window produced, with zero GC failures -- and is skipped:
the balance ratio needs a collected-batches counter (`SHOW RETENTION`),
the engine never advances `collected_transactions`, and there is no
on-demand collect verb, so collection is unobservable (the
maintenance-under-load precedent).

Scope (same as the reference): version churn only; deletes are out of
scope.

## Env knobs

- `MURMUR_GC_BALANCE_CHURN_SECONDS` (default 30): churn phase length
  for the lossless-convergence test (port-only knob; the reference
  paces its window off a commit floor instead).

## Deviations from the reference

- Nodes are native replication drivers over VFS stores, driven
  in-process through `goharness` (see `../PORTING.md`) instead of
  `murmur-server` children over pgwire.
- Retention comes from `murmur_config` (`retention_min_kept 10`,
  `retention_max_offline_ms 20000`) applied with a replication restart
  (the graceful-shutdown mechanism); the reference's 1 s retention and
  1 s collection cadence have no native equivalent (the native
  retention tick runs about every 60 s).
- `$N` placeholders are translated to `?` automatically; the
  `contention` DDL uses cr-sqlite form (`NOT NULL` primary key,
  `DEFAULT` on every `NOT NULL` column). Digest agreement compares full
  ordered row vectors directly instead of hashing.
- There is no `SyncAll` verb here; convergence waits carry the drain
  (the crash-recovery precedent).
- The measurement window, commit floor, GC-error check, and
  `MURMUR RETENTION COLLECT` drain belong to the skipped balance proof.

## Verification

```sh
cd clients/go && go vet ./tests-live/gc-balance/ && \
  MURMUR_ENGINE_INTEGRATION=1 go test -count=1 -timeout 600s ./tests-live/gc-balance/
```
