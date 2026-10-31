# maintenance-under-load

Three writers insert into bounded owned ranges and then update names
while background retention runs. A retention pass must land on every
node while writes are active. After stopping the writers, all four
columns must converge exactly, including untouched phone and score
values. A post-maintenance insert must still replicate.

`MURMUR_MAINT_LOAD_SEED` defaults to 120 rows,
`MURMUR_MAINT_LOAD_MAX_INSERTS` to 4,000 per writer, and
`MURMUR_MAINT_LOAD_GC_TIMEOUT` to 150 seconds (seconds or an s/m/h suffix).

## Deviations from the reference

- Native replication drivers over VFS stores, in-process through
  `goharness` (see `../PORTING.md`), instead of `murmur-server` children
  over pgwire.
- The reference's `retention_runs` counter maps to the health
  snapshot's `retention.last_collection_millis`, which advances on
  every pass whether or not floors moved.
- The pruning half is skipped with `harness: retention pruning
  observability`: the native pass runs, but the engine never advances
  the `collected_transactions` health counter, so actual collection is
  unobservable (`TestRetentionCollectsUnderSustainedLoad`).
- Retention tuning maps to `retention_min_kept = 1` in
  `murmur_config` (the pass reads its parameters from the store, so no
  restart is needed). The native retention pass runs on the 60 s
  engine tick rather than the reference's 100 ms interval, so the
  collection wait lands on the first or second tick; the 150 s
  `MURMUR_MAINT_LOAD_GC_TIMEOUT` default is unchanged.
- Writers yield 60 ms per iteration: the reference loops unpaced, but
  native replication converges only tens of rows per second, so
  unpaced ingest leaves a backlog the 120 s convergence wait can never
  drain (and unpaced in-process volume hangs native teardown). The load
  stays sustained on all three nodes for the full run-to-tick window.
- A durability flush on every node follows the writer join (the
  flap-port final sync): one node's stream tail otherwise stalls once
  its writer stops and never converges.
- cr-sqlite DDL: the `PRIMARY KEY` column carries explicit `NOT NULL`,
  and every `NOT NULL` column carries a `DEFAULT`.

Run from `clients/go`:

```sh
MURMUR_ENGINE_INTEGRATION=1 go test -count=1 -timeout 600s ./tests-live/maintenance-under-load/
```
