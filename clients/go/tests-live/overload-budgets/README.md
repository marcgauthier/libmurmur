# overload-budgets

Two nodes take a small baseline write, then 8 concurrent writers x 50
inserts fully converge with p99 insert latency under 10 s while both
nodes stay responsive (full peer set plus a successful read probe).

## Pass criteria

- A small baseline write converges on both nodes.
- 8 x 50 concurrent inserts on node 0 all succeed, p99 insert latency is
  under 10 s, and both nodes converge on identical digests of all 401 rows.
- Both nodes finish responsive (full peer set + a successful read probe).

## Env knobs

None; the standard harness gate (`MURMUR_ENGINE_INTEGRATION=1`) applies.

## Deviations from the reference

- Native replication drivers over VFS stores, in-process through
  `goharness` (see `../PORTING.md`), instead of `murmur-server` children
  over pgwire.
- The oversize-write rejection legs are skipped with `harness: local
  commit budget enforcement`: this stack enforces byte budgets on the
  replication export path only — a local insert carrying a value past
  any budget is accepted, so the "rejected naming the budget / no
  partial row / writer not poisoned" assertions cannot run, and there
  is no replayable `40001` backpressure signal to retry.
- `WaitNodeReady` maps to a `ShowPeers` connected count plus read probe.
- Plain SQL (`records(id, name, phone, score)`) with an explicitly
  replicated table; the convergence digest is a sorted row dump (same
  criterion: identical ordered row sets).
- cr-sqlite DDL: the `PRIMARY KEY` column carries explicit `NOT NULL`,
  and every `NOT NULL` column carries a `DEFAULT`.

Run from `clients/go`:

```sh
MURMUR_ENGINE_INTEGRATION=1 go test -count=1 -timeout 600s ./tests-live/overload-budgets/
```
