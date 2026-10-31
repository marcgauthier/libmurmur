# crdt-contention

Three meshed nodes share one logical row (`contention(id, name, phone,
score)`): concurrent edits to separate cells (name on node 1, phone on
node 2, score on node 3) must all survive regardless of arrival order,
and 40 same-cell `name` updates per node must resolve to one winner,
identical on every node, with the full logical row equal everywhere.

## Pass criteria (same as the reference)

- Full `[2, 2, 2]` mesh, then the baseline row converges everywhere.
- Disjoint concurrent cell edits converge to the exact expected row.
- Same-cell contention converges with phone/score undisturbed; the
  winner is non-empty and comes from the concurrent write set; the
  whole logical row is identical on all three nodes.

## Env knobs

None beyond the standard harness gate (`MURMUR_ENGINE_INTEGRATION=1`).

## Deviations from the reference

- Native replication drivers over VFS stores, in-process through
  `goharness` (see `../PORTING.md`), instead of `murmur-server` children
  over pgwire.
- Session counts come from `ShowPeers` (connected rows) instead of
  `MURMUR SHOW REPLICATION`.
- cr-sqlite DDL: every `PRIMARY KEY` column carries explicit `NOT
  NULL`, and every `NOT NULL` column carries a `DEFAULT`.

Run from `clients/go`:

```sh
MURMUR_ENGINE_INTEGRATION=1 go test -count=1 -timeout 600s ./tests-live/crdt-contention/
```
