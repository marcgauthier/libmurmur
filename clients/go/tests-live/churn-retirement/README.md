# churn-retirement

Three nodes mesh; node 3 is excluded on the survivors. The port keeps
the runnable pass criteria:

1. Baseline: five rows written on node 1 converge identically on all nodes.
2. Sessions to node 3 drop on both survivors; each survivor sees exactly one
   open session (the other survivor).
3. Node 3's writes stop arriving (survivors keep only the five baseline rows
   across a 5 s hold).
4. Exclusion survives a survivor restart with no rediscovery re-mesh
   (restarted node 1 re-meshes only its fellow survivor).
5. Explicit re-adding heals replication (all nodes converge on six rows).
6. The retired peer releases its GC retention pin — SKIPPED (see below).

## Env knobs

None beyond the standard harness gate (`MURMUR_ENGINE_INTEGRATION=1`).

## Deviations from the reference

- Native replication drivers over VFS stores, in-process through
  `goharness` (see `../PORTING.md`), instead of `murmur-server` children
  over pgwire.
- This stack has no runtime peer-removal verb, so exclusion and
  re-adding use per-node `allowed_peers` allow-lists plus replication
  restarts (the partition-port technique); the transport refuses
  excluded sessions in both directions.
- Node ids are the harness-fixed sequential ids: the reference's
  pinned adversarial id order (restarted node sorting last) is not
  expressible in `ClusterOptions`.
- The retirement leg is skipped with `harness: peer retirement +
  retention introspection`: the C engine implements retire/retention
  introspection behind a SQL verb surface that is never registered on
  driver connections and has no Go binding, so neither the `retired`
  retention record nor the gating-set shrink is observable.
- cr-sqlite DDL: the `PRIMARY KEY` column carries explicit `NOT NULL`,
  and `name` carries a `DEFAULT`.

Run from `clients/go`:

```sh
MURMUR_ENGINE_INTEGRATION=1 go test -count=1 -timeout 600s ./tests-live/churn-retirement/
```
