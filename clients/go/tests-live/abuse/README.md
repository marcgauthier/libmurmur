# Mesh abuse across four phases

Continuous writers exercise a healthy mesh, a two-sided partition, a
partial-node outage and a whole-mesh kill/restart storm. Before a node
is stopped, its writer slot is drained through a flush; surviving nodes
keep accepting writes during the partial outage. The verdict compares
every ordered application column on every node against the exact
acknowledged-row ledger.

## Defaults

`MURMUR_ABUSE_NODES=10` (clamped to 3..256),
`MURMUR_ABUSE_DURATION_SECONDS=600`,
`MURMUR_ABUSE_SETTLE_SECONDS=900`,
`MURMUR_ABUSE_WRITE_INTERVAL_MS=100`, `MURMUR_ABUSE_SEED=1`, and
`MURMUR_ABUSE_STATUS_SECONDS=15`. Four phases share the requested load
duration; readiness and convergence add time. The seed selects a
reproducible rotating target schedule.

## Deviations from the reference

- Native replication drivers over VFS stores in child processes through
  `goharness` (see `../PORTING.md`), instead of `murmur-server` children
  over pgwire. Needs the node binary
  (`go build -o /tmp/murmur-test-node ./tests-live/node` and
  `MURMUR_NODE_BIN=/tmp/murmur-test-node`).
- Stop legs are graceful process exits plus reboot-on-dir, not the
  reference's `Process.Kill`: on this stack SIGKILL loses all local
  state (the store persists on clean close only), so crash stops
  cannot preserve the acknowledged set. The suite still proves the
  acknowledged set survives outage and whole-mesh restart churn.
- This stack has no runtime peer-removal verb, so the partition uses
  per-node `allowed_peers` allow-lists plus replication restarts (the
  partition-port technique) instead of live `PEER REMOVE`/`ADD`; the
  transport refuses cross-partition sessions in both directions. This
  does not simulate kernel-level packet loss.
- Static fanout-2 peering maps to the `gossip_fanout` setting applied
  at boot; full snapshot-donor trust is already the harness default
  (`snapshot_trusted_sources` covers every node id), so the reference's
  per-node trust-config rewrite is unnecessary.
- cr-sqlite DDL: the `PRIMARY KEY` column carries explicit `NOT NULL`,
  and every `NOT NULL` column carries a `DEFAULT`.

Run from `clients/go` (full duration is for soak qualification; a short
proof run overrides the knobs):

```sh
MURMUR_ENGINE_INTEGRATION=1 go test -count=1 -timeout 600s ./tests-live/abuse/
MURMUR_ENGINE_INTEGRATION=1 MURMUR_ABUSE_NODES=4 MURMUR_ABUSE_DURATION_SECONDS=60 MURMUR_ABUSE_SETTLE_SECONDS=180 go test -count=1 -timeout 600s ./tests-live/abuse/
```
