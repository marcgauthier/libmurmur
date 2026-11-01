# tests-live porting guide

Source: `/home/marc/DEV/MURMUR-SQL/tests-live/<suite>/`. Target:
`clients/go/tests-live/<suite>/` in this module. The reference
drives `murmur-server` children over pgwire; here nodes are native
replication drivers over VFS stores, in-process by default.

## Harness

```go
import goharness "github.com/marcgauthier/libmurmur/clients/go/tests-live/goharness"

goharness.SkipUnlessLive(t) // MURMUR_ENGINE_INTEGRATION=1 gate
cluster, err := goharness.NewCluster(goharness.ClusterOptions{
    Name: "my-suite", NumNodes: 3,
    // ChildNodes: true,        // all nodes as child processes
    // ChildSet: map[int]bool{1: true}, // mixed mode
    // NoMesh: true,            // wire peers manually
    // Files: true,             // stage file-object stores
})
failed := true
defer func() { cluster.Finish(failed) }()
```

`cluster.Node(i)` has `Simple(query)`, `Execute(query, args...)`,
`Flush()`, `SetTableReplicated(table, bool)`, `PeerAdd(addr)`,
`ShowPeers()`, `ShowStatus()`, `ShowReplication()`, `ShowHealth()`,
`FileUpload/Download/Available/List` (with `Files: true`),
`Start/Stop/Close`. `cluster` has `StopNode/StartNode/KillNode/
RestartNode/PeerMesh/WaitPeers/Backup/Restore/NodeID/GroupHex`.

Shared assertions: `Fixture`, `Rows`, `Status`, `Peers`,
`Converge`, `AssertRows`, `PeerCounts`.

Child-process legs need the node binary built and pointed at:
`go build -o /tmp/murmur-test-node ./tests-live/node` and
`MURMUR_NODE_BIN=/tmp/murmur-test-node`.

## SQL rules

- `$N` placeholders are translated to `?` automatically; keep
  suite SQL verbatim otherwise.
- cr-sqlite DDL: every `PRIMARY KEY` column needs explicit
  `NOT NULL`, and every `NOT NULL` column needs a `DEFAULT`.
  (`id INTEGER PRIMARY KEY NOT NULL`, `name TEXT NOT NULL
  DEFAULT ''`.)
- No Postgres types: `TIMESTAMPTZ`/`UUID`/`JSONB`/`BYTEA` become
  `TEXT`/`BLOB`; `SERIAL` becomes `INTEGER PRIMARY KEY NOT NULL`;
  booleans become `INTEGER` 0/1.
- `ON CONFLICT ... DO UPDATE` and `RETURNING` work in SQLite;
  keep them.
- There is no `id_murmur_primary_key` column: compare full
  ordered rows instead.
- pgwire error codes (`42703`/`42P01`) do not exist;
  `ErrorCode(err) == "noparam"` covers missing-table/column
  during convergence.

## MURMUR remap

| Reference | Port |
|---|---|
| `MURMUR FLUSH` | `node.Flush()` |
| `MURMUR SET TABLE t REPLICATED true` | `node.SetTableReplicated("t", true)` |
| `MURMUR SHOW PEERS` | `node.ShowPeers()` (typed rows) |
| `MURMUR SHOW STATUS` | `node.ShowStatus()` (decoded JSON) |
| `MURMUR SHOW REPLICATION` | `node.ShowReplication()` |
| `MURMUR PEER ADD <addr>` | `node.PeerAdd(addr)` |
| `MURMUR BACKUP/RESTORE` | `cluster.Backup(i, dest)` / `cluster.Restore(...)` |
| config.yaml settings | `NewCluster` options + settings (ask if missing) |

Keep suite intent identical; adapt mechanics. Timeouts: keep
reference values unless the suite genuinely needs more (slow
CI), and note the change.

## Gaps

- Never edit `goharness/`, `bindings/`, or `node/`: if a suite
  needs a missing harness capability, `t.Skip("harness: <what>")`
  the blocked leg (or suite) and report it in your result.
- Never edit the reference tree at `/home/marc/DEV/MURMUR-SQL`.
- Every ported package must `go vet` clean and pass (or skip
  with a named reason) under `MURMUR_ENGINE_INTEGRATION=1`.
