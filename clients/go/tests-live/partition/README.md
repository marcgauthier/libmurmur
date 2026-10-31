# Four-node partition and healing

Start with four connected nodes and a baseline row. Restart all nodes into
isolated pairs, then write on both sides. Verify each pair has exactly its
own rows, restore the full topology, and require complete ordered
convergence plus a post-heal write.

Nodes are native replication drivers over VFS stores, driven in-process
through `goharness` (see `../PORTING.md`). This stack has no peer-removal
or membership switch, so isolation uses per-node `allowed_peers` identity
allow-lists (pair members only); the transport refuses cross-pair sessions
in both directions. Healing clears the allow-lists and remeshes.

Run from `clients/go`:

```sh
MURMUR_ENGINE_INTEGRATION=1 go test -count=1 -timeout 600s ./tests-live/partition/
```

Topology changes use config rewrites and replication restarts. This does not emulate packet loss on an otherwise running connection.
