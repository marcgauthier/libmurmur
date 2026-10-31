# allow-nodes

Certificate validity alone does not authorize a peer: node 1's identity
allow-list accepts only node 0, while node 0 and node 2 accept every
identity. All three nodes write concurrently; the unauthorized
node 1-to-node 2 session must stay absent throughout (topology `[2, 1, 1]`),
and afterwards every node must hold all rows (node 2's rows reach node 1
through node 0).

Nodes are native replication drivers over VFS stores, driven in-process
through `goharness` (see `../PORTING.md`). The allow-list is the
`allowed_peers` setting in `murmur_config`, applied with a replication
restart.

Run from `clients/go`:

```sh
MURMUR_ENGINE_INTEGRATION=1 go test -count=1 -timeout 600s ./tests-live/allow-nodes/
```
