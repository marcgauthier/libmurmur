# clock-skew

Contended same-key writes across nodes must resolve deterministically to
identical LWW winners on every node: concurrent writes on two nodes
converge everywhere, then a third node's later updates win on all nodes.

Nodes are native replication drivers over VFS stores, driven in-process
through `goharness` (see `../PORTING.md`).

Run from `clients/go`:

```sh
MURMUR_ENGINE_INTEGRATION=1 go test -count=1 -timeout 600s ./tests-live/clock-skew/
```
