# chaos-load

Three writers run while one node is partitioned from the other pair.
The test requires actual divergent row sets before healing while writers are
still active, then exact convergence of all 240 acknowledged rows. A post-heal
write must also replicate successfully.

Nodes are native replication drivers over VFS stores, driven in-process
through `goharness` (see `../PORTING.md`). This stack has no peer removal,
so the cluster boots unmeshed and only the pair is peered, which isolates
the third node identically (nobody learns its address); healing remeshes
fully.

Run from `clients/go`:

```sh
MURMUR_ENGINE_INTEGRATION=1 go test -count=1 -timeout 600s ./tests-live/chaos-load/
```
