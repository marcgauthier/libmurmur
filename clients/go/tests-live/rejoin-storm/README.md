# rejoin-storm

Two of three nodes are killed after baseline convergence. The survivor
commits and flushes 30 more rows. Both stopped nodes restart concurrently,
rejoin the mesh, and must recover every acknowledged row. Status must show
received replication traffic (`applied_batches`) and no final error.

Kill/restart legs run as child processes through `goharness` (see
`../PORTING.md`).

Run from `clients/go`:

```sh
go build -o /tmp/murmur-test-node ./tests-live/node
MURMUR_ENGINE_INTEGRATION=1 MURMUR_NODE_BIN=/tmp/murmur-test-node go test -count=1 -timeout 600s ./tests-live/rejoin-storm/
```
