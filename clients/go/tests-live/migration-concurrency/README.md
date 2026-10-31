# Concurrent migrations

Race the same ADD COLUMN on two nodes while a third writes 60 acknowledged records. Require a successful migration, one complete column on every node, every acknowledged record, and replicated writes to the new column from each node.

Nodes are native replication drivers over VFS stores, driven in-process
through `goharness` (see `../PORTING.md`). The reference's independent
SQL connections map to the three native node handles directly.

Run from `clients/go`:

```sh
MURMUR_ENGINE_INTEGRATION=1 go test -count=1 -timeout 600s ./tests-live/migration-concurrency/
```

A duplicate migration may fail after another node has applied it; at least one migration must succeed. Every application write must succeed.
