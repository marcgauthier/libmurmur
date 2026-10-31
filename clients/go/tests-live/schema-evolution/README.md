# Additive SQL schema evolution

Add a nullable column while one of three nodes is offline, write the new column, and restart the offline node. Verify new schema and exact data, and permitted destructive DDL on a local table.

Each node is a native replication driver over a VFS-backed store, run
in-process by the `goharness` test harness. Only the local-DDL leg
runs. The additive-migration leg is skipped: `ALTER TABLE ADD COLUMN`
on a replicated table leaves stale CRR triggers behind, so the next
write fails (`harness: ALTER TABLE on replicated tables breaks CRR
writes`). The replicated-DDL guard legs are skipped too: raw SQLite
accepts DROP/RENAME on replicated tables and there is no per-table
replication-flag view (`harness: replicated-DDL guard and per-table
replication flags`).

Run from `clients/go`:

```sh
MURMUR_ENGINE_INTEGRATION=1 go test -count=1 -timeout 600s ./tests-live/schema-evolution/
```

`MURMUR_LIVE_RUNTIME` selects the parent directory for unique per-test
runtime folders. Successful tests remove their runtime folders; failures
retain the config and logs at the path printed in the test output.

This scenario covers additive column adoption. Replicated table and column drops/renames are rejected by design on the reference server, but the native SQL surface has no such guard.
