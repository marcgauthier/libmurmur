# migration-crash

An isolated node recovers from a crash at the schema-manifest store
boundary while its two peers stay on the old epoch; afterwards it
rejoins, the peers adopt the new schema and rebind, and a
migrated-field write converges with every node at the new epoch. Two
cases: `before-store` (recovery reopens at epoch 1 and retries the
migration) and `after-store` (recovery reopens at epoch 2).

This suite is fully skipped in the native port: a bare `ALTER TABLE
ADD COLUMN` on a replicated (CRR) table leaves stale triggers behind,
so the very next write fails and neither the migration nor the
converged migrated-field write can proceed (`harness: ALTER TABLE on
replicated tables breaks CRR writes`; same block as
schema-evolution).

Run from `clients/go`:

```sh
MURMUR_ENGINE_INTEGRATION=1 go test -count=1 -timeout 600s ./tests-live/migration-crash/
```

The crash-boundary legs stop/restart on either side of the synchronous
migration store. They do not inject a crash mid-store.
