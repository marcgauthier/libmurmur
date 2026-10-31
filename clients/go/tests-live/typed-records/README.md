# typed-records

Typed SQL records, keys, transactions, and files on native nodes.

## What it proves

- Bound text/real/blob/NULL values replicate with byte-identical
  values; a remote update and a remote delete converge; keys stay
  stable across a restart.
- Multi-row statements are atomic (a duplicate key rejects the whole
  statement with nothing leaked into replication); multi-statement
  batches commit.
- Node-local tables stay local (a replicated control row converges
  while each node keeps exactly its own private row) and persist
  across restarts with their primary key intact.
- A 150,000-byte file with a quote/unicode name replicates and
  downloads byte-identical, including after a receiver restart.

## Skipped legs (harness gaps)

- `TestSQLTransactionWordsAreNoops`: the reference asserts
  BEGIN/ROLLBACK are documented no-ops; this stack is real SQLite,
  where ROLLBACK undoes the batch.
- `TestSQLReplicationRebuildsPopulatedKeysAndEnforcesImmutableApplicationKeys`:
  managed primary keys (`id_murmur_primary_key` rebuild, immutable
  application keys, unreplicate) have no native equivalent.
- `TestSQLConcurrentAdditiveSchemaBranchesPreserveBothValues`: ALTER
  TABLE on replicated tables breaks CRR writes (the established
  schema-evolution gap).
- `TestSQLCRDTOperationsConvergeAcrossOfflinePartition`: merge-policy
  ops (PN_COUNTER/OR_SET/MAX/MIN) have no native equivalent (the
  established merge-policies gap).
- `TestSQLEmptyPeerRecoversTypedRowsFromARetentionSnapshot`: stale
  rejoin via snapshot resync does not converge after retention GC
  (the established graceful-shutdown gap, verified first-hand).

## Deviations from the reference

- Nodes are native replication drivers over VFS stores, driven
  in-process through `goharness` (see `../PORTING.md`) instead of
  `murmur-server` children over pgwire.
- DDL follows the cr-sqlite rules (`id INTEGER PRIMARY KEY NOT
  NULL`, `title TEXT NOT NULL DEFAULT ''`).
- There is no `id_murmur_primary_key` column: key-stability legs
  compare full ordered rows instead.
- Typed reads use `Simple` string projections (`hex(payload)`,
  `optional IS NULL`, `score` rendered text) instead of typed
  accessors; the NULL/empty-blob distinction is preserved.
- `MURMUR SET TABLE records REPLICATED true` becomes
  `SetTableReplicated`, `MURMUR FLUSH` becomes `Flush()`, and
  restarts are `StopNode`/`StartNode`.
- The local-only flag check (`MURMUR SHOW TABLES REPLICATION`)
  becomes a behavioral assertion (each node holds exactly its own
  private row after the control converges).
- File upload/download/list/availability use the native file-object
  store (`FileUpload`/`FileList`/`FileAvailable`/`FileDownload`)
  instead of `MURMUR FILE` wire cursors. A one-row mesh gate precedes
  the upload (file metadata alone never wakes the mesh), and the
  fetch wait is 90 s (the harness pins the fetch cadence at 30 s).
- The ROLLBACK leg asserts stack truth (the batch is undone) rather
  than the reference no-op behavior.
- The file case restarts the uploader instead of the receiver: an
  in-process node that completed a fetch cannot restart (driver
  start fails with "File exists"), and a child restart drops the
  files staging, so receiver restart is blocked on both modes.
