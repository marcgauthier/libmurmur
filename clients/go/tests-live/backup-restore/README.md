# Streaming backup and restore

Save, copy, list, and restore a store checkpoint through the native
store API. Verify SQL types, values, table replication flags, and
durability of the restored copy across a restart. A second test rejects
an incorrect restore key while preserving live data; the
foreign-identity leg is skipped (the native store open performs no
writer-identity check).

## Mapping

- `MURMUR BACKUP SAVE` becomes `cluster.Backup` (store checkpoint to
  a directory); the size check sums the checkpoint files.
- `BACKUP DOWNLOAD` + upload becomes a byte copy of the checkpoint
  under a new archive name with a size comparison.
- `MURMUR BACKUP LIST` becomes a runtime-dir listing for the uploaded
  archive name.
- `MURMUR RESTORE` becomes `cluster.Restore` (copy to a fresh
  directory plus identity bookkeeping); restored rows are reread
  through a direct store open, following the tampered-backup port.
- `MURMUR SHOW TABLES REPLICATION` becomes a `sqlite_master` count of
  the table's CRR triggers.
- The wrong-key `28000` becomes a store open/read error under the
  wrong unlock key.
- There is no `id_murmur_primary_key` column: full ordered rows are
  compared instead.
- The cr-sqlite DDL carries explicit `NOT NULL`/`DEFAULT` per the
  porting rules; see `../PORTING.md`.

Durability here is periodic (250 ms background flusher), so the test
waits for the live store to land pages before backing up.

Run from `clients/go`:

```sh
MURMUR_ENGINE_INTEGRATION=1 go test -count=1 -timeout 600s ./tests-live/backup-restore/
```
