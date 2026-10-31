# Corrupt backups fail closed

Create a thirty-row backup and corrupt its header, flip a payload byte, or truncate it. Restore must reject each bad archive and the live data must still read untouched. The pristine archive must restore the exact original rows.

Nodes are native replication drivers over VFS stores, driven in-process
through `goharness` (see `../PORTING.md`). The reference SQL archive
streams map to store checkpoints: `cluster.Backup` saves a checkpoint,
corruption targets the files the store open verifies (MANIFEST header,
SST payload), and `cluster.Restore` rejects the tampered copies at open.
Durability here is periodic (250 ms background flusher), so the test waits
for the live store to land pages before backing up.

Run from `clients/go`:

```sh
MURMUR_ENGINE_INTEGRATION=1 go test -count=1 -timeout 600s ./tests-live/tampered-backup/
```
