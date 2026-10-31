# Online backups during transactions

A writer commits forty atomic five-row INSERT statements while the
driver takes four online backups. Restore each archive and require a
nondecreasing exact committed prefix of the acknowledged records; no
archive may split an atomic statement.

## Mapping

- `MURMUR BACKUP SAVE` + download/upload becomes `cluster.Backup`
  (store checkpoint to a directory); the size check sums the
  checkpoint files.
- `MURMUR RESTORE` becomes `cluster.Restore` (copy to a fresh
  directory); restored rows are reread through a direct store open,
  following the tampered-backup port.
- The separate writer connection becomes a goroutine over the shared
  node handle (the harness serializes statements).
- The multi-row INSERT keeps ten ordered `$1..$10` placeholders (the
  harness translates `$N` to `?` only in order from 1).
- The cr-sqlite DDL carries explicit `NOT NULL`/`DEFAULT` per the
  porting rules; see `../PORTING.md`.

Transaction-control words are no-ops; each INSERT statement is atomic.
This tests snapshot consistency under concurrent writes, without a
throughput or latency SLO.

Timing is stretched from the reference (writer 5 ms to 30 ms per
batch, backups 30 ms to 300 ms apart): durability is periodic (250 ms
background flusher), so the write phase must span several landing
intervals for the backups to capture growing prefixes.

Run from `clients/go`:

```sh
MURMUR_ENGINE_INTEGRATION=1 go test -count=1 -timeout 600s ./tests-live/backup-under-fire/
```
