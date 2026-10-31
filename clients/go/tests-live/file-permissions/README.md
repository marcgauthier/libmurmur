# SQL storage and backup permissions

Checks product-created data directories and files after initialization,
after SQL writes, and after backup/restore and restart. Every audited
POSIX path must have zero group/other permission bits. The encrypted
key registry must exist, and all 25 control rows must survive restore
and restart.

The test is skipped: the harness creates node/data/TLS dirs mode 0755,
the engine writes store files mode 0644, and there is no encrypted key
registry (`keys.enc`), so every permission audit would fail on
harness-owned modes. The functional backup/restore round trip is
covered by the backup-restore port instead.

Runs on Unix, where POSIX permission bits apply. The port never hides
a permission bug by chmodding a path.

Run from `clients/go`:

```sh
MURMUR_ENGINE_INTEGRATION=1 go test -count=1 -timeout 600s ./tests-live/file-permissions/
```
