# diskfull-live

One node is stopped, its directory is moved onto a tiny tmpfs, and it is
restarted there; writes past ENOSPC must fail closed (error, no partial
row, node keeps answering reads) with pre-full data intact, and freeing
space plus a restart must recover to exact convergence.

## Pass criteria

- 20-row baseline converges within 30 s; survive the tmpfs move and
  converge again within 30 s.
- The fs proves tiny (< 5 MiB free) before filling (else vacuous).
- Fixed filler lands first; the fill loop records every acked/errored
  outcome and stops after 5 errors; at least one error is required
  (ENOSPC must actually hit).
- While still full: reads answer; a probe write either acks (tracked) or
  errors cleanly.
- After freeing space + restart: every acked row intact everywhere,
  every errored row absent-on-all or whole-on-all (never torn).
- Post-recovery writes on both nodes converge within 30 s.
- Knobs: `MURMUR_DISKFULL_TMPFS_SIZE_MB` (8),
  `MURMUR_DISKFULL_FILLER_SIZE_MB` (1), `MURMUR_DISKFULL_VALUE_SIZE_KB`
  (128). SKIPs (restoring the dir) when the mount fails; SKIPs on
  non-Unix. Teardown never leaks the mount (unmount failure is loud).

## Deviations from the reference

- Nodes are native replication drivers over VFS stores through
  `goharness` (see `../PORTING.md`) instead of `murmur-server`
  children over pgwire; plain SQL
  (`live_typed_records(name, value)`) with the per-node replicated
  flag.
- Node 0 runs as a child process (`ChildSet`): only a child releases
  its directory for the tmpfs move. It is stopped gracefully, reaped,
  moved, and rebooted on the same dir with `RestartNode`; the
  post-recovery restart is a same-process stop/start. The reference's
  re-`SET TABLE REPLICATED` after restarts is dropped: CRR state
  persists in the copied store.
- The acked set settles onto the peer (60 s) before the exact
  post-recovery audit; the reference audits immediately after
  re-mesh.
- Free space via `unix.Statfs` from `golang.org/x/sys/unix`;
  mount/copy/unmount via `mount`/`cp`/`umount`.
- On failure the tmpfs content is copied aside before the unmount so
  the `finish` snapshot still captures it.

Run from `clients/go` (child legs need the node binary):

```sh
go build -o /tmp/murmur-test-node ./tests-live/node
MURMUR_NODE_BIN=/tmp/murmur-test-node MURMUR_ENGINE_INTEGRATION=1 go test -count=1 -timeout 600s ./tests-live/diskfull-live/
```
