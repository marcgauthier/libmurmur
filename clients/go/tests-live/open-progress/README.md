# open-progress

A real encrypted store holding 6000 rows x 2 tables (~30 MB) is
populated, closed and reopened, and every reopen must recover identical
contents (count + ordinal sum per table). A fresh empty database must
open with zero rows.

Nodes are native replication drivers over VFS stores, driven in-process
through `goharness` (see `../PORTING.md`). Reloads are real close +
reopen cycles on the same dir and key; there is no unlock watchdog on
this stack, so the reopen is the substance and no phase/heartbeat
progress is asserted. The wrong-key / short-key open-failure legs and
the fail-closed watchdog leg need a wire unlock surface that native
nodes do not expose, so `TestOpenFailureLegs` and
`TestWatchdogFailsClosed` skip (`harness: wire unlock handshake
(wrong/short key rejection)`, `harness: unlock watchdog with stall
window`).

Run from `clients/go`:

```sh
MURMUR_ENGINE_INTEGRATION=1 go test -count=1 -timeout 600s ./tests-live/open-progress/
```

Pass criteria: `populate` takes 6000 `requests` + 6000 `events` rows,
flushes, verifies by count + ordinal sum; `reload-1` /
`reload-2-recovery` verify both tables by count + ordinal sum after
each reopen; `empty-db` opens a fresh database with 0 rows.
