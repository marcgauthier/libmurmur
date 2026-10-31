# Bounded SQL replication history

Runs alternating acknowledged SQL writes while aggressive background
retention operates. Samples committed and collected cursors and
data-directory bytes at the start, midpoint and end. Requires actual
collection on both nodes, bounded retained growth, disk growth at most
8 KiB per row, bounded second-half acceleration, unchanged replication
errors, and exact ordered convergence.

This suite is fully skipped in the native port: the native retention
pass runs every 60 s with no interval knob, and under sustained write
load the pass deterministically latches
`Protocol: cursor pruned; snapshot required` on both nodes — at
unthrottled in-process rates (~23K rows/s) and at wire-paced rates
(~800 rows/s), with `retention_min_kept` 10 and 10000 alike — after
which sync stalls and the final exact convergence times out. Failure
teardown additionally wedges in `sqlite3_close` until the go test
timeout. Idle clusters stay clean, floors do advance, and collection
does run; the breakage is the retention/sync coordination under load,
which needs engine changes, not suite tuning
(`harness: retention-under-load without cursor prune (pass interval
knob, prune-free floors, working snapshot fallback, close-hang
fix)`).

Run from `clients/go`:

```sh
MURMUR_ENGINE_INTEGRATION=1 go test -count=1 -timeout 600s ./tests-live/log-boundedness/
```

`MURMUR_LOG_BOUNDEDNESS_SECONDS` defaults to 75 and accepts a positive
integer. At least 100 rows must be acknowledged and the midpoint must
be sampled.
