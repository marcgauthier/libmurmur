# txchunk-resume

A single transaction larger than the replication frame travels as
~64 KiB transaction chunks; the receiving node is killed
mid-transfer and restarted, and the retry must complete with
all-or-nothing visibility and converged digests.

## What it proves

- Positive control: one multi-chunk transaction (~3.5 MiB) replicates
  to every node with no stopping.
- Resume trials (up to `MURMUR_TXCHUNK_ATTEMPTS`): while the victim
  is partitioned, the sender commits a fresh big transaction; the
  survivors converge while the victim sees none of it; after the
  heal the victim is SIGKILLed once trial chunks stage on it with no
  trial rows visible, rebooted, and the retry completes with the
  sender always showing the full trial and the victim showing none
  or all of it (never a partial transaction).
- The kill provably lands mid-transfer (chunks staged, none visible)
  and the victim provably applies after the reboot (none visible
  right after the reboot, before any session resumes); trials whose
  kill landed too late are discarded and retried with fresh rows.
- Final: exact row counts and identical ordered digests everywhere.

## Skipped legs (harness gaps)

- `TestChunkedTransactionWatermarkNeverAdvancesBeforeCompletion`:
  the absolute ack baseline, the per-trial commit-cursor advance,
  and the first-advance-precedes-visibility bound need MURMUR SHOW
  RETENTION and a commit cursor, neither of which has a native
  equivalent (the progress snapshot carries per-origin
  applied/observed plus retained floors only, updated
  asynchronously).

## Env knobs

- `MURMUR_TXCHUNK_ROWS` (default 400): rows per big transaction.
- `MURMUR_TXCHUNK_VALUE_BYTES` (default 9000): payload bytes per row.
- `MURMUR_TXCHUNK_ATTEMPTS` (default 3): resume trials before failing
  loudly (a trial is discarded when the kill lands too late).

Defaults are rescaled for this stack's geometry (reference: 1200
rows x 9000 B): 400 rows x 9000 B is ~3.5 MiB, which travels as ~57
wire chunks yet ships as one batch under the 4 MiB unit. Overrides
must keep the trial above the 1 MiB default unit (so it travels
chunked), at or below the 4 MiB single-unit ceiling, and at or below
1024 rows (the batch cell cap); anything else fails loudly in
`commitBigTx`.

## Deviations from the reference

- Nodes are native replication drivers over VFS stores, driven
  through `goharness` (see `../PORTING.md`) instead of
  `murmur-server` children over pgwire. The victim runs as a child
  process (`MURMUR_NODE_BIN`) so the mid-transfer stop is a real
  SIGKILL; the sender and witness are in-process.
- DDL follows the cr-sqlite rules (`id TEXT NOT NULL DEFAULT ''
  PRIMARY KEY`, `NOT NULL DEFAULT ''` on every column).
- Single-unit shipping is restored with `batch_bytes` 4 MiB via
  `murmur_config` (read live on every export, so no restart is
  needed). The reference additionally stretches the capture tick
  and uses a 16 MiB unit; this stack exposes no capture-interval
  knob, batches past ~4 MiB break the stream instead of resuming,
  and 1000-row trials stall even at the same byte size (all verified
  by probe), hence the rescaled trial.
- The big transaction is one `BEGIN`..`COMMIT` script (400
  multi-kilobyte inserts) executed as a batch instead of
  parameterized inserts over one connection.
- This stack has no runtime peer-removal switch, so the partition
  uses per-node `allowed_peers` identity allow-lists (the
  partition-suite pattern) applied with a replication restart, and
  healing clears the lists, restarts, and remeshes. The victim's
  zero-peer check runs after the survivors converge so it holds
  under dial pressure (sessions only establish once unacked rows
  give the sync loop something to ship).
- The mid-transfer trigger is the victim's `murmur_stage` chunk
  gauge with no trial rows visible (the reference staged-gauge
  shape, read from the store): the engine buffers each incoming
  batch's chunks there and applies atomically at END. There is no
  head-start fallback; a victim that converges first discards the
  attempt.
- The sender-advanced check reads the sender's trial prefix count
  (no commit cursor exists). The too-late check samples the
  victim's trial visibility immediately after the reboot, before
  any session can resume the transfer; the reference's
  post-restart applied counter is subsumed because per-origin
  counters update asynchronously here.
- Snapshot exclusion is behavioral only: this harness always
  configures `snapshot_trusted_sources`, so the reference's
  structural "no snapshot could have been taken" argument does not
  transfer. The kill firing with chunks staged plus none visible
  after the reboot proves the retry received and applied the trial
  over the log/chunk path.
- The post-restart peer wait is 90 s instead of 30 s: after a
  mid-transfer SIGKILL the survivors hold the dead session until
  it times out, so the rebooted victim's redials only succeed
  after ~30 s (verified by probe).
