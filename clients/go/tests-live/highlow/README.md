# highlow

Real Low (exporter) and High (importer) domains move logical writes
across a directory drop, over a `contacts(id, name, score)` table
plus an `email` column for the schema leg:

- `disconnected_transfer_with_one_way_role_gating`: distinct Low/High
  DBIDs, structural one-way role gating (a receiver on the Low node
  itself never imports, and High-owned claims never flow back), and
  Low/High contact-state equality after export+import.
- `gap_delivery_with_duplicate_recovery`: three rounds export three
  bundles; withholding the middle one applies only the first (gap, no
  skip-ahead); restoring it converges all three; duplicate redelivery
  changes nothing and quarantines nothing.
- `two_receivers_converge`: two High receivers import the same
  staging independently and both converge to the Low state.
- `forgeries_rejected_without_partial_apply`: tampered and
  wrong-recipient artifacts each fail closed alone (quarantined, High
  stays empty, no progress recorded); rogue-domain bundles and
  wrong-extension files are ignored in place; oversized inputs are
  rejected without a quarantine copy; the genuine bundle still
  applies afterwards.
- `restart_resumes_without_recapture_or_reapply`: a Low restart
  exports nothing new; a High restart re-applies nothing (durable
  receipts turn redelivery into duplicates); the restarted pair still
  transfers.
- `schema_hold_survives_restart_and_releases_on_local_migration`:
  the unknown `email` column holds the bundles (High stays empty, no
  DDL crosses); the hold survives a High restart; a local `ADD
  COLUMN` migration releases the held bundles and the email reads
  back.
- `signer_rotation_and_outage_catch_up`: round 1 imports under the
  predecessor key; both sides rotate and round 2 imports on top
  during key overlap; after full rotation a retired-signer replay of
  committed bytes stages as a duplicate while fresh retired-signer
  bytes are quarantined, and a current-key duplicate stages cleanly;
  then a 5-event outage queues durably across a Low restart and
  catches up to exactly `{ann: 1, backlog: 4, bob: 2}`.
- `high_owned_field_reorder_converges_across_peers`: still skipped —
  needs peer replication of bridge ownership/shadows across High
  peers (HIGHLOW release gate 1), which is unimplemented.

## Status: enabled except the High-peer mesh leg

Seven legs run against the native bridge workers (capture, sender,
receiver, typed LWW import). Only the cross-peer reorder leg skips,
with `native: High-peer replication of bridge ownership/shadows
unimplemented (HIGHLOW release gate 1)`.

## Native deviations from the reference

- Bundles pinned to another source database are ignored in place,
  not quarantined: untrusted routing hints skip unrelated streams
  before authentication.
- Oversized (and tiny) inputs count `Rejected` without a quarantine
  copy.
- A replay of already-committed bytes always stages as `Duplicate`
  (receipts decide replays), even when its signer has since retired;
  only fresh bytes from a retired signer are quarantined.
- Receiver counters count attempts, not distinct files: a bad bundle
  left in the ferry re-rejects on every pass. Legs evict each proven
  forgery so later assertions stay exact.

Per-test contact maps converge exactly as listed; gap, hold, forgery,
and suppression legs assert exact visible row sets; restart legs
assert exact file-set/row stability; rotation asserts quarantine
placement for fresh retired-signer bytes and clean staging for
duplicates. Convergence waits are 10 s with 10 ms polls.

Run from `clients/go`:

```sh
MURMUR_ENGINE_INTEGRATION=1 go test -count=1 -timeout 600s ./tests-live/highlow/
```
