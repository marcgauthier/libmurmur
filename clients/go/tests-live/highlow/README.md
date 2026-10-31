# highlow

Real Low (exporter) and High (importer) domains move logical writes
across a directory drop, over a `contacts(id, name, score)` table
plus an `email` column for the schema leg:

- `disconnected_transfer_with_one_way_role_gating`: distinct Low/High
  DBIDs, structural one-way role gating, and Low/High contact-state
  equality after export+import.
- `gap_delivery_with_duplicate_recovery`: three rounds export three
  bundles; withholding the middle one applies only the first (gap, no
  skip-ahead); restoring it converges all three; duplicate redelivery
  changes nothing and quarantines nothing.
- `two_receivers_converge`: two High receivers import the same
  staging independently and the High mesh converges both to the Low
  state.
- `forgeries_rejected_without_partial_apply`: rogue-domain,
  wrong-recipient, tampered, and oversized artifacts each fail closed
  alone (quarantined, High stays empty, no progress recorded);
  wrong-extension artifacts are ignored in place; the genuine bundle
  still applies afterwards.
- `restart_resumes_without_recapture_or_reapply`: a Low restart
  exports nothing new; a High restart re-applies nothing.
- `schema_hold_survives_restart_and_releases_on_local_migration`:
  the unknown `email` column holds the bundles (High stays empty, no
  DDL crosses); the hold survives a High restart; a local `ADD
  COLUMN` migration releases the held bundles and the email reads
  back.
- `signer_rotation_and_outage_catch_up`: round 1 imports under the
  predecessor key; both sides rotate and round 2 imports on top; a
  retired-signer replay is quarantined while a current-key duplicate
  stages cleanly; then a 5-event outage queues durably across a Low
  restart and catches up to exactly `{ann: 1, bob: 2, backlog: 4}`.
- `high_owned_field_reorder_converges_across_peers`: peer A
  (override-then-import) and peer B (import-then-override) converge
  over the mesh on the High bytes with High-owned provenance.

## Status: skipped (no bridge machinery in this stack)

Every leg needs bridge domains — Low exporter / High receiver roles,
bundle staging dirs, the one-way ferry, quarantine, signer/recipient
config — none of which the harness or bindings expose (same gap as
the bridge-two-streams and files-bridge ports). Each test skips with
`harness: bridge domains (...)`.

## Reference pass criteria (for when bridge lands)

Per-test contact maps converge exactly as listed; gap, hold, forgery,
and suppression legs assert exact visible row sets; restart legs
assert exact file-set/row stability; rotation asserts quarantine
placement for the replay and clean staging for the duplicate.
Convergence waits are 30 s with 50 ms polls.

Run from `clients/go`:

```sh
MURMUR_ENGINE_INTEGRATION=1 go test -count=1 -timeout 600s ./tests-live/highlow/
```
