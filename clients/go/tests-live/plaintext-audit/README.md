# Plaintext audit of SQL artifacts

Replicate confidential markers between two nodes, create a backup, flush and stop both nodes, and scan all scenario artifacts for plaintext markers and the database unlock key. Restart both and verify the exact rows.

Each node is a native replication driver over a VFS-backed store, run
in-process by the `goharness` test harness. The byte-level audit is
inlined in the test; these tests do not open an embedded database to
perform it.

Run from `clients/go`:

```sh
MURMUR_ENGINE_INTEGRATION=1 go test -count=1 -timeout 600s ./tests-live/plaintext-audit/
```

`MURMUR_LIVE_RUNTIME` selects the parent directory for unique per-test
runtime folders. Successful tests remove their runtime folders; failures
retain the config and logs at the path printed in the test output.

The audit includes storage and backup archives. The scan detects exact byte sequences; replication signing keys and test TLS keys are configuration credentials and are not treated as database unlock keys.
