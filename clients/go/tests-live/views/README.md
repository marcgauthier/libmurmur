# SQL projection after replication and restart

Three nodes insert contacts independently and update their scores. An ordered SELECT must return ann and bob while excluding hidden, both before and after stopping and restarting node 3.

Each node is a native replication driver over a VFS-backed store, run
in-process by the `goharness` test harness. Application operations use
the harness SQL surface directly; there is no PostgreSQL wire protocol
here.

Run from `clients/go`:

```sh
MURMUR_ENGINE_INTEGRATION=1 go test -count=1 -timeout 600s ./tests-live/views/
```

`MURMUR_LIVE_RUNTIME` selects the parent directory for unique per-test
runtime folders. Successful tests remove their runtime folders; failures
retain the config and logs at the path printed in the test output.

Application CREATE VIEW remains unsupported. This scenario checks a SELECT projection over replicated base rows.
