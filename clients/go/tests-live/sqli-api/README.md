# SQL parameter binding and errors

Insert SQL injection strings, quotes, Unicode, and retired HTTP-route text as bound data. Verify exact replicated values, unchanged application tables, a UNIQUE violation for a duplicate key, and a usable store after a SQL error.

Each node is a native replication driver over a VFS-backed store, run
in-process by the `goharness` test harness. Application operations use
the harness SQL surface directly; there is no PostgreSQL wire protocol
here, so pgwire SQLSTATEs (23505) map to the underlying SQLite errors
and the table listing excludes `murmur_*`/`*crsql*` internal tables.

Run from `clients/go`:

```sh
MURMUR_ENGINE_INTEGRATION=1 go test -count=1 -timeout 600s ./tests-live/sqli-api/
```

`MURMUR_LIVE_RUNTIME` selects the parent directory for unique per-test
runtime folders. Successful tests remove their runtime folders; failures
retain the config and logs at the path printed in the test output.
