# Downgrade guard through live SQL

Write rows with SQL, flush them, and stop the server. Copy the durable
directory, mark only that copy with the next unsupported format, and
require a live server to reject the copied store during unlock without
changing any file; the pristine directory must still reopen with
identical rows.

This suite is fully skipped in the native port: there is no
future-format injector artifact, the native store has no release-format
downgrade guard to trip, the bindings expose no key-rotation verb, and
the harness cannot repoint a node at an alternate data dir
(`harness: downgrade guard (format injector, format refusal check,
rotate verb, restart against alternate store)`).

Run from `clients/go`:

```sh
MURMUR_ENGINE_INTEGRATION=1 go test -count=1 -timeout 600s ./tests-live/downgrade-guard/
```

The refusal must leave the future store content-untouched; the pristine
store must reopen with exact data fidelity.
