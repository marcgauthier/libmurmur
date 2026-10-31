# Large payload replication

Two nodes replicate 250 small rows and one 1.5 MiB bound text value. The receiver must return every row and the exact full payload.

Nodes are native replication drivers over VFS stores, driven in-process
through `goharness` (see `../PORTING.md`); this port keeps the reference
SQL verbatim (`$N` placeholders are translated to `?` automatically).

Run from `clients/go`:

```sh
MURMUR_ENGINE_INTEGRATION=1 go test -count=1 -timeout 600s ./tests-live/large-payload/
```

The payload is 1.5 MiB; this is a correctness test rather than a throughput benchmark.
