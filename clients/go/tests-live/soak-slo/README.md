# soak-slo

Three concurrent writers use bounded ranges of 1,000 rows per node,
then update their own rows. The test checks exact final values, at
least 60 writes, write p95 at most 5 seconds and maximum at most 20
seconds, and a null `last_error` on every node (the portable analog of
the reference's null storage error). The staged-transactions / spool /
pending-bytes gauge legs are skipped: the native status snapshot
exposes none of those gauges.

`MURMUR_SLO_DURATION_SECONDS` defaults to 5 seconds; the soak runner
defaults to 7,200 seconds. `MURMUR_SLO_SETTLE_SECONDS` defaults to 30
seconds. Full-duration runs are for CI; short runs prove the port.

## Mapping

- The reference harness meshes fully by default; native nodes only
  dial their seed, so the port calls `cluster.PeerMesh()` explicitly.
- `MURMUR FLUSH` becomes `node.Flush()`; suite SQL is otherwise
  verbatim.
- Fixture, peer counts, convergence, and timeouts are unchanged; see
  `../PORTING.md`.

Run from `clients/go`:

```sh
MURMUR_ENGINE_INTEGRATION=1 go test -count=1 -timeout 600s ./tests-live/soak-slo/
```
