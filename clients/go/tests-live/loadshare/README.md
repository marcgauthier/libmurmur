# loadshare

Four writers commit 240 rows on one node while its peer commits another
20 rows. Both origins must converge exactly, and the slowest local
write must stay within 10 s. The reference's scheduler-acquisitions /
debt snapshot leg is skipped: the native status snapshot exposes no
scheduler acquisition counters or debt gauge.

## Mapping

- The four per-worker SQL connections become goroutines over the
  shared node 0 handle (the harness serializes statements); the
  remote paced writer stays on the test goroutine.
- `MURMUR FLUSH` becomes `node.Flush()`; suite SQL is otherwise
  verbatim (`$N` placeholders are translated automatically).
- Fixture, convergence, and timeouts are unchanged; see
  `../PORTING.md`.

Run from `clients/go`:

```sh
MURMUR_ENGINE_INTEGRATION=1 go test -count=1 -timeout 600s ./tests-live/loadshare/
```
