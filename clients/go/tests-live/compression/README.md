# compression

Three single-node spools at compression levels 1, 6, and 12 take a
text/config/blob workload. High shrinks text-heavy tenants versus
low, per-tenant billable bytes stay byte-exact, every snapshot
matches its source, and blob-heavy tenants shrink too.

## Status: skipped (no compression knob in this stack)

Every leg compares compression levels, but the engine exposes no
`engine.compression_level` setting, so levels cannot be formed and
the relational gates have nothing to compare. The suite skips with
`harness: spool compression levels (engine.compression_level knob)`.

## Reference pass criteria (for when the knob lands)

- High-vs-low shrinkage > 5 %; blob-heavy tenants also shrink.
- Billable bytes byte-exact per tenant; usage snapshots match
  sources.
- Recorded compression ratio sane (0.05..1.0).

## Env knobs (reference)

- `MURMUR_COMPRESSION_ROWS` (default 2000).

Run from `clients/go`:

```sh
MURMUR_ENGINE_INTEGRATION=1 go test -count=1 -timeout 600s ./tests-live/compression/
```
