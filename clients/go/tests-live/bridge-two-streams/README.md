# bridge-two-streams

Two low bridge domains (First/Second Low) export through one shared
staging directory into a single high domain. Both streams converge
marker rows, keep separate outbox budgets, and the High side's
per-stream import wins, inbox burn-down, and isolation all hold.

## Status: skipped (no bridge machinery in this stack)

Every leg needs bridge domains plus bundle export/import over a
shared staging directory, none of which the harness or bindings
expose (same gap as the typed-bridge port). The suite skips with
`harness: bridge domains (per-stream bridge export/import over a
shared staging dir)`.

## Reference pass criteria (for when bridge lands)

- Both streams converge marker rows on High.
- Per-stream outbox budgets stay separate; second stream quarantines
  correctly.
- High-side import wins, inbox burn-down, and isolation hold.

Run from `clients/go`:

```sh
MURMUR_ENGINE_INTEGRATION=1 go test -count=1 -timeout 600s ./tests-live/bridge-two-streams/
```
