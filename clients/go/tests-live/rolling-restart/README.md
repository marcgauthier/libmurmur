# rolling-restart

Two tests perform three rolling restarts and six churn restarts respectively.
Acknowledged baseline rows are flushed before each real process restart. Writers
on both surviving nodes continue issuing SQL while the stopped node restarts;
every acknowledged row must converge on all three nodes after each round.

Restarts are child-process kills plus reboots on the same dir through
`goharness` (see `../PORTING.md`).

Run from `clients/go`:

```sh
go build -o /tmp/murmur-test-node ./tests-live/node
MURMUR_ENGINE_INTEGRATION=1 MURMUR_NODE_BIN=/tmp/murmur-test-node go test -count=1 -timeout 600s ./tests-live/rolling-restart/
```
