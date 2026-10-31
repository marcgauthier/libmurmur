# long-running-five-node

Five SQL writers run while two nodes restart at one-third and two-thirds
of the requested duration. Per-node connection slots keep durable
acknowledgements synchronized with restarts; every acknowledged row is
checked after recovery and final convergence. The test requires at
least 10 writes per node, 100 total, a 2 GiB per-node spool budget, no
storage error, and a successfully replicated post-soak write.

Nodes are native replication drivers over VFS stores, driven as child
processes through `goharness` (see `../PORTING.md`; build the node
binary with `go build -o /tmp/murmur-test-node ./tests-live/node` and
export `MURMUR_NODE_BIN=/tmp/murmur-test-node`). Restarts are graceful
replication Stop/Start with the store staying open (real process
restarts are covered by rolling-restart). The reference status legs remap to native
snapshots: zero pending bytes become fully-applied replication progress
(`applied == observed`) on every origin, the spool budget becomes
data-dir bytes, and the storage error becomes the engine failure triple
(`last_error_code/kind/message` absent). The soft `last_error` text is
forensics only: stopping a node under load tears live sessions, and the
survivors record transport noise into the same latch the reference's
storage-scoped field does not see.

`MURMUR_FIVE_NODE_DURATION_SECONDS` defaults to 30 (minimum 3),
`MURMUR_FIVE_NODE_INTERVAL_MS` to 50, and
`MURMUR_FIVE_NODE_SETTLE_SECONDS` to 120. The soak runner requests 3,600
seconds. Short runs require an appropriately short write interval to
meet progress gates.

Run from `clients/go`:

```sh
MURMUR_ENGINE_INTEGRATION=1 go test -count=1 -timeout 600s ./tests-live/long-running-five-node/
```

Full-duration runs are required for soak qualification; a compile check
or short smoke run does not establish it.
