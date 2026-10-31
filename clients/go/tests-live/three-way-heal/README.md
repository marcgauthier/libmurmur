# Three-way healing through live SQL

Four nodes converge on 10 base rows, then split into isolated pairs.
Each pair performs its own SQL inserts and conflicting updates to
shared baseline rows. Exact row counts and differing row values prove
the partition held. Links heal one at a time in two different orders,
with peer/row checks after each link; all nodes must converge to the
same exact rows and the same later conflict winner.

Nodes are native replication drivers over VFS stores, driven in-process
through `goharness` (see `../PORTING.md`). This stack has no peer
removal or per-link surgery, so splits and heals use per-node
`allowed_peers` identity allow-lists applied with a replication restart
(the partition-suite mechanism); each heal step widens the two
endpoints' allow-lists to admit each other and remeshes.

`MURMUR_THREE_WAY_HEAL_ORDER` defaults to `0,1,2,3` and
`MURMUR_THREE_WAY_HEAL_ORDER_B` to `3,2,1,0`. Both must be permutations
of the four cross-pair links.

Run from `clients/go`:

```sh
MURMUR_ENGINE_INTEGRATION=1 go test -count=1 -timeout 600s ./tests-live/three-way-heal/
```

Topology changes use config rewrites and replication restarts. This does
not emulate packet loss on an otherwise running connection.
