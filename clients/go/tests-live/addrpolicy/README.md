# addrpolicy

Address admission is enforced on the replication mesh: node 0 admits
loopback peers (`127.0.0.0/8`), node 1's TEST-NET policy
(`198.51.100.0/24`) excludes every actual loopback socket address, and
node 2 is unrestricted. The admitted node 0 - node 2 pair forms a
session and replicates, while the denied node 1 keeps its writes local.

## Pass criteria

- `NewCluster` boots 3 native nodes.
- Node 0 has `allowed_networks = ["127.0.0.0/8"]` in `murmur_config`.
- Node 1 has `allowed_networks = ["198.51.100.0/24"]`.
- Node 2 has unrestricted `allowed_networks` (default empty allows all).
- Replicated table `records(id INTEGER PRIMARY KEY NOT NULL,
  name TEXT NOT NULL DEFAULT '')` created and enabled across nodes.
- One row inserted per node (`allowed-loopback`, `denied-testnet`,
  `unrestricted-loopback`).
- Nodes 0 and 2 converge on both admitted rows.
- After a 1 s settle window, node 1 still holds only its local row.
- Node 0 holds only the 2 admitted rows.
- Peer topology via `ShowPeers` confirms node 1 has no connected peers.

The reference `SetConfig` section writes become `murmur_config`
updates plus replication restart (QUIC settings reload on every
`Start`); see `../PORTING.md`. The cr-sqlite DDL carries explicit
`NOT NULL`/`DEFAULT` per the porting rules.

Run from `clients/go`:

```sh
MURMUR_ENGINE_INTEGRATION=1 go test -count=1 -timeout 600s ./tests-live/addrpolicy/
```
