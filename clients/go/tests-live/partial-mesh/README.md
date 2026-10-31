# partial-mesh

Two tests verify forwarding along a three-node chain with exact peer counts
(1, 2, 1) and no direct endpoint link, and automatic seed-based discovery into a
full mesh. SQL inserts from multiple origins must converge to exact ordered rows.

Each node is a native replication driver over a VFS-backed store, run
in-process by the `goharness` test harness. Manual chain wiring uses
`NoMesh` plus runtime peer adds; peer topology uses typed `ShowPeers`
rows. The reference disables membership gossip for the chain leg; the
native harness has no such toggle, so the chain leg asserts the
forwarding behavior directly. The discovery leg is currently skipped:
seed-bootstrapped native nodes stay hub-and-spoke and never discover a
full mesh (`harness: seed-bootstrapped dynamic peer discovery does not
mesh the cluster`).

Run from `clients/go`:

```sh
MURMUR_ENGINE_INTEGRATION=1 go test -count=1 -timeout 600s ./tests-live/partial-mesh/
```

`MURMUR_LIVE_RUNTIME` selects the parent directory for unique per-test
runtime folders. Successful tests remove their runtime folders; failures
retain the config and logs at the path printed in the test output.
