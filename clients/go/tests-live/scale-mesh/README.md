# scale-mesh

Ten live nodes converge on 400 rows from two origins (300 on node 1,
100 on node 8). Every node must hold identical ordered row values;
the convergence deadline is 300 seconds.

Each node is a native replication driver over a VFS-backed store, run
in-process by the `goharness` test harness. The reference's concurrent
fanout sampler is skipped: the harness exposes no `gossip_fanout`
setting and peer rows carry no selected-push-peer flag (`harness:
gossip fanout setting and selected-push-peer introspection`).

Run from `clients/go`:

```sh
MURMUR_ENGINE_INTEGRATION=1 go test -count=1 -timeout 600s ./tests-live/scale-mesh/
```

`MURMUR_LIVE_RUNTIME` selects the parent directory for unique per-test
runtime folders. Successful tests remove their runtime folders; failures
retain the config and logs at the path printed in the test output.
Full-duration runs are required for soak qualification; a compile check
or short smoke run does not establish it.
