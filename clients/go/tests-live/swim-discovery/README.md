# swim-discovery

Four nodes discover a full mesh from a single bootstrap seed. Both
tests check peer/member status and exact replicated rows. The second
kills the seed, writes on survivors, restarts the same data directory,
and requires rediscovery and exact row convergence.

Both tests are skipped: seed-bootstrapped native nodes never dial
beyond their seeds, so the cluster stays hub-and-spoke and no gossip
discovery forms the full mesh (the partial-mesh port skips its
discovery leg for the same reason). The native status snapshot also
has no replication member count.

Run from `clients/go`:

```sh
MURMUR_ENGINE_INTEGRATION=1 go test -count=1 -timeout 600s ./tests-live/swim-discovery/
```
