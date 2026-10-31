# plumtree-live

Three nodes in Plumtree dissemination mode converge end to end (10 rows
from node 0 on every node), while a gossip-mode node meshed with
Plumtree peers stays isolated in both directions (10/10/1 row counts
after a leak window) with handshake incompatibility refusals recorded.

This suite is fully skipped in the native port: the native engine has
no dissemination mode at all — gossip is the only transport behavior,
with no Plumtree setting and no per-node mode overlay
(`harness: Plumtree dissemination mode (per-node dissemination
setting)`).

Run from `clients/go`:

```sh
MURMUR_ENGINE_INTEGRATION=1 go test -count=1 -timeout 600s ./tests-live/plumtree-live/
```

Pass criteria in the reference: all-Plumtree mesh converges on the 10
`plum-{0..9}` names within 60 s; mixed mesh counts are exactly 10/10/1
after the leak window; at least one node records an `incompatible`
handshake refusal; the gossip node holds 0 sessions while each Plumtree
node holds exactly 1.
