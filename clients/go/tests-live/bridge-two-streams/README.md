# bridge-two-streams

Two native single-node Low domains export different streams through a shared
directory into one native High node. Each stream retains its source identity,
signing and receiver keys, queue budget, progress and private quarantine.
The test verifies both streams import, High-owned fields remain protected,
queues drain, and a forgery in the second stream does not stop the first.

Native artifact-store tests additionally check that one lane's queued bytes
cannot consume another lane's configured budget. All lanes retain a shared
1 GiB hard cap per inbox/outbox for overall database resource control.
Cross-peer forwarding and file chunks are separate release gates.

Run from `clients/go`:

```sh
MURMUR_ENGINE_INTEGRATION=1 go test -count=1 -timeout 90s ./tests-live/bridge-two-streams/
```
