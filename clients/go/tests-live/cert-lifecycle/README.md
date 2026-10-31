# cert-lifecycle

A node whose certificate expires is rejected on fresh replication
handshakes, and rotation restores the mesh: converge a marker (positive
control), swap B to a short-expiry cert for the same NodeID and show the
mesh stays connected pre-expiry, wait past NotAfter and reboot B so both
sides must re-handshake (survivor sees no session, connected peers
1->0, an A-side marker never reaches B during the isolation window),
then rotate to a fresh cert and show full reconvergence plus a
bidirectional write.

## Pass criteria

- Phase 0: `marker-init` converges on both nodes; A holds a session to B
  and `connected_peers(A) == 1`.
- Phase 1: after rotating B to a TTL cert, the served leaf is fresh
  rotation-time material (stale-cert guard), A connects to B, and
  `marker-pre-expiry` converges before NotAfter minus 5 s.
- Phase 2: past NotAfter + 2 s, with B rebooted on the same expired
  leaf: A reports B not connected, `connected_peers(A) == 0`, B's own
  view agrees, the served leaf is byte-identical to the minted short
  leaf whose TTL has fully elapsed, and during the isolation window
  `marker-post-expiry` never reaches B while A keeps serving all 3
  markers with `connected_peers(A) == 0` throughout.
- Phase 3: after rotating B to a fresh 24 h cert, the mesh reconnects,
  all 3 markers converge, a B-side `marker-rotated` converges back, and
  both nodes hold equal ordered names.

## Env knobs

- `MURMUR_CERT_LIFECYCLE_TTL_S` (default 25): short-cert lifetime. Values
  below 15 s abort: too little pre-expiry budget (same guard as the
  reference).
- `MURMUR_CERT_LIFECYCLE_WINDOW_S` (default 10): post-expiry isolation
  window.

## Deviations from the reference

- Nodes are native replication drivers over VFS stores instead of
  `murmur-server` children over the PG wire. Node A runs in-process;
  node B runs as a child process (`MURMUR_NODE_BIN`) so crashes are
  real SIGKILLs and rotations reload via process reboot.
- Plain SQL (`records(id INTEGER PRIMARY KEY NOT NULL, name TEXT NOT
  NULL DEFAULT '')`) instead of the reference DDL.
- Session state comes from typed `SHOW PEERS` rows (connected counts
  stand in for the `peers` column of `MURMUR SHOW REPLICATION`).
- No TLS-served-cert fetch: expiry is proven against the minted TTL
  clock (rotation instant + TTL) instead of parsing the served leaf's
  NotAfter. The stale-cert and non-vacuity legs read the node's
  `tls/node.pem`, which rotation rewrites from the same material the
  rebooted child loads: phase 1 asserts the bytes change at rotation
  time with a fresh mtime, and phase 2 asserts the served bytes are
  still that same short leaf while its TTL has fully elapsed. The
  rejection assertions themselves fail closed: a silently un-swapped
  cert would stay connected and time out the rejection waits.
- Rotation is a scenario-local helper (issue a fresh leaf for the same
  NodeID from the cluster CA, rewrite `tls/node.pem` +
  `tls/node-key.pem`, reboot the child) instead of a harness helper;
  every reboot is followed by an explicit re-mesh.
- The survivor's replication bounces gracefully before every reboot
  of node B: this engine closes a fresh inbound session as a
  duplicate while any entry for the peer lives, so without the
  bounce the rebooted node's dials die on the survivor's zombie
  entry and markers never flow (murmur-server replaces zombies by
  tie-break instead). The expiry-rejection proof is unaffected: the
  handshake itself rejects the expired leaf before any session
  registers.
- All three restarts are crash-style (SIGKILL plus fresh child boot on
  the same dir), including the phase-2 expiry restart where the
  reference stops/starts: every form forces fresh handshakes, and the
  reboot form provably reloads `tls/` from disk.
- Node ids are the harness deterministic ids (index+1 in the last
  byte), so the pinned adversarial order (survivor A < restarted B)
  holds without extra options: the survivor's pre-restart session is in
  its tie-break-preferred direction, so the rotation legs
  deterministically exercise zombie replacement.
- The isolation-window argument is unchanged: the re-mesh redials
  immediately and the engine keeps dialing, so a steady zero across the
  window proves rejection rather than idleness.

Run from `clients/go`:

```sh
go build -o /tmp/murmur-test-node ./tests-live/node
MURMUR_ENGINE_INTEGRATION=1 MURMUR_NODE_BIN=/tmp/murmur-test-node go test -count=1 -timeout 600s ./tests-live/cert-lifecycle/
```
