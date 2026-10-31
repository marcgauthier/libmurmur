# corrupt-snapshot

A stale node rejoins while its only available snapshot source is
hostile: it must reject the corrupt chunk with nothing partially
published, then converge via the honest snapshot path.

## Status: skipped (harness gaps)

`TestStaleNodeDiscardsCorruptSnapshotThenConverges` skips with:

- `harness: raw-QUIC attacker fixture and snapshot delivery both
  unavailable (no wire-protocol peer; stale rejoin never converges)`

Two independent blockers:

1. The attacker dialogue needs a raw-QUIC peer speaking the
   replication wire protocol: dial the victim, induce a snapshot
   pull with an unsolicited history-unavailable error, serve a
   structurally valid manifest plus one intact and one bit-flipped
   chunk, and assert no `SnapshotApplied` arrives. No such fixture
   exists in `goharness`, and scenario packages must not import
   engine internals to build one.
2. Both the corrupt-transfer leg and the honest-resync leg need the
   snapshot path, which never delivers on this stack: a stale node
   whose range was pruned never converges after rejoin (the
   snapshot-resync gap, verified first-hand).

## What the reference proves

- 3 nodes mesh; node3 writes 5 `stale-*` rows; all converge.
- Node3 is isolated and stopped; node1 writes 60 `fresh-*` rows;
  survivors converge and prune past retention.
- Node3 restarts peerless; the attacker dials it as its only peer,
  induces a snapshot pull, and serves a forged manifest plus one
  intact and one bit-flipped chunk.
- The victim records a `snapshot chunk` authentication error, never
  sends `SnapshotApplied`, and keeps exactly its 5 pre-stop rows
  with an identical digest, commit cursor, and log-path counters.
- After the staged corrupt transfer expires, honest peers return
  and all converge on 65 rows with equal digests while the
  victim's log-path counters stay flat; the commit cursor never
  regresses and the 5 pre-stop rows survive.
