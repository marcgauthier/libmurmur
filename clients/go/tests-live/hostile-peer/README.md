# hostile-peer

A malicious authenticated peer (cluster-CA QUIC identity, untrusted
origin key) fires forged batches, invalid identities, a replayed
handshake, a 256 MiB allocation-claim frame, a compressed snapshot
bomb, and a far-future-HLC batch at an honest 2-node cluster. Every
attack must be rejected on the wire and in product latches/counters,
nothing foreign may apply, and the honest pair must stay converged
and responsive throughout.

## Status: partial (harness gap after the portable prefix)

`TestHostilePeerAttacksRejected` runs the honest setup and
pre-attack positive control, then skips with:

- `harness: raw-QUIC wire attacker fixture with frame injection and
  error-latch recorder unavailable (no wire-protocol peer; no
  attack leg can run)`

The blocked legs need a raw-QUIC peer speaking the replication wire
protocol: authenticated dials with chosen schema bytes, framed
transaction sends, raw frame injection (allocation-claim, compressed
snapshot chunk), handshake replay, wire `Error{code: 1}` observation,
and stream-death (ping silence) observation, plus a background
`last_error` latch recorder. No such fixture exists in `goharness`,
and scenario packages must not import engine internals to build one.

## What runs here

- 2 nodes mesh; `records` is created and flagged replicated on both.
- Positive control (pre-attack): `honest-1` on node0 and `honest-2`
  on node1 converge both ways.
- Counter baseline read from the progress snapshot (the stillness
  reference the attack legs would assert against).

## What the reference proves beyond this port

- Schema-learn dial returns the node's real schema bytes; the
  control dial is welcomed with no `SchemaRequest`.
- P1a: zero-sequence, wrong-database, oversized, and zero-from
  `Need` probes each draw `Error{code: 1}`; session stays alive.
- P2: replayed handshake draws `Error{code: 1}`; session stays alive.
- P1b: forged matched-schema batch kills its session, latches
  `untrusted transaction origin`, moves no counters, leaves rows
  unchanged.
- P3: 256 MiB allocation-claim frame kills its stream; node survives.
- P4: zstd snapshot bomb kills its stream; node survives.
- P-HLC: far-future-HLC batch rejected with `untrusted` latched and
  counters unmoved.
- Post-attack: schema bytes unchanged, then `post-attack-1` /
  `post-attack-2` converge both ways.

## Deviations from the reference

- 2 nodes instead of 3: the stopped credential-donor node exists
  only to back the attacker fixture.
- No `max_transaction_bytes` overlay: the harness exposes no
  replication tuning knobs (the oversized leg is blocked anyway).
- `AssertRows` convergence (60 s) instead of the 30 s per-leg waits.
