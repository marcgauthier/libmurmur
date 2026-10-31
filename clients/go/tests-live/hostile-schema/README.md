# hostile-schema

A malicious authenticated peer (cluster-CA QUIC identity, untrusted
origin key) serves hostile signed schema manifests at an honest
3-node cluster: a revision with a corrupted signature, a
self-consistent revision from an untrusted signer, an oversized
revision, and a zero-sequence revision. Every forgery must be
refused and quarantined (never adopted): served schema bytes and
rows stay put while honest writes keep converging.

## Status: partial (harness gap after the portable prefix)

`TestHostileSchemaManifestsQuarantined` runs the honest setup and
pre-attack positive control, then skips with:

- `harness: raw-QUIC wire attacker fixture for schema manifests
  and error-latch recorder unavailable (no wire-protocol peer; no
  forgery leg can run)`

The blocked legs need a raw-QUIC peer speaking the replication wire
protocol: authenticated dials with chosen schema bytes, served
schema-manifest fetch, forged-manifest sends, and stream-death (ping
silence / missing `SchemaAck`) observation, plus a background
`last_error` latch recorder. No such fixture exists in `goharness`,
and scenario packages must not import engine internals to build one.

## What runs here

- 3 nodes mesh; `records` is created and flagged replicated on all.
- Positive control (pre-attack): `baseline` on node0 converges on
  all three nodes.

## What the reference proves beyond this port

- S1: served tip with flipped signature bytes kills its stream
  (ping unanswered, no `SchemaAck`), latches the signature refusal,
  moves nothing; node survives.
- S2: self-consistent revision from the untrusted signer kills its
  stream and latches `untrusted schema signer`; never adopted.
- S3: 2 MiB revision against the 1 MiB cap kills its stream and
  latches the envelope refusal.
- S4: zero-sequence revision kills its stream and latches the
  envelope refusal.
- Quarantine: adoptions unmoved, served schema bytes unchanged,
  rows unchanged; all 6 attack handshakes attached.
- Post-attack: `post-attack-1` / `post-attack-2` /
  `attacked-node-write` converge on all nodes.

## Deviations from the reference

- 3 nodes instead of 4: the stopped credential-donor node exists
  only to back the attacker fixture.
- No `max_transaction_bytes` overlay: the harness exposes no
  replication tuning knobs (the oversized leg is blocked anyway).
- `AssertRows` convergence (60 s) instead of the 30 s per-leg waits.
