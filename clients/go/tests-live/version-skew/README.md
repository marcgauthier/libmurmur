# version-skew

A peer advertising an unknown protocol version is refused
fail-closed: converge a pair while node 3 stays isolated, run a raw
version-99 fixture against each survivor, assert the refusal gates
(invalid frame header, incompatible hello, no session, no rows, no
state shift), and prove the pair still converges with node 3 empty
afterwards.

## Status: skipped (no protocol version on the native wire)

The native wire protocol has no protocol-version field
(`MsgHello` carries group/node/site/schema/incarnation/addr; frames
carry no version), so a version-99 fixture cannot be constructed and
the refusal gates have nothing to assert. The isolation/convergence
legs alone would prove nothing about version skew, so the whole
suite skips with `harness: protocol versioning on the native wire
(no version field to skew)` rather than shipping a vacuous port.

## Reference pass criteria (for when the wire versions)

- Version-99 fixture refused: invalid frame header on connect,
  incompatible hello on re-hello, no session row for the fixture.
- Fixture receives no rows; survivor state (counts, last-error)
  unshifted.
- Pair still converges after; isolated node holds no rows and no
  local write leaks.

Run from `clients/go`:

```sh
MURMUR_ENGINE_INTEGRATION=1 go test -count=1 -timeout 600s ./tests-live/version-skew/
```
