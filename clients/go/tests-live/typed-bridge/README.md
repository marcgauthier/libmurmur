# typed-bridge (fully skipped)

The reference proves a typed bridge record imports into the native
path, honors ownership, and survives restart: two single-node clusters
form the Low (exporter) and High (importer) bridge domains sharing one
staging directory (stream `typed-stream`); a typed row inserted on Low
is exported and imported through High's typed durable path; a High
write overrides the field (automatic ownership); a Low update while the
field is High-owned is imported but suppressed; `MURMUR BRIDGE RELEASE`
drops the ownership so the next Low update flows through; and the
imported result survives a High-node restart.

## Why it is skipped

None of that is expressible natively (`harness: typed bridge (bridge
domains, bundle export/import, BRIDGE RELEASE)`):

- `NewCluster` has no bridge-domain option (roles, staging directory,
  stream, recipient/secrets, trust maps), and the suite needs two
  clusters with distinct database ids in one test.
- The bindings expose no bundle export/import path: no staging-dir
  bundle files are ever written, so neither the export proof nor the
  import/suppression legs can run.
- There is no `BRIDGE RELEASE` verb to drop field ownership.

## Deviations from the reference

- None apply: the suite is skipped before any cluster boots.

Run from `clients/go` (skips with the named reason):

```sh
MURMUR_ENGINE_INTEGRATION=1 go test -count=1 -timeout 600s ./tests-live/typed-bridge/
```
