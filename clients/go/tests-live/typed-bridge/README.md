# typed-bridge

Two single-node native deployments, with separate database IDs, CAs and storage
keys, exchange typed rows through a shared immutable directory. Native capture
and workers perform export and import; High edits retain field ownership while
later Low updates change unowned fields. Native release restores Low values.
The High store is fully closed and reopened twice to prove ownership, released
state and duplicate receipts survive without recapture or reapplication.

The harness invokes the native release API instead of a legacy SQL management
verb. Writes use the harness's native transactional `Execute` path; ordinary
`database/sql` interception is tested separately in `murmurdb` and bridge
binding tests. This suite does not prove replication between High peers or
forwarding changes from other Low peers; those remain separate release gates.

Run from `clients/go`:

```sh
MURMUR_ENGINE_INTEGRATION=1 go test -count=1 -timeout 90s ./tests-live/typed-bridge/
```
