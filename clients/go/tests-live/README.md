# tests-live: libmurmur live multi-node scenarios

Port of the reference `tests-live` suite (74 scenarios) onto the
[Go client](../../README.md) and the native `libmurmur` engine. Each scenario
is a standalone Go test package under this directory; the shared hybrid
harness lives in [goharness/](./goharness/).

## Topology

- **In-process nodes**: open a real engine database with the native bindings
  (`driver` + `store` + `files`), no pgwire, no TCP SQL listener.
- **Child nodes**: spawned `tests-live/node` binaries speaking newline
  JSON over stdio (launch/step/kill/snapshot), for crash/kill/partition
  scenarios.

The harness picks child nodes for suites whose tags demand process
isolation and in-process nodes otherwise; suites can force either mode.

## Running

Live scenarios are opt-in and never run by default:

```sh
export MURMUR_ENGINE_INTEGRATION=1
# one scenario (skip-gated, operator/CI only runs the full runner):
cd clients/go && go test -count=1 ./tests-live/three-node-sync/
# full runner:
./clients/go/tests-live/run.sh all
./clients/go/tests-live/run.sh gate     # release-gate subset
./clients/go/tests-live/run.sh soak     # long soaks
./clients/go/tests-live/run.sh stress   # restart/partition stress x5
```

The runner builds `libmurmur.a` (if missing) and the node binary, then runs
each scenario package alone with a per-scenario timeout. Server processes
rooted at `$MURMUR_LIVE_RUNTIME` (default `tests-live/runtime`) are reaped
on exit.

Without `MURMUR_ENGINE_INTEGRATION=1` every suite skips with
`"integration: engine tests are opt-in"`.

## Porting contract (see [PORTING.md](./PORTING.md))

- Never edit the reference tree; only read it.
- `import ".../goharness"` only — scenario packages must not import engine
  internals directly.
- `%s`/`$N` placeholders become `?`; DDL uses `INTEGER PRIMARY KEY NOT
  NULL` plus `DEFAULT ''`/`0` on every mirrored column.
- `MURMUR SHOW` / pgwire admin surfaces are remapped to native JSON
  snapshots from the harness.
- Missing harness capability ⇒ `t.Skip("harness: ...")` with the reason;
  never fake assertions.
- When the ported engine disagrees with the reference on a verifiable
  behavior, fix the engine code, not the port.

## Layout

- `goharness/` — shared harness: cluster/node lifecycle, certs, SQL helpers,
  child-node stdio protocol, artifacts, backups, forensics.
- `node/` — child node binary (`main.go`).
- `<scenario>/` — one package per live scenario (ported from reference).
- `PORTING.md` — full porting contract and remap tables.
- `run.sh` — CI/operator runner (this file's sibling).

## Managed signed profiles

The separate `managedharness/` and `managed-node/` exercise the managed C API
in real child processes. `managed-profiles/` covers all merge policies,
hostile relays, origin receipts, writer contention, search metadata, migration
crashes and resource bounds. `managed-durability/` audits exact acknowledged
payloads after immediate SIGKILL and rolls back a transaction killed before
COMMIT. These new suites use controlled signed-record delivery over stdio;
native signed QUIC integration remains pending.

From the repository root:

```sh
make test-live-managed
# Equivalent opt-in runner, using the Go race detector in the controller:
MURMUR_ENGINE_INTEGRATION=1 bash clients/go/tests-live/run.sh managed
```

The managed runner builds its own child with test-only migration crash
hooks. Once enabled, missing capabilities fail the test. It needs no legacy
node binary. Failure artifacts retain stores, identities, signed record/RPC
traces, progress and acknowledgment audits. See
[test coverage and stress commands](../../../docs/native/test_expansion.md).
