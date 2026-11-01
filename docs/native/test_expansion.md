# Managed test coverage

The test expansion covers eight areas. Native tests link the actual C/C++
implementation. Managed live tests run independent child processes, each
with its own encrypted store and signing identity.

| Area | Assertions |
| --- | --- |
| Independent policy model | Seeded operation-history oracle across 3–5 stores; all seven policies, partitions, reordered delivery, replay, missing dependencies, delete/reinsert generations, reopen, exact projections and original-record receipts |
| Persistence faults | Local and remote pre-COMMIT, WAL write and sync failures, including EIO/ENOSPC; application rows, causal state, epochs, log, clocks and receipts recover atomically; retries resolve uncertain committed outcomes |
| Strict acknowledged-write survival | SIGKILL immediately after ACK, without a flush, drain, sleep or intervening query; exact transaction IDs, parts and payloads survive six restarts and converge on three stores; a second test kills a real transaction staged before COMMIT and proves its complete rollback |
| Writer scheduling | Sustained native contention at three configured service shares, debt bounds, FIFO, cancellation, maintenance and shutdown; live local writes compete with real signed remote applies, service counters and exact ACK audits |
| Codec and authenticated-input fuzzing | Eight bounded codec entry points, seeded mutation corpus and round-trip/join invariants; 464 re-signed adversarial transaction/schema cases must leave visible and private persistent state unchanged, followed by successful honest writes |
| Independent search oracle | Fresh in-memory FTS rebuild and brute-force L2/cosine/L1 results over 620+ documents; mutation through two handles, renames, invalid-vector failure/repair and reopen; live metadata adoption and migration crashes before/after COMMIT |
| Go ownership and cancellation | Cancellation before/during execution, prepared statements, late cancellation, early rows close, scan failures, rollback/reuse and copied parameter/result bytes under the race detector |
| Resource bounds | Statement count and native retained-byte budgets, open/close and failure workloads, Go heap, process RSS, descriptors, goroutines, search queues and temporary files; separate long-lived child and process-churn phases |

Sources: [native model](../../deps/murmur/managed_model_selftest.cc),
[fault matrix](../../deps/murmur/managed_fault_selftest.cc),
[scheduler](../../deps/murmur/scheduler_contention_selftest.cc),
[search oracle](../../deps/murmur/managed_search_oracle_selftest.cc),
[fuzz runner](../../deps/murmur/managed_fuzz_selftest.cc),
[Go driver tests](../../clients/go/murmurdb/),
[live durability](../../clients/go/tests-live/managed-durability/), and
[live managed profiles](../../clients/go/tests-live/managed-profiles/).

## Short validation

From the repository root on Linux (resource sampling uses `/proc`), with
the vendored native dependencies built:

```sh
make -j4 selftest test-native-sanitize
make test-go-managed
make test-live-managed
```

`make test-managed` runs the five focused native expansion suites, Go race
tests and managed live scenarios. `make test-live-managed` explicitly opts
into integration testing. Direct live invocation remains opt-in:

```sh
MURMUR_ENGINE_INTEGRATION=1 bash clients/go/tests-live/run.sh managed
# Or just one managed suite:
MURMUR_ENGINE_INTEGRATION=1 bash clients/go/tests-live/run.sh managed-durability
```

The managed runner uses the race detector in the Go test controller. Its
child executable uses normal cgo builds of the native managed API; Go's
race detector does not instrument C/C++ or that separately built child.
Native ASan/UBSan instruments owned managed modules. Vendored storage and
SQLite archives remain uninstrumented; vptr checks are disabled because
RocksDB is built without RTTI. ASan leak detection remains enabled.

## Stress and reproduction

```sh
make test-managed-stress
# Individual reproducible runs:
build/managedmodeltest 42 1000 5
build/managedfuzztest 1592594996 250000
MURMUR_ENGINE_INTEGRATION=1 MURMUR_MANAGED_RESOURCE_CYCLES=400 \
  MURMUR_MANAGED_TEST_COUNT=3 bash clients/go/tests-live/run.sh managed
```

The stress target runs eight model seeds with 500 steps and varying store
counts, 250,000 codec mutations and three repetitions of all managed live
tests with 400 resource cycles. Model limits are 10,000 steps and 3–5 stores;
fuzz mutations are bounded at 1,000,000; resource cycles accept 20–10,000.
The default resource test uses 80 steady cycles per child after warmup,
then eight separate rounds of restarting both children. SST descriptors
are compared with existing SST files; other descriptors have their own
fixed budget. RSS includes native caches and allocator arenas and is
checked as a bounded regression metric, not an exact allocation count.

Model failures retain stores and `model-trace.txt`: seed, SQL operations,
delivery/reopen order, original signed bytes, expected receipts and actual
origin progress. Codec failures print a saved input path, replayable with
`build/managedfuzztest --replay PATH`. Signed-apply failures additionally
retain the original envelope/payload and destination stores.

Live failures preserve a directory printed as `managed failure artifacts`:
encrypted stores, deterministic test identities, stderr, JSON request/response
traces (including original signed bytes and progress), archived restart
traces and, for the ACK crash audit, `acknowledged-transactions.json` with
exact payloads. Current-process traces retain the latest 16 MiB (a single
larger frame is retained intact). `MURMUR_LIVE_RUNTIME` chooses the parent
directory. Successful runs remove their stores and reap every child.

## Scope and fixes found

The managed harness delivers original signed records over controlled stdio
RPC schedules. These tests exercise real capture, authentication, scheduler
admission, persistence, adoption and materialization. Signed native QUIC
transport, network chaos, checkpoints and coordinated upgrades remain
unfinished. Existing legacy scenario skips are unchanged; legacy driver
tests do not establish managed signed-profile behavior. An explicitly
enabled managed suite fails on a missing child capability or build error.

The fuzz target also exports `LLVMFuzzerTestOneInput` in
[managed_codec_fuzz.cc](../../tests/native/managed_codec_fuzz.cc). The default
gate runs deterministic mutations and authenticated rejection cases;
coverage-guided execution is available with `make -j4 test-native-libfuzzer`.
This builds owned modules with Clang coverage, ASan and UBSan, exports valid
codec fixtures into a persistent corpus, and runs libFuzzer for 60 seconds.
Override `FUZZ_CXX` to select another Clang installation. The build selects
the C++ toolchain used by `CXX`, avoiding incomplete GCC installations.

The new tests exposed and fixed three production issues: Go statements
ignored cancellation once SQLite execution began; the driver's prepared
statement cache retained unbounded entries/operands; local policy inserts
could keep NULL or noncanonical JSON/list projections while peers stored
canonical values. Regressions cover in-flight cancellation, 128-entry and
8 MiB statement-cache bounds without evicting active rows, and exact local/
remote policy projections across fresh generations and reopen. The fixes
add no dependencies.

Validation of this expansion passed the full native selftest gate, all five
ASan/UBSan suites, Go binding/driver/harness race tests and both managed live
packages. The stress gate passed seeds 1–8 at 500 steps across 3–5 stores,
250,000 codec mutations and three live repetitions with 400 resource cycles.
The strengthened persistence fault matrix additionally passed in normal
and sanitizer builds. One initial legacy `test_serve_snapshot` run failed
its `snap sent` counter assertion; two direct reruns and the subsequent
full selftest run passed. Follow-up investigation identified a receiver/
donor completion race in that assertion. It now reads the donor counter
after joining the donor thread, and 20 consecutive sync-suite runs passed.
An instrumented 60-second libFuzzer run also completed without a finding.
