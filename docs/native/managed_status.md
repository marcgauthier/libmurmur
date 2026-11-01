# Managed native implementation status

The managed API is opt-in and does not yet complete the feature-parity plan.
Local policies/search, signed schema adoption and signed transaction-log/apply
paths for ordinary and policy-bearing tables are implemented.
Network transport, baseline upgrades for existing data and coordinated store
upgrades remain incomplete. The legacy
runtime retains its protocol and rejects stores activated for the signed
profile. These APIs are not a completed cluster upgrade.

Implemented:

- A native scheduler with local/remote/maintenance admission, service-time
  debt, FIFO queues, maintenance reservations, deadlines, cancellation,
  shutdown, and diagnostics. Managed handles for the same canonical store
  path share a coordinator. The legacy driver still uses its existing lock.
- Managed writer connections with callback-scoped transactions, typed bound
  parameters/results, statement finalization, rollback, and connection
  authorizer guards. The writer connection is private. Callers must join all
  operations before closing a handle. Other raw SQLite connections remain
  outside these guarantees. Callbacks must not retain transaction pointers
  or borrowed row data, and must not throw exceptions.
- Atomic local DDL migrations, a persisted generation, table/column IDs,
  explicit rename mappings, and persisted FTS/vector declarations. Mapping
  entries describe either a table rename or a column rename; when renaming
  both, put column entries before the table entry.
- Persisted search declarations now drive FTS5/vec0 temp indexes on open,
  migration and declaration changes. Index names derive from stable IDs,
  including across explicit renames. Candidate schema/index changes roll
  back together on validation failure. Each handle runs bounded 256-row
  maintenance turns under scheduler admission every 100ms. An explicit
  refresh drains pending work; status reports index names, readiness and
  build errors. Unpublished or stale indexes reject application queries.
  Source queries remain available to repair invalid data. Other managed
  handles' committed data/schema changes invalidate or reconstruct local
  indexes before queries. Raw connections remain outside coordination.
- Canonical Ed25519 envelope signing and verification through vendored
  AWS-LC. The signed preimage is domain-separated, uses little-endian integer
  fields, and never includes C struct padding. Verification authenticates a
  payload against an explicitly supplied database, origin, public key, and
  size limit. Fixed 200-byte MOR2 envelope encoding excludes C padding.
- Durable signed log capture commits canonical cr-sqlite changes and origin
  envelopes atomically with application writes. The managed signed profile
  pins database/node/public-key/site identities; trusted-origin bindings are
  immutable and revocable. Sequences, hybrid clocks, receipts and progress
  persist in the encrypted database. Export forwards original bytes; apply
  verifies signatures/schema/site and commits effects/log/progress together,
  without re-originating imported writes. Replay is idempotent; gaps and
  equivocation are rejected. Signed local commit, export and successful
  remote apply include the native WAL durability barrier. A sync failure
  after commit is an uncertain outcome; retry flush/apply before acknowledging.
  Native store writes now serialize with that barrier to prevent a concurrent
  background sync from clearing a newer async write's dirty flag.
- Initial signed activation requires no existing CRR history or causal policy
  state. Enabling replication currently requires an empty table with
  cr-sqlite-compatible NOT NULL primary keys. Replicated tables support additive
  migrations and explicit stable-ID renames under a pinned schema authority.
  Dropping/redefining existing replicated columns or tables is rejected.
  New empty replicated tables can be added after data history. Reopened
  handles must provide their pinned signing seed before making replicated
  writes; read-only transactions and authenticated remote apply need no seed.
  Disabled tables retain local data while signed receipts advance. Re-enabling
  a table with signed history requires checkpoint restore and is rejected
  until that upgrade path exists. History also prevents rebinding live IDs.
- Signed MMS2 schema artifacts bind enabled tables, stable table/column IDs,
  DDL, indexes, policies and search declarations to a schema authority.
  Followers pin a trusted authority before application history. Adoption
  verifies the original signature and applies DDL/metadata/search changes
  atomically under remote writer admission. Constrained DDL preparation
  rejects protected namespaces, extra statements and unrelated operations.
  Historical artifacts are retained by digest without rolling back the live
  schema, so older signed data can map original names through stable IDs
  after renames. Sequence equivocation and unauthorized follower changes are
  rejected. Publication/adoption and metadata configuration wait for native
  durability; a failure after commit has an uncertain committed outcome.
- A native causal core for counters, observed-remove sets, JSON maps and
  lists, including deterministic projections and postcard encodings matching
  the Go reference. Counter actor-component overflow and projection overflow
  are distinguished. Joins preserve concurrent unobserved writes and are
  idempotent; conflicting values under one JSON/list operation tag are
  rejected atomically. Values remain opaque canonical bytes at this layer.
  Causal authorization allows only the signing actor to introduce
  components/tags; foreign components and observed removals require covered
  history. Missing dependencies return SQLITE_BUSY without mutation.
- Managed policy configuration now covers all seven policies. Typed C
  operations and SQL functions share the same implementation. Non-LWW
  columns reject direct UPDATEs; primary keys of policy tables are also
  protected. Counters retain integer baselines and use wide projection
  arithmetic. Sets persist canonical Value vectors; JSON maps and lists
  render scalar JSON with reference-compatible ordering/escaping. Causal
  state and projections commit/roll back with application transactions.
  Per-operation savepoints allow callers to catch an operation error without
  retaining partial effects. The 10,000-operation transaction limit bounds
  policy intents. Typed composite/BLOB keys are supported.
- Persisted row epochs separate delete/reinsert and REPLACE generations;
  old causal state is retained rather than unsafely collected. Policy
  metadata follows explicit column/table mappings. Dropping established
  policy columns/tables and rebuilding a protected table through an
  intermediate rename are rejected. After altering a policy table, the
  migration also rejects subsequent table drops until that migration ends.
  Existing non-LWW policies cannot be changed or disabled through the
  configuration API. Initial signed activation binds policy actor IDs to the
  pinned database/node identity before any causal history exists.
- A replicated-row join/codec covers all seven policies, immutable
  generation baselines, retained deletion versions, insert replacement,
  per-column LWW versions and min/max numeric ties. Joins are pure and tested
  across all three-writer permutations. Provenance checks require original
  insertion authority for new baselines and covered causal history for
  forwarded state. MMT2 transaction records atomically capture ordinary CRR
  cells and managed policy rows. Apply joins authenticated causal state and
  materializes policy rows with CRR capture suppressed. Projected CRR cells
  cannot overwrite policy values. Original records remain byte-preserving
  in the origin log, with no remote re-origination. Per-generation history
  survives replacement and late old-generation records. Initial declarations
  on empty tables work; adding policies to established replicated data/history
  still requires a coordinated signed baseline anchor and is rejected.

Next integration work, in dependency order:

1. Implement signed baseline anchors for policies enabled on existing
   replicated rows/history. Signed causal capture/apply, generation joins,
   schema publication/adoption, CRR alter lifecycle, destructive-change
   rejection and managed search metadata adoption are implemented. Non-LWW
   policy declarations on empty tables are supported.
2. Connect the signed log/apply APIs to a new network protocol/ALPN with
   bounded transfer, membership, catch-up and backpressure. Ordinary CRR
   capture, immutable key/site bindings, atomic apply/replay receipts and
   durability barriers are implemented, including policy state and metadata.
3. Add live network convergence and chaos gates for causal records, including
   dependency catch-up and conflicting schema/baseline transitions. Direct
   multi-store policy capture/apply now works; the network driver is pending.
4. Extend snapshots, retention and restore for metadata, causal state and
   signed checkpoint attestations. Implement the coordinated, backed-up,
   resumable store upgrade with legacy-binary rejection.
5. Route driver, schema adoption and retention through the shared
   coordinator. Remove the legacy global writer lock only after all entry
   points participate; expose actual admission coverage in health.
6. Add thin Go/Rust bindings, update examples, and run reference differential
   fixtures, crash injection, multi-node convergence and sanitizer gates.

`make selftest` includes `schedulertest`, `origintest`, `managedtest`,
`managedsearchtest`, `causaltest`, `managedpolicytest`, `managedvaluetest`,
`managedorigintest`, `managedschematest`, `managedrowtest` and `managedreplicatest`.
The causal test checks nine committed
Go-reference vectors generated by `testdata/generate_causal_vectors.go`,
plus joins, projections, truncation/overflow and trailing-byte rejection.
The search test covers FTS/vector queries, other-handle changes, declaration
rollback, stable rename identities, failed migrations, reopen, multiple
simultaneous build errors, data repair, disablement and background readiness.
The policy test covers C/SQL operations, composite and BLOB keys, wide
counter projections, error-catching savepoints, direct-write guards,
failed trigger installation, rollback, reopen, multiple handles, row
replacement and migration guards. The value test checks 19 Go-generated
codec/JSON fixtures and exact integer/real comparisons around float64's
precision and int64's limits.
The signed-origin test covers multi-store capture/apply, byte-preserving
forwarding, no re-origination, replay, gaps, equivocation, database/site/key
tampering, revocation, rollback, concurrent LWW convergence, deletes, reopen,
missing signing seeds, and rejection of the unsigned runtime. Subprocess
tests exit abruptly before/after commit and verify effects and signed log
recover consistently. Targeted ASan/UBSan also covers this signed path.
The schema test covers authority pinning, signed adoption, historical
transaction mapping, additive changes, table/column/PK renames, DDL injection,
equivocation, rollback, indexes and persisted search identities. The row test
covers all seven policies, three-writer join permutations, signer/dependency
checks, replacement/deletion generations and malformed canonical records.
The replica test covers three stores, all policies, concurrent operations,
foreign-history catch-up, delete/reinsert, late old-generation edits,
concurrent inserts with different baselines, typed composite/BLOB keys,
mixed ordinary/policy commits, renamed schemas, invalid signed state,
missing seeds, rollback, reopen and subprocess exits before/after commit.
These do not establish the outstanding replication/policy integration
acceptance criteria.

Targeted ASan/UBSan runs cover the new causal core, managed policy operations
and managed search plus the native search manager. Managed runs disable UBSan's vptr
check because the vendored RocksDB archive is built without RTTI; ASan leak
detection remains enabled. Managed close now explicitly finalizes cr-sqlite
before releasing SQLite, matching the existing Go binding's lifecycle.
