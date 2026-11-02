# Native HighLow implementation

## Current status

The native envelope codec, transactional artifact store, durable directory
publisher, typed LWW row projection, persisted High ownership/release,
transaction-scoped automatic capture, resumable baseline export, SQL-driver
write interception, bounded native directory workers, streaming file bridging,
and opt-in signed High ownership replication are implemented.
Original signed Low transactions are forwarded by the designated exporter,
and independently verified by High directory receivers and High peer recipients.
Application orchestration, signer-rotation administration and Windows validation
remain release work. OVERWATCH must not cut over on primitive tests alone.
The ownership core preserves claim epochs across field edits,
advances epochs on release and row deletion, rejects stale local operations,
and rejects conflicting content under an identical logical version. It is
connected to capture, persistence and materialization for explicit bridge
transactions. Attached `murmurdb` connections intercept ordinary SQL writes,
prepared writes, `RETURNING`, and explicit `database/sql` transactions.

`make bridgecheck` runs nine native selftests. Go bindings and encrypted-store
restart tests live in `clients/go/bindings/bridge`. The opt-in `typed-bridge`
live suite now drives single-node Low/High native deployments through the
ferry and full High-store reopen. The `bridge-two-streams` live suite proves
independent Low domains importing into one High store. The `highlow` live
suite covers single-node Low-send / High-download transfer with role gating,
gap delivery, two receivers, forgery rejection, restart resumption, schema
hold/migration, and signer rotation plus outage catch-up. The four-node `highlow-peer` scenario and the named HighLow peer leg cover
two Low and two High nodes, original Low writer proofs, High ownership/release,
and exporter/High reopen with only one High directory scanner.

## MHB1 envelope

MHB1 is a new native format. Legacy Murmur-SQL bundles are unsupported.
All integers are fixed-width unsigned little endian. The 281-byte header is:

| Field | Bytes |
| --- | ---: |
| Magic `MHB1` | 4 |
| Source database, source node, transaction ID | 16 each |
| Stream sequence, starting at 1 | 8 |
| Stream name length | 1 |
| Stream name, padded with zero bytes | 64 |
| Replicated schema digest | 32 |
| Receiver X25519 public key | 32 |
| Ephemeral X25519 public key | 32 |
| AES-GCM nonce | 12 |
| Uncompressed payload SHA-256 | 32 |
| Uncompressed payload length | 8 |
| Ciphertext length, including GCM tag | 8 |

The header is followed by ciphertext and a 64-byte Ed25519 signature. Payloads
are one complete Zstandard frame at compression level 3. The AEAD is
AES-256-GCM with the complete header as associated data and an appended 16-byte
tag. Each seal generates a fresh ephemeral private key and nonce.

HKDF-SHA-256 derives the AEAD key from the X25519 shared secret, using ASCII
`murmur/native-highlow/v1` as salt and the complete header as info. Ed25519 signs
that same ASCII domain followed by the header and complete ciphertext.

The receiver supplies the expected source database, stream, authorized signer
public key, and receiver private key from trusted configuration. The envelope
does not nominate its own signer. Verification precedes decryption; frame
length, payload size, and payload digest are checked before returning output.
Trailing bytes, concatenated compression frames, noncanonical stream padding,
zero identities/sequences, and unknown magic are rejected. Errors return no
plaintext or parsed header. Source-node/origin authorization and provenance
validation must additionally be enforced by the eventual typed importer.

Native APIs accept lower caller limits within the hard limits of 16 MiB per
bundle and 64 MiB per decoded payload. Keys are never put in SQL or errors.

## Transactional artifact store

These APIs reserve the borrowed connection synchronously and use the native
recursive writer guard. Callers must additionally reserve the connection for
the entire outer transaction and hold native writer admission across it
(`sqlite.LockWriter`/`UnlockWriter` in a synchronous Go callback). They must
not expose a shared raw handle to
uncoordinated writers.

- `store_init` creates node-local bridge lane, artifact, and receipt tables.
- `store_queue` requires the caller's source-write transaction. A savepoint
  allocates the stream sequence and seals/enqueues its artifact together.
  Failure restores both allocation and queue. The caller commits and flushes
  the source transaction. Stream sequence allocation uses signed SQLite
  integers and fails rather than wrapping at `INT64_MAX`.
- `store_next` reads a stable artifact without removing it. `bridge_publish`
  writes, syncs, and atomically publishes it before calling `store_ack`.
  Retrying publication reuses the queued bytes and accepts an identical
  SHA-256-named destination file. Conflicting files are not overwritten.
  POSIX publication uses exclusive temporary files, `linkat`, file sync and
  directory sync; the Windows path uses `MoveFileExW` with write-through.
  The Windows path still requires platform validation.
- `store_stage` authenticates/decrypts before storing the sealed artifact.
  Identical duplicates are idempotent; a different envelope using an existing
  sequence is rejected. Restaging requires currently trusted credentials.
- `store_apply` applies only the next contiguous sequence. It reauthenticates
  the artifact and checks the expected schema before invoking the importer.
  Imported effects, receipt, applied progress, and inbox deletion commit
  together. Callback errors and Go callback panics roll back the import.
  The callback may execute application SQL but must not commit, roll back,
  throw a C++ exception, or retain borrowed pointers.

Stage, acknowledgment, and successful import issue the native durability
barrier. An error from the barrier after COMMIT is an uncertain outcome:
the caller must retry and resolve persisted state before acknowledging work.
`SQLITE_NOTFOUND` means no queued or contiguous work; `SQLITE_SCHEMA` leaves
the authenticated artifact staged for a compatible migration. A full staging
budget returns `SQLITE_FULL`; an artifact exceeding its configured capacity
returns `SQLITE_TOOBIG`.

Inbox and outbox each enforce a caller-specified per-source/stream queued-byte
budget. All lanes also share a hard 1 GiB cap per kind. Receipts retain SHA-256
digests rather than whole bundles. Retention diagnostics must be added with
the full runtime; callers must not prune receipts in ways that permit sequence equivocation.

## Remaining release gates

1. Integrate file-bridge limits and administration in the application. Native
   bounded chunks, High-side re-encryption and four-node live coverage pass.
2. Integrate worker status, quarantine, signer rotation and shutdown in the
   application; validate Windows filesystem and link behavior.
3. Maintain the named HighLow and files-bridge live tests, including multiple
   peers and reordered delivery. Typed-bridge ferry/release/reopen,
   two-stream isolation/quarantine, and HighLow single-node transfer/gap/
   forgery/restart/schema-hold/rotation/outage live coverage are enabled;
   the four-node original-Low/High-peer mesh leg is enabled.
4. Migrate OVERWATCH database/management APIs, fixtures, configuration and
   documentation; verify a copy of its converted database before cutover.

## Typed rows and automatic capture

`bridge_rows_register` creates an explicit table allowlist with deterministic
16-byte table/column IDs and a digest of the registered SQL declarations.
Registration and schema validation inspect local tables; bundles cannot execute
DDL. Views, virtual/internal tables, generated columns and tables without a
primary key are rejected. `MBT1` payloads package up to 1024 canonical native
row records, reusing the existing typed value/row codecs. The initial importer
supports LWW fields. Other policies return a mismatch rather than losing their
semantics. Stable-ID rename mappings and destructive schema upgrades are not
implemented by this registration API.

`bridge_rows_apply` verifies the bundle and current registered schema through
the transactional artifact store, merges per-source Low shadows, then projects
the result into bound SQL statements. NULL, int64, real, text, blobs and
composite primary keys retain their SQL types. Unknown columns or SQL constraint
failures roll back the entire bundle, including shadows and receipts. Compatible
local additive migrations allow a held bundle to retry. Low domains cannot
reuse an origin already bound to another domain or the configured High node.
An attached Low cannot import typed bridge data, and an attached High rejects
its own database as a bridge source. Standalone typed-row envelopes attest source domain state. The signed Low
peer profile instead forwards and verifies each original writer's proof,
independently of exporter sealing.

`bridge_capture_attach` installs connection-local temporary triggers and scalar
functions. Before-images and dirty keys are journaled in the encrypted main
database, not plaintext temporary storage. `bridge_write` holds the native
writer guard over the complete synchronous callback, finalizes capture before
commit, and then runs the durability barrier. Only registered tables participate.
Low transactions enqueue one atomic typed bundle; High transactions claim only
changed non-key fields and claim row deletions. No-op changes and insert/delete
pairs with no final row produce no bundle. Callback errors, callback panics in
the Go wrapper, and queue/batch limits roll back the data and capture state.
Callbacks must use ordinary DML and must not execute transaction control or DDL.

Release reprojects the latest Low shadow without reclaiming the projected
values. A High reinsertion revokes its previous row-delete claim and claims its
new fields. Persisted logical clocks, ownership and Low shadows survive reopen;
attach the runtime again for each new native connection. Schema/trigger caches
are invalidated on registration and SQLite schema-version changes.

`bridge_capture_prepare` exports existing Low data in resumable batches without
rewriting application rows. Batches are configurable from 1 to 1024 rows. A
source/stream/table-declaration scope records prepared keys, and a durable
source/stream/schema marker makes completed preparation skip table scans after
restart. Changing streams or adding columns gets its own preparation scope.
The caller should publish pending artifacts between batches to respect queue
capacity. Raw writes made outside `bridge_write` or the SQL-driver capture transaction are not captured;
callers must not treat attachment alone as application integration.

The Go API exposes `RegisterTable`, `CaptureRow`, `PackRows`, `ApplyRows`,
`Claim`, `Release`, `AttachCapture`, `Write`, and `Prepare`. Use
`murmurdb.WithConnection` to reserve the SQL driver's native connection around
these synchronous operations. No Go implementation of the merge or capture
algorithm is maintained in parallel with the native implementation.


## SQL-driver integration and release

Attaching capture through `murmurdb.WithConnection` enables interception on that
pool's native connection. A dedicated OS-thread-pinned worker preserves native
writer ownership across separate `database/sql` transaction calls, even across
Go goroutines. Plain connections retain streaming reads; native-resource
connections materialize results before releasing admission, including DML
`RETURNING`. Multi-statement scripts use a statement savepoint inside an
explicit transaction, so a failed script cannot retain a successful prefix.
Explicit transaction-control SQL is rejected; use `db.Begin`/`Tx` instead.

`bridge.ReleaseOwnership` performs a standalone High release using the native
logical clock. False means no active claim; no caller timestamp is required.
It atomically reprojects the latest Low shadow and persists the release. A nil
column releases a row-deletion claim, while a name releases a field claim.

Use `WithNativeControl` for starting/stopping resources that manage their own
SQL admission. Joining a native worker under `WithConnection` would deadlock
if the worker is waiting for its writer guard. Stop and free workers before
closing the database, detaching capture, or changing table registrations.

## Native directory workers

`bridge.NewSender` requires matching attached Low capture. Poll drains up to
256 immutable artifacts before preparing another baseline batch (up to 256
rows). Restart resumes the durable queue and baseline marker. `Start` runs a
native polling thread; `Stop` joins it and can be followed by another `Start`.

`bridge.NewReceiver` pins one source database, stream, exporter node and up to
eight trusted Ed25519 public keys for overlap rotation. Each poll examines at
most 256 directory entries, continuing from a native directory cursor. Valid
shared artifacts remain in place for other receivers. A receipt-digest index
skips previously committed ciphertext without retaining an unbounded cache.
Gaps are deferred on disk rather than staged, preserving inbox capacity for
the next contiguous sequence. Schema mismatches remain held in the encrypted
inbox and can resume after a local migration and receiver recreation.

An optional private quarantine directory retains rejected bounded ciphertext
under its immutable digest name, using the same synced publication helper as
the sender. It never removes the shared artifact. Native receivers serialize
quota checks and enforce 64 MiB and 1024 entries; a full quarantine reports
`SQLITE_FULL` and leaves work retryable. Nonregular files and oversized inputs
are rejected without copying. Directories must already exist, be owned by the
operator, and differ from the shared ferry directory. POSIX reads reject
symlinks and nonregular files; Windows reads reject reparse-point files.

Status counters count attempts, not distinct files; revisiting a held or
rejected artifact increments its counter again. A receiver cannot be manually
polled while its worker is started. Polling and status APIs are exposed through
thin Go bindings; crypto, queues, row projection and workers remain native.


## Streaming native file bridge

Attach a borrowed native file store with `Sender.Files` or `Receiver.Files`
while stopped; the store must use the same SQL handle and outlive the worker.
The sender pins a verified native object and exports canonical `MBF1` parts
with a name, SHA-256 content digest, total length, offset, final marker and
at most 64 KiB data. Each part uses the ordinary authenticated `MHB1` lane.
Queue sequence and export offset commit in the same native source transaction.
Completed object/generation markers prevent recapture after reopen. A bounded
prefix scan resumes a pinned encrypted object after an interrupted export.

The receiver commits verified chunks and contiguous lane receipts together.
Chunk bytes reside in encrypted main SQL, never plaintext ferry files. Duplicate
parts must agree exactly; gaps, conflicting offsets, malformed lengths and
oversized content are rejected. Per-source/stream byte budgets and a shared
1 GiB staged-data ceiling apply; files over 1 GiB report backpressure/error
rather than being silently skipped. File-store limits can be lower still.

A final marker makes a transfer ready. The receiver streams its SQL chunks
through a native upload, re-encrypting under the High object key in bounded
memory. A new atomic upload callback verifies total/content digest and commits
file metadata, completion receipt and chunk deletion together after the object
has been synced. Failed validation rolls back SQL metadata and retains chunks;
retry after a crash is idempotent. Incomplete encrypted object files are ordinary
native file-store staging/orphans and use its cleanup policy.

Local file metadata replicates over the existing native file transport; High
peers fetch the re-encrypted object using their domain's key. Native file SQL
helpers take writer admission independently, with file gates preceding SQL
admission. Call file/worker lifecycle through `WithNativeControl`.

## Signed High ownership journal

`ConfigurePeer` opts an attached High connection into an immutable signed
ownership journal. It pins database/node identity and Ed25519 public key in
SQL, retaining the private seed only in native connection memory. Initial
activation requires no previous ownership state and disabled raw replication
for bridged user tables. Existing CRR clocks may be retained when native table
flags disable transport; existing ownership needs a separately authenticated
baseline upgrade.
Reopen requires the same identity/key before captured SQL can proceed.
`TrustPeer` pins other High keys and supports revocation without rebinding.

A captured High transaction collects changed ownership records into one `MBH1`
packet. A `MOR2` origin envelope signs its database, origin, sequence, schema,
clock, transaction and payload digest; the `MBJ1` journal record wraps envelope
and payload. SHA-256 record IDs and receipts detect replay/equivocation. Native
CRR transports the fixed internal journal table. Raw user-row CRR stays disabled
for the bridged tables so their values are owned by semantic projection.

Native sync verifies records and joins ownership under its existing transaction,
committing projection, journal receipt and origin progress together. A node can
introduce only its own operations; retained foreign epochs/cells require prior
authenticated history. Missing origin dependencies, sequence gaps and schema
mismatches remain pending. A bounded native tick retries pages of pending
records, so an earlier held page cannot indefinitely hide later dependencies.
Stale claims cannot resurrect released ownership. Imported journal records
never create new local claim records.

The journal also forwards original sealed source bundles in `MBS1` packets.
Each High peer loads its own source/exporter/signer/receiver policy with
`ConfigurePeerSource`, independently verifies the original `MHB1` signature,
recipient, schema and contiguous stream sequence, then commits Low shadows,
projection, source receipt and High-journal receipt in the same native apply
transaction. Operators need no ferry directory or scanner on those peers.
Creating a directory receiver after peer configuration installs the same source
policy automatically. Exact committed bundle digests remain idempotent after
signer retirement; fresh bytes still require a currently authorized signer.

File parts use the same proof path. `PeerFiles` explicitly authorizes receiving
file parts against the driver's native file store. Their encrypted SQL chunks
and source receipts commit with peer progress; the native tick finalizes ready
files with shutdown cancellation and atomically retains completion receipts.
The live file suite checks the second High node's source receipts and drained
chunk staging while its ferry scanner remains absent.

`ConfigureLowPeer` captures original signed Low transactions in the native peer
journal. Only the designated exporter seals them in `MHP1` proof payloads;
receivers pin each original writer with `TrustSourceOrigin`. Original writer
signatures and causal cell dependencies are verified independently of the
exporter signature. Configuring original source keys disables unsigned typed-row
fallback, including after those keys are revoked. Initial activation requires
no previous capture/ownership state; upgrading an earlier experimental profile
requires a separate authenticated baseline migration.
