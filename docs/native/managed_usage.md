# Managed transactions, policies and search

The opt-in managed API owns its SQLite connection. Include `libmurmur.h`,
call `murmur_init()`, and open with `murmur_managed_open(path, key, &db)`.
The key is exactly 32 bytes. Join application operations before closing
the handle with `murmur_managed_close(db)`.

This API implements local transactions, policies/search and a signed-log/apply
path for ordinary and policy-bearing tables, with signed schema adoption.
Network replication, policy baseline upgrades and legacy cluster upgrades
remain incomplete. See
[implementation status](managed_status.md) for remaining work.

Create ordinary tables with an atomic migration:

```c
int rc = murmur_managed_migrate(db,
    "CREATE TABLE docs(id INTEGER PRIMARY KEY, body TEXT, "
    "visits INTEGER NOT NULL DEFAULT 0, labels BLOB, settings TEXT, "
    "events TEXT, embedding BLOB)");
if (rc == 0)
    rc = murmur_managed_set_policy(db, "docs", "visits", MURMUR_POLICY_COUNTER);
```

Check every return code. Configuration calls take maintenance admission and
must run outside a transaction callback. Use
`murmur_managed_transaction(db, MURMUR_WRITER_LOCAL, timeout_ms, cancel,
cancel_ctx, callback, context)` for application writes and queries. Negative
timeouts wait indefinitely; zero polls admission. Cancellation is checked
during admission and before commit. Callbacks must not throw or retain the
transaction pointer or borrowed row data.

Inside a transaction callback, execute one statement per call with
`murmur_transaction_execute(tx, sql, params, count, row_callback, context)`.
Parameters are `murmur_value_t` values; TEXT/BLOB byte lengths are explicit.
Every statement is finalized before the call returns. Return a nonzero
SQLite result code from the transaction callback to roll back all work.

## Column policies

`murmur_managed_set_policy` accepts LWW, Counter, Set, Min, Max, Json and
List. Non-LWW policies require a table with an explicit primary key. Policy
columns cannot be primary keys or generated columns. Initial INSERT values
establish baselines; subsequent direct UPDATEs of policy columns or the
table's primary key columns are rejected. Non-LWW policies cannot be
changed or disabled through this configuration API.

Counter baselines are INTEGER. Set baselines are NULL or canonical postcard
`Vec<Value>` BLOBs. JSON/list baselines are NULL or flat scalar object/array
TEXT. JSON booleans become integer 1/0, nested containers are rejected, and
JSON/list operands must be NULL, integer, finite real or text. Min/max compare
NULL, numbers, text and BLOBs in that order; integer/real comparisons preserve
integer precision. Lists retain duplicates and render in deterministic
operation-tag order.

C callers pass typed primary key values and a `murmur_policy_operation_t`
to `murmur_transaction_policy`. For example, within a transaction callback:

```c
murmur_value_t key = {0};
key.type = MURMUR_INTEGER;
key.integer = 42;
murmur_policy_operation_t op = {0};
op.kind = MURMUR_OP_COUNTER_ADD;
op.delta = 1;
return murmur_transaction_policy(tx, "docs", &key, 1, "visits", &op);
```

SQL functions use the same operation path and return 1 on success:

```sql
SELECT murmur_counter_add('docs', '[42]', 'visits', 1);
SELECT murmur_set_add('docs', '[42]', 'labels', 'go');
SELECT murmur_set_remove('docs', '[42]', 'labels', 'go');
SELECT murmur_json_set('docs', '[42]', 'settings', 'theme', 'dark');
SELECT murmur_json_remove('docs', '[42]', 'settings', 'theme');
SELECT murmur_list_append('docs', '[42]', 'events', 'opened');
SELECT murmur_list_remove('docs', '[42]', 'events', 'opened');
```

`murmur_min` and `murmur_max` take table, key, column and operand. Configure
the column's matching policy first. Keys accept scalar JSON arrays or a
canonical key BLOB from `murmur_policy_key(pk1, ...)`; the latter supports
BLOB primary keys. JSON paths are nonempty flat object keys, not nested
JSONPath expressions. Missing rows return `SQLITE_NOTFOUND`; policy/type
mismatches, protected writes and overflow fail without partial policy state.
A callback may catch a failed operation and continue. At most 10,000
successful policy operations run in one transaction.

DELETE and REPLACE track row generations. Reinserting the same key starts
from the new row's baseline. Persisted policy state survives reopen and is
shared by handles for the same store. Old generations are retained pending
replication-aware retention. Inspect declarations with
`murmur_managed_policy_status`.

## Search and migrations

Declare search with `murmur_managed_set_search(db, table, column, fts,
dimensions, distance)`. FTS requires TEXT; vectors require BLOB, 1..8192
float32 dimensions and distance 0=L2, 1=cosine or 2=L1. Sources need one
INTEGER PRIMARY KEY. A zero dimension count disables vectors; an unset FTS
flag disables that column's FTS participation.

Maintenance runs in bounded turns under scheduler admission. Use
`murmur_managed_refresh_indexes` to drain work explicitly and
`murmur_managed_search_status` to discover temp index names, readiness and
errors. Query published FTS tables with MATCH and vector tables with
`embedding MATCH '[1,0]' AND k=2`, joining the source on rowid. Stale or
unpublished indexes reject queries until rebuilt; source reads remain
available for repairing invalid data.

`murmur_managed_migrate_mapped` accepts explicit table/column rename
mappings. These preserve identities, search declarations and policy state.
When renaming both table and columns, list column mappings before the table
mapping. Established policy columns/tables cannot be dropped or destructively
rebuilt through ordinary migrations. An ALTER of a policy table also blocks
subsequent table drops in that migration. Failed migrations roll back DDL,
metadata and search changes together.

## Signed transactions and schema artifacts

`murmur_managed_origin_configure(db, database_id, node_id, seed)` activates a
signed profile and pins its Ed25519 public key and cr-sqlite site identity.
Supply the same 32-byte seed after reopening; the seed is kept in memory and
wiped on close. Initial activation requires no prior CRR history or causal
policy state. Use distinct node IDs and seeds with a shared database ID.

Create an empty table with an explicitly NOT NULL primary key, then opt it in
with `murmur_managed_set_replication(db, table, 1)`. This supports ordinary LWW
and policy-bearing tables. Configure non-LWW policies before data history.
Adding them to an established replicated table requires a coordinated signed
baseline upgrade and is currently rejected. Replicated tables allow additive migrations
and explicit renames under the pinned schema authority. Dropping or
redefining existing replicated columns/tables is rejected. New empty tables
may be enabled after signed history exists.

Disabling replication preserves the table's local data and still advances
verified origin receipts. Re-enabling a table with signed history requires
a checkpoint restore, which is not implemented yet; the API rejects that
transition with `SQLITE_CONSTRAINT`.

Get a peer's public identity with `murmur_managed_origin_identity`; provision
trusted origin identities with `murmur_managed_origin_trust`. Identity
provisioning is an application responsibility. Public keys and site IDs
cannot be replaced under an existing origin. Revocation disables trust while
retaining the binding. This authentication is separate from peer TLS.

The local origin is initially its own schema authority. On followers, trust
the intended authority, then call `murmur_managed_schema_master(db, origin)`
before application data history. Export the authority's current artifact
with `murmur_managed_schema_export`, forward it unchanged, and adopt it with
`murmur_managed_schema_adopt`. A follower can adopt into an empty store or
bind IDs to matching empty tables created independently. Binding a different
ID to live rows is rejected. Followers cannot migrate replicated tables or
change their replicated search declarations themselves.

Schema artifacts include table/column IDs, SQL DDL and indexes, plus policy
and search declarations. Adopt the relevant artifact before applying its
signed data. Use `murmur_managed_schema_find(db, envelope.schema, &record)`
to export a historical artifact. Historical adoption retains that mapping
without reverting the live schema; old transactions then map their original
table/column names through stable IDs. Free all exported records with
`murmur_origin_record_free`. Schema artifacts use MMS2 payloads with separate
authority sequences; pass them to schema adoption, not origin-data apply.

Managed transactions automatically capture signed table changes and append
an origin envelope before committing. Signed commits wait for durability.
`murmur_managed_origin_next` returns the next immutable record for an origin;
free its owned payload with `murmur_origin_record_free`. Forward that record
unchanged and apply it with `murmur_managed_origin_apply`. Apply returns only
after the durability barrier; it reports whether the record was newly
applied. Duplicate records succeed without repeated effects, sequence gaps
and missing causal dependencies return `SQLITE_BUSY`, schema mismatches
return `SQLITE_SCHEMA`, and signature,
trust, site or equivocation failures return `SQLITE_AUTH`.

The canonical envelope encoding is MOR2 plus fixed little-endian fields,
200 bytes total. Use the envelope encode/decode APIs; never send the C struct
directly. Ordinary records use CRSB. Mixed/policy records use MMT2, containing
ordinary CRR cells and canonical row-generation/causal state; all payloads are
capped at 64MiB and policy batches at 10,000 rows. Applying forwarded state
requires coverage of its foreign actor components by previously applied
original records. On `SQLITE_BUSY`, deliver missing per-origin records and
retry. Policy projections are materialized only after state join; raw CRR
cells cannot overwrite them. The QUIC integration is still pending.

If a durability barrier fails after SQL commit, the API reports an uncertain
committed outcome. Query origin progress/log records and retry
`murmur_managed_flush` or duplicate apply before acknowledging the transaction.
The legacy replication runtime rejects signed-profile stores. A reopened
handle without its signing seed can read/apply authenticated records but its
replicated application writes roll back with `SQLITE_AUTH`.
