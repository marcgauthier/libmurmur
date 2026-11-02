# Storage administration

Operational CLI for murmur stores. C port of
the original admin client: the same 9 subcommands, flags, and report style,
linked against `libmurmur.a` with no Go involved.

Build: `make sqlite3-murmur-tool`. Exercise: `make sqlite3-murmur-tool-admin-check` (11 groups: all 9
commands in text and JSON, credential providers, error paths).

Run commands through the combined executable:

```sh
sqlite3-murmur --admin --help
sqlite3-murmur --admin --json status ./my-store
```

## Commands

All commands take `--json` and the credential flags
(`--key-hex`, `--passphrase`, `--key-provider-uri`). With no flag
the built-in default key is used.

| Command | Effect |
|---|---|
| `status <data-dir>` | Identity, seal/KDF, SQLite and RocksDB metrics |
| `inspect <data-dir>` | Key-hint fields, schema tables, disk size |
| `verify <data-dir> [--backup]` | Offline page verification (+ manifest in backup mode) |
| `backup <src> <dest>` | Consistent online hot backup (checkpoint + manifest) |
| `restore <backup> <dest>` | Copy + optional identity rewrite |
| `keys <data-dir>` | Key registry and data-key inventory |
| `rekey <data-dir>` | Re-protect under `--new-key-hex` / `--new-passphrase` |
| `compact <data-dir>` | Offline full compaction until quiescent |
| `repair <data-dir> [--out]` | Copy + `RepairDB` + database-open proof |

## Substrate mapping

The reference admin drives the spool segment store; this port
stores pages in RocksDB. Reports keep the reference JSON style
with port-native fields:

- Identity: `database_id` is `murmur_config.group_id`,
  `node_id` is `murmur_identity.node` (both SQL-level).
- Sequences: the spool's committed/durable sequences do not
  exist; `status` reports `committed_bytes` / `flush_batches`
  from the store sync stats instead.
- Segments/compactions: `inspect`/`compact` report RocksDB
  figures (files, disk bytes, estimated keys/live bytes).
- `verify` is exclusive (offline trial-decrypt): it reports
  "store is locked" while the server runs. Backup mode also
  checks `manifest.json` (format_version 1).
- `backup` needs replication identity configured (group +
  node), since the manifest embeds both.
- `restore` copies the tree and rewrites the SQL identity
  rows; `--fresh-node-id` / `--fresh-db-id` take an explicit
  32-hex-char id or mint random when bare.
- `repair` leaves the source untouched, repairs the copy in
  place, verifies it, and proves it opens as a database.
  `RepairDB` reports no gap list, so `gaps` is always empty;
  `records` counts salvaged pages and `verified` is the
  database-open proof.
- `keys` prefers the live shell and falls back to the offline
  inventory when another process holds the store.

## Credentials

Every secret resolves to a 32-byte master: 64 hex chars decode
raw, anything else hashes with SHA-256. scrypt envelopes
stretch those master bytes; direct envelopes use them in HKDF.
The reference branches string passphrases on the envelope KDF;
this port has no string-passphrase open path, so the mapping is
KDF-independent by construction.

`--key-provider-uri` supports `file:`, `env:`, and `exec:` with
the reference semantics (32 raw bytes or 64 hex chars after
whitespace stripping, 1 MiB cap, absolute helper path,
`timeout=` within (0, 5m], default 30s).
