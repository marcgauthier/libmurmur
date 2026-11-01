# sqlite3-murmur

The vendored SQLite command-line shell using libmurmur's encrypted,
compressed RocksDB storage. Persistent database names are **directories**.

Build from the repository root:

```sh
make -j4 sqlite3-murmur-tool
./build/sqlite3-murmur-tool/sqlite3-murmur ./my-store
```

`make sqlite3-murmur-tool-bin` works here or from the repository root and
packages Linux x86-64 and Windows x64 executables with SHA-256 checksums in
`bin/linux-x86_64/` and `bin/win64/`. This directory's `bin` links to
`../sqlite-murmur-tool/bin`. For only Linux, use
`make sqlite3-murmur-tool-linux-bin`; for Windows, use
`make sqlite3-murmur-tool-win64-bin`.

A hidden passphrase prompt reads from `/dev/tty` on Linux or the Windows console, independently of SQL
stdin. Creation asks for confirmation. The credential is reused for every
store opened in that process, including `ATTACH`, `.open`, and backups.
Use another process for stores with different credentials. No passphrase
is placed in SQL, command history, or command-line arguments by the tool.

```sql
CREATE TABLE example(id INTEGER PRIMARY KEY, value TEXT);
INSERT INTO example(value) VALUES ('hello');
.tables
.mode box
SELECT * FROM example;
.backup ./my-backup
```

The backup is another encrypted Murmur directory and opens with the same
passphrase. `.save`, `.clone`, `.restore`, and `VACUUM INTO` also operate on
Murmur stores. These are SQLite-level database copies, not operational
backup archives with a replication manifest. Replication is not started
automatically. Continue using the existing admin client for operational
backups, passphrase changes, key management, and repair.

For scripting, provide one nonempty passphrase line through an open file
descriptor (maximum 4096 bytes; LF or CRLF is removed). For example, with
an existing passphrase file whose access you control:

```sh
./build/sqlite3-murmur-tool/sqlite3-murmur \
  --passphrase-fd 3 ./my-store 'SELECT * FROM example;' 3<./passphrase.txt

./build/sqlite3-murmur-tool/sqlite3-murmur \
  --passphrase-fd 3 ./my-store 3<./passphrase.txt <./commands.sql
```

Without a controlling terminal, encrypted access requires
`--passphrase-fd N`. `:memory:`, help, and version do not need a credential.
Passphrase bytes are preserved, including spaces and UTF-8. For compatibility
with `murmur-admin`, exactly 64 hexadecimal characters decode to a raw
32-byte key; all other input is hashed with SHA-256. The resulting value
is supplied to libmurmur's existing key API. **New stores additionally use
the native salted Argon2id keyring** (3 iterations, 64 MiB, 4 lanes).
Existing stores keep their keyring and protection settings.

New stores use AES-256-GCM and Zstandard level 3. Existing PRAGMAs remain
available, including:

```sql
PRAGMA cipher;                   -- aes256gcm or aegis256
PRAGMA compression;              -- none or zstd1 through zstd22
PRAGMA compression = 'zstd9';
PRAGMA murmur_kdf;
PRAGMA journal_mode;
```

Change the cipher only on an empty store, before creating user tables.
Compression settings affect subsequent writes and use the native default
when a store is reopened. The shell adds an explicit final flush on store
close; commit acknowledgment otherwise retains libmurmur's existing
background-flush semantics.

The shell retains SQL, transactions, schema inspection, parameters, query
formatting, import/export, `.dump`, `.read`, `.output`, and `.load`.
Scripts, CSV, dumps, and other explicitly exported text use ordinary files.
Dump output contains plaintext SQL and data, as in the upstream shell.

Persistent database operations support Murmur stores only:

- Stock SQLite files and alternative VFS choices are rejected.
- WAL and memory mapping are unavailable; journal mode must be DELETE.
- Append, ZIP, hex, and deserialize database modes, `.open --new`, and
  `.backup --append` / `--async` are rejected. Create a separate directory
  rather than replacing a store with `.open --new`.
- RocksDB locks prevent opening a store concurrently from another process.
- `.restore` requires an existing source. `.clone` requires a new destination
  and uses SQLite's backup API; it is not a salvage operation.
- Features that depend on optional SQLite modules are limited to those
  present in the vendored build. No new line-editing or archive library is
  introduced.

The Linux build uses the existing native toolchain and `patch`. The Windows
cross-build uses CMake and MinGW, rebuilding the same storage, codec, SQLite,
RocksDB and AWS-LC code for Windows. Unused replication/transport objects are
omitted from its storage archive. The test suite additionally uses Python 3's
standard library.

```sh
make sqlite3-murmur-tool-check
```

`tool.c` contains credential handling and the process-local VFS adapter.
`shell.patch` is applied with zero fuzz to a generated copy under `build/`;
the vendored shell is unchanged. Upstream changes that invalidate a patch
hunk fail the build and require review.
