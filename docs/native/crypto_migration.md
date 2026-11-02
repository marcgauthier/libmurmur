# AES-256-GCM and scrypt format change

libmurmur now uses AWS-LC for page encryption and password derivation:

- AES-256-GCM is the only supported page cipher (`PRAGMA cipher='aes256gcm'`).
- Password keyrings use scrypt followed by HKDF-SHA256 (`PRAGMA murmur_kdf='scrypt'`).
- Raw 32-byte master keys still use direct HKDF (`PRAGMA murmur_kdf='direct'`).

The `aegis` and `argon2` vendor libraries and Go AEGIS bindings are removed.
This is an intentional breaking change, without an in-place conversion path.
Existing AES records (`EXP1`/`EXP3`) and direct-HKDF envelopes remain supported.
AEGIS records (`EXP2`/`EXP4`), AEGIS store metadata, and Argon2id envelopes
(KDF ID 1) are rejected. A numeric cipher ID of 2 is not an alias for AES.

## Scrypt parameters

The default is N=65536, r=8, p=1 (~64 MiB). Stage parameters before sealing:

```sql
PRAGMA murmur_scrypt_n=65536;
PRAGMA murmur_scrypt_r=8;
PRAGMA murmur_scrypt_p=1;
PRAGMA murmur_kdf='scrypt';
```

The old `murmur_kdf_time`, `murmur_kdf_memory_kib`, and `murmur_kdf_threads`
parameters are replaced by these N/r/p parameters. Native parameter IDs 2, 3,
and 4 now represent N, r, and p. The keyring C API fields are `scrypt_n`,
`scrypt_r`, and `scrypt_p`; the Go fields are `ScryptN`, `ScryptR`, and `ScryptP`.

Scrypt uses KDF ID 2, leaving ID 1 reserved for the removed Argon2id format.
The authenticated envelope retains its v3 layout; its parameter fields encode
N/r/p for ID 2. An older build cannot open a new scrypt-protected keyring.
Malformed or excessive costs are rejected before derivation. See
[the keyring documentation](../../deps/keyring/README.md) for limits.

## Export with the old build and import into a new store

1. Keep an old build that can open the source store and keep its credentials.
   Stop writes and take a backup of the source directory.
2. Use that old build to export the application schema and data in plaintext
   SQL. The old SQLite shell can produce a starting export:

   ```sh
   /path/to/old/sqlite3-murmur /path/to/old-store .dump > export.sql
   ```

3. Review the SQL as an application-data migration. Preserve user tables,
   values, indexes, and application triggers. Recreate libmurmur replication,
   managed schemas, virtual indexes, and other internal state using their
   supported APIs; do not blindly import internal replication tables/triggers.
   File-object payloads outside SQL require a separate application-level export.
4. Import the reviewed schema/data into a **different, new** store using the
   new build. Its SQLite shell defaults to AES-256-GCM and scrypt and prompts
   for the new passphrase:

   ```sh
   /path/to/new/sqlite3-murmur /path/to/new-store < reviewed-user-data.sql
   ```

5. Reopen the new store and verify table counts, representative values, indexes,
   application behavior, and any separately migrated file objects. Retain the
   old store and old build until verification is complete.

Copying a store directory or restoring an encrypted backup preserves its old
cipher/KDF and does not perform this conversion. Changing `PRAGMA cipher` is
also not a migration for a populated database. The new build never rewrites an
unsupported old store into a new format automatically.
