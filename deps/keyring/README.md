# Native keyring

Project-owned C++ implementation of the `SPLK` v3 keyring envelope. The body
uses AES-256-GCM from AWS-LC, with the header included as authenticated
associated data. Protectors use direct HKDF-SHA256 for a supplied
32-byte master key, or AWS-LC scrypt followed by HKDF-SHA256 for passwords.

- `keyring.{h,cc}`: create/open/rotate/drop, envelope serialization and wiping.
- `scrypt.{h,cc}`: AWS-LC scrypt with bounded memory/work parameters.
- `sha256.{h,c}`, `hkdf.{h,c}`, `crc32c.{h,c}`: project-owned primitives.

KDF ID 0 remains direct-HKDF. ID 1 was Argon2id and is rejected. ID 2 is
scrypt. The three envelope parameter fields at offsets 47, 51, and 55 contain
N (u32le), r (u32le), and p (u8) for ID 2; they are zero for ID 0. The new ID
prevents an old envelope from being interpreted with different algorithms.

Defaults are N=65536, r=8, p=1, approximately 64 MiB. Validation applies during
creation and opening: N is a power of two >=2, r is 1..32, p is 1..16,
N*r <= 2^20 and N*r*p <= 2^22. AWS-LC receives a 256 MiB allocation limit.
The working-memory estimate 128*N*r is therefore bounded at 128 MiB.

See [crypto format migration](../../docs/native/crypto_migration.md) for the
breaking removal of AEGIS and Argon2id.
