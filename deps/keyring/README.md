# keys.enc v3 keyring (C++ port) for sqlite-murmur-go

Project-owned C++ port of `clients/go/pkgs/storage/keyring.go`: the `SPLK`
envelope (CRC32-Castagnoli header checksum, AES-256-GCM body),
protector derivation (HKDF-SHA256 direct, Argon2id + HKDF-SHA256
for passphrases), and the Create/Rotate/DropKeys operations. The Go
keyring stays as the file-backend implementation and interop
oracle; this port serves the native (registry) path so no key
material or envelope crypto crosses cgo.

- `keyring.h`, `keyring.cc` — the port plus the flat test API.
- `sha256.h/.c` — FIPS 180-4 SHA-256 (project-owned, spec-written).
- `hkdf.h/.c` — HMAC-SHA256 + HKDF (RFC 5869, `hkdf.Key` semantics).
- `crc32c.h/.c` — Castagnoli table CRC32 (matches Go `hash/crc32`).

Crypto sources: AES-256-GCM comes from `../codec/aesgcm.cc`
(requires AES-NI, like the page codec); Argon2id from
`../argon2` (reference `ref` backend + pthreads, version 0x13).
CSPRNG is `getrandom(2)` with a `/dev/urandom` fallback.

Correctness: `clients/go/bindings/nvfs/keyring_diff_test.go` cross-checks
this port against the Go implementation both directions (seal
either side, open both sides) and replays the sqlite-murmur fixed
vectors plus the tamper matrix. Hostile envelopes (e.g. Argon2
threads=255) fail closed with CORRUPT here; the Go side can panic
inside x/crypto on the same inputs — fail-closed is intended.

Build: `clients/go/bindings/nvfs/keyring_tu.cc` compiles this directory and
`clients/go/bindings/nvfs/argon2_tu.c` the Argon2 sources into the nvfs cgo
package (TU pattern; see `clients/go/bindings/nvfs/aesgcm_tu.cc` and
`../codec/retouch.sh`).
