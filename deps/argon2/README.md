# Argon2 reference (PHC) vendored for sqlite-murmur-go

Argon2id password hashing for the keys.enc v3 keyring protector
(`deriveProtector`, Argon2id + HKDF-SHA256). Upstream is
P-H-C/phc-winner-argon2 at tag 20190702 (CC0-1.0 OR Apache-2.0, see
LICENSE). Only the portable `ref` backend plus pthread threading is
vendored; Argon2 runs once per open/seal (cold path), so the
reference backend's speed is irrelevant and its portability wins.

- `argon2.h`, `argon2.c` — public API (`argon2id_hash_raw`).
- `core.c`, `core.h` — instance/memory/segment engine.
- `ref.c` — portable Blamka blocks (no `opt.c`, no x86 intrinsics).
- `encoding.c`, `encoding.h` — raw encoding helpers (linked for
  completeness; the keyring uses raw hashes only).
- `thread.c`, `thread.h` — pthread lane workers (Win32 fallback
  retained upstream, unused here).
- `blake2/` — BLAKE2b long-digest + `blamka-round-ref.h` (no
  `blamka-round-opt.h`, no kat/bench/test tools).

Build: add `-I../argon2` and compile `argon2.c core.c ref.c
encoding.c thread.c blake2/blake2b.c` with `-lpthread`. Output is
byte-identical to `golang.org/x/crypto/argon2.IDKey` at version
0x13 (pinned by `keyring_vectors_test.go` via the C++ keyring
differential test).
