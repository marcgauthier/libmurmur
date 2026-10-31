# sqlite-murmur-go

A Go distribution of [sqlite-murmur](../sqlite-murmur): an embedded
encrypted SQLite database. Same on-disk format, same PRAGMA surface,
same performance target (~200k writes/s single-tx, ~400k/s batched,
with replication on).

Direction: `sqlite-murmur-go` is mostly a C and Rust library
("sqlite-murmur", libmurmur). SQLite, cr-sqlite, zstd, AES/AEGIS,
RocksDB, and the QUIC/TLS transport all live inside the native
library and talk to each other without crossing into Go. What
remains Go is the `clients/go/` client: a thin Go API that only
sends SQL + values to the library, with everything else running via
PRAGMAs and C/Rust doing the work in the backend.

## Layout

- `deps/` — native sources, the core of the library:
  - `sqlite/` — vendored SQLite amalgamation.
  - `crsqlite/` — real Rust cr-sqlite static bundle
    (`libcrsql_bundle_isolated.a` + headers), initialized in SQLite.
  - `zstd/` — vendored Meta zstd core (portable C, no asm/DictBuilder).
  - `aegis/` — AEGIS-256 AEAD; `rocksdb/` — RocksDB container.
  - `aws-lc/` — AWS-LC libcrypto (AES-256-GCM backend), prebuilt archive.
  - `codec/` — project-owned page codec (compress + encrypt records).
- `clients/go/bindings/sqlite/` — cgo binding over the amalgamation, batch
  helpers (`ExecBatch`/`FetchInt64`/`FetchMany`), cr-sqlite init.
- `clients/go/bindings/nvfs/` — native VFS: C++ page cache, lock table,
  RocksDB pump, and (in progress) the full control plane —
  store registry, lifecycle, flusher, and the PRAGMA table.
- `clients/go/bindings/zstd/`, `clients/go/bindings/aegis/` — thin primitive bindings
  over the vendored C (VFS use; file-storage oracle only in Go).
- `clients/go/bindings/nvapi/` — dependency-free shared types for the seams.
- `clients/go/pkgs/murmur/` — Go management API (register/open/close, offline
  tools, live control). Shrinking toward SQL-only as the C++
  control plane lands.
- `clients/go/pkgs/storage/` — engine/keyring/PRAGMA logic moving into the
  VFS; file backend stays as the interop oracle.
- `clients/go/bindings/picoquic/` — native QUIC transport (vendored
  picoquic + picotls + mbedTLS, mutual TLS, `murmur-crsqlite/1`).
- `clients/go/pkgs/replication/`, `clients/go/pkgs/tx/` — replication core, protocol,
  snapshots, retention; moving native behind the QUIC transport.
- `clients/go/benchmarks/` — write benchmark (single + micro suites).
- `clients/go/tools/xcheck/`, `clients/go/tools/format_xcheck.sh` — cross-implementation
  format check; proves Rust/Go interop both directions.
- `archived/c-cr-sqlite/` — retired custom C CR-SQLite (kept with
  history; the real Rust bundle replaced it).

## Prerequisites

- Go 1.24+
- A C/C++ compiler (gcc/g++ or clang) for the cgo builds
- `../sqlite-murmur/build-a1` for the format cross-check and
  Rust reference benchmarks

## Build, test, benchmark

```sh
# From the repo root: build the unified native library first.
# Every Go package links libmurmur.a; go commands fail without it.
make -j$(nproc)   # → libmurmur.a (SQLite, cr-sqlite, codec, VFS, QUIC, …)

cd clients/go
go build ./...
go test ./... -count=1

go build -o /tmp/benchmark ./benchmarks/
/tmp/benchmark --suite=single --backend=murmur --replication=on \
  --seconds=15 --batch-size=1    # single-tx writes/s
/tmp/benchmark --suite=single --backend=murmur --replication=on \
  --seconds=15 --batch-size=100  # batched writes/s

cd ../..   # back to repo root
sh clients/go/tools/format_xcheck.sh   # XCHECK-OK (14 checks)
```

All benchmarks run with `--replication=on` so cr-sqlite is in the
loop. Fair-parity flags with the Rust reference: page_size 4096,
cipher on, zstd level 3, 100 ms flush, `journal_mode=DELETE`,
`synchronous=FULL`, 1 GiB cache, 4 reads per write.

Recent same-box numbers (15 s, `--replication=on`): Go ~187k/s at
1x and ~373k/s at 100x vs Rust ~199k/s and ~377k/s (reference
60 s: 199k/392k). 60 s runs on a loaded desktop skew lower; gate
on a quiet box (load < 1.5).

## Status

Done: page codec, write-back cache, VFS byte path with
cross-connection locks, real Rust cr-sqlite linked into SQLite,
vendored zstd, keyring/Argon2 config, PRAGMA table, backup/offline
tools, and Rust↔Go format compat proven both ways.

In progress (P0): the C++ control plane — store registry,
lifecycle, state snapshot, flusher thread, and the full PRAGMA
table in `clients/go/bindings/nvfs/`, so Go talks to the library through
SQLite + SQL only. Interim cold-path callbacks into Go (key
provisioning, seal, extension PRAGMAs) stay until P1 ports the
keyring/Argon2 and `PRAGMA key`, and P2 dissolves the Go
management API into SQL.
