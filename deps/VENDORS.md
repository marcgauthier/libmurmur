# Dependency sources and vendors

This inventory covers every immediate subdirectory of `deps/` except `murmur/`.
Author and organization names describe the upstream source; the linked upstream
repositories, source headers, and bundled license files provide attribution.

## Third-party dependencies

| Directory | Dependency | Company, project, or author | Website | Upstream source |
| --- | --- | --- | --- | --- |
| `aws-lc/` | AWS-LC (AWS libcrypto) | Amazon Web Services, AWS Cryptography team; derived from Google's BoringSSL and OpenSSL | [AWS](https://aws.amazon.com/) | [aws/aws-lc](https://github.com/aws/aws-lc) |
| `crsqlite/` | cr-sqlite | Matt Wonlaw and contributors; vlcn.io / Vulcan project | [vlcn.io](https://vlcn.io/) | [vlcn-io/cr-sqlite](https://github.com/vlcn-io/cr-sqlite) |
| `mbedtls/` | Mbed TLS | Mbed TLS contributors; Trusted Firmware project | [Mbed TLS at Trusted Firmware](https://www.trustedfirmware.org/projects/mbed-tls/) | [Mbed-TLS/mbedtls](https://github.com/Mbed-TLS/mbedtls) |
| `picoquic/` | picoquic | Christian Huitema, Private Octopus, Inc., and contributors | [Private Octopus](https://www.privateoctopus.com/) | [private-octopus/picoquic](https://github.com/private-octopus/picoquic) |
| `picotls/` | picotls | Kazuho Oku, DeNA Co., Ltd., and contributors; H2O project | [H2O project](https://h2o.examp1e.net/) | [h2o/picotls](https://github.com/h2o/picotls) |
| `rocksdb/` | RocksDB | Meta Platforms, Inc. (originally Facebook); derived from Google's LevelDB | [RocksDB](https://rocksdb.org/) | [meta/rocksdb](https://github.com/meta/rocksdb) |
| `sqlite/` | SQLite | Richard Hipp and the SQLite development team; Hwaci (Hipp, Wyrick & Company, Inc.) | [SQLite](https://www.sqlite.org/) | [SQLite source repository](https://sqlite.org/src/) |
| `zstd/` | Zstandard | Yann Collet and contributors; Meta Platforms, Inc. (originally Facebook) | [Zstandard project](https://github.com/meta/zstd) | [meta/zstd](https://github.com/meta/zstd) |

## Project-owned code

These directories are included for completeness because they also live under
`deps/`. Their source belongs to libmurmur rather than a separate vendor.

| Directory | Component | Author / project | Website and source |
| --- | --- | --- | --- |
| `codec/` | Page compression and encryption integration | libmurmur contributors | [marcgauthier/libmurmur](https://github.com/marcgauthier/libmurmur/tree/main/deps/codec) |
| `keyring/` | Keyring, SHA-256, HKDF, and CRC32C implementation | libmurmur contributors | [marcgauthier/libmurmur](https://github.com/marcgauthier/libmurmur/tree/main/deps/keyring) |
| `vec0/` | Minimal brute-force vector index | libmurmur contributors | [marcgauthier/libmurmur](https://github.com/marcgauthier/libmurmur/tree/main/deps/vec0) |

`vec0/vec0.c` explicitly identifies itself as libmurmur's own implementation of
the `vec0` interface, not vendored sqlite-vec source.

## Bundled source details

- `crsqlite/rs/sqlite-rs-embedded/` is the upstream SQLite Rust bindings source
  by Matt Wonlaw and contributors, also under the vlcn.io project:
  [vlcn-io/sqlite-rs-embedded](https://github.com/vlcn-io/sqlite-rs-embedded).
  Exact cr-sqlite and bindings revisions are recorded in
  [crsqlite/UPSTREAM.json](crsqlite/UPSTREAM.json). Registry dependencies used
  during its build are pinned in
  [crsqlite/rs/bundle_static/Cargo.lock](crsqlite/rs/bundle_static/Cargo.lock).
- The flattened Zstandard source was imported through DataDog's packaging of
  upstream Zstandard, as documented in [zstd/README.md](zstd/README.md):
  [DataDog/zstd](https://github.com/DataDog/zstd). The compression library's
  upstream authorship remains Zstandard / Meta.
- AWS-LC and RocksDB retain attribution to their predecessor projects in their
  source and license notices. Those notices remain the detailed attribution
  record for bundled supporting code.
