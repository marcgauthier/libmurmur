# Rust client benchmark

This benchmark depends on the small Rust client in `clients/rust`, which calls
the public `libmurmur` C ABI. The client crate has no third-party dependencies.
It uses the Murmur VFS, AEGIS-256, Zstandard level 3, and cr-sqlite CRDT
tracking. The workload is four reads and one insert (80% reads / 20% writes),
with batch sizes 1 and 100.

```sh
make -j"$(nproc)"
./benchmarks/rust-client-benchmark/run.sh --seconds=15 --batch-size=1
./benchmarks/rust-client-benchmark/run.sh --seconds=15 --batch-size=100
```

Options: `--seconds=N`, `--seed-rows=N`, `--batch-size=1|100`, and
`--database=DIR`. By default it creates a fresh temporary Murmur store. CSV
output identifies the workload and storage settings, reports throughput and
verified CRDT changes, then compares logical SQLite bytes with all regular
files in the store after close. The disk/raw ratio includes RocksDB metadata,
so it is a store-size ratio rather than codec-only compression.
