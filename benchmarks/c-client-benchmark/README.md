# C client replication benchmark

Standalone C application linked against the repository's libmurmur.a. It
registers the Murmur VFS, opens and keys a Murmur store through libmurmur,
initializes bundled cr-sqlite, marks records as a CRR table, and checks that
each measured insert creates one tracked change. The run uses AES-256-GCM
encryption, Zstandard level 3 compression, and cr-sqlite CRDT replication;
these settings are included in the CSV output. The workload is four
primary-key reads and one insert per operation, matching the sibling
benchmark's 1x workload: each write is accompanied by four primary-key reads,
so the measured mix is 80% reads and 20% writes. Batch size 100 measures its
100x batched case.

```sh
make -C benchmarks/c-client-benchmark
./benchmarks/c-client-benchmark/c-client-benchmark --batch-size=1
./benchmarks/c-client-benchmark/c-client-benchmark --batch-size=100
```

Options: --seconds=N (default 15), --seed-rows=N (default 50000),
--batch-size=1|10|100 (default 1), and --database=PATH (default a temporary
directory). PATH names a Murmur store directory. Output is CSV and includes
writes/s, total operations/s (reads plus writes), the 80/20 read/write mix,
encryption and cipher, compression, CRDT replication mode, tracked changes,
logical SQLite bytes (`page_count * page_size`), and all regular-file bytes under the
store directory after close. `disk_to_raw_pct` compares physical store size
with logical database size; it includes RocksDB metadata and should be read
as a storage ratio rather than a codec-only compression measurement.
