# Go client benchmark

Runs the benchmark implemented by the Go client at `clients/go/benchmarks`.
The client uses the `clients/go/pkgs/murmur` API to open a Murmur store and
the Go replication package to enable cr-sqlite CRDT tracking. Default run:

```sh
./benchmarks/go-client-benchmark/run.sh --seconds=15 --batch-size=1
./benchmarks/go-client-benchmark/run.sh --seconds=15 --batch-size=100
```

Arguments are passed through to the existing Go client benchmark. It reports
the workload configuration, operations/s, tracked changes, logical and disk
sizes, and persistence time. Run `./benchmarks/go-client-benchmark/run.sh
--help` for available options.
