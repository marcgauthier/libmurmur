# Rust client

This is a dependency-free Rust wrapper over the stable `libmurmur.h` C ABI.
It provides a small Murmur connection and prepared-statement surface for the
Rust benchmark in `benchmarks/rust-client-benchmark`. Build `libmurmur.a` at
the repository root before running Cargo.

The benchmark key is fixed and intended only for throwaway benchmark stores.
Applications must manage key provisioning for their own data.
