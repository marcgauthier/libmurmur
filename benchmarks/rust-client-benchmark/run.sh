#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
exec cargo run --release --manifest-path "$ROOT/benchmarks/rust-client-benchmark/Cargo.toml" -- "$@"
