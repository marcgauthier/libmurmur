#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
cd "$ROOT/clients/go"
exec go run ./benchmarks --suite=single --backend=murmur --replication=on "$@"
