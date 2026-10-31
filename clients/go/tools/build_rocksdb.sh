#!/bin/sh
# Rebuild the vendored RocksDB static library (offline).
# Flags mirror sqlite-murmur's cmake/VendorDependencies.cmake: no system
# codecs or allocators, portable build, static only.
# Usage: sh clients/go/tools/build_rocksdb.sh [jobs]
set -eu
cd "$(dirname "$0")/../../../deps/rocksdb"
JOBS="${1:-$(nproc 2>/dev/null || echo 4)}"
BUILD="$PWD/build-cmake"
cmake -S . -B "$BUILD" -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
  -DWITH_GFLAGS=OFF -DWITH_SNAPPY=OFF -DWITH_LZ4=OFF -DWITH_ZLIB=OFF \
  -DWITH_BZ2=OFF -DWITH_ZSTD=OFF -DWITH_JEMALLOC=OFF -DWITH_LIBURING=OFF \
  -DWITH_NUMA=OFF -DWITH_TBB=OFF -DWITH_TESTS=OFF -DWITH_BENCHMARK_TOOLS=OFF \
  -DWITH_CORE_TOOLS=OFF -DWITH_TOOLS=OFF -DWITH_TRACE_TOOLS=OFF \
  -DWITH_EXAMPLES=OFF -DWITH_BENCHMARK=OFF -DROCKSDB_BUILD_SHARED=OFF \
  -DFAIL_ON_WARNINGS=OFF -DPORTABLE=ON
cmake --build "$BUILD" -j "$JOBS" --target rocksdb
mkdir -p lib
cp "$BUILD/librocksdb.a" lib/librocksdb.a
echo "installed lib/librocksdb.a"
