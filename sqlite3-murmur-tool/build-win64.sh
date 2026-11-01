#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"
jobs=${MURMUR_BUILD_JOBS:-3}
mkdir -p build/win64/toolchain
if ! command -v x86_64-w64-mingw32-g++-posix >/dev/null 2>&1 &&
   [ ! -x build/win64/toolchain/root/usr/bin/x86_64-w64-mingw32-g++-posix ]; then
  # A local extraction suffices; no sudo or system package changes.
  (cd build/win64/toolchain && apt-get download g++-mingw-w64-x86-64-posix)
  for package in build/win64/toolchain/g++-mingw-w64-x86-64-posix_*.deb; do
    dpkg-deb -x "$package" build/win64/toolchain/root
  done
fi
toolchain="$root/sqlite3-murmur-tool/win64-toolchain.cmake"
cmake -S deps/aws-lc -B build/win64/aws-lc -DCMAKE_TOOLCHAIN_FILE="$toolchain" \
  -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=OFF -DBUILD_TOOL=OFF \
  -DBUILD_LIBSSL=OFF -DOPENSSL_NO_ASM=ON -DDISABLE_GO=ON -DDISABLE_PERL=ON
cmake --build build/win64/aws-lc --target crypto -j "$jobs"
cmake -S deps/rocksdb -B build/win64/rocksdb -DCMAKE_TOOLCHAIN_FILE="$toolchain" \
  -DCMAKE_BUILD_TYPE=Release -DPORTABLE=ON -DWITH_TESTS=OFF \
  -DWITH_BENCHMARK_TOOLS=OFF -DWITH_TOOLS=OFF -DWITH_CORE_TOOLS=OFF \
  -DWITH_GFLAGS=OFF -DWITH_LIBURING=OFF -DWITH_WINDOWS_UTF8_FILENAMES=ON \
  -DFAIL_ON_WARNINGS=OFF -DROCKSDB_BUILD_SHARED=OFF
cmake --build build/win64/rocksdb --target rocksdb -j "$jobs"
cmake -S sqlite3-murmur-tool -B build/win64/cli -DCMAKE_TOOLCHAIN_FILE="$toolchain" -DCMAKE_BUILD_TYPE=Release
cmake --build build/win64/cli -j "$jobs"
mkdir -p sqlite-murmur-tool/bin/win64
install -m 755 build/win64/cli/sqlite3-murmur.exe sqlite-murmur-tool/bin/win64/sqlite3-murmur.exe
(cd sqlite-murmur-tool/bin/win64 && sha256sum sqlite3-murmur.exe > SHA256SUMS)
