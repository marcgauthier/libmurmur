#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"
jobs=${MURMUR_BUILD_JOBS:-3}
cmake --preset win64-cross "$@"
cmake --build --preset win64-cross --target sqlite3-murmur --parallel "$jobs"
mkdir -p sqlite3-murmur-tool/bin/win64
install -m 755 build/cmake-win64/sqlite3-murmur-tool/sqlite3-murmur.exe sqlite3-murmur-tool/bin/win64/sqlite3-murmur.exe
(cd sqlite3-murmur-tool/bin/win64 && sha256sum sqlite3-murmur.exe > SHA256SUMS)
