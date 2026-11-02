#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"
test "$(uname -sm)" = "Linux x86_64" || { echo 'This packaging target requires Linux x86_64.' >&2; exit 1; }
jobs=${MURMUR_BUILD_JOBS:-3}
cmake --preset linux "$@"
cmake --build --preset linux --target sqlite3-murmur --parallel "$jobs"
mkdir -p sqlite3-murmur-tool/bin/linux-x86_64
install -m 755 build/cmake-linux/sqlite3-murmur-tool/sqlite3-murmur sqlite3-murmur-tool/bin/linux-x86_64/sqlite3-murmur
(cd sqlite3-murmur-tool/bin/linux-x86_64 && sha256sum sqlite3-murmur > SHA256SUMS)
