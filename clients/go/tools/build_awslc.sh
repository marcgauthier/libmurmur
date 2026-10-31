#!/bin/sh
# Rebuild the vendored AWS-LC static library (offline).
# Builds libcrypto only (no libssl, tests, or tools), static with PIC,
# using the pre-generated assembly in generated-src (no Perl/NASM/Go
# needed for the library itself).
# Usage: sh clients/go/tools/build_awslc.sh [jobs]
set -eu
cd "$(dirname "$0")/../../../deps/aws-lc"
JOBS="${1:-$(nproc 2>/dev/null || echo 4)}"
BUILD="$PWD/build-cmake"
cmake -S . -B "$BUILD" -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
  -DBUILD_SHARED_LIBS=OFF \
  -DBUILD_TESTING=OFF \
  -DBUILD_LIBSSL=OFF
cmake --build "$BUILD" -j "$JOBS" --target crypto
mkdir -p lib
cp "$BUILD/crypto/libcrypto.a" lib/libcrypto.a
echo "installed lib/libcrypto.a"
