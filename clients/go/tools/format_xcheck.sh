#!/bin/sh
# Cross-implementation format proof: the Go driver (tools/xcheck) and
# the C driver built against the Rust static libraries must read each
# other's databases (pages, keyrings, rekeys, both ciphers).
# Usage: sh clients/go/tools/format_xcheck.sh
set -eu
cd "$(dirname "$0")/.."
GO_ROOT="$PWD"
REPO_ROOT="$(cd "$GO_ROOT/../.." && pwd)"
RUST_ROOT="${SQLITE_MURMUR_SRC:-$(dirname "$REPO_ROOT")/sqlite-murmur}"
RUST_BUILD="$RUST_ROOT/build-a1"
WORK="$(mktemp -d)"
export GOTOOLCHAIN=local

echo "== build Go driver =="
go build -o "$WORK/xcheck_go" ./tools/xcheck

echo "== build Rust driver =="
gcc -o "$WORK/xcheck_rust" tests/format_xcheck.c \
  "-I$RUST_ROOT/include" "-I$RUST_ROOT/third-party/sqlite" \
  "$RUST_BUILD/murmur-storage/base+aes256gcm/release/libmurmur_storage.a" \
  "$RUST_BUILD/murmur-storage-api/base+crsqlite+murmur/release/libmurmur_storage_api.a" \
  "$RUST_BUILD/libsqlite_murmur.a" \
  "$RUST_BUILD/murmur/static/release/libmurmur_replication.a" \
  "$RUST_BUILD/libsqlite_murmur_crsqlite.a" \
  "$RUST_BUILD/crsqlite2/libcrsql_bundle_isolated.a" \
  "$RUST_BUILD/third-party/rocksdb/librocksdb.a" \
  "$RUST_BUILD/third-party/aegis/libaegis.a" \
  "$RUST_BUILD/third-party/zstd/lib/libzstd.a" \
  "$RUST_BUILD/libsqlite_murmur_sqlite.a" \
  "$RUST_BUILD/murmur/static/release/libmurmur_replication.a" \
  "$RUST_BUILD/libsqlite_murmur_crsqlite.a" \
  -ldl -lm -lpthread -lstdc++

pass=0
check_rows() { # <actual> <expected...> (compares ROWS line)
  desc="$1"; shift
  if [ "$1" = "$2" ]; then pass=$((pass+1)); echo "ok: $desc";
  else echo "MISMATCH $desc:"; echo "  got:      $1"; echo "  expected: $2"; exit 1; fi
}

for cipher in aes256gcm; do
  echo "== cipher $cipher =="
  # Rust writes, Go reads.
  "$WORK/xcheck_rust" write "$WORK/r2g-$cipher" "$cipher" >/dev/null
  rows_go="$("$WORK/xcheck_go" read "$WORK/r2g-$cipher" | grep '^ROWS:')"
  check_rows "rust-write go-read $cipher" "$rows_go" \
    "ROWS: alpha beta gamma delta epsilon"
  "$WORK/xcheck_go" read "$WORK/r2g-$cipher" | grep -q '"sealed":true' || { echo "MISMATCH seal flag"; exit 1; }
  pass=$((pass+1)); echo "ok: seal flag $cipher"
  # Go writes, Rust reads.
  "$WORK/xcheck_go" write "$WORK/g2r-$cipher" "$cipher" >/dev/null
  rows_rust="$("$WORK/xcheck_rust" read "$WORK/g2r-$cipher" | grep '^ROWS:')"
  check_rows "go-write rust-read $cipher" "$rows_rust" \
    "ROWS: alpha beta gamma delta epsilon"
  # Ping-pong appends.
  "$WORK/xcheck_go" append "$WORK/r2g-$cipher" >/dev/null
  rows_rust="$("$WORK/xcheck_rust" read "$WORK/r2g-$cipher" | grep '^ROWS:')"
  check_rows "rust-go-rust append $cipher" "$rows_rust" \
    "ROWS: alpha beta gamma delta epsilon zeta"
  "$WORK/xcheck_rust" append "$WORK/g2r-$cipher" >/dev/null
  rows_go="$("$WORK/xcheck_go" read "$WORK/g2r-$cipher" | grep '^ROWS:')"
  check_rows "go-rust-go append $cipher" "$rows_go" \
    "ROWS: alpha beta gamma delta epsilon zeta"
  # Cross rekeys.
  "$WORK/xcheck_rust" write "$WORK/rk-$cipher" "$cipher" >/dev/null
  "$WORK/xcheck_go" rekey "$WORK/rk-$cipher" >/dev/null
  rows_rust="$("$WORK/xcheck_rust" readnew "$WORK/rk-$cipher" | grep '^ROWS:')"
  check_rows "go-rekey rust-read $cipher" "$rows_rust" \
    "ROWS: alpha beta gamma delta epsilon"
  "$WORK/xcheck_go" write "$WORK/gk-$cipher" "$cipher" >/dev/null
  "$WORK/xcheck_rust" rekey "$WORK/gk-$cipher" >/dev/null
  rows_go="$("$WORK/xcheck_go" readnew "$WORK/gk-$cipher" | grep '^ROWS:')"
  check_rows "rust-rekey go-read $cipher" "$rows_go" \
    "ROWS: alpha beta gamma delta epsilon"
done

echo "XCHECK-OK ($pass checks)"

# This external legacy oracle covers AES/direct-HKDF only; scrypt coverage is
# provided by native crypto-policy and Go keyring differential tests.
