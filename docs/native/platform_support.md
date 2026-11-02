# Windows and Linux builds

The intended baseline is Windows 10/11 x64 with MinGW-w64 (POSIX threads),
and Linux x86-64 with GCC or Clang. Windows native builds use MSYS2 MINGW64.
The CMake build covers the full native library, C demo/admin, and SQLite shell.
Go/Rust binding portability, MSVC, ARM, and DLL packaging are outside this change.

## Current verification limits

The complete cr-sqlite C/Rust sources are vendored together from the pinned
upstream revision in `deps/crsqlite/UPSTREAM.json`. CMake builds its isolated
static bundle from source. No sibling checkout is needed. The C CRSB adapter
preserves libmurmur's ingest API using upstream's public change table.

Full cross-platform runtime support still requires the broader integration,
crash/reopen, and mixed-platform replication gates below. The focused upstream
integration test covers initialization, replication, binary values, repeated
imports, malformed input, and batch rollback.
The portable socket and filesystem helpers have independent tests. The existing
membership, framing, message/file codec, and scheduler suites are also included. The CI
workflow runs those natively on Linux and Windows and cross-builds them from
Linux. Compile-check mode validates the complete native source set and C tools without
producing a linkable library; it does not certify runtime behavior or validate
RocksDB/AWS-LC builds.

## Full builds

Install CMake 3.21+, Ninja, a C/C++ compiler, and `patch`. For cross-compilation,
install the x86-64 MinGW-w64 compiler with the POSIX thread model. MSYS2 requires
its MinGW GCC, CMake and Ninja packages plus `patch`. Dependency installation is
explicit; build scripts do not install system packages.

Install rustup's `nightly-2023-10-05` toolchain and libclang for cr-sqlite's
bindgen build. For Windows also install the toolchain's `x86_64-pc-windows-gnu`
Rust target. See [cr-sqlite build details](../../deps/crsqlite/README.md).
MSYS2 additionally needs MinGW Python and Clang, and rustup on PATH.

Build all dependencies from the vendored source:

```sh
cmake --preset linux
cmake --build --preset linux --parallel 4

# From an MSYS2 MINGW64 terminal on Windows:
cmake --preset mingw
cmake --build --preset mingw --parallel 4

# From Linux:
cmake --preset win64-cross
cmake --build --preset win64-cross --parallel 4
```

RocksDB and AWS-LC build from vendored sources. The static `libmurmur.a` merges
those archives and cr-sqlite without extracting members with duplicate names.
CMake consumers link `murmur::murmur` to inherit system/runtime dependencies.
The existing Linux Makefile remains available with its existing archive inputs.

An optional `MURMUR_CRSQL_ARCHIVE` override accepts a matching target-specific
prebuilt bundle. Normal builds do not require it.

## Independent checks

```sh
# SQLite + upstream cr-sqlite, without waiting for RocksDB:
cmake -S . -B build/crsqlite -DMURMUR_CRSQL_TESTS_ONLY=ON
cmake --build build/crsqlite --parallel 4
ctest --test-dir build/crsqlite --output-on-failure

cmake -S . -B build/platform -DMURMUR_PLATFORM_TESTS_ONLY=ON
cmake --build build/platform
ctest --test-dir build/platform --output-on-failure

cmake -S . -B build/compile -DMURMUR_COMPILE_CHECK_ONLY=ON
cmake --build build/compile --parallel 4
```

Add `-DCMAKE_TOOLCHAIN_FILE=cmake/mingw-w64.cmake` and use a different build
directory for cross-checks. Cross-built executables must run on Windows; CTest
must not be treated as passing when those executables have only compiled.

Remaining acceptance gates include the native subsystem suite, CLI integration,
crash/reopen, mixed Windows/Linux replication and file transfer, and logical
backup exchange. File maintenance rejects Windows reparse points rather than
recursing through junctions. Windows directory-flush behavior retains the
existing best-effort implementation and needs durability validation.
