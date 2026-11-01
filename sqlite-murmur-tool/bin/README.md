# CLI binaries

The CLI source is in [sqlite3-murmur-tool](../../sqlite3-murmur-tool/README.md).

From the repository root or `sqlite3-murmur-tool/`, build both platforms with:

```sh
make sqlite3-murmur-tool-bin
./sqlite-murmur-tool/bin/linux-x86_64/sqlite3-murmur ./my-store
```

The Linux package contains `sqlite3-murmur` and `SHA256SUMS`. Verify it from
`linux-x86_64/` with `sha256sum -c SHA256SUMS`.

This is a dynamically linked Linux executable built on the local host,
requiring its compatible glibc, libstdc++, libgcc_s, and libm runtimes.
It is not a universal Linux or musl build. Generated Linux artifacts are
ignored by Git and can be recreated with the target above.

The Windows package is `win64/sqlite3-murmur.exe`, with its own `SHA256SUMS`.
It statically links the C++/thread runtimes and storage dependencies.
Both folders are also accessible through `sqlite3-murmur-tool/bin/`.

Build just one platform with `make sqlite3-murmur-tool-linux-bin` or
`make sqlite3-murmur-tool-win64-bin`. The Windows cross-build uses CMake,
MinGW GCC, and a POSIX-thread MinGW C++ compiler. If only the C compiler is
installed on Ubuntu, the build script extracts the matching C++ package
locally under `build/win64/toolchain/`, without changing system packages.
