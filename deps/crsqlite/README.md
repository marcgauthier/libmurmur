# cr-sqlite (Rust core) vendored for sqlite-murmur-go

Real cr-sqlite, same fork and build the Rust `sqlite-murmur` links, so Go
and Rust capture, merge, and replicate with identical code and format.

- `src/` — the three C integration files plus their headers, copied
  unmodified from `third-party/cr-sqlite/core/src/` in the sibling
  `sqlite-murmur` checkout: `crsqlite.c`, `changes-vtab.c`,
  `ext-data.c`. Compiled with `-DSQLITE_CORE` against the vendored
  SQLite 3.54.1 in `../sqlite/` (same version the Rust build uses).
- `include/sqlite_murmur_crsqlite.h` — public init header, copied from
  `sqlite-murmur/include/`. Open a connection, then call
  `sqlite3_crsqlite_init(db, &err, NULL)`; run
  `SELECT crsql_finalize()` before `sqlite3_close()`.
- `lib/libcrsql_bundle_isolated.a` — prebuilt Rust core
  (`core/rs/bundle_static`, release) with its Rust runtime symbols
  renamed to the `crsql_` prefix so the archive links alongside any
  other static libraries. Copied from
  `sqlite-murmur/build-a1/crsqlite2/`.
- `LICENSE` — cr-sqlite MIT license.

## Rebuild

From the sibling `sqlite-murmur` checkout (needs its pinned Rust
nightly toolchain plus libclang):

```
cmake -S . -B build-a1 -DSQLITE_MURMUR_ENABLE_CRSQLITE=ON
cmake --build build-a1 --target crsqlite_isolated_build
cp build-a1/crsqlite2/libcrsql_bundle_isolated.a \
  ../sqlite-murmur-go/deps/crsqlite/lib/
```

If the Rust revision changes, re-copy `src/` and `include/` from the
same checkout so the C and Rust halves stay in sync, then run
`go test ./...` and `sh clients/go/tools/format_xcheck.sh`.
