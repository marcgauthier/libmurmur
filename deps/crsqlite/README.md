# Vendored upstream cr-sqlite

Source: https://github.com/vlcn-io/cr-sqlite

`UPSTREAM.json` pins revision `43ab94cac537d080aac7cb7628a435c02ee9e268`
and its `sqlite-rs-embedded` submodule revision. This folder contains the C
integration in `src/` and Rust implementations in `rs/`, including the SQLite
bindings submodule. Upstream source files are copied without local changes.
The upstream Cargo lockfile and `nightly-2023-10-05` toolchain are retained.

`wrapper_tu.c` compiles upstream's three integration sources as one translation
unit against libmurmur's bundled SQLite with `SQLITE_CORE`. It then registers
libmurmur's C CRSB compatibility adapter (`deps/murmur/crsqlite_ingest.c`).
The adapter implements `crsql_ingest_blob` through upstream's public
`crsql_changes` virtual table. The previous fork-specific bulk-merge
optimizations and shared C/Rust structure extensions are replaced by the
matching upstream implementations. Wire envelopes remain in libmurmur.

## Build

Install Rust through rustup, the pinned nightly, and libclang (for bindgen):

```sh
rustup toolchain install nightly-2023-10-05 --profile minimal
rustup target add --toolchain nightly-2023-10-05 x86_64-pc-windows-gnu
```

The root CMake build builds this core automatically. Cargo uses `--locked`;
registry packages download on first build. No sibling checkout or prebuilt
archive is required. CMake accepts `MURMUR_CRSQL_ARCHIVE` as an optional
explicit override for a matching target-specific bundle.

To build the core alone:

```sh
python3 tools/build_crsqlite.py --target x86_64-unknown-linux-gnu \
  --target-dir build/crsqlite-cargo \
  --output build/crsqlite-linux/libcrsql_bundle_isolated.a
```

For Windows cross-compilation use `--target x86_64-pc-windows-gnu` with
`--cc x86_64-w64-mingw32-gcc`, `--nm x86_64-w64-mingw32-nm`, and
`--objcopy x86_64-w64-mingw32-objcopy`, and a separate target/output directory.
`LIBCLANG_PATH` may be set to select the installed libclang.

The build isolates Rust-internal symbols with the target's objcopy while
preserving the C entry points. Generated archives and Cargo output stay under
`build/`; they are not vendored binaries.

The legacy Makefile can consume the built archive by passing
`CRSQL_A=build/crsqlite-linux/libcrsql_bundle_isolated.a`.
