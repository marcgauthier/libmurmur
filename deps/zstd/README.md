# Zstandard (Meta) vendored for sqlite-murmur-go

Single-threaded core of zstd 1.5.x (same sources as DataDog/zstd
v1.5.7, which this replaces): one-shot and context compress /
decompress at levels 1-22. This is the only zstd in the binary: the
C++ page codec (`../codec/codec.cc`) calls it directly, and the Go
file-storage backend reaches it through the thin `clients/go/bindings/zstd`
wrapper. No Go runs on the native compress path.

- `zstd.h`, `zstd_errors.h` — the public headers (identical to the
  copies formerly kept in `../codec/`).
- 22 `.c` files — common, compress, decompress cores. Omitted
  upstream units: multithreading (`zstdmt_compress`, `pool`,
  `threading`), legacy decoders (`zstd_v0*`, `zbuff_*`), dictionary
  builders (`cover`, `fastcover`, `divsufsort`, `zdict`),
  `debug.c`, and the x86 Huffman/BMI2 asm loops
  (`ZSTD_DISABLE_ASM=1`, portable C fallback; micro-benched at
  4KB pages with no measurable difference vs asm).
  None were ever called (the legacy decoders only widened the
  attack surface).
- `LICENSE` — zstd BSD license (upstream `ZSTD_LICENSE`).

## Rebuild

The sources match DataDog/zstd v1.5.7 byte-for-byte (flat layout).
To refresh from a newer zstd, copy the same 22 units plus headers
from upstream `lib/{common,compress,decompress}` (flattened), then
run `go test ./...` and `sh clients/go/tools/format_xcheck.sh`; the codec
differentials prove frame compatibility.
