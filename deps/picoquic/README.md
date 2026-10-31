# picoquic (vendored subset)

QUIC stack for Murmur's native replication transport. Upstream:
https://github.com/private-octopus/picoquic — BSD-3-Clause (see LICENSE).

- Version: `v2026.10.29.3012b39` (commit 3012b39, 2026-10-29)
- Subset: `picoquic/*.c,*.h` (QUIC core, 58 files) + `picoquic_mbedtls/*`
  (picotls<->mbedTLS glue: `ptls_mbedtls.c`, `ptls_mbedtls_sign.c`).
- Deliberately excluded: `picohttp/` (HTTP/3, unneeded), tests, samples,
  certs, demo apps, log tools, `picoquic_ptls_fusion.c` (needs the fusion
  crypto backend; excluded via `-DPTLS_WITHOUT_FUSION`, file kept for
  subset completeness but gets no build shim).

## Backend selection (compile-time)

Murmur uses mbedTLS as the sole TLS/X.509 backend:

- `-DPICOQUIC_WITH_MBEDTLS` — enables the mbedTLS crypto provider
  (last registration wins, so it overrides the others).
- `-DPTLS_WITHOUT_OPENSSL` — stubs the OpenSSL backend to a no-op loader.
- `-DPTLS_WITHOUT_FUSION` — drops the fusion backend (needs libaegis).
- minicrypto: NOT vendored (no X.509 stack; would be an insecure fallback).
  `tls_api.c` still references its symbols, so `clients/go/bindings/picoquic/`
  provides fail-closed link-only stubs (`minicrypto_stub.c`, all ids
  0xFFFF = never negotiable); the transport manager additionally sets
  `TLS_API_INIT_FLAGS_NO_MINICRYPTO` so the stubs are never referenced.

## Build

No cmake. Each `.c` file is compiled as its own translation unit through a
generated per-file shim in `clients/go/bindings/picoquic/qp_pico_*.c` (single-TU
amalgamation is impossible for mbedtls: same-named file-scope statics
collide). Regenerate after touching this tree:

    sh clients/go/tools/gen_pq_shims.sh   # or: sh deps/codec/retouch.sh

## Updating

1. Download the new picoquic release tarball.
2. Replace `picoquic/` and `picoquic_mbedtls/` with the new files.
3. Regenerate shims, rebuild, run the loopback smoke test (N1 gate).
4. Update the version line above.
