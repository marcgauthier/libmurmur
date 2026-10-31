/* Link-only stubs for the picotls minicrypto provider (never selected).
 *
 * picoquic's tls_api.c calls picoquic_ptls_minicrypto_load() unconditionally
 * at provider-init time, so the minicrypto symbols must exist at link time
 * even though Murmur uses the mbedTLS provider exclusively (X.509 is
 * mandatory for mutual TLS; minicrypto has no X.509 stack, so vendoring it
 * would only add an insecure fallback path).
 *
 * Fail-closed by construction, three layers:
 *  1. The transport manager sets TLS_API_INIT_FLAGS_NO_MINICRYPTO, so the
 *     minicrypto load function is never called and these objects are never
 *     referenced at runtime; they exist only to satisfy the linker.
 *  2. Every stub carries id 0xFFFF (reserved, never negotiated), so even if
 *     registration ran, no peer could negotiate a stub suite or group.
 *  3. The stub functions abort (random_bytes: zeros would be catastrophic)
 *     or return an error (load_private_key), never fake success.
 */
#include <stdlib.h>
#include "picotls.h"
#include "picotls/minicrypto.h"

ptls_cipher_suite_t ptls_minicrypto_aes128gcmsha256 = {
    .id = 0xFFFF, .name = "minicrypto-stub (unsupported)"
};
ptls_cipher_suite_t ptls_minicrypto_aes256gcmsha384 = {
    .id = 0xFFFF, .name = "minicrypto-stub (unsupported)"
};
ptls_cipher_suite_t ptls_minicrypto_chacha20poly1305sha256 = {
    .id = 0xFFFF, .name = "minicrypto-stub (unsupported)"
};

ptls_key_exchange_algorithm_t ptls_minicrypto_secp256r1 = {
    .id = 0xFFFF, .name = "minicrypto-stub (unsupported)"
};
ptls_key_exchange_algorithm_t ptls_minicrypto_x25519 = {
    .id = 0xFFFF, .name = "minicrypto-stub (unsupported)"
};

void ptls_minicrypto_random_bytes(void *buf, size_t len)
{
    (void)buf;
    (void)len;
    abort(); /* unreachable: mbedTLS provides randomness */
}

int ptls_minicrypto_load_private_key(ptls_context_t *ctx, char const *pem_fname)
{
    (void)ctx;
    (void)pem_fname;
    return -1; /* unreachable: mbedTLS loads keys */
}
