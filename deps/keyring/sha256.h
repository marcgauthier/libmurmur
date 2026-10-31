/* SHA-256 (FIPS 180-4) for the keys.enc v3 protector KDF.
 * Project-owned, written from the spec; no third-party code.
 * Byte-identical to Go crypto/sha256 (pinned by the keyring
 * differential test plus the RFC 6234 vectors in hkdf_test).
 */
#ifndef MURMUR_SHA256_H
#define MURMUR_SHA256_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MURMUR_SHA256_LEN 32

typedef struct {
  uint32_t h[8];
  uint64_t total;
  uint8_t buf[64];
  size_t used;
} murmur_sha256_t;

void murmur_sha256_init(murmur_sha256_t *c);
void murmur_sha256_update(murmur_sha256_t *c, const uint8_t *in, size_t len);
/* Finalizes into out[32]. The context is wiped and reusable. */
void murmur_sha256_final(murmur_sha256_t *c, uint8_t out[MURMUR_SHA256_LEN]);

/* One-shot. */
void murmur_sha256(const uint8_t *in, size_t len,
                   uint8_t out[MURMUR_SHA256_LEN]);

#ifdef __cplusplus
}
#endif

#endif
