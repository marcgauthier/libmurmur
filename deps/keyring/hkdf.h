/* HMAC-SHA256 and HKDF-SHA256 (RFC 5869) for the keys.enc v3
 * protector KDF. Project-owned, written from the spec.
 * hkdf.Key semantics match Go crypto/hkdf exactly (empty salt =>
 * HashLen zeros; L up to 255*HashLen).
 */
#ifndef MURMUR_HKDF_H
#define MURMUR_HKDF_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* HMAC-SHA256 one-shot into out[32]. */
void murmur_hmac_sha256(const uint8_t *key, size_t key_len, const uint8_t *in,
                        size_t in_len, uint8_t out[32]);

/* HKDF-Extract(salt, ikm) into prk[32]. Empty salt => 32 zeros. */
void murmur_hkdf_extract(const uint8_t *salt, size_t salt_len,
                         const uint8_t *ikm, size_t ikm_len, uint8_t prk[32]);

/* HKDF-Expand(prk, info, L) into okm. Returns 0, or -1 when
 * L == 0 or L > 255*32 (Go's hkdf.Key refuses the same). */
int murmur_hkdf_expand(const uint8_t prk[32], const uint8_t *info,
                       size_t info_len, uint8_t *okm, size_t okm_len);

/* HKDF one-shot (extract then expand). Returns 0, or -1 on bad L. */
int murmur_hkdf(const uint8_t *ikm, size_t ikm_len, const uint8_t *salt,
                size_t salt_len, const uint8_t *info, size_t info_len,
                uint8_t *okm, size_t okm_len);

#ifdef __cplusplus
}
#endif

#endif
