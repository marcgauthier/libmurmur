/* AES-256-GCM page-cipher backend for the native codec.
 *
 * Provided by AWS-LC (deps/aws-lc, EVP_aead_aes_256_gcm; prebuilt
 * libcrypto.a merged into libmurmur.a), so the backend is always
 * available wherever libmurmur links. No hand-rolled field math: the
 * GCM compose is the library's, pinned by NIST vectors in
 * aesgcm_selftest.c and Go-stdlib differentials in
 * clients/go/bindings/nvfs/aesgcm_test.go.
 */
#ifndef MURMUR_AESGCM_H
#define MURMUR_AESGCM_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Reports whether the AES-GCM backend is available. Always true:
 * AWS-LC is linked into libmurmur unconditionally. */
int murmur_aes_available(void);

/* Raw AES-256 block encrypt (test seam + CTR core). Returns 0, or -1
 * on misuse. */
int murmur_aes256_block(const uint8_t key[32], const uint8_t in16[16],
                        uint8_t out16[16]);

/* AES-256-GCM one-shot. ct has room for pt_len bytes. Returns 0, -1 on
 * misuse. */
int murmur_aes256gcm_encrypt(const uint8_t key[32], const uint8_t nonce[12],
                             const uint8_t *pt, size_t pt_len, const uint8_t *aad,
                             size_t aad_len, uint8_t *ct, uint8_t tag[16]);

/* Verifies then decrypts (no plaintext released on failure). Returns 0,
 * -2 on authentication failure, -1 on misuse. */
int murmur_aes256gcm_decrypt(const uint8_t key[32], const uint8_t nonce[12],
                             const uint8_t *ct, size_t ct_len, const uint8_t tag[16],
                             const uint8_t *aad, size_t aad_len, uint8_t *pt);

/* AES-256-GCM seal with appended tag: out has room for pt_len +
 * 16 bytes. Returns 0, -1 on misuse. */
int murmur_aes256gcm_seal(const uint8_t key[32], const uint8_t nonce[12],
                          const uint8_t *pt, size_t pt_len, const uint8_t *aad,
                          size_t aad_len, uint8_t *out);

/* Verifies then decrypts a sealed (ct||tag) buffer; out has room
 * for in_len - 16 bytes. Returns 0, -2 on authentication failure
 * (output wiped), -1 on misuse. */
int murmur_aes256gcm_open(const uint8_t key[32], const uint8_t nonce[12],
                          const uint8_t *in, size_t in_len, const uint8_t *aad,
                          size_t aad_len, uint8_t *out);

/* Cryptographic randomness (AWS-LC RAND_bytes). Returns 0, -1 on
 * failure. (SHA-256 and HKDF live in deps/keyring; files.c uses
 * those directly.) */
int murmur_rand_bytes(uint8_t *out, size_t len);

#ifdef __cplusplus
}
#endif

#endif
