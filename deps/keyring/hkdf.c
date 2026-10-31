/* HMAC-SHA256 and HKDF-SHA256 (RFC 5869). */
#include "hkdf.h"

#include <string.h>

#include "sha256.h"

void murmur_hmac_sha256(const uint8_t *key, size_t key_len, const uint8_t *in,
                        size_t in_len, uint8_t out[32]) {
  uint8_t kb[64];
  if (key_len > 64) {
    murmur_sha256(key, key_len, kb);
    memset(kb + 32, 0, 32);
  } else {
    if (key_len > 0) {
      memcpy(kb, key, key_len);
    }
    memset(kb + key_len, 0, 64 - key_len);
  }
  uint8_t ipad[64], opad[64];
  for (int i = 0; i < 64; i++) {
    ipad[i] = kb[i] ^ 0x36;
    opad[i] = kb[i] ^ 0x5c;
  }
  murmur_sha256_t c;
  uint8_t inner[32];
  murmur_sha256_init(&c);
  murmur_sha256_update(&c, ipad, 64);
  if (in_len > 0) {
    murmur_sha256_update(&c, in, in_len);
  }
  murmur_sha256_final(&c, inner);
  murmur_sha256_init(&c);
  murmur_sha256_update(&c, opad, 64);
  murmur_sha256_update(&c, inner, 32);
  murmur_sha256_final(&c, out);
  volatile uint8_t *v;
  v = (volatile uint8_t *)kb;
  for (size_t i = 0; i < sizeof(kb); i++) {
    v[i] = 0;
  }
  v = (volatile uint8_t *)inner;
  for (size_t i = 0; i < sizeof(inner); i++) {
    v[i] = 0;
  }
}

void murmur_hkdf_extract(const uint8_t *salt, size_t salt_len,
                         const uint8_t *ikm, size_t ikm_len, uint8_t prk[32]) {
  uint8_t zeros[32];
  memset(zeros, 0, sizeof(zeros));
  if (salt == NULL || salt_len == 0) {
    salt = zeros;
    salt_len = sizeof(zeros);
  }
  murmur_hmac_sha256(salt, salt_len, ikm, ikm_len, prk);
}

int murmur_hkdf_expand(const uint8_t prk[32], const uint8_t *info,
                       size_t info_len, uint8_t *okm, size_t okm_len) {
  if (okm_len == 0 || okm_len > 255 * 32) {
    return -1;
  }
  uint8_t t[32];
  size_t tlen = 0;
  size_t done = 0;
  uint8_t ctr = 1;
  /* T(0) is empty; T(i) = HMAC(prk, T(i-1) | info | i). Feed the
   * pieced input through one HMAC per block. */
  while (done < okm_len) {
    /* HMAC rebuilt manually per block (T(i-1) chaining). */
    murmur_sha256_t c;
    uint8_t kb[64];
    memcpy(kb, prk, 32);
    memset(kb + 32, 0, 32);
    uint8_t ipad[64], opad[64];
    for (int i = 0; i < 64; i++) {
      ipad[i] = kb[i] ^ 0x36;
      opad[i] = kb[i] ^ 0x5c;
    }
    murmur_sha256_init(&c);
    murmur_sha256_update(&c, ipad, 64);
    if (tlen > 0) {
      murmur_sha256_update(&c, t, tlen);
    }
    if (info_len > 0) {
      murmur_sha256_update(&c, info, info_len);
    }
    murmur_sha256_update(&c, &ctr, 1);
    uint8_t inner[32];
    murmur_sha256_final(&c, inner);
    murmur_sha256_init(&c);
    murmur_sha256_update(&c, opad, 64);
    murmur_sha256_update(&c, inner, 32);
    murmur_sha256_final(&c, t);
    volatile uint8_t *v = (volatile uint8_t *)inner;
    for (size_t i = 0; i < sizeof(inner); i++) {
      v[i] = 0;
    }
    tlen = 32;
    size_t take = okm_len - done;
    if (take > 32) {
      take = 32;
    }
    memcpy(okm + done, t, take);
    done += take;
    ctr++;
  }
  volatile uint8_t *v = (volatile uint8_t *)t;
  for (size_t i = 0; i < sizeof(t); i++) {
    v[i] = 0;
  }
  return 0;
}

int murmur_hkdf(const uint8_t *ikm, size_t ikm_len, const uint8_t *salt,
                size_t salt_len, const uint8_t *info, size_t info_len,
                uint8_t *okm, size_t okm_len) {
  uint8_t prk[32];
  murmur_hkdf_extract(salt, salt_len, ikm, ikm_len, prk);
  int rc = murmur_hkdf_expand(prk, info, info_len, okm, okm_len);
  volatile uint8_t *v = (volatile uint8_t *)prk;
  for (size_t i = 0; i < sizeof(prk); i++) {
    v[i] = 0;
  }
  return rc;
}
