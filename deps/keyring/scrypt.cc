#include "scrypt.h"
#include "openssl/evp.h"
extern "C" int murmur_scrypt_params_valid(uint32_t n, uint32_t r, uint8_t p) {
  return n >= 2 && (n & (n - 1)) == 0 && r >= 1 && r <= 32 &&
         p >= 1 && p <= 16 && (uint64_t)n * r <= (1u << 20) &&
         (uint64_t)n * r * p <= (1u << 22);
}
extern "C" int murmur_scrypt_derive(const uint8_t *pass, size_t pass_len,
                                    const uint8_t *salt, size_t salt_len,
                                    uint32_t n, uint32_t r, uint8_t p,
                                    uint8_t *out, size_t out_len) {
  if ((!pass && pass_len) || (!salt && salt_len) || !out || !out_len ||
      !murmur_scrypt_params_valid(n, r, p)) return -1;
  return EVP_PBE_scrypt(pass ? (const char *)pass : "", pass_len,
      salt ? salt : (const uint8_t *)"", salt_len, n, r, p,
      256ull << 20, out, out_len) == 1 ? 0 : -1;
}
