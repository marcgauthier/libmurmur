#ifndef MURMUR_SCRYPT_H
#define MURMUR_SCRYPT_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
/* Defaults: N=65536, r=8, p=1 (~64 MiB). Memory/work bounds apply on read too. */
int murmur_scrypt_params_valid(uint32_t n, uint32_t r, uint8_t p);
int murmur_scrypt_derive(const uint8_t *pass, size_t pass_len,
                         const uint8_t *salt, size_t salt_len,
                         uint32_t n, uint32_t r, uint8_t p,
                         uint8_t *out, size_t out_len);
#ifdef __cplusplus
}
#endif
#endif
