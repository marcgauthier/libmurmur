/* Buffer contract for the native (C++) page path. The codec
 * (deps/codec/murmur_codec.h) seals/opens records entirely in C++;
 * no key material and no per-page call crosses into Go. */
#ifndef NV_CRYPTO_H
#define NV_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

enum {
  /* Plaintext page size; decrypt output is always exactly this. */
  NV_BLOCK = 4096,
  /* Seal output bound. Worst case is ~4.3 KiB (9-byte keyed header +
   * 32-byte AEGIS nonce + zstd worst-case expansion of 4 KiB + 32-byte
   * tag); 8 KiB leaves headroom for future flags. */
  NV_MAX_RECORD = 8192,

  /* Negative returns from the codec (mirrored in murmur_codec.h). */
  NV_ERR_HANDLE = -1, /* unknown engine handle (legacy; unused) */
  NV_ERR_AUTH = -2, /* authentication failure */
  NV_ERR_CORRUPT = -3, /* corrupt record / wrong key */
  NV_ERR_SHORT = -4, /* out_cap too small (never for sized buffers) */
  NV_ERR_MISUSE = -5 /* bad input size, closed engine */
};

#endif
