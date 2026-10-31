/* SHA-256 (FIPS 180-4). Straightforward portable implementation:
 * one 64-byte block transform, big-endian length padding.
 */
#include "sha256.h"

#include <string.h>

static const uint32_t K[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu,
    0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u, 0xd807aa98u, 0x12835b01u,
    0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u,
    0xc19bf174u, 0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
    0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau, 0x983e5152u,
    0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u,
    0x06ca6351u, 0x14292967u, 0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu,
    0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u, 0xd192e819u,
    0xd6990624u, 0xf40e3585u, 0x106aa070u, 0x19a4c116u, 0x1e376c08u,
    0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu,
    0x682e6ff3u, 0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u,
};

#define ROR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

static void transform(uint32_t h[8], const uint8_t blk[64]) {
  uint32_t w[64];
  for (int i = 0; i < 16; i++) {
    w[i] = ((uint32_t)blk[i * 4] << 24) | ((uint32_t)blk[i * 4 + 1] << 16) |
           ((uint32_t)blk[i * 4 + 2] << 8) | (uint32_t)blk[i * 4 + 3];
  }
  for (int i = 16; i < 64; i++) {
    uint32_t s0 = ROR(w[i - 15], 7) ^ ROR(w[i - 15], 18) ^ (w[i - 15] >> 3);
    uint32_t s1 = ROR(w[i - 2], 17) ^ ROR(w[i - 2], 19) ^ (w[i - 2] >> 10);
    w[i] = w[i - 16] + s0 + w[i - 7] + s1;
  }
  uint32_t a = h[0], b = h[1], c = h[2], d = h[3];
  uint32_t e = h[4], f = h[5], g = h[6], hh = h[7];
  for (int i = 0; i < 64; i++) {
    uint32_t s1 = ROR(e, 6) ^ ROR(e, 11) ^ ROR(e, 25);
    uint32_t ch = (e & f) ^ (~e & g);
    uint32_t t1 = hh + s1 + ch + K[i] + w[i];
    uint32_t s0 = ROR(a, 2) ^ ROR(a, 13) ^ ROR(a, 22);
    uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
    uint32_t t2 = s0 + maj;
    hh = g;
    g = f;
    f = e;
    e = d + t1;
    d = c;
    c = b;
    b = a;
    a = t1 + t2;
  }
  h[0] += a;
  h[1] += b;
  h[2] += c;
  h[3] += d;
  h[4] += e;
  h[5] += f;
  h[6] += g;
  h[7] += hh;
}

void murmur_sha256_init(murmur_sha256_t *c) {
  c->h[0] = 0x6a09e667u;
  c->h[1] = 0xbb67ae85u;
  c->h[2] = 0x3c6ef372u;
  c->h[3] = 0xa54ff53au;
  c->h[4] = 0x510e527fu;
  c->h[5] = 0x9b05688cu;
  c->h[6] = 0x1f83d9abu;
  c->h[7] = 0x5be0cd19u;
  c->total = 0;
  c->used = 0;
}

void murmur_sha256_update(murmur_sha256_t *c, const uint8_t *in, size_t len) {
  c->total += (uint64_t)len;
  while (len > 0) {
    size_t take = 64 - c->used;
    if (take > len) {
      take = len;
    }
    memcpy(c->buf + c->used, in, take);
    c->used += take;
    in += take;
    len -= take;
    if (c->used == 64) {
      transform(c->h, c->buf);
      c->used = 0;
    }
  }
}

void murmur_sha256_final(murmur_sha256_t *c, uint8_t out[MURMUR_SHA256_LEN]) {
  uint64_t bits = c->total * 8;
  uint8_t pad = 0x80;
  murmur_sha256_update(c, &pad, 1);
  /* Pad with zeros until 56 bytes mod 64, then the 8-byte length. The
   * update path handles the extra block when fewer than 9 bytes
   * remain. */
  uint8_t zero = 0;
  while (c->used != 56) {
    murmur_sha256_update(c, &zero, 1);
  }
  uint8_t lenb[8];
  for (int i = 0; i < 8; i++) {
    lenb[i] = (uint8_t)(bits >> (56 - 8 * i));
  }
  /* Feed the length (total already excludes padding: bits was
   * captured first, and the context is wiped below). */
  murmur_sha256_update(c, lenb, 8);
  for (int i = 0; i < 8; i++) {
    out[i * 4] = (uint8_t)(c->h[i] >> 24);
    out[i * 4 + 1] = (uint8_t)(c->h[i] >> 16);
    out[i * 4 + 2] = (uint8_t)(c->h[i] >> 8);
    out[i * 4 + 3] = (uint8_t)c->h[i];
  }
  volatile uint8_t *v = (volatile uint8_t *)c;
  for (size_t i = 0; i < sizeof(*c); i++) {
    v[i] = 0;
  }
}

void murmur_sha256(const uint8_t *in, size_t len,
                   uint8_t out[MURMUR_SHA256_LEN]) {
  murmur_sha256_t c;
  murmur_sha256_init(&c);
  if (len > 0) {
    murmur_sha256_update(&c, in, len);
  }
  murmur_sha256_final(&c, out);
}
