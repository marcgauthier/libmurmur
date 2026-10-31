/* aesgcm_selftest - NIST vectors plus codec roundtrips for the
 * AES-256-GCM backend (AWS-LC) through the codec C API. Links
 * libmurmur.a with no Go involved.
 *
 * Or: make selftest
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "aesgcm.h"
#include "murmur_codec.h"

static int failures = 0;

#define CHECK(cond, ...)                                                 \
  do {                                                                   \
    if (!(cond)) {                                                       \
      printf("FAIL %s:%d: ", __func__, __LINE__);                        \
      printf(__VA_ARGS__);                                               \
      printf("\n");                                                      \
      failures++;                                                        \
    }                                                                    \
  } while (0)

static void hex(const uint8_t *p, size_t n, char *out) {
  static const char *d = "0123456789abcdef";
  for (size_t i = 0; i < n; i++) {
    out[2 * i] = d[p[i] >> 4];
    out[2 * i + 1] = d[p[i] & 15];
  }
  out[2 * n] = '\0';
}

/* NIST SP 800-38D test cases 1-2 (AES-256-GCM, zero key/IV). */
static void test_nist(void) {
  CHECK(murmur_aes_available() == 1, "backend unavailable");
  uint8_t key[32], nonce[12];
  memset(key, 0, sizeof(key));
  memset(nonce, 0, sizeof(nonce));
  uint8_t ct[16], tag[16];
  char buf[65];
  /* case 1: empty PT/AAD */
  memset(ct, 0xA5, sizeof(ct));
  memset(tag, 0, sizeof(tag));
  CHECK(murmur_aes256gcm_encrypt(key, nonce, NULL, 0, NULL, 0, NULL, tag) == 0,
        "case1 rc");
  hex(tag, 16, buf);
  CHECK(strcmp(buf, "530f8afbc74536b9a963b4f1c4cb738b") == 0, "case1 tag %s",
        buf);
  /* case 2: 16 zero bytes, empty AAD */
  uint8_t pt[16];
  memset(pt, 0, sizeof(pt));
  CHECK(murmur_aes256gcm_encrypt(key, nonce, pt, sizeof(pt), NULL, 0, ct,
                                 tag) == 0,
        "case2 rc");
  hex(ct, 16, buf);
  CHECK(strcmp(buf, "cea7403d4d606b6e074ec5d3baf39d18") == 0, "case2 ct %s",
        buf);
  hex(tag, 16, buf);
  CHECK(strcmp(buf, "d0d1c8a799996bf0265b98b5d48ab919") == 0, "case2 tag %s",
        buf);
  /* case 2 decrypts */
  uint8_t back[16];
  memset(back, 0xA5, sizeof(back));
  CHECK(murmur_aes256gcm_decrypt(key, nonce, ct, sizeof(ct), tag, NULL, 0,
                                 back) == 0,
        "case2 dec rc");
  CHECK(memcmp(back, pt, sizeof(pt)) == 0, "case2 dec bytes");
}

/* FIPS-197 C.3 AES-256 block vector. */
static void test_block(void) {
  static const uint8_t key[32] = {
      0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae,
      0xf0, 0x85, 0x7d, 0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61,
      0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4};
  static const uint8_t in[16] = {0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40,
                                 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11,
                                 0x73, 0x93, 0x17, 0x2a};
  static const uint8_t want[16] = {0xf3, 0xee, 0xd1, 0xbd, 0xb5, 0xd2,
                                   0xa0, 0x3c, 0x06, 0x4b, 0x5a, 0x7e,
                                   0x3d, 0xb1, 0x81, 0xf8};
  uint8_t out[16];
  CHECK(murmur_aes256_block(key, in, out) == 0, "block rc");
  CHECK(memcmp(out, want, sizeof(want)) == 0, "block bytes");
  CHECK(murmur_aes256_block(NULL, in, out) == -1, "block null accepted");
}

static void test_roundtrip(void) {
  uint8_t key[32], nonce[12], aad[13], pt[100], ct[100], tag[16], back[100];
  for (size_t i = 0; i < sizeof(key); i++) {
    key[i] = (uint8_t)(i * 7 + 1);
  }
  for (size_t i = 0; i < sizeof(nonce); i++) {
    nonce[i] = (uint8_t)(i * 13 + 5);
  }
  for (size_t i = 0; i < sizeof(aad); i++) {
    aad[i] = (uint8_t)i;
  }
  for (size_t i = 0; i < sizeof(pt); i++) {
    pt[i] = (uint8_t)(i * 31);
  }
  CHECK(murmur_aes256gcm_encrypt(key, nonce, pt, sizeof(pt), aad, sizeof(aad),
                                 ct, tag) == 0,
        "rt enc rc");
  CHECK(memcmp(ct, pt, sizeof(pt)) != 0, "rt identity");
  CHECK(murmur_aes256gcm_decrypt(key, nonce, ct, sizeof(ct), tag, aad,
                                 sizeof(aad), back) == 0,
        "rt dec rc");
  CHECK(memcmp(back, pt, sizeof(pt)) == 0, "rt bytes");
}

static void test_tamper(void) {
  uint8_t key[32], nonce[12], pt[64], ct[64], tag[16], back[64];
  memset(key, 0x11, sizeof(key));
  memset(nonce, 0x22, sizeof(nonce));
  memset(pt, 0x33, sizeof(pt));
  CHECK(murmur_aes256gcm_encrypt(key, nonce, pt, sizeof(pt), NULL, 0, ct,
                                 tag) == 0,
        "tamper enc rc");
  tag[15] ^= 0x01;
  memset(back, 0xA5, sizeof(back));
  CHECK(murmur_aes256gcm_decrypt(key, nonce, ct, sizeof(ct), tag, NULL, 0,
                                 back) == -2,
        "tamper tag accepted");
  for (size_t i = 0; i < sizeof(back); i++) {
    if (back[i] != 0) {
      CHECK(0, "tamper released plaintext at %zu", i);
      break;
    }
  }
  ct[0] ^= 0x80;
  tag[15] ^= 0x01;
  CHECK(murmur_aes256gcm_decrypt(key, nonce, ct, sizeof(ct), tag, NULL, 0,
                                 back) == -2,
        "tamper ct accepted");
}

static void test_misuse(void) {
  uint8_t key[32], nonce[12], pt[8], ct[8], tag[16];
  memset(key, 0, sizeof(key));
  memset(nonce, 0, sizeof(nonce));
  memset(pt, 0, sizeof(pt));
  CHECK(murmur_aes256gcm_encrypt(NULL, nonce, pt, sizeof(pt), NULL, 0, ct,
                                 tag) == -1,
        "null key accepted");
  CHECK(murmur_aes256gcm_encrypt(key, nonce, NULL, 8, NULL, 0, ct, tag) == -1,
        "null pt accepted");
  CHECK(murmur_aes256gcm_decrypt(key, nonce, ct, sizeof(ct), NULL, NULL, 0,
                                 pt) == -1,
        "null tag accepted");
}

/* Both page ciphers seal/open one page through the codec. */
static void test_codec(void) {
  uint8_t page_key[32], master[32], page[4096], rec[8192], back[4096];
  for (size_t i = 0; i < 32; i++) {
    page_key[i] = (uint8_t)(i + 1);
    master[i] = (uint8_t)(0x80 + i);
  }
  for (size_t i = 0; i < sizeof(page); i++) {
    page[i] = (uint8_t)(i * 17 + 3);
  }
  static const int ciphers[] = {1, 2};
  static const char *magics[] = {"EXP1", "EXP2"};
  for (size_t i = 0; i < 2; i++) {
    MurmurCodec *c = murmur_codec_create(ciphers[i], 0, page_key, 0, NULL, 0,
                                         NULL, NULL, 0, master);
    CHECK(c != NULL, "codec %d create", ciphers[i]);
    if (!c) {
      continue;
    }
    int n = murmur_codec_seal(c, 7, page, rec, sizeof(rec), NULL);
    CHECK(n > 4096 && memcmp(rec, magics[i], 4) == 0, "codec %d seal n=%d",
          ciphers[i], n);
    int m = murmur_codec_open(c, 7, rec, (size_t)n, back, sizeof(back));
    CHECK(m == 4096 && memcmp(back, page, sizeof(page)) == 0,
          "codec %d open m=%d", ciphers[i], m);
    rec[n - 1] ^= 0x01;
    CHECK(murmur_codec_open(c, 7, rec, (size_t)n, back, sizeof(back)) < 0,
          "codec %d tamper accepted", ciphers[i]);
    murmur_codec_destroy(c);
  }
}

int main(void) {
  test_nist();
  test_block();
  test_roundtrip();
  test_tamper();
  test_misuse();
  test_codec();
  if (failures == 0) {
    printf("AES-OK (6 suites)\n");
    return 0;
  }
  printf("AES-FAIL (%d)\n", failures);
  return 1;
}
