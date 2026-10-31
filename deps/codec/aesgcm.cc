// AES-256-GCM backend on AWS-LC (deps/aws-lc, vendored v5.12.0,
// prebuilt libcrypto.a merged into libmurmur.a). One context per
// call: no shared state, safe under the codec mutex and elsewhere.
// Return contract matches the codec seam: 0 ok, -2 auth failure
// (decrypt only, plaintext wiped), -1 misuse.
#include "aesgcm.h"

#include <new>
#include <string.h>

#include "openssl/aead.h"
#include "openssl/aes.h"
#include "openssl/mem.h"
#include "openssl/rand.h"

namespace {

void wipe_mem(void *p, size_t n) { OPENSSL_cleanse(p, n); }

// Callers pass NULL for empty spans; normalize to a dummy byte so
// AWS-LC never sees a NULL cursor. (NULL with nonzero length is
// rejected as misuse before these run.)
const uint8_t *nonnull(const uint8_t *p) {
  static const uint8_t dummy = 0;
  return p ? p : &dummy;
}

uint8_t *nonnull_out(uint8_t *p) {
  static uint8_t dummy = 0;
  return p ? p : &dummy;
}

}  // namespace

extern "C" {

int murmur_aes_available(void) { return 1; }

int murmur_aes256_block(const uint8_t key[32], const uint8_t in16[16],
                        uint8_t out16[16]) {
  if (!key || !in16 || !out16) {
    return -1;
  }
  AES_KEY aeskey;
  if (AES_set_encrypt_key(key, 256, &aeskey) != 0) {
    return -1;
  }
  AES_encrypt(in16, out16, &aeskey);
  wipe_mem(&aeskey, sizeof(aeskey));
  return 0;
}

int murmur_aes256gcm_encrypt(const uint8_t key[32], const uint8_t nonce[12],
                             const uint8_t *pt, size_t pt_len,
                             const uint8_t *aad, size_t aad_len, uint8_t *ct,
                             uint8_t tag[16]) {
  if (!key || !nonce || !tag || (!pt && pt_len) || (!aad && aad_len) ||
      (!ct && pt_len)) {
    return -1;
  }
  EVP_AEAD_CTX ctx;
  if (!EVP_AEAD_CTX_init(&ctx, EVP_aead_aes_256_gcm(), key, 32,
                         EVP_AEAD_DEFAULT_TAG_LENGTH, nullptr)) {
    return -1;
  }
  // seal emits ct||tag contiguously; stage it aside, then split into
  // the caller's ct and tag (ct only has room for pt_len).
  size_t total = pt_len + 16;
  uint8_t stack[8192 + 16];
  uint8_t *buf = stack;
  uint8_t *heap = nullptr;
  if (total > sizeof(stack)) {
    heap = new (std::nothrow) uint8_t[total];
    if (!heap) {
      EVP_AEAD_CTX_cleanup(&ctx);
      return -1;
    }
    buf = heap;
  }
  size_t out_len = 0;
  int rc = -1;
  if (EVP_AEAD_CTX_seal(&ctx, buf, &out_len, total, nonce, 12, nonnull(pt),
                        pt_len, nonnull(aad), aad_len) &&
      out_len == total) {
    if (pt_len > 0) {
      memcpy(ct, buf, pt_len);
    }
    memcpy(tag, buf + pt_len, 16);
    rc = 0;
  }
  wipe_mem(buf, total);
  delete[] heap;
  EVP_AEAD_CTX_cleanup(&ctx);
  return rc;
}

int murmur_aes256gcm_decrypt(const uint8_t key[32], const uint8_t nonce[12],
                             const uint8_t *ct, size_t ct_len,
                             const uint8_t tag[16], const uint8_t *aad,
                             size_t aad_len, uint8_t *pt) {
  if (!key || !nonce || !tag || (!ct && ct_len) || (!aad && aad_len) ||
      (!pt && ct_len)) {
    return -1;
  }
  EVP_AEAD_CTX ctx;
  if (!EVP_AEAD_CTX_init(&ctx, EVP_aead_aes_256_gcm(), key, 32,
                         EVP_AEAD_DEFAULT_TAG_LENGTH, nullptr)) {
    return -1;
  }
  // open takes ct||tag contiguously; join caller buffers on the stack
  // for page-sized inputs, heap for larger.
  int rc = -2;
  size_t joined_len = ct_len + 16;
  uint8_t stack[8192];
  uint8_t *joined = stack;
  uint8_t *heap = nullptr;
  if (joined_len > sizeof(stack)) {
    heap = new (std::nothrow) uint8_t[joined_len];
    if (!heap) {
      EVP_AEAD_CTX_cleanup(&ctx);
      return -1;
    }
    joined = heap;
  }
  if (ct_len > 0) {
    memcpy(joined, nonnull(ct), ct_len);
  }
  memcpy(joined + ct_len, tag, 16);
  size_t out_len = 0;
  uint8_t *out = nonnull_out(pt);
  if (EVP_AEAD_CTX_open(&ctx, out, &out_len, ct_len, nonce, 12, joined,
                        joined_len, nonnull(aad), aad_len) &&
      out_len == ct_len) {
    rc = 0;
  } else if (pt && ct_len > 0) {
    wipe_mem(pt, ct_len);
  }
  wipe_mem(joined, joined_len);
  delete[] heap;
  EVP_AEAD_CTX_cleanup(&ctx);
  return rc;
}

int murmur_aes256gcm_seal(const uint8_t key[32], const uint8_t nonce[12],
                          const uint8_t *pt, size_t pt_len,
                          const uint8_t *aad, size_t aad_len, uint8_t *out) {
  if (!key || !nonce || (!pt && pt_len) || (!aad && aad_len) ||
      (!out && pt_len + 16 > 0)) {
    return -1;
  }
  EVP_AEAD_CTX ctx;
  if (!EVP_AEAD_CTX_init(&ctx, EVP_aead_aes_256_gcm(), key, 32,
                         EVP_AEAD_DEFAULT_TAG_LENGTH, nullptr)) {
    return -1;
  }
  size_t out_len = 0;
  int rc = -1;
  if (EVP_AEAD_CTX_seal(&ctx, nonnull_out(out), &out_len, pt_len + 16, nonce,
                        12, nonnull(pt), pt_len, nonnull(aad), aad_len) &&
      out_len == pt_len + 16) {
    rc = 0;
  }
  EVP_AEAD_CTX_cleanup(&ctx);
  return rc;
}

int murmur_aes256gcm_open(const uint8_t key[32], const uint8_t nonce[12],
                          const uint8_t *in, size_t in_len,
                          const uint8_t *aad, size_t aad_len, uint8_t *out) {
  if (!key || !nonce || !in || in_len < 16 || (!aad && aad_len) ||
      (!out && in_len > 16)) {
    return -1;
  }
  EVP_AEAD_CTX ctx;
  if (!EVP_AEAD_CTX_init(&ctx, EVP_aead_aes_256_gcm(), key, 32,
                         EVP_AEAD_DEFAULT_TAG_LENGTH, nullptr)) {
    return -1;
  }
  size_t pt_len = in_len - 16;
  size_t out_len = 0;
  int rc = -2;
  uint8_t *dst = nonnull_out(out);
  if (EVP_AEAD_CTX_open(&ctx, dst, &out_len, pt_len, nonce, 12, in, in_len,
                        nonnull(aad), aad_len) &&
      out_len == pt_len) {
    rc = 0;
  } else if (out && pt_len > 0) {
    wipe_mem(out, pt_len);
  }
  EVP_AEAD_CTX_cleanup(&ctx);
  return rc;
}

int murmur_rand_bytes(uint8_t *out, size_t len) {
  if (!out && len) {
    return -1;
  }
  if (len == 0) {
    return 0;
  }
  return RAND_bytes(out, len) ? 0 : -1;
}

}  // extern "C"
