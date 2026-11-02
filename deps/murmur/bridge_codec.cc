#include "bridge_codec.h"
#include "../aws-lc/include/openssl/curve25519.h"
#include "../aws-lc/include/openssl/mem.h"
#include "../aws-lc/include/openssl/sha.h"
#include "../codec/aesgcm.h"
#include "../keyring/hkdf.h"
#include "../zstd/zstd.h"
#include "sqlite3.h"
#include <cstdlib>
#include <cstring>
#include <limits>
#include <new>
#include <vector>

namespace {
/* Fixed-width canonical header: magic, source IDs, sequence, padded stream,
 * schema, recipient, ephemeral key, nonce, plaintext digest, plaintext size,
 * ciphertext size. Signature follows the complete ciphertext. */
constexpr size_t header_size =
    4 + 16 + 16 + 16 + 8 + 1 + 64 + 32 + 32 + 32 + 12 + 32 + 8 + 8;
constexpr size_t signature_size = 64, tag_size = 16;
const uint8_t domain[] = "murmur/native-highlow/v1";
struct Secret {
  uint8_t b[32]{};
  ~Secret() { OPENSSL_cleanse(b, sizeof(b)); }
};
bool zero(const uint8_t *p, size_t n) {
  uint8_t v = 0;
  for (size_t i = 0; i < n; ++i)
    v |= p[i];
  return !v;
}
bool stream_ok(const char *s, size_t *n) {
  if (!s)
    return false;
  for (*n = 0; *n < 65 && s[*n]; ++*n) {
    unsigned char c = s[*n];
    if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
          (c >= '0' && c <= '9') || c == '_' || c == '-'))
      return false;
  }
  return *n > 0 && *n <= 64;
}
void u64(std::vector<uint8_t> &b, uint64_t n) {
  for (unsigned i = 0; i < 8; ++i)
    b.push_back((uint8_t)(n >> (8 * i)));
}
uint64_t read64(const uint8_t *p) {
  uint64_t n = 0;
  for (unsigned i = 0; i < 8; ++i)
    n |= (uint64_t)p[i] << (8 * i);
  return n;
}
void append(std::vector<uint8_t> &b, const void *p, size_t n) {
  if (n) {
    auto q = (const uint8_t *)p;
    b.insert(b.end(), q, q + n);
  }
}
bool limits(size_t bundle, size_t payload) {
  return bundle >= header_size + tag_size + signature_size &&
         bundle <= MURMUR_BRIDGE_MAX_BUNDLE && payload > 0 &&
         payload <= MURMUR_BRIDGE_MAX_PAYLOAD;
}
int derive(const uint8_t secret[32], const uint8_t peer[32],
           const uint8_t *header, size_t n, Secret &key) {
  Secret shared;
  if (!X25519(shared.b, secret, peer))
    return SQLITE_AUTH;
  return murmur_hkdf(shared.b, 32, domain, sizeof(domain) - 1, header, n, key.b,
                     32) == 0
             ? SQLITE_OK
             : SQLITE_ERROR;
}
int copy_result(const std::vector<uint8_t> &b, murmur_bridge_bytes_t *out) {
  uint8_t *p = (uint8_t *)malloc(b.empty() ? 1 : b.size());
  if (!p)
    return SQLITE_NOMEM;
  if (!b.empty())
    memcpy(p, b.data(), b.size());
  out->data = p;
  out->len = b.size();
  return SQLITE_OK;
}
int seal(const murmur_bridge_header_t *h, const uint8_t seed[32],
         const uint8_t recipient[32], const void *payload, size_t n,
         size_t max_bundle, size_t max_payload, murmur_bridge_bytes_t *out) {
  size_t stream_len;
  if (!h || !seed || !recipient || (!payload && n) ||
      !stream_ok(h->stream, &stream_len) || !h->sequence ||
      zero(h->database, 16) || zero(h->node, 16) || zero(h->transaction, 16) ||
      zero(recipient, 32) || !limits(max_bundle, max_payload))
    return SQLITE_MISUSE;
  if (n > max_payload)
    return SQLITE_TOOBIG;
  std::vector<uint8_t> compressed(ZSTD_compressBound(n));
  size_t z = ZSTD_compress(compressed.data(), compressed.size(),
                           payload ? payload : "", n, 3);
  if (ZSTD_isError(z))
    return SQLITE_ERROR;
  if (z > max_bundle - header_size - tag_size - signature_size)
    return SQLITE_TOOBIG;
  compressed.resize(z);
  Secret ephemeral, key;
  uint8_t pub[32], nonce[12], digest[32];
  if (murmur_rand_bytes(ephemeral.b, 32) || murmur_rand_bytes(nonce, 12))
    return SQLITE_ERROR;
  X25519_public_from_private(pub, ephemeral.b);
  SHA256((const uint8_t *)(payload ? payload : ""), n, digest);
  std::vector<uint8_t> b;
  append(b, "MHB1", 4);
  append(b, h->database, 16);
  append(b, h->node, 16);
  append(b, h->transaction, 16);
  u64(b, h->sequence);
  b.push_back((uint8_t)stream_len);
  append(b, h->stream, stream_len);
  b.resize(b.size() + 64 - stream_len, 0);
  append(b, h->schema, 32);
  append(b, recipient, 32);
  append(b, pub, 32);
  append(b, nonce, 12);
  append(b, digest, 32);
  u64(b, n);
  u64(b, z + tag_size);
  int rc = derive(ephemeral.b, recipient, b.data(), b.size(), key);
  if (rc != SQLITE_OK)
    return rc;
  b.resize(header_size + z + tag_size);
  if (murmur_aes256gcm_seal(key.b, nonce, compressed.data(), z, b.data(),
                            header_size, b.data() + header_size))
    return SQLITE_ERROR;
  std::vector<uint8_t> signed_bytes;
  append(signed_bytes, domain, sizeof(domain) - 1);
  append(signed_bytes, b.data(), b.size());
  uint8_t signing_key[64], signer_pub[32], sig[64];
  ED25519_keypair_from_seed(signer_pub, signing_key, seed);
  int ok =
      ED25519_sign(sig, signed_bytes.data(), signed_bytes.size(), signing_key);
  OPENSSL_cleanse(signing_key, sizeof(signing_key));
  if (!ok)
    return SQLITE_ERROR;
  append(b, sig, 64);
  return copy_result(b, out);
}
int unseal(const void *input, size_t n, const uint8_t database[16],
           const char *stream, const uint8_t signer[32],
           const uint8_t secret[32], size_t max_bundle, size_t max_payload,
           murmur_bridge_header_t *header, murmur_bridge_bytes_t *out) {
  size_t slen;
  if (!input || !database || !signer || !secret || !header ||
      !stream_ok(stream, &slen) || !limits(max_bundle, max_payload))
    return SQLITE_MISUSE;
  if (n > max_bundle)
    return SQLITE_TOOBIG;
  if (n < header_size + tag_size + signature_size)
    return SQLITE_CORRUPT;
  auto b = (const uint8_t *)input;
  if (memcmp(b, "MHB1", 4))
    return SQLITE_CORRUPT;
  murmur_bridge_header_t h{};
  size_t at = 4;
  memcpy(h.database, b + at, 16);
  at += 16;
  memcpy(h.node, b + at, 16);
  at += 16;
  memcpy(h.transaction, b + at, 16);
  at += 16;
  h.sequence = read64(b + at);
  at += 8;
  size_t stream_len = b[at++];
  if (stream_len == 0 || stream_len > 64)
    return SQLITE_CORRUPT;
  memcpy(h.stream, b + at, stream_len);
  size_t validated;
  if (!stream_ok(h.stream, &validated) || validated != stream_len ||
      !zero(b + at + stream_len, 64 - stream_len))
    return SQLITE_CORRUPT;
  at += 64;
  memcpy(h.schema, b + at, 32);
  at += 32;
  const uint8_t *recipient = b + at;
  at += 32;
  const uint8_t *ephemeral = b + at;
  at += 32;
  const uint8_t *nonce = b + at;
  at += 12;
  const uint8_t *digest = b + at;
  at += 32;
  uint64_t plain_size = read64(b + at);
  at += 8;
  uint64_t cipher_size = read64(b + at);
  if (!h.sequence || zero(h.node, 16) || zero(h.transaction, 16) ||
      zero(h.database, 16) || cipher_size != n - header_size - signature_size)
    return SQLITE_CORRUPT;
  if (plain_size > max_payload)
    return SQLITE_TOOBIG;
  uint8_t own_public[32];
  X25519_public_from_private(own_public, secret);
  if (CRYPTO_memcmp(h.database, database, 16) || strcmp(h.stream, stream) ||
      CRYPTO_memcmp(recipient, own_public, 32))
    return SQLITE_AUTH;
  std::vector<uint8_t> signed_bytes;
  append(signed_bytes, domain, sizeof(domain) - 1);
  append(signed_bytes, b, n - signature_size);
  if (!ED25519_verify(signed_bytes.data(), signed_bytes.size(),
                      b + n - signature_size, signer))
    return SQLITE_AUTH;
  Secret key;
  int rc = derive(secret, ephemeral, b, header_size, key);
  if (rc != SQLITE_OK)
    return rc;
  std::vector<uint8_t> compressed((size_t)cipher_size - tag_size);
  if (murmur_aes256gcm_open(key.b, nonce, b + header_size, (size_t)cipher_size,
                            b, header_size, compressed.data()))
    return SQLITE_AUTH;
  if (ZSTD_findFrameCompressedSize(compressed.data(), compressed.size()) !=
      compressed.size())
    return SQLITE_CORRUPT;
  unsigned long long frame_size =
      ZSTD_getFrameContentSize(compressed.data(), compressed.size());
  if (frame_size != plain_size)
    return SQLITE_CORRUPT;
  std::vector<uint8_t> plain((size_t)plain_size);
  size_t size = ZSTD_decompress(plain.data(), plain.size(), compressed.data(),
                                compressed.size());
  if (ZSTD_isError(size) || size != plain_size)
    return SQLITE_CORRUPT;
  uint8_t actual[32];
  SHA256(plain.empty() ? (const uint8_t *)"" : plain.data(), plain.size(),
         actual);
  if (CRYPTO_memcmp(digest, actual, 32))
    return SQLITE_AUTH;
  rc = copy_result(plain, out);
  if (rc == SQLITE_OK)
    *header = h;
  return rc;
}
} // namespace
extern "C" void murmur_bridge_bytes_free(murmur_bridge_bytes_t *b) {
  if (!b)
    return;
  if (b->data) {
    OPENSSL_cleanse(b->data, b->len);
    free(b->data);
  }
  *b = {};
}
extern "C" int murmur_bridge_recipient_public(const uint8_t secret[32],
                                              uint8_t out[32]) {
  if (!secret || !out)
    return SQLITE_MISUSE;
  X25519_public_from_private(out, secret);
  return SQLITE_OK;
}
extern "C" int murmur_bridge_seal(const murmur_bridge_header_t *h,
                                  const uint8_t signer[32],
                                  const uint8_t recipient[32],
                                  const void *payload, size_t len, size_t mb,
                                  size_t mp, murmur_bridge_bytes_t *out) {
  if (!out)
    return SQLITE_MISUSE;
  *out = {};
  try {
    return seal(h, signer, recipient, payload, len, mb, mp, out);
  } catch (const std::bad_alloc &) {
    return SQLITE_NOMEM;
  } catch (...) {
    return SQLITE_ERROR;
  }
}
extern "C" int murmur_bridge_unseal(const void *b, size_t len,
                                    const uint8_t db[16], const char *stream,
                                    const uint8_t signer[32],
                                    const uint8_t receiver[32], size_t mb,
                                    size_t mp, murmur_bridge_header_t *h,
                                    murmur_bridge_bytes_t *out) {
  if (!out || !h)
    return SQLITE_MISUSE;
  *out = {};
  *h = {};
  try {
    return unseal(b, len, db, stream, signer, receiver, mb, mp, h, out);
  } catch (const std::bad_alloc &) {
    return SQLITE_NOMEM;
  } catch (...) {
    return SQLITE_ERROR;
  }
}
