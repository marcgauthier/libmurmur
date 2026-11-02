/* keys.enc v3 keyring: C++ port of pkgs/storage/keyring.go.
 * Layout, KDF, and error taxonomy mirror Go exactly; see keyring.h.
 */
#include "keyring.h"

#include <stdlib.h>
#include <string.h>
#include "../codec/os_random.h"

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <vector>

#include "scrypt.h"
#include "../../deps/codec/aesgcm.h"
#include "crc32c.h"
#include "hkdf.h"

namespace {

constexpr uint8_t kMagic[4] = {'S', 'P', 'L', 'K'};
constexpr uint16_t kVersion = 3;
constexpr size_t kNonceLen = 12;
constexpr size_t kKeyLen = 32;
constexpr size_t kSaltLen = 32;
constexpr size_t kIDLen = 16;
constexpr size_t kMaxWrapID = 128;
constexpr size_t kMaxDataKeys = 1 << 16;
constexpr size_t kMaxSealed = 1 << 24;
constexpr size_t kEntryLen = 4 + 8 + 1 + 32;
constexpr char kInfoPrefix[] = "spool/keys-enc/v3/";

void wipe_mem(void *p, size_t n) {
  volatile uint8_t *v = (volatile uint8_t *)p;
  for (size_t i = 0; i < n; i++) {
    v[i] = 0;
  }
}

bool rand_fill(uint8_t *p, size_t n) {
  return murmur_os_random(p, n) != 0;
}

uint16_t load16le(const uint8_t *p) {
  return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

uint32_t load32le(const uint8_t *p) {
  return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
         ((uint32_t)p[3] << 24);
}

uint64_t load64le(const uint8_t *p) {
  uint64_t v = 0;
  for (int i = 7; i >= 0; i--) {
    v = (v << 8) | p[i];
  }
  return v;
}

void store16le(uint8_t *p, uint16_t v) {
  p[0] = (uint8_t)v;
  p[1] = (uint8_t)(v >> 8);
}

void store32le(uint8_t *p, uint32_t v) {
  p[0] = (uint8_t)v;
  p[1] = (uint8_t)(v >> 8);
  p[2] = (uint8_t)(v >> 16);
  p[3] = (uint8_t)(v >> 24);
}

void store64le(uint8_t *p, uint64_t v) {
  for (int i = 0; i < 8; i++) {
    p[i] = (uint8_t)(v >> (8 * i));
  }
}

/* Derives the 32-byte envelope protector. Mirrors deriveProtector. */
int derive_protector(uint8_t kdf, const uint8_t *master, size_t master_len,
                     const uint8_t *pass, size_t pass_len, const uint8_t *salt,
                     uint32_t a_time, uint32_t a_mem, uint8_t a_threads,
                     const uint8_t store_id[16], const uint8_t context_id[16],
                     uint8_t out[32]) {
  uint8_t info[sizeof(kInfoPrefix) - 1 + 32];
  memcpy(info, kInfoPrefix, sizeof(kInfoPrefix) - 1);
  memcpy(info + sizeof(kInfoPrefix) - 1, store_id, 16);
  memcpy(info + sizeof(kInfoPrefix) - 1 + 16, context_id, 16);
  size_t info_len = sizeof(info);
  if (kdf == MURMUR_KDF_DIRECT) {
    if (master_len != kKeyLen) {
      return MURMUR_KR_AUTH;
    }
    if (murmur_hkdf(master, master_len, salt, kSaltLen, info, info_len, out,
                    kKeyLen) != 0) {
      return MURMUR_KR_CORRUPT;
    }
    return MURMUR_KR_OK;
  }
  if (kdf == MURMUR_KDF_SCRYPT) {
    if (pass_len == 0) {
      return MURMUR_KR_AUTH;
    }
    if (!murmur_scrypt_params_valid(a_time, a_mem, a_threads)) {
      return MURMUR_KR_CORRUPT;
    }
    uint8_t stretched[32];
    int rc = murmur_scrypt_derive(pass, pass_len, salt, kSaltLen,
                                  a_time, a_mem, a_threads, stretched, sizeof(stretched));
    if (rc != 0) {
      wipe_mem(stretched, sizeof(stretched));
      return MURMUR_KR_CORRUPT;
    }
    rc = murmur_hkdf(stretched, sizeof(stretched), salt, kSaltLen, info,
                     info_len, out, kKeyLen);
    wipe_mem(stretched, sizeof(stretched));
    if (rc != 0) {
      return MURMUR_KR_CORRUPT;
    }
    return MURMUR_KR_OK;
  }
  return MURMUR_KR_CORRUPT;
}

struct SealArgs {
  uint8_t kdf;
  uint64_t seq;
  const uint8_t *store_id;
  const uint8_t *context_id;
  const uint8_t *wrap_id;
  size_t wrap_len;
  uint32_t scrypt_n;
  uint32_t scrypt_r;
  uint8_t scrypt_p;
  const uint8_t *master;
  size_t master_len;
  const uint8_t *pass;
  size_t pass_len;
  std::vector<murmur_key_entry_t> keys; /* sorted on the wire */
};

/* seal_locked mirrors Seal: fresh salt/nonce, AES-GCM body. */
int seal_locked(const SealArgs &a, std::vector<uint8_t> *env) {
  if (a.kdf != MURMUR_KDF_DIRECT && a.kdf != MURMUR_KDF_SCRYPT) {
    return MURMUR_KR_MISUSE;
  }
  if (a.wrap_len > kMaxWrapID || a.keys.empty() ||
      a.keys.size() > kMaxDataKeys) {
    return MURMUR_KR_MISUSE;
  }
  std::vector<murmur_key_entry_t> keys = a.keys;
  std::sort(keys.begin(), keys.end(),
            [](const murmur_key_entry_t &x, const murmur_key_entry_t &y) {
              return x.id < y.id;
            });
  for (size_t i = 1; i < keys.size(); i++) {
    if (keys[i].id == keys[i - 1].id) {
      return MURMUR_KR_MISUSE;
    }
  }
  uint8_t salt[kSaltLen];
  if (!rand_fill(salt, sizeof(salt))) {
    return MURMUR_KR_NOMEM;
  }
  uint8_t protector[kKeyLen];
  int rc = derive_protector(a.kdf, a.master, a.master_len, a.pass, a.pass_len,
                            salt, a.scrypt_n, a.scrypt_r, a.scrypt_p,
                            a.store_id, a.context_id, protector);
  if (rc != MURMUR_KR_OK) {
    return rc;
  }

  std::vector<uint8_t> body;
  body.reserve(4 + 16 + 1 + a.wrap_len + keys.size() * kEntryLen);
  uint8_t tmp[8];
  store32le(tmp, (uint32_t)keys.size());
  body.insert(body.end(), tmp, tmp + 4);
  body.insert(body.end(), a.context_id, a.context_id + 16);
  body.push_back((uint8_t)a.wrap_len);
  body.insert(body.end(), a.wrap_id, a.wrap_id + a.wrap_len);
  for (const auto &k : keys) {
    store32le(tmp, k.id);
    body.insert(body.end(), tmp, tmp + 4);
    store64le(tmp, (uint64_t)k.created_at);
    body.insert(body.end(), tmp, tmp + 8);
    body.push_back(k.active ? 0 : 1);
    body.insert(body.end(), k.key, k.key + 32);
  }

  std::vector<uint8_t> hdr;
  hdr.reserve(61 + a.wrap_len);
  hdr.insert(hdr.end(), kMagic, kMagic + 4);
  hdr.push_back(0);
  hdr.push_back(0);
  store16le(hdr.data() + 4, kVersion);
  hdr.push_back(a.kdf);
  for (int i = 0; i < 8; i++) {
    hdr.push_back(0);
  }
  store64le(hdr.data() + 7, a.seq);
  hdr.insert(hdr.end(), salt, salt + kSaltLen);
  for (int i = 0; i < 4; i++) {
    hdr.push_back(0);
  }
  store32le(hdr.data() + 47, a.scrypt_n);
  for (int i = 0; i < 4; i++) {
    hdr.push_back(0);
  }
  store32le(hdr.data() + 51, a.scrypt_r);
  hdr.push_back(a.scrypt_p);
  hdr.push_back((uint8_t)a.wrap_len);
  hdr.insert(hdr.end(), a.wrap_id, a.wrap_id + a.wrap_len);
  uint8_t crc[4];
  store32le(crc, murmur_crc32c(hdr.data(), hdr.size()));
  hdr.insert(hdr.end(), crc, crc + 4);

  uint8_t nonce[kNonceLen];
  if (!rand_fill(nonce, sizeof(nonce))) {
    wipe_mem(protector, sizeof(protector));
    wipe_mem(body.data(), body.size());
    return MURMUR_KR_NOMEM;
  }
  std::vector<uint8_t> aad;
  aad.reserve(hdr.size() + 16);
  aad.insert(aad.end(), hdr.begin(), hdr.end());
  aad.insert(aad.end(), a.store_id, a.store_id + 16);
  std::vector<uint8_t> ct(body.size());
  uint8_t tag[16];
  int grc = murmur_aes_available()
                ? murmur_aes256gcm_encrypt(protector, nonce, body.data(),
                                           body.size(), aad.data(), aad.size(),
                                           ct.data(), tag)
                : -1;
  wipe_mem(protector, sizeof(protector));
  wipe_mem(body.data(), body.size());
  if (grc != 0) {
    return MURMUR_KR_NOMEM;
  }
  env->clear();
  env->reserve(hdr.size() + kNonceLen + 4 + ct.size() + 16);
  env->insert(env->end(), hdr.begin(), hdr.end());
  env->insert(env->end(), nonce, nonce + kNonceLen);
  /* sealed = ct || tag, like Go's aead.Seal append. */
  uint8_t slen[4];
  store32le(slen, (uint32_t)(ct.size() + 16));
  env->insert(env->end(), slen, slen + 4);
  env->insert(env->end(), ct.begin(), ct.end());
  env->insert(env->end(), tag, tag + 16);
  return MURMUR_KR_OK;
}

struct OpenedRing {
  murmur_keyring_t ring;
  int rc = MURMUR_KR_CORRUPT;
};

/* open_locked mirrors Open. */
OpenedRing open_locked(const uint8_t *env, size_t env_len,
                       const uint8_t *master, size_t master_len,
                       const uint8_t *pass, size_t pass_len,
                       const uint8_t store_id[16], const uint8_t context_id[16]) {
  OpenedRing o;
  if (env_len < 61) {
    return o;
  }
  if (memcmp(env, kMagic, 4) != 0) {
    return o;
  }
  if (load16le(env + 4) != kVersion) {
    return o;
  }
  uint8_t kdf = env[6];
  if (kdf != MURMUR_KDF_DIRECT && kdf != MURMUR_KDF_SCRYPT) {
    return o;
  }
  size_t wrap_len = env[56];
  if (wrap_len > kMaxWrapID || env_len < 61 + wrap_len) {
    return o;
  }
  size_t hdr_len = 61 + wrap_len;
  uint32_t want = load32le(env + 57 + wrap_len);
  if (murmur_crc32c(env, 57 + wrap_len) != want) {
    return o;
  }
  if (env_len < hdr_len + kNonceLen + 4) {
    return o;
  }
  uint64_t seq = load64le(env + 7);
  const uint8_t *salt = env + 15;
  uint32_t a_time = load32le(env + 47);
  uint32_t a_mem = load32le(env + 51);
  uint8_t a_threads = env[55];
  uint8_t protector[kKeyLen];
  int rc = derive_protector(kdf, master, master_len, pass, pass_len, salt,
                            a_time, a_mem, a_threads, store_id, context_id,
                            protector);
  if (rc != MURMUR_KR_OK) {
    o.rc = rc;
    return o;
  }
  size_t off = hdr_len;
  const uint8_t *nonce = env + off;
  off += kNonceLen;
  uint32_t sealed_len = load32le(env + off);
  off += 4;
  if (sealed_len > kMaxSealed || (uint64_t)(env_len - off) != sealed_len) {
    o.rc = MURMUR_KR_CORRUPT;
    wipe_mem(protector, sizeof(protector));
    return o;
  }
  if (sealed_len < 16) {
    /* Go's GCM Open fails closed on sub-tag input as an auth error. */
    o.rc = MURMUR_KR_AUTH;
    wipe_mem(protector, sizeof(protector));
    return o;
  }
  std::vector<uint8_t> aad;
  aad.reserve(hdr_len + 16);
  aad.insert(aad.end(), env, env + hdr_len);
  aad.insert(aad.end(), store_id, store_id + 16);
  /* sealed = ct || tag (Go aead.Seal layout). */
  const uint8_t *ct = env + off;
  size_t ct_len = sealed_len - 16;
  const uint8_t *tag = env + off + ct_len;
  std::vector<uint8_t> body(ct_len);
  int grc = murmur_aes_available()
                ? murmur_aes256gcm_decrypt(protector, nonce, ct, ct_len, tag,
                                           aad.data(), aad.size(), body.data())
                : -1;
  wipe_mem(protector, sizeof(protector));
  if (grc == -2) {
    o.rc = MURMUR_KR_AUTH;
    return o;
  }
  if (grc != 0) {
    o.rc = MURMUR_KR_NOMEM;
    return o;
  }
  const uint8_t *b = body.data();
  size_t blen = body.size();
  auto fail = [&]() {
    wipe_mem(body.data(), body.size());
    o.rc = MURMUR_KR_CORRUPT;
    return o;
  };
  if (blen < 4 + 16 + 1) {
    return fail();
  }
  uint32_t count = load32le(b);
  if (count == 0 || count > kMaxDataKeys) {
    return fail();
  }
  if (memcmp(b + 4, context_id, 16) != 0) {
    return fail();
  }
  size_t w = b[20];
  if (w > kMaxWrapID || blen < 21 + w) {
    return fail();
  }
  if ((uint64_t)(blen - 21 - w) != (uint64_t)count * kEntryLen) {
    return fail();
  }
  murmur_keyring_t &r = o.ring;
  r.seq = seq;
  r.kdf = kdf;
  r.scrypt_n = a_time;
  r.scrypt_r = a_mem;
  r.scrypt_p = a_threads;
  memcpy(r.context, context_id, 16);
  r.wrap_id = nullptr;
  r.wrap_len = w;
  if (w > 0) {
    r.wrap_id = (uint8_t *)malloc(w);
    if (!r.wrap_id) {
      wipe_mem(body.data(), body.size());
      o.rc = MURMUR_KR_NOMEM;
      return o;
    }
    memcpy(r.wrap_id, b + 21, w);
  }
  r.keys = (murmur_key_entry_t *)calloc(count, sizeof(murmur_key_entry_t));
  if (!r.keys) {
    free(r.wrap_id);
    r.wrap_id = nullptr;
    wipe_mem(body.data(), body.size());
    o.rc = MURMUR_KR_NOMEM;
    return o;
  }
  r.nkeys = count;
  r.current = 0;
  size_t pos = 21 + w;
  for (uint32_t i = 0; i < count; i++) {
    const uint8_t *e = b + pos;
    pos += kEntryLen;
    uint32_t id = load32le(e);
    int active;
    if (e[12] == 0) {
      active = 1;
    } else if (e[12] == 1) {
      active = 0;
    } else {
      free(r.wrap_id);
      r.wrap_id = nullptr;
      free(r.keys);
      r.keys = nullptr;
      wipe_mem(body.data(), body.size());
      return fail();
    }
    if (id == 0) {
      free(r.wrap_id);
      r.wrap_id = nullptr;
      free(r.keys);
      r.keys = nullptr;
      wipe_mem(body.data(), body.size());
      return fail();
    }
    for (uint32_t j = 0; j < i; j++) {
      if (r.keys[j].id == id) {
        free(r.wrap_id);
        r.wrap_id = nullptr;
        free(r.keys);
        r.keys = nullptr;
        wipe_mem(body.data(), body.size());
        return fail();
      }
    }
    r.keys[i].id = id;
    memcpy(r.keys[i].key, e + 13, 32);
    r.keys[i].created_at = (int64_t)load64le(e + 4);
    r.keys[i].active = active;
    if (active && id > r.current) {
      r.current = id;
    }
  }
  wipe_mem(body.data(), body.size());
  if (r.current == 0) {
    free(r.wrap_id);
    r.wrap_id = nullptr;
    free(r.keys);
    r.keys = nullptr;
    o.rc = MURMUR_KR_CORRUPT;
    return o;
  }
  std::sort(r.keys, r.keys + r.nkeys,
            [](const murmur_key_entry_t &x, const murmur_key_entry_t &y) {
              return x.id < y.id;
            });
  o.rc = MURMUR_KR_OK;
  return o;
}

uint8_t *vec_to_malloc(std::vector<uint8_t> *v, size_t *out_len) {
  uint8_t *p = (uint8_t *)malloc(v->size() ? v->size() : 1);
  if (!p) {
    return nullptr;
  }
  if (!v->empty()) {
    memcpy(p, v->data(), v->size());
  }
  *out_len = v->size();
  return p;
}

}  // namespace

extern "C" {

murmur_keyring_t *murmur_kr_open(const uint8_t *env, size_t env_len,
                                 const uint8_t *master, size_t master_len,
                                 const uint8_t *pass, size_t pass_len,
                                 const uint8_t store_id[16],
                                 const uint8_t context_id[16], int *rc) {
  int code = MURMUR_KR_CORRUPT;
  if (!env || !store_id || !context_id || (master_len && !master) ||
      (pass_len && !pass)) {
    code = MURMUR_KR_MISUSE;
    if (rc) {
      *rc = code;
    }
    return nullptr;
  }
  OpenedRing o = open_locked(env, env_len, master, master_len, pass, pass_len,
                             store_id, context_id);
  if (rc) {
    *rc = o.rc;
  }
  if (o.rc != MURMUR_KR_OK) {
    return nullptr;
  }
  murmur_keyring_t *r =
      (murmur_keyring_t *)malloc(sizeof(murmur_keyring_t));
  if (!r) {
    murmur_kr_free_ring(&o.ring);
    if (rc) {
      *rc = MURMUR_KR_NOMEM;
    }
    return nullptr;
  }
  *r = o.ring;
  return r;
}

int murmur_kr_create(uint8_t kdf, uint32_t scrypt_n, uint32_t scrypt_r,
                     uint8_t scrypt_p, const uint8_t *wrap_id,
                     size_t wrap_len, const uint8_t store_id[16],
                     const uint8_t context_id[16], const uint8_t *master,
                     size_t master_len, const uint8_t *pass, size_t pass_len,
                     uint8_t **out_env, size_t *out_len) {
  if (!store_id || !context_id || !out_env || !out_len ||
      (wrap_len && !wrap_id) || (master_len && !master) || (pass_len && !pass)) {
    return MURMUR_KR_MISUSE;
  }
  if (kdf != MURMUR_KDF_DIRECT && kdf != MURMUR_KDF_SCRYPT) {
    return MURMUR_KR_MISUSE;
  }
  if (kdf == MURMUR_KDF_DIRECT &&
      (scrypt_n != 0 || scrypt_r != 0 || scrypt_p != 0)) {
    return MURMUR_KR_MISUSE;
  }
  if (kdf == MURMUR_KDF_SCRYPT &&
      (!murmur_scrypt_params_valid(scrypt_n, scrypt_r, scrypt_p))) {
    return MURMUR_KR_MISUSE;
  }
  murmur_key_entry_t first;
  first.id = 1;
  first.created_at = 0;
  first.active = 1;
  if (!rand_fill(first.key, sizeof(first.key))) {
    return MURMUR_KR_NOMEM;
  }
  SealArgs a;
  a.kdf = kdf;
  a.seq = 1;
  a.store_id = store_id;
  a.context_id = context_id;
  a.wrap_id = wrap_id;
  a.wrap_len = wrap_len;
  a.scrypt_n = scrypt_n;
  a.scrypt_r = scrypt_r;
  a.scrypt_p = scrypt_p;
  a.master = master;
  a.master_len = master_len;
  a.pass = pass;
  a.pass_len = pass_len;
  a.keys.push_back(first);
  wipe_mem(first.key, sizeof(first.key));
  std::vector<uint8_t> env;
  int rc = seal_locked(a, &env);
  wipe_mem(a.keys.data(), a.keys.size() * sizeof(a.keys[0]));
  if (rc != MURMUR_KR_OK) {
    return rc;
  }
  *out_env = vec_to_malloc(&env, out_len);
  wipe_mem(env.data(), env.size());
  if (!*out_env) {
    return MURMUR_KR_NOMEM;
  }
  return MURMUR_KR_OK;
}

int murmur_kr_rotate(const murmur_keyring_t *ring, const uint8_t store_id[16],
                     const uint8_t *master, size_t master_len,
                     const uint8_t *pass, size_t pass_len, uint8_t **out_env,
                     size_t *out_len, uint32_t *out_next) {
  if (!ring || !store_id || !out_env || !out_len || !out_next ||
      (master_len && !master) || (pass_len && !pass)) {
    return MURMUR_KR_MISUSE;
  }
  if (ring->nkeys == 0 || ring->current == 0) {
    return MURMUR_KR_MISUSE;
  }
  uint32_t next = 1;
  for (size_t i = 0; i < ring->nkeys; i++) {
    if (ring->keys[i].id >= next) {
      next = ring->keys[i].id + 1;
    }
  }
  if (next == 0) {
    return MURMUR_KR_MISUSE; /* id space exhausted */
  }
  if (ring->nkeys + 1 > kMaxDataKeys) {
    return MURMUR_KR_CORRUPT;
  }
  SealArgs a;
  a.kdf = ring->kdf;
  a.seq = ring->seq + 1;
  a.store_id = store_id;
  a.context_id = ring->context;
  a.wrap_id = ring->wrap_id;
  a.wrap_len = ring->wrap_len;
  a.scrypt_n = ring->scrypt_n;
  a.scrypt_r = ring->scrypt_r;
  a.scrypt_p = ring->scrypt_p;
  a.master = master;
  a.master_len = master_len;
  a.pass = pass;
  a.pass_len = pass_len;
  a.keys.assign(ring->keys, ring->keys + ring->nkeys);
  for (auto &k : a.keys) {
    if (k.id == ring->current) {
      k.active = 0;
    }
  }
  murmur_key_entry_t fresh;
  fresh.id = next;
  fresh.created_at = 0;
  fresh.active = 1;
  if (!rand_fill(fresh.key, sizeof(fresh.key))) {
    wipe_mem(a.keys.data(), a.keys.size() * sizeof(a.keys[0]));
    return MURMUR_KR_NOMEM;
  }
  a.keys.push_back(fresh);
  wipe_mem(fresh.key, sizeof(fresh.key));
  std::vector<uint8_t> env;
  int rc = seal_locked(a, &env);
  wipe_mem(a.keys.data(), a.keys.size() * sizeof(a.keys[0]));
  if (rc != MURMUR_KR_OK) {
    return rc;
  }
  *out_env = vec_to_malloc(&env, out_len);
  wipe_mem(env.data(), env.size());
  if (!*out_env) {
    return MURMUR_KR_NOMEM;
  }
  *out_next = next;
  return MURMUR_KR_OK;
}

int murmur_kr_drop(const murmur_keyring_t *ring, const uint32_t *drop_ids,
                   size_t ndrop, const uint8_t store_id[16],
                   const uint8_t *master, size_t master_len,
                   const uint8_t *pass, size_t pass_len, uint8_t **out_env,
                   size_t *out_len) {
  if (!ring || !store_id || !out_env || !out_len || (master_len && !master) ||
      (pass_len && !pass) || (ndrop && !drop_ids)) {
    return MURMUR_KR_MISUSE;
  }
  if (ndrop == 0 || ring->nkeys == 0 || ring->current == 0) {
    return MURMUR_KR_MISUSE;
  }
  SealArgs a;
  a.kdf = ring->kdf;
  a.seq = ring->seq + 1;
  a.store_id = store_id;
  a.context_id = ring->context;
  a.wrap_id = ring->wrap_id;
  a.wrap_len = ring->wrap_len;
  a.scrypt_n = ring->scrypt_n;
  a.scrypt_r = ring->scrypt_r;
  a.scrypt_p = ring->scrypt_p;
  a.master = master;
  a.master_len = master_len;
  a.pass = pass;
  a.pass_len = pass_len;
  for (size_t i = 0; i < ring->nkeys; i++) {
    bool dropped = false;
    for (size_t j = 0; j < ndrop; j++) {
      if (drop_ids[j] != ring->keys[i].id) {
        continue;
      }
      if (ring->keys[i].active || ring->keys[i].id == ring->current) {
        wipe_mem(a.keys.data(), a.keys.size() * sizeof(a.keys[0]));
        return MURMUR_KR_MISUSE;
      }
      dropped = true;
      break;
    }
    if (!dropped) {
      a.keys.push_back(ring->keys[i]);
    }
  }
  std::vector<uint8_t> env;
  int rc = seal_locked(a, &env);
  wipe_mem(a.keys.data(), a.keys.size() * sizeof(a.keys[0]));
  if (rc != MURMUR_KR_OK) {
    return rc;
  }
  *out_env = vec_to_malloc(&env, out_len);
  wipe_mem(env.data(), env.size());
  if (!*out_env) {
    return MURMUR_KR_NOMEM;
  }
  return MURMUR_KR_OK;
}

void murmur_kr_free_ring(murmur_keyring_t *ring) {
  if (!ring) {
    return;
  }
  if (ring->keys) {
    wipe_mem(ring->keys, ring->nkeys * sizeof(ring->keys[0]));
    free(ring->keys);
  }
  if (ring->wrap_id) {
    wipe_mem(ring->wrap_id, ring->wrap_len);
    free(ring->wrap_id);
  }
  wipe_mem(ring->context, sizeof(ring->context));
  wipe_mem(ring, sizeof(*ring));
  free(ring);
}

void murmur_kr_free(void *p) { free(p); }

int murmur_kr_open_flat(const uint8_t *env, size_t env_len,
                        const uint8_t *master, size_t master_len,
                        const uint8_t *pass, size_t pass_len,
                        const uint8_t store_id[16], const uint8_t context_id[16],
                        uint8_t **out_flat, size_t *out_len) {
  if (!out_flat || !out_len) {
    return MURMUR_KR_MISUSE;
  }
  int rc = MURMUR_KR_CORRUPT;
  murmur_keyring_t *r = murmur_kr_open(env, env_len, master, master_len, pass,
                                       pass_len, store_id, context_id, &rc);
  if (!r) {
    return rc;
  }
  std::vector<uint8_t> flat;
  flat.reserve(8 + 1 + 4 + 4 + 1 + 4 + 4 + 1 + r->wrap_len +
               r->nkeys * (4 + 8 + 1 + 32));
  uint8_t tmp[8];
  store64le(tmp, r->seq);
  flat.insert(flat.end(), tmp, tmp + 8);
  flat.push_back(r->kdf);
  store32le(tmp, r->scrypt_n);
  flat.insert(flat.end(), tmp, tmp + 4);
  store32le(tmp, r->scrypt_r);
  flat.insert(flat.end(), tmp, tmp + 4);
  flat.push_back(r->scrypt_p);
  store32le(tmp, r->current);
  flat.insert(flat.end(), tmp, tmp + 4);
  store32le(tmp, (uint32_t)r->nkeys);
  flat.insert(flat.end(), tmp, tmp + 4);
  flat.push_back((uint8_t)r->wrap_len);
  flat.insert(flat.end(), r->wrap_id, r->wrap_id + r->wrap_len);
  for (size_t i = 0; i < r->nkeys; i++) {
    store32le(tmp, r->keys[i].id);
    flat.insert(flat.end(), tmp, tmp + 4);
    store64le(tmp, (uint64_t)r->keys[i].created_at);
    flat.insert(flat.end(), tmp, tmp + 8);
    flat.push_back(r->keys[i].active ? 1 : 0);
    flat.insert(flat.end(), r->keys[i].key, r->keys[i].key + 32);
  }
  murmur_kr_free_ring(r);
  *out_flat = vec_to_malloc(&flat, out_len);
  wipe_mem(flat.data(), flat.size());
  if (!*out_flat) {
    return MURMUR_KR_NOMEM;
  }
  return MURMUR_KR_OK;
}

int murmur_kr_seal_flat(uint8_t kdf, uint64_t seq, const uint8_t store_id[16],
                        const uint8_t context_id[16], const uint8_t *wrap_id,
                        size_t wrap_len, uint32_t scrypt_n,
                        uint32_t scrypt_r, uint8_t scrypt_p,
                        const uint8_t *master, size_t master_len,
                        const uint8_t *pass, size_t pass_len,
                        const uint8_t *flat_keys, size_t nkeys,
                        uint8_t **out_env, size_t *out_len) {
  if (!store_id || !context_id || !out_env || !out_len ||
      (wrap_len && !wrap_id) || (master_len && !master) ||
      (pass_len && !pass) || (nkeys && !flat_keys)) {
    return MURMUR_KR_MISUSE;
  }
  SealArgs a;
  a.kdf = kdf;
  a.seq = seq;
  a.store_id = store_id;
  a.context_id = context_id;
  a.wrap_id = wrap_id;
  a.wrap_len = wrap_len;
  a.scrypt_n = scrypt_n;
  a.scrypt_r = scrypt_r;
  a.scrypt_p = scrypt_p;
  a.master = master;
  a.master_len = master_len;
  a.pass = pass;
  a.pass_len = pass_len;
  for (size_t i = 0; i < nkeys; i++) {
    /* Entry layout mirrors the flat form: id u32le, created i64le,
     * active u8, key[32]. */
    const uint8_t *e = flat_keys + i * (4 + 8 + 1 + 32);
    murmur_key_entry_t k;
    k.id = load32le(e);
    k.created_at = (int64_t)load64le(e + 4);
    k.active = e[12] ? 1 : 0;
    memcpy(k.key, e + 13, 32);
    a.keys.push_back(k);
    wipe_mem(k.key, sizeof(k.key));
  }
  std::vector<uint8_t> env;
  int rc = seal_locked(a, &env);
  wipe_mem(a.keys.data(), a.keys.size() * sizeof(a.keys[0]));
  if (rc != MURMUR_KR_OK) {
    return rc;
  }
  *out_env = vec_to_malloc(&env, out_len);
  wipe_mem(env.data(), env.size());
  if (!*out_env) {
    return MURMUR_KR_NOMEM;
  }
  return MURMUR_KR_OK;
}

int murmur_kr_rotate_flat(const uint8_t *env, size_t env_len,
                          const uint8_t store_id[16],
                          const uint8_t context_id[16], const uint8_t *master,
                          size_t master_len, const uint8_t *pass,
                          size_t pass_len, uint8_t **out_env, size_t *out_len,
                          uint32_t *out_next) {
  if (!env || !store_id || !context_id || !out_env || !out_len || !out_next ||
      (master_len && !master) || (pass_len && !pass)) {
    return MURMUR_KR_MISUSE;
  }
  int rc = MURMUR_KR_CORRUPT;
  murmur_keyring_t *r = murmur_kr_open(env, env_len, master, master_len, pass,
                                       pass_len, store_id, context_id, &rc);
  if (!r) {
    return rc;
  }
  rc = murmur_kr_rotate(r, store_id, master, master_len, pass, pass_len,
                        out_env, out_len, out_next);
  murmur_kr_free_ring(r);
  return rc;
}

int murmur_kr_drop_flat(const uint8_t *env, size_t env_len,
                        const uint32_t *drop_ids, size_t ndrop,
                        const uint8_t store_id[16], const uint8_t context_id[16],
                        const uint8_t *master, size_t master_len,
                        const uint8_t *pass, size_t pass_len,
                        uint8_t **out_env, size_t *out_len) {
  if (!env || !store_id || !context_id || !out_env || !out_len ||
      (ndrop && !drop_ids) || (master_len && !master) || (pass_len && !pass)) {
    return MURMUR_KR_MISUSE;
  }
  int rc = MURMUR_KR_CORRUPT;
  murmur_keyring_t *r = murmur_kr_open(env, env_len, master, master_len, pass,
                                       pass_len, store_id, context_id, &rc);
  if (!r) {
    return rc;
  }
  rc = murmur_kr_drop(r, drop_ids, ndrop, store_id, master, master_len, pass,
                      pass_len, out_env, out_len);
  murmur_kr_free_ring(r);
  return rc;
}

}  // extern "C"
