// krflat.h - shared keyring-envelope trial open for open.cc
// (provision/seal) and offline.cc (rekey/verify). Ports Go
// openRekeyRing (dir.go): try the master as a direct master, then
// as scrypt passphrase bytes, against murmur_kr_open_flat.
#ifndef MURMUR_KRFLAT_H
#define MURMUR_KRFLAT_H

#include <stddef.h>
#include <stdint.h>
#include <cstdio>
#include <string.h>
#include <string>
#include <vector>

#include "../keyring/keyring.h"

inline void krflat_wipe(void *p, size_t n) {
  if (p && n) {
    volatile uint8_t *v = (volatile uint8_t *)p;
    for (size_t i = 0; i < n; i++) {
      v[i] = 0;
    }
  }
}

struct KrFlatRing {
  uint8_t active[32] = {0};
  uint32_t current = 0;
  std::vector<uint32_t> retiredIDs;
  std::vector<uint8_t> retiredKeys;  // flat, 32 per id
  std::vector<uint8_t> wrap;         // wrap-id bytes (rekey Create)
  // Full key list for inventory (parallel to retired above).
  std::vector<uint32_t> allIDs;
  std::vector<int64_t> allCreated;  // nanos, parallel to allIDs
  std::vector<uint8_t> allActive;   // 1/0, parallel to allIDs
  uint64_t seq = 0;
  uint8_t kdf = 0;
  uint32_t time = 0;
  uint32_t mem = 0;
  uint8_t threads = 0;
  ~KrFlatRing() {
    krflat_wipe(active, sizeof(active));
    if (!retiredKeys.empty()) {
      krflat_wipe(retiredKeys.data(), retiredKeys.size());
    }
  }
};

inline uint32_t krflat_load_u32le(const uint8_t *p) {
  return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
         ((uint32_t)p[3] << 24);
}

// Parses the murmur_kr_open_flat layout: seq u64le, kdf u8,
// atime u32le, amem u32le, athreads u8, current u32le, nkeys u32le,
// wraplen u8, wrapid, keys x {id u32le, created i64le, active u8,
// key[32]}. Matches Go ByID (id match ignores the active flag) and
// the retired list (every inactive entry, current included).
inline bool krflat_parse(const uint8_t *flat, size_t len, KrFlatRing *r) {
  if (len < 8 + 1 + 4 + 4 + 1 + 4 + 4 + 1) {
    return false;
  }
  size_t o = 0;
  r->seq = (uint64_t)flat[0] | ((uint64_t)flat[1] << 8) |
           ((uint64_t)flat[2] << 16) | ((uint64_t)flat[3] << 24) |
           ((uint64_t)flat[4] << 32) | ((uint64_t)flat[5] << 40) |
           ((uint64_t)flat[6] << 48) | ((uint64_t)flat[7] << 56);
  o = 8;
  r->kdf = flat[o++];
  r->time = krflat_load_u32le(flat + o);
  o += 4;
  r->mem = krflat_load_u32le(flat + o);
  o += 4;
  r->threads = flat[o++];
  r->current = krflat_load_u32le(flat + o);
  o += 4;
  uint32_t nkeys = krflat_load_u32le(flat + o);
  o += 4;
  uint8_t wraplen = flat[o++];
  if (wraplen > len - o || nkeys > (len - o - wraplen) / 41) {
    return false;
  }
  r->wrap.assign(flat + o, flat + o + wraplen);
  o += wraplen;
  bool found = false;
  for (uint32_t i = 0; i < nkeys; i++) {
    uint32_t id = krflat_load_u32le(flat + o);
    o += 4;
    int64_t created = (int64_t)((uint64_t)flat[o] | ((uint64_t)flat[o + 1] << 8) |
                                ((uint64_t)flat[o + 2] << 16) |
                                ((uint64_t)flat[o + 3] << 24) |
                                ((uint64_t)flat[o + 4] << 32) |
                                ((uint64_t)flat[o + 5] << 40) |
                                ((uint64_t)flat[o + 6] << 48) |
                                ((uint64_t)flat[o + 7] << 56));
    o += 8;
    uint8_t active = flat[o++];
    const uint8_t *key = flat + o;
    o += 32;
    r->allIDs.push_back(id);
    r->allCreated.push_back(created);
    r->allActive.push_back(active ? 1 : 0);
    if (id == r->current) {
      memcpy(r->active, key, 32);
      found = true;
    }
    if (!active) {
      r->retiredIDs.push_back(id);
      size_t was = r->retiredKeys.size();
      r->retiredKeys.resize(was + 32);
      memcpy(r->retiredKeys.data() + was, key, 32);
    }
  }
  return found && r->current != 0;
}

// Opens the envelope with the master, falling back to passphrase
// bytes (context = store id). Returns 0 on success,
// MURMUR_KR_AUTH on wrong key, -1 on corrupt/parse failure;
// callers map to their own code taxonomy.
inline int krflat_open_trial(const uint8_t *env, size_t env_len,
                             const uint8_t master[32], const uint8_t sid[16],
                             KrFlatRing *r) {
  uint8_t *flat = nullptr;
  size_t flat_len = 0;
  int rc = murmur_kr_open_flat(env, env_len, master, 32, nullptr, 0, sid, sid,
                               &flat, &flat_len);
  if (rc != MURMUR_KR_OK) {
    rc = murmur_kr_open_flat(env, env_len, nullptr, 0, master, 32, sid, sid,
                             &flat, &flat_len);
  }
  if (rc != MURMUR_KR_OK || !flat) {
    return rc == MURMUR_KR_AUTH ? MURMUR_KR_AUTH : -1;
  }
  bool ok = krflat_parse(flat, flat_len, r);
  krflat_wipe(flat, flat_len);
  murmur_kr_free(flat);
  return ok ? 0 : -1;
}

// JSON string escape mirroring Go jsonEscape (engine.go).
inline void krflat_json_escape(const uint8_t *in, size_t n, std::string *out) {
  static const char *hexd = "0123456789abcdef";
  for (size_t i = 0; i < n; i++) {
    uint8_t c = in[i];
    switch (c) {
      case '"':
        *out += "\\\"";
        break;
      case '\\':
        *out += "\\\\";
        break;
      case '\n':
        *out += "\\n";
        break;
      case '\r':
        *out += "\\r";
        break;
      case '\t':
        *out += "\\t";
        break;
      default:
        if (c < 0x20) {
          *out += "\\u00";
          *out += hexd[c >> 4];
          *out += hexd[c & 15];
        } else {
          *out += (char)c;
        }
        break;
    }
  }
}

// Serializes a decoded ring exactly like Go InventoryJSON:
// `{"sealed":true,"seq":N,...}`. Shared by the offline inventory
// and the live store inventory so the two cannot drift.
inline void krflat_inventory_json(const KrFlatRing *r, std::string *js) {
  char num[64];
  *js = "{\"sealed\":true,\"seq\":";
  snprintf(num, sizeof(num), "%llu", (unsigned long long)r->seq);
  *js += num;
  *js += ",\"kdf\":\"";
  *js += (r->kdf == 1 ? "scrypt" : "direct");
  *js += "\",\"scrypt_n\":";
  snprintf(num, sizeof(num), "%u", r->time);
  *js += num;
  *js += ",\"scrypt_r\":";
  snprintf(num, sizeof(num), "%u", r->mem);
  *js += num;
  *js += ",\"scrypt_p\":";
  snprintf(num, sizeof(num), "%u", r->threads);
  *js += num;
  *js += ",\"wrap_id\":\"";
  krflat_json_escape(r->wrap.data(), r->wrap.size(), js);
  *js += "\",\"current\":";
  snprintf(num, sizeof(num), "%u", r->current);
  *js += num;
  *js += ",\"keys\":[";
  for (size_t i = 0; i < r->allIDs.size(); i++) {
    if (i > 0) {
      *js += ",";
    }
    *js += "{\"id\":";
    snprintf(num, sizeof(num), "%u", r->allIDs[i]);
    *js += num;
    *js += ",\"created_nanos\":";
    snprintf(num, sizeof(num), "%lld", (long long)r->allCreated[i]);
    *js += num;
    *js += ",\"active\":";
    *js += (r->allActive[i] ? "true" : "false");
    *js += "}";
  }
  *js += "]}";
}

#endif  // MURMUR_KRFLAT_H
