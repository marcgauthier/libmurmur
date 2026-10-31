// sqlite-murmur page codec: seal/open EXP1-EXP4 page records entirely in
// C++. Layouts, AAD, bounds, and error mapping mirror pkgs/storage/crypto.go
// exactly (including quirks: the AES-only 4175 plain bound, legacy
// chains failing corrupt after exhausting keys); the Go engine is the
// differential oracle. Keys are provisioned once and never leave the
// codec; zstd contexts are reused across seals/opens.
#include "murmur_codec.h"

#include <string.h>
#include <sys/random.h>
#include <unistd.h>

#include <fcntl.h>

#include <mutex>
#include <utility>
#include <vector>

#include "aesgcm.h"
#include "aegis.h"
#include "aegis256.h"
#include "zstd.h"

namespace {

const int kBlock = 4096;
const int kMaxRecord = 8192;
const int kScratch = 4175;

const int kErrAuth = -2;
const int kErrCorrupt = -3;
const int kErrShort = -4;
const int kErrMisuse = -5;

void wipe(void *p, size_t n) {
  // explicit_bzero: vectorized like memset but never elided.
  explicit_bzero(p, n);
}

struct KeyEntry {
  uint32_t id;
  uint8_t key[32];
};

struct CodecImpl {
  std::mutex mu;
  int cipher;
  int level;
  bool sealed;
  uint8_t page[32];
  uint8_t active[32];
  uint32_t current = 0;
  std::vector<KeyEntry> retired;
  uint8_t master[32];
  ZSTD_CCtx *cctx = nullptr;
  ZSTD_DCtx *dctx = nullptr;
  int urandom_fd = -1;  // lazy getrandom(2) fallback
  bool aegis_ready = false;
};

bool rand_bytes(CodecImpl *c, uint8_t *p, size_t n) {
  size_t done = 0;
  while (done < n) {
    ssize_t r = getrandom(p + done, n - done, 0);
    if (r <= 0) {
      break;
    }
    done += (size_t)r;
  }
  if (done == n) {
    return true;
  }
  if (c->urandom_fd < 0) {
    c->urandom_fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (c->urandom_fd < 0) {
      return false;
    }
  }
  while (done < n) {
    ssize_t r = read(c->urandom_fd, p + done, n - done);
    if (r <= 0) {
      return false;
    }
    done += (size_t)r;
  }
  return true;
}

bool ensure_aegis(CodecImpl *c) {
  if (c->aegis_ready) {
    return true;
  }
  if (aegis_init() != 0) {
    return false;
  }
  c->aegis_ready = true;
  return true;
}

void put_u64be(uint8_t o[8], uint64_t v) {
  for (int i = 0; i < 8; i++) {
    o[i] = (uint8_t)(v >> (56 - 8 * i));
  }
}

void put_u32le(uint8_t o[4], uint32_t v) {
  o[0] = (uint8_t)v;
  o[1] = (uint8_t)(v >> 8);
  o[2] = (uint8_t)(v >> 16);
  o[3] = (uint8_t)(v >> 24);
}

// AES AAD: flag | page_be8 [| keyid_le4]. Returns length (9 or 13).
size_t aes_aad(uint8_t o[13], uint8_t flag, uint64_t page, const uint32_t *kid) {
  o[0] = flag;
  put_u64be(o + 1, page);
  if (kid) {
    put_u32le(o + 9, *kid);
    return 13;
  }
  return 9;
}

// AEGIS AAD: magic | flag | page_be8 [| keyid_le4]. Returns 13 or 17.
size_t aegis_aad(uint8_t o[17], const char magic[4], uint8_t flag, uint64_t page,
                 const uint32_t *kid) {
  memcpy(o, magic, 4);
  o[4] = flag;
  put_u64be(o + 5, page);
  if (kid) {
    put_u32le(o + 13, *kid);
    return 17;
  }
  return 13;
}

const uint8_t *find_retired(const CodecImpl *c, uint32_t id) {
  for (const auto &e : c->retired) {
    if (e.id == id) {
      return e.key;
    }
  }
  return nullptr;
}

// --- AES seal/open on one key. open returns plain length (>0) or kErr*.

int aes_seal_one(const uint8_t key[32], uint64_t page, const uint8_t *data,
                 size_t len, bool compressed, uint32_t key_id, uint8_t *out,
                 size_t cap, CodecImpl *c) {
  const bool keyed = key_id != 0;
  const size_t head = keyed ? 9 : 5;
  if (cap < head + 12 + len + 16) {
    return kErrShort;
  }
  uint8_t nonce[12];
  if (!rand_bytes(c, nonce, sizeof(nonce))) {
    return kErrMisuse;
  }
  uint8_t flag = compressed ? 1 : 0;
  uint8_t aad[13];
  const uint32_t *kid = keyed ? &key_id : nullptr;
  size_t aad_len = aes_aad(aad, flag, page, kid);
  uint8_t *body = out + head + 12;
  uint8_t tag[16];
  if (murmur_aes256gcm_encrypt(key, nonce, data, len, aad, aad_len, body, tag) != 0) {
    wipe(nonce, sizeof(nonce));
    return kErrMisuse;
  }
  memcpy(out, keyed ? "EXP3" : "EXP1", 4);
  out[4] = flag;
  if (keyed) {
    put_u32le(out + 5, key_id);
  }
  memcpy(out + head, nonce, 12);
  memcpy(body + len, tag, 16);
  wipe(nonce, sizeof(nonce));
  wipe(tag, sizeof(tag));
  return (int)(head + 12 + len + 16);
}

int aes_open_one(const uint8_t key[32], uint64_t page, const uint8_t *rec,
                 size_t len, uint8_t *plain, size_t cap, bool *compressed) {
  if (len < 4) {
    return kErrCorrupt;
  }
  const bool keyed = memcmp(rec, "EXP3", 4) == 0;
  const size_t head = keyed ? 9 : 5;
  const char *magic = keyed ? "EXP3" : "EXP1";
  if (len < head + 12 + 16 || memcmp(rec, magic, 4) != 0) {
    return kErrCorrupt;
  }
  uint8_t flag = rec[4];
  if (flag > 1) {
    return kErrCorrupt;
  }
  uint32_t kid = 0;
  const uint32_t *kidp = nullptr;
  if (keyed) {
    kid = (uint32_t)rec[5] | ((uint32_t)rec[6] << 8) | ((uint32_t)rec[7] << 16) |
          ((uint32_t)rec[8] << 24);
    kidp = &kid;
  }
  size_t payload = len - head - 12 - 16;
  if (payload > ZSTD_compressBound(kBlock)) {
    return kErrCorrupt;
  }
  if (cap < payload) {
    return kErrShort;
  }
  uint8_t aad[13];
  size_t aad_len = aes_aad(aad, flag, page, kidp);
  const uint8_t *nonce = rec + head;
  const uint8_t *body = rec + head + 12;
  uint8_t tag[16];
  memcpy(tag, body + payload, 16);
  int rc = murmur_aes256gcm_decrypt(key, nonce, body, payload, tag, aad,
                                    aad_len, plain);
  wipe(tag, sizeof(tag));
  if (rc == -2) {
    return kErrAuth;
  }
  if (rc != 0) {
    return kErrMisuse;
  }
  if (payload > (size_t)kScratch) {
    wipe(plain, payload);
    return kErrCorrupt;
  }
  *compressed = flag != 0;
  return (int)payload;
}

// --- AEGIS seal/open on one key. Nonce/tag are 32 bytes; combined
// ct||tag layout like the Go binding.

int aegis_seal_one(const uint8_t key[32], uint64_t page, const uint8_t *data,
                   size_t len, bool compressed, uint32_t key_id, uint8_t *out,
                   size_t cap, CodecImpl *c) {
  const bool keyed = key_id != 0;
  const size_t head = keyed ? 9 : 5;
  if (cap < head + 32 + len + 32) {
    return kErrShort;
  }
  if (!ensure_aegis(c)) {
    return kErrMisuse;
  }
  uint8_t nonce[32];
  if (!rand_bytes(c, nonce, sizeof(nonce))) {
    return kErrMisuse;
  }
  const char *magic = keyed ? "EXP4" : "EXP2";
  uint8_t flag = compressed ? 1 : 0;
  uint8_t aad[17];
  const uint32_t *kid = keyed ? &key_id : nullptr;
  size_t aad_len = aegis_aad(aad, magic, flag, page, kid);
  uint8_t *body = out + head + 32;
  if (aegis256_encrypt(body, 32, data, len, aad, aad_len, nonce, key) != 0) {
    wipe(nonce, sizeof(nonce));
    return kErrMisuse;
  }
  memcpy(out, magic, 4);
  out[4] = flag;
  if (keyed) {
    put_u32le(out + 5, key_id);
  }
  memcpy(out + head, nonce, 32);
  wipe(nonce, sizeof(nonce));
  return (int)(head + 32 + len + 32);
}

int aegis_open_one(const uint8_t key[32], uint64_t page, const uint8_t *rec,
                   size_t len, uint8_t *plain, size_t cap, bool *compressed,
                   CodecImpl *c) {
  if (len < 4) {
    return kErrCorrupt;
  }
  const bool keyed = memcmp(rec, "EXP4", 4) == 0;
  const size_t head = keyed ? 9 : 5;
  const char *magic = keyed ? "EXP4" : "EXP2";
  if (len < head + 32 + 32 || memcmp(rec, magic, 4) != 0) {
    return kErrCorrupt;
  }
  uint8_t flag = rec[4];
  uint32_t kid = 0;
  const uint32_t *kidp = nullptr;
  if (keyed) {
    kid = (uint32_t)rec[5] | ((uint32_t)rec[6] << 8) | ((uint32_t)rec[7] << 16) |
          ((uint32_t)rec[8] << 24);
    kidp = &kid;
  }
  size_t payload = len - head - 32 - 32;
  if (flag > 1 || payload > ZSTD_compressBound(kBlock)) {
    return kErrCorrupt;
  }
  if (!ensure_aegis(c)) {
    return kErrMisuse;
  }
  if (cap < payload) {
    return kErrShort;
  }
  uint8_t aad[17];
  size_t aad_len = aegis_aad(aad, magic, flag, page, kidp);
  const uint8_t *nonce = rec + head;
  const uint8_t *body = rec + head + 32;
  if (aegis256_decrypt(plain, body, payload + 32, 32, aad, aad_len, nonce, key) != 0) {
    return kErrAuth;
  }
  *compressed = flag != 0;
  return (int)payload;
}

bool valid_cipher(int c) { return c == 1 || c == 2; }

bool codec_init_ctx(CodecImpl *c) {
  c->cctx = ZSTD_createCCtx();
  c->dctx = ZSTD_createDCtx();
  if (!c->cctx || !c->dctx) {
    return false;
  }
  if (c->level != 0 &&
      ZSTD_isError(ZSTD_CCtx_setParameter(c->cctx, ZSTD_c_compressionLevel, c->level))) {
    return false;
  }
  return true;
}

}  // namespace

extern "C" {

// Opaque handle <-> impl cast (MurmurCodec is incomplete here).
static CodecImpl *impl(MurmurCodec *c) { return (CodecImpl *)c; }

MurmurCodec *murmur_codec_create(int cipher, int level, const uint8_t page_key[32],
                                 int sealed, const uint8_t active[32],
                                 uint32_t current_id, const uint32_t *retired_ids,
                                 const uint8_t *retired_keys, size_t retired_count,
                                 const uint8_t master[32]) {
  if (!valid_cipher(cipher) || level < 0 || level > 22 || !page_key || !master ||
      (sealed && !active) || (retired_count > 0 && (!retired_ids || !retired_keys))) {
    return nullptr;
  }
  if (cipher == 1 && !murmur_aes_available()) {
    return nullptr;  // AES fails closed without its backend
  }
  CodecImpl *c = new (std::nothrow) CodecImpl();
  if (!c) {
    return nullptr;
  }
  c->cipher = cipher;
  c->level = level;
  c->sealed = sealed != 0;
  memcpy(c->page, page_key, 32);
  if (sealed) {
    memcpy(c->active, active, 32);
    c->current = current_id;
  }
  memcpy(c->master, master, 32);
  for (size_t i = 0; i < retired_count; i++) {
    KeyEntry e;
    e.id = retired_ids[i];
    memcpy(e.key, retired_keys + 32 * i, 32);
    c->retired.push_back(e);
  }
  if (!codec_init_ctx(c)) {
    murmur_codec_destroy((MurmurCodec *)c);
    return nullptr;
  }
  return (MurmurCodec *)c;
}

int murmur_codec_set_cipher(MurmurCodec *raw, int cipher) {
  CodecImpl *c = impl(raw);
  if (!c || !valid_cipher(cipher)) {
    return kErrMisuse;
  }
  if (cipher == 1 && !murmur_aes_available()) {
    return kErrMisuse;
  }
  std::lock_guard<std::mutex> l(c->mu);
  c->cipher = cipher;
  return 0;
}

int murmur_codec_set_level(MurmurCodec *raw, int level) {
  CodecImpl *c = impl(raw);
  if (!c || level < 0 || level > 22) {
    return kErrMisuse;
  }
  std::lock_guard<std::mutex> l(c->mu);
  c->level = level;
  if (level != 0 &&
      ZSTD_isError(ZSTD_CCtx_setParameter(c->cctx, ZSTD_c_compressionLevel, level))) {
    return kErrMisuse;
  }
  return 0;
}

int murmur_codec_install_ring(MurmurCodec *raw, const uint8_t active[32],
                              uint32_t current_id, const uint32_t *retired_ids,
                              const uint8_t *retired_keys, size_t retired_count) {
  CodecImpl *c = impl(raw);
  if (!c || !active || (retired_count > 0 && (!retired_ids || !retired_keys))) {
    return kErrMisuse;
  }
  std::lock_guard<std::mutex> l(c->mu);
  memcpy(c->active, active, 32);
  c->current = current_id;
  c->retired.clear();
  for (size_t i = 0; i < retired_count; i++) {
    KeyEntry e;
    e.id = retired_ids[i];
    memcpy(e.key, retired_keys + 32 * i, 32);
    c->retired.push_back(e);
  }
  c->sealed = true;
  return 0;
}

int murmur_record_key_id(const uint8_t *in, size_t in_len,
                          uint32_t *key_id) {
  if (!in || in_len < 4 || !key_id) {
    return 0;
  }
  bool exp3 = memcmp(in, "EXP3", 4) == 0;
  bool exp4 = memcmp(in, "EXP4", 4) == 0;
  if (!exp3 && !exp4) {
    return 0;
  }
  // Go RecordKeyID gates each magic on its own cipher lengths.
  if (exp3 && in_len < (size_t)(4 + 1 + 4 + 12 + 16)) {
    return 0;
  }
  if (exp4 && in_len < (size_t)(4 + 1 + 4 + 32 + 32)) {
    return 0;
  }
  *key_id = (uint32_t)in[5] | ((uint32_t)in[6] << 8) |
            ((uint32_t)in[7] << 16) | ((uint32_t)in[8] << 24);
  return 1;
}

static int codec_seal_inner(CodecImpl *c, uint64_t page,
                            const uint8_t in[4096], uint8_t *out,
                            size_t out_cap, uint32_t key_id,
                            size_t *payload_len) {
  const uint8_t *payload = in;
  size_t plen = kBlock;
  bool compressed = false;
  uint8_t zbuf[ZSTD_compressBound(kBlock)];
  if (c->level != 0) {
    size_t n = ZSTD_compress2(c->cctx, zbuf, sizeof(zbuf), in, kBlock);
    if (!ZSTD_isError(n) && n < (size_t)kBlock) {
      payload = zbuf;
      plen = n;
      compressed = true;
    }
  }
  const uint8_t *key = c->sealed ? c->active : c->page;
  int rc;
  if (c->cipher == 1) {
    rc = aes_seal_one(key, page, payload, plen, compressed, key_id, out,
                      out_cap, c);
  } else {
    rc = aegis_seal_one(key, page, payload, plen, compressed, key_id, out,
                        out_cap, c);
  }
  wipe(zbuf, sizeof(zbuf));
  if (rc > 0 && payload_len) {
    *payload_len = plen;
  }
  return rc;
}

int murmur_codec_seal(MurmurCodec *raw, uint64_t page, const uint8_t in[4096],
                      uint8_t *out, size_t out_cap, size_t *payload_len) {
  CodecImpl *c = impl(raw);
  if (!c || !in || !out || out_cap < (size_t)kMaxRecord) {
    return kErrMisuse;
  }
  std::lock_guard<std::mutex> l(c->mu);
  return codec_seal_inner(c, page, in, out, out_cap,
                          c->sealed ? c->current : 0, payload_len);
}

int murmur_codec_seal_as(MurmurCodec *c, uint64_t page,
                         const uint8_t in[4096], uint8_t *out, size_t out_cap,
                         uint32_t key_id, size_t *payload_len) {
  CodecImpl *impl_c = impl(c);
  if (!impl_c || !in || !out || out_cap < (size_t)kMaxRecord) {
    return kErrMisuse;
  }
  std::lock_guard<std::mutex> l(impl_c->mu);
  return codec_seal_inner(impl_c, page, in, out, out_cap, key_id, payload_len);
}

int murmur_codec_open(MurmurCodec *raw, uint64_t page, const uint8_t *in,
                      size_t in_len, uint8_t *out, size_t out_cap) {
  CodecImpl *c = impl(raw);
  if (!c || (!in && in_len > 0) || !out || out_cap < (size_t)kBlock) {
    return kErrMisuse;
  }
  std::lock_guard<std::mutex> l(c->mu);
  // Keyed records take the direct-id path with no backstop, like Go.
  bool want_keyed = false;
  uint32_t want_id = 0;
  if (in_len >= 4) {
    bool exp3 = memcmp(in, "EXP3", 4) == 0;
    bool exp4 = memcmp(in, "EXP4", 4) == 0;
    if ((c->cipher == 1 && exp3) || (c->cipher == 2 && exp4)) {
      size_t min = c->cipher == 1 ? 9 + 12 + 16 : 9 + 32 + 32;
      if (in_len >= min) {
        want_keyed = true;
        want_id = (uint32_t)in[5] | ((uint32_t)in[6] << 8) |
                  ((uint32_t)in[7] << 16) | ((uint32_t)in[8] << 24);
      }
    } else if (exp3 || exp4) {
      return kErrCorrupt;  // keyed magic of the other cipher
    }
  }
  uint8_t stage[ZSTD_compressBound(kBlock) > kBlock ? ZSTD_compressBound(kBlock)
                                                   : kBlock];
  auto finish = [&](int plen, bool comp) -> int {
    if (plen < 0) {
      return plen;
    }
    if (!comp) {
      if (plen != kBlock) {
        wipe(stage, (size_t)plen);
        return kErrCorrupt;
      }
      memcpy(out, stage, kBlock);
      wipe(stage, kBlock);
      return kBlock;
    }
    size_t n = ZSTD_decompressDCtx(c->dctx, out, kBlock, stage, (size_t)plen);
    wipe(stage, (size_t)plen);
    if (ZSTD_isError(n) || n != (size_t)kBlock) {
      return kErrCorrupt;
    }
    return kBlock;
  };
  auto open_one = [&](const uint8_t *key) -> int {
    bool comp = false;
    int plen;
    if (c->cipher == 1) {
      plen = aes_open_one(key, page, in, in_len, stage, sizeof(stage), &comp);
    } else {
      plen =
          aegis_open_one(key, page, in, in_len, stage, sizeof(stage), &comp, c);
    }
    return finish(plen, comp);
  };
  if (want_keyed) {
    if (want_id == 0) {
      return kErrCorrupt;
    }
    const uint8_t *direct = nullptr;
    if (c->sealed && want_id == c->current) {
      direct = c->active;
    } else {
      direct = find_retired(c, want_id);
    }
    if (!direct) {
      return kErrCorrupt;
    }
    return open_one(direct);
  }
  // Legacy trial chain: page key, retired keys, master (sealed only);
  // exhausting the chain fails corrupt, exactly like Go.
  if (open_one(c->page) == kBlock) {
    return kBlock;
  }
  if (c->sealed) {
    for (const auto &e : c->retired) {
      if (open_one(e.key) == kBlock) {
        return kBlock;
      }
    }
    if (open_one(c->master) == kBlock) {
      return kBlock;
    }
  }
  return kErrCorrupt;
}

void murmur_codec_destroy(MurmurCodec *raw) {
  CodecImpl *c = impl(raw);
  if (!c) {
    return;
  }
  if (c->cctx) {
    ZSTD_freeCCtx(c->cctx);
  }
  if (c->dctx) {
    ZSTD_freeDCtx(c->dctx);
  }
  if (c->urandom_fd >= 0) {
    close(c->urandom_fd);
  }
  wipe(c->page, 32);
  wipe(c->active, 32);
  wipe(c->master, 32);
  for (auto &e : c->retired) {
    wipe(e.key, 32);
  }
  delete c;
}

}  // extern "C"
