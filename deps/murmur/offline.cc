// offline.cc - native offline rekey/verify. Ports dir.go RekeyDir /
// VerifyDir against raw nv_store_* opens (no registry): RocksDB's
// LOCK serializes against live same-process stores (BUSY) exactly
// like the Go raw opens. Error taxonomy mirrors dir.go line for
// line; the Go tests in dir_test.go pin it.
#include "offline.h"

#include <cstdio>
#include <cstdlib>
#include <string>
#include <string.h>
#include <sys/stat.h>
#include <vector>

#include "../codec/murmur_codec.h"
#include "krflat.h"

typedef struct NvStore NvStore;
typedef struct NvScan NvScan;

extern "C" {
NvStore *nv_store_open(const char *dir, int create, char *err,
                       size_t err_cap);
void nv_store_close(NvStore *s);
int nv_store_get(NvStore *s, const uint8_t *key, size_t klen, uint8_t *val,
                 size_t vcap, size_t *vlen, char *err, size_t err_cap);
int nv_store_put(NvStore *s, const uint8_t *key, size_t klen,
                 const uint8_t *val, size_t vlen, int sync, char *err,
                 size_t err_cap);
int nv_store_del(NvStore *s, const uint8_t *key, size_t klen, int sync,
                 char *err, size_t err_cap);
int nv_store_sync(NvStore *s, char *err, size_t err_cap);
NvScan *nv_scan_open(NvStore *s);
int nv_scan_next(NvScan *sc, uint64_t *id, uint8_t *vbuf, size_t vcap,
                 size_t *vlen);
void nv_scan_close(NvScan *sc);
void nv_page_key(uint64_t page, uint8_t out[9]);
}

namespace {

const char *kMetaCipher = "meta:cipher";
const char *kMetaKeyring = "meta:keyring";
const char *kMetaRekey = "meta:keyring.REKEY";
const char *kMetaStoreID = "meta:store_id";

bool is_dir(const char *dir) {
  struct stat st;
  return dir && stat(dir, &st) == 0 && S_ISDIR(st.st_mode);
}

// RocksDB LOCK contention surfaces as Busy/Try-again text (Go
// isBusyOrRetry over rocksKind).
bool err_busy(const char *err) {
  return err && (strstr(err, "Busy") || strstr(err, "Try again"));
}

// meta_get mirrors nvGet with 8KiB start and growth to 1MiB.
// Returns 1 found, 0 missing, -1 error/oversize.
int meta_get(NvStore *s, const char *key, std::vector<uint8_t> *out) {
  size_t cap = 8192;
  for (;;) {
    out->resize(cap);
    size_t vlen = 0;
    char err[512];
    int rc = nv_store_get(s, (const uint8_t *)key, strlen(key), out->data(),
                          cap, &vlen, err, sizeof(err));
    if (rc == 1) {
      out->resize(vlen);
      return 1;
    }
    if (rc == 0) {
      out->clear();
      return 0;
    }
    if (rc == -2 && vlen > cap && vlen <= (1u << 20)) {
      cap = vlen;
      continue;
    }
    out->clear();
    return -1;
  }
}

}  // namespace

int nvOfflineInventory(const char *dir, const uint8_t master[32], char *out,
                       size_t cap, size_t *out_len) {
  if (!out_len) {
    return NV_OFF_MISUSE;
  }
  *out_len = 0;
  if (!is_dir(dir)) {
    return NV_OFF_CANTOPEN;
  }
  char err[512] = {0};
  NvStore *s = nv_store_open(dir, 0, err, sizeof(err));
  if (!s) {
    return err_busy(err) ? NV_OFF_BUSY : NV_OFF_CANTOPEN;
  }
  int code = NV_OFF_OK;
  std::string js;
  {
    std::vector<uint8_t> env, sid_raw;
    if (meta_get(s, kMetaKeyring, &env) != 1 || env.empty()) {
      js = "{\"sealed\":false}";
    } else {
      if (meta_get(s, kMetaStoreID, &sid_raw) != 1 || sid_raw.size() != 16) {
        code = NV_OFF_CORRUPT;
        goto done;
      }
      uint8_t sid[16];
      memcpy(sid, sid_raw.data(), 16);
      KrFlatRing ring;
      int trc = krflat_open_trial(env.data(), env.size(), master, sid, &ring);
      if (trc == MURMUR_KR_AUTH) {
        code = NV_OFF_AUTH;
        goto done;
      }
      if (trc != 0) {
        code = NV_OFF_CORRUPT;
        goto done;
      }
      krflat_inventory_json(&ring, &js);
    }
  }
done:
  nv_store_close(s);
  if (code != NV_OFF_OK) {
    return code;
  }
  *out_len = js.size();
  if (js.size() + 1 > cap || !out) {
    return -2;
  }
  memcpy(out, js.data(), js.size());
  return NV_OFF_OK;
}

int nvOfflineVerify(const char *dir, const uint8_t master[32]) {
  if (!is_dir(dir)) {
    return NV_OFF_CANTOPEN;
  }
  char err[512] = {0};
  NvStore *s = nv_store_open(dir, 0, err, sizeof(err));
  if (!s) {
    return err_busy(err) ? NV_OFF_BUSY : NV_OFF_CANTOPEN;
  }
  int code = NV_OFF_OK;
  std::vector<uint8_t> val;
  // Cipher: read errors fall back to AES; bad values are corrupt
  // (Go VerifyDir ignores read errors the same way).
  int cipher = MURMUR_CIPHER_AES256GCM;
  if (meta_get(s, kMetaCipher, &val) == 1) {
    if (!(val.size() == 9 && memcmp(val.data(), "aes256gcm", 9) == 0)) {
      code = NV_OFF_CORRUPT;
      goto done;
    }
  }
  {
    // The envelope is optional (Go verifies unsealed stores with
    // the master as the page key).
    std::vector<uint8_t> env, sid_raw;
    int sealed = 0;
    KrFlatRing ring;
    uint8_t page_key[32];
    memcpy(page_key, master, 32);
    if (meta_get(s, kMetaKeyring, &env) == 1 && !env.empty()) {
      sealed = 1;
      if (meta_get(s, kMetaStoreID, &sid_raw) != 1 || sid_raw.size() != 16) {
        code = NV_OFF_CORRUPT;
        goto done;
      }
      uint8_t sid[16];
      memcpy(sid, sid_raw.data(), 16);
      int trc = krflat_open_trial(env.data(), env.size(), master, sid, &ring);
      if (trc == MURMUR_KR_AUTH) {
        code = NV_OFF_AUTH;
        goto done;
      }
      if (trc != 0) {
        code = NV_OFF_CORRUPT;
        goto done;
      }
      // Go snapshotRing leaves page/active zero when the current id
      // is missing; the trial then fails closed below.
      memcpy(page_key, ring.active, 32);
    }
    const uint32_t *rids =
        ring.retiredIDs.empty() ? nullptr : ring.retiredIDs.data();
    const uint8_t *rkeys =
        ring.retiredKeys.empty() ? nullptr : ring.retiredKeys.data();
    MurmurCodec *codec = murmur_codec_create(
        cipher, 0, page_key, sealed, ring.active, ring.current, rids, rkeys,
        ring.retiredIDs.size(), master);
    krflat_wipe(page_key, sizeof(page_key));
    if (!codec) {
      code = NV_OFF_IOERR;
      goto done;
    }
    NvScan *sc = nv_scan_open(s);
    if (!sc) {
      murmur_codec_destroy(codec);
      code = NV_OFF_IOERR;
      goto done;
    }
    std::vector<uint8_t> rec(8192);
    uint8_t plain[4096];
    for (;;) {
      uint64_t id = 0;
      size_t vlen = 0;
      int rc = nv_scan_next(sc, &id, rec.data(), rec.size(), &vlen);
      if (rc == 0) {
        break;
      }
      if (rc == -2) {
        if (vlen > (64u << 20)) {
          code = NV_OFF_CORRUPT;
          break;
        }
        rec.resize(vlen ? vlen : rec.size() * 2);
        continue;
      }
      if (rc != 1) {
        code = NV_OFF_IOERR;
        break;
      }
      if (murmur_codec_open(codec, id, rec.data(), vlen, plain,
                            sizeof(plain)) != 4096) {
        code = NV_OFF_CORRUPT;
        break;
      }
    }
    krflat_wipe(plain, sizeof(plain));
    krflat_wipe(rec.data(), rec.size());
    nv_scan_close(sc);
    murmur_codec_destroy(codec);
  }
done:
  krflat_wipe(val.data(), val.size());
  nv_store_close(s);
  return code;
}

int nvOfflineRekey(const char *dir, const uint8_t old_master[32],
                   const uint8_t new_master[32], int fault_after) {
  if (!is_dir(dir)) {
    return NV_OFF_CANTOPEN;
  }
  char err[512] = {0};
  NvStore *s = nv_store_open(dir, 0, err, sizeof(err));
  if (!s) {
    return err_busy(err) ? NV_OFF_BUSY : NV_OFF_CANTOPEN;
  }
  int code = NV_OFF_OK;
  std::vector<uint8_t> val;
  int cipher = MURMUR_CIPHER_AES256GCM;
  if (meta_get(s, kMetaCipher, &val) == 1) {
    if (!(val.size() == 9 &&
                 memcmp(val.data(), "aes256gcm", 9) == 0)) {
      code = NV_OFF_CORRUPT;
      goto done;
    }
  }
  {
    std::vector<uint8_t> current_env, sid_raw;
    if (meta_get(s, kMetaKeyring, &current_env) != 1) {
      code = NV_OFF_ERROR;
      goto done;
    }
    if (meta_get(s, kMetaStoreID, &sid_raw) != 1 || sid_raw.size() != 16) {
      code = NV_OFF_CORRUPT;
      goto done;
    }
    uint8_t sid[16];
    memcpy(sid, sid_raw.data(), 16);
    KrFlatRing old_ring;
    int trc =
        krflat_open_trial(current_env.data(), current_env.size(), old_master,
                          sid, &old_ring);
    if (trc == MURMUR_KR_AUTH) {
      code = NV_OFF_AUTH;
      goto done;
    }
    if (trc != 0) {
      code = NV_OFF_CORRUPT;
      goto done;
    }
    std::vector<uint8_t> staged;
    if (meta_get(s, kMetaRekey, &staged) == 1 && !staged.empty()) {
      // Resume: reuse the staged envelope (Go reads it raw).
    } else {
      staged.clear();
      bool argon = old_ring.kdf == MURMUR_KDF_SCRYPT;
      const uint8_t *c_master = argon ? nullptr : new_master;
      const uint8_t *c_pass = argon ? new_master : nullptr;
      const uint8_t *wrap =
          old_ring.wrap.empty() ? nullptr : old_ring.wrap.data();
      uint8_t *env = nullptr;
      size_t env_len = 0;
      int krc = murmur_kr_create(
          old_ring.kdf, argon ? old_ring.time : 0, argon ? old_ring.mem : 0,
          argon ? old_ring.threads : 0, wrap, old_ring.wrap.size(), sid, sid,
          c_master, argon ? 0 : 32, c_pass, argon ? 32 : 0, &env, &env_len);
      if (krc == MURMUR_KR_AUTH) {
        code = NV_OFF_AUTH;
        goto done;
      }
      if (krc != MURMUR_KR_OK || !env) {
        if (env) {
          murmur_kr_free(env);
        }
        code = krc == MURMUR_KR_MISUSE ? NV_OFF_MISUSE : NV_OFF_ERROR;
        goto done;
      }
      staged.assign(env, env + env_len);
      krflat_wipe(env, env_len);
      murmur_kr_free(env);
      char perr[512];
      if (nv_store_put(s, (const uint8_t *)kMetaRekey, strlen(kMetaRekey),
                       staged.data(), staged.size(), 1, perr,
                       sizeof(perr)) != 0) {
        code = NV_OFF_IOERR;
        goto done;
      }
    }
    KrFlatRing new_ring;
    // Go maps every staged-open error to CORRUPT (no AUTH here).
    if (krflat_open_trial(staged.data(), staged.size(), new_master, sid,
                          &new_ring) != 0) {
      code = NV_OFF_CORRUPT;
      goto done;
    }
    {
      const uint32_t *o_rids = old_ring.retiredIDs.empty()
                                   ? nullptr
                                   : old_ring.retiredIDs.data();
      const uint8_t *o_rkeys = old_ring.retiredKeys.empty()
                                   ? nullptr
                                   : old_ring.retiredKeys.data();
      // Old trial: page key = current data key (Go snapshotRing).
      MurmurCodec *old_codec = murmur_codec_create(
          cipher, 0, old_ring.active, 1, old_ring.active, old_ring.current,
          o_rids, o_rkeys, old_ring.retiredIDs.size(), old_master);
      // New codec seals at zstd-3; page+master back the rewritten
      // legacy fallback the way Go Decrypt(newCur) does.
      MurmurCodec *new_codec = murmur_codec_create(
          cipher, 3, new_ring.active, 1, new_ring.active, new_ring.current,
          nullptr, nullptr, 0, new_ring.active);
      if (!old_codec || !new_codec) {
        if (old_codec) {
          murmur_codec_destroy(old_codec);
        }
        if (new_codec) {
          murmur_codec_destroy(new_codec);
        }
        code = NV_OFF_IOERR;
        goto done;
      }
      NvScan *sc = nv_scan_open(s);
      if (!sc) {
        murmur_codec_destroy(old_codec);
        murmur_codec_destroy(new_codec);
        code = NV_OFF_IOERR;
        goto done;
      }
      std::vector<uint8_t> rec(8192);
      uint8_t plain[4096];
      uint8_t sealed[8192];
      int chunk = 0, total = 0;
      int scan_code = NV_OFF_OK;
      for (;;) {
        uint64_t id = 0;
        size_t vlen = 0;
        int rc = nv_scan_next(sc, &id, rec.data(), rec.size(), &vlen);
        if (rc == 0) {
          break;
        }
        if (rc == -2) {
          if (vlen > (64u << 20)) {
            scan_code = NV_OFF_CORRUPT;
            break;
          }
          rec.resize(vlen ? vlen : rec.size() * 2);
          continue;
        }
        if (rc != 1) {
          scan_code = NV_OFF_IOERR;
          break;
        }
        if (murmur_codec_open(old_codec, id, rec.data(), vlen, plain,
                              sizeof(plain)) != 4096 &&
            murmur_codec_open(new_codec, id, rec.data(), vlen, plain,
                              sizeof(plain)) != 4096) {
          scan_code = NV_OFF_CORRUPT;
          break;
        }
        uint32_t kid = 0;
        uint32_t target = 0;
        if (murmur_record_key_id(rec.data(), vlen, &kid)) {
          target = new_ring.current;
        }
        int n = murmur_codec_seal_as(new_codec, id, plain, sealed,
                                     sizeof(sealed), target, nullptr);
        krflat_wipe(plain, sizeof(plain));
        if (n <= 0) {
          scan_code = NV_OFF_IOERR;
          break;
        }
        uint8_t pkey[9];
        nv_page_key(id, pkey);
        char perr[512];
        if (nv_store_put(s, pkey, sizeof(pkey), sealed, (size_t)n, 0, perr,
                         sizeof(perr)) != 0) {
          scan_code = NV_OFF_IOERR;
          break;
        }
        chunk++;
        total++;
        if (fault_after > 0 && total >= fault_after) {
          char ferr[512];
          nv_store_sync(s, ferr, sizeof(ferr));
          scan_code = NV_OFF_IOERR;
          break;
        }
        if (chunk >= 100) {
          char serr[512];
          if (nv_store_sync(s, serr, sizeof(serr)) < 0) {
            scan_code = NV_OFF_IOERR;
            break;
          }
          chunk = 0;
        }
      }
      krflat_wipe(sealed, sizeof(sealed));
      krflat_wipe(rec.data(), rec.size());
      nv_scan_close(sc);
      murmur_codec_destroy(old_codec);
      murmur_codec_destroy(new_codec);
      if (scan_code != NV_OFF_OK) {
        code = scan_code;
        goto done;
      }
      {
        char serr[512];
        int sync_rc = 0;
        if (chunk > 0) {
          sync_rc = nv_store_sync(s, serr, sizeof(serr));
        }
        if (sync_rc < 0 ||
            nv_store_put(s, (const uint8_t *)kMetaKeyring,
                         strlen(kMetaKeyring), staged.data(), staged.size(),
                         1, serr, sizeof(serr)) != 0 ||
            nv_store_del(s, (const uint8_t *)kMetaRekey, strlen(kMetaRekey),
                         1, serr, sizeof(serr)) != 0) {
          code = NV_OFF_IOERR;
          goto done;
        }
      }
    }
  }
done:
  krflat_wipe(val.data(), val.size());
  nv_store_close(s);
  return code;
}
