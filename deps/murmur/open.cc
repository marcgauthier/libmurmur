// C++ control plane for murmur stores. Owns the store registry,
// lifecycle, per-store state, the background flusher, and the
// PRAGMA table; ported from pkgs/storage (engine/dir/pragma) and
// the bindings/nvfs Go registry.
//
// Lock order: g_mu (registry) -> OpenStore::mu (state). The flusher
// takes only the store lock; destruction (flusher join, codec and
// store teardown) runs outside g_mu. A store is destroyed only at
// refs==0, so no file or shell operation can be in flight on it:
// every op runs on an open file/shell that holds a reference
// (SQLite pairs each open with exactly one close; shells are
// explicitly closed).
//
// Interim Go callbacks (cold paths, killed by replication-native, see
// open.h): the nvMurmurExt*Go pair serves extension murmur_* PRAGMAs,
// and nvCloseFileGo drops a file's extension slot. Extension dispatch
// drops the store lock before calling out, because extension code may
// call back into this API. Key provisioning and seal crypto are fully
// native (PRAGMA key + keyring.h); no key material crosses into Go.
#include "open.h"

#include <errno.h>
#include <fcntl.h>
#ifndef _WIN32
#include <ftw.h>
#else
#include <filesystem>
#include <direct.h>
#include <io.h>
#define fsync _commit
#define lstat stat
#endif
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "../codec/os_random.h"
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <mutex>
#include <set>
#include <string>
#include <thread>
#include <vector>
#include <unordered_map>
#include <vector>

#include "../codec/murmur_codec.h"
#include "../keyring/keyring.h"
#include "../sqlite/sqlite3.h"
#include "krflat.h"

typedef struct NvStore NvStore;
typedef struct NvDb NvDb;

extern "C" {
// store.cc
NvStore *nv_store_open(const char *dir, int create, char *err,
                       size_t err_cap);
void nv_store_close(NvStore *s);
int nv_store_get(NvStore *s, const uint8_t *key, size_t klen, uint8_t *val,
                 size_t vcap, size_t *vlen, char *err, size_t err_cap);
int nv_store_put(NvStore *s, const uint8_t *key, size_t klen,
                 const uint8_t *val, size_t vlen, int sync, char *err,
                 size_t err_cap);
int nv_store_sync(NvStore *s, char *err, size_t err_cap);
int nv_store_checkpoint(NvStore *s, const char *dir, uint64_t *seq, char *err,
                        size_t err_cap);
int nv_store_set_options(NvStore *s, const char **keys, const char **vals,
                         int n, char *err, size_t err_cap);
int nv_store_set_db_option(NvStore *s, const char *name, const char *value,
                           char *err, size_t err_cap);
int nv_store_live_option(NvStore *s, const char *name, uint64_t *out,
                         char *err, size_t err_cap);
void nv_store_set_cache_capacity(NvStore *s, size_t bytes);
size_t nv_store_cache_capacity(NvStore *s);
// db.cc
NvDb *nv_db_create(NvStore *s, int cipher, int level,
                   const uint8_t page_key[32], int sealed,
                   const uint8_t active[32], uint32_t current_id,
                   const uint32_t *retired_ids, const uint8_t *retired_keys,
                   size_t retired_count, const uint8_t master[32],
                   size_t cache_cap, uint64_t init_size);
void nv_db_destroy(NvDb *d);
int nv_db_set_cipher(NvDb *d, int cipher);
int nv_db_set_level(NvDb *d, int level);
int nv_db_install_ring(NvDb *d, const uint8_t active[32], uint32_t current_id,
                       const uint32_t *retired_ids,
                       const uint8_t *retired_keys, size_t retired_count);
int nv_db_flush(NvDb *d);
int64_t nv_db_size(NvDb *d);
int nv_db_locked(NvDb *d);
// Interim Go extension callbacks (nvfs.go). Out-blobs are malloc'd
// by Go; C++ copies, wipes, and frees them.
int nvMurmurExtFileGo(uint64_t file, const char *name, const char *value,
                      int has_value, char *out, size_t cap, size_t *out_len);

// Page-scan API (store.cc) for offline/prune paths.
typedef struct NvScan NvScan;
NvScan *nv_scan_open(NvStore *s);
int nv_scan_next(NvScan *sc, uint64_t *id, uint8_t *vbuf, size_t vcap,
                 size_t *vlen);
void nv_scan_close(NvScan *sc);
int nvMurmurExtStoreGo(uint64_t handle, const char *name, const char *value,
                       int has_value, char *out, size_t cap, size_t *out_len);
void nvCloseFileGo(uint64_t file);
}

namespace {

// Metadata keys (pkgs/storage record.go).
constexpr char kMetaSize[] = "meta:size";
constexpr char kMetaCipher[] = "meta:cipher";
constexpr char kMetaStoreID[] = "meta:store_id";
constexpr char kMetaKeyring[] = "meta:keyring";

// Cipher ids match the C ABI (murmur_cipher_t) and Go Cipher.
constexpr int kCipherAES = 1;
constexpr int kCipherAEGIS = 2;

// KDF ids match Go KDFDirectHKDF/KDFArgon2ID.
constexpr uint8_t kKDFDirect = 0;
constexpr uint8_t kKDFArgon2ID = 1;

// Defaults mirror Go newEngine.
constexpr int kCachePagesDefault = 16384;
constexpr unsigned kFlushMsDefault = 250;
constexpr int kCompressionDefault = 3;
constexpr int kCompressionMax = 22;  // bindings/zstd MaxLevel
constexpr uint32_t kArgonTimeDefault = 3;
constexpr uint32_t kArgonMemoryDefault = 65536;
constexpr uint8_t kArgonThreadsDefault = 4;
constexpr size_t kStoreIDLen = 16;
constexpr size_t kMaxValue = 1 << 20;  // nativeMaxValue

void wipe(void *p, size_t n) {
  if (p && n) {
    volatile uint8_t *v = (volatile uint8_t *)p;
    for (size_t i = 0; i < n; i++) {
      v[i] = 0;
    }
  }
}

// parseUint parses a decimal unsigned integer with overflow
// rejection. Empty and non-digit input fails.
bool parseUint(const char *text, uint64_t *out) {
  if (!text || !*text) {
    return false;
  }
  uint64_t v = 0;
  for (const char *p = text; *p; p++) {
    if (*p < '0' || *p > '9') {
      return false;
    }
    uint64_t d = (uint64_t)(*p - '0');
    if (v > (UINT64_MAX - d) / 10) {
      return false;
    }
    v = v * 10 + d;
  }
  *out = v;
  return true;
}

std::string utoa(uint64_t v) {
  char buf[32];
  snprintf(buf, sizeof(buf), "%llu", (unsigned long long)v);
  return std::string(buf);
}

// ASCII-only lowercase. PRAGMA names and tokens are ASCII
// identifiers; Go strings.ToLower/EqualFold agree on those inputs.
std::string asciiLower(const std::string &s) {
  std::string o = s;
  for (char &c : o) {
    if (c >= 'A' && c <= 'Z') {
      c = (char)(c - 'A' + 'a');
    }
  }
  return o;
}

bool endsWith(const char *s, const char *suffix) {
  size_t sl = strlen(s), xl = strlen(suffix);
  return sl >= xl && memcmp(s + sl - xl, suffix, xl) == 0;
}

uint32_t loadU32LE(const uint8_t *p) {
  return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
         ((uint32_t)p[3] << 24);
}

uint64_t loadU64LE(const uint8_t *p) {
  uint64_t v = 0;
  for (int i = 7; i >= 0; i--) {
    v = (v << 8) | p[i];
  }
  return v;
}

struct OpenStore {
  std::string canon;
  NvStore *store = nullptr;
  // Live codec, null until PRAGMA key provisions. Atomic so VFS
  // files and shell holders can refresh a stale NULL without taking
  // the store lock (written once under st->mu at provision).
  std::atomic<NvDb *> db{nullptr};
  int refs = 0;
  std::mutex mu;
  // Staged PRAGMA key master + retained envelope for deferred
  // provisioning. Wiped at destroy.
  uint8_t stagedMaster[32] = {0};
  bool hasMaster = false;
  std::vector<uint8_t> keyringEnv;
  int cacheCap = 0;
  // PRAGMA/engine state.
  int cipher = kCipherAES;
  int compression = kCompressionDefault;
  uint32_t flushInterval = kFlushMsDefault;
  uint32_t bgThreads = 0;  // set at open (NumCPU equivalent)
  bool rocksSync = false;
  bool sealed = false;
  uint8_t kdf = kKDFDirect;  // envelope header once sealed
  uint32_t ringTime = 0;
  uint32_t ringMem = 0;
  uint8_t ringThreads = 0;
  uint32_t ringCurrent = 0;
  uint8_t stagedKDF = kKDFDirect;  // write-never, like Go
  uint32_t stagedTime = kArgonTimeDefault;
  uint32_t stagedMemory = kArgonMemoryDefault;
  uint8_t stagedThreads = kArgonThreadsDefault;
  bool hasSID = false;
  uint8_t storeID[kStoreIDLen] = {0};
  uint64_t committedSize = 0;
  uint64_t flushBatches = 0;
  // Flusher.
  std::thread flusher;
  bool flusherStarted = false;
  bool stop = false;
  std::condition_variable cv;
};

struct Entry {
  OpenStore *store = nullptr;
  bool isFile = false;
  bool readOnly = false;
};

std::mutex g_mu;
std::unordered_map<std::string, OpenStore *> g_stores;
std::unordered_map<uint64_t, Entry> g_entries;
uint64_t g_nextID = 0;
int g_cachePages = 0;
unsigned g_flushMs = 0;

uint32_t defaultBgThreads() {
  unsigned n = std::thread::hardware_concurrency();
  if (n == 0) {
    n = 4;
  }
  return (uint32_t)n;
}

// mkdirAll replicates os.MkdirAll(dir, 0700).
bool mkdirAll(const std::string &dir) {
#ifdef _WIN32
  if (dir.empty()) return false;
  std::error_code ec;
  auto path = std::filesystem::u8path(dir);
  std::filesystem::create_directories(path, ec);
  return !ec && std::filesystem::is_directory(path, ec);
#else
  if (dir.empty()) {
    return false;
  }
  std::string cur;
  cur.reserve(dir.size());
  for (size_t i = 0; i < dir.size(); i++) {
    cur.push_back(dir[i]);
    if (dir[i] != '/' && i + 1 < dir.size()) {
      continue;
    }
    if (cur.size() <= 1) {
      continue;  // root or empty
    }
    std::string part = cur;
    while (part.size() > 1 && part.back() == '/') {
      part.pop_back();
    }
    if (part.empty() || part == "/") {
      continue;
    }
    if (mkdir(part.c_str(), 0700) != 0 && errno != EEXIST) {
      return false;
    }
  }
  struct stat st;
  return stat(dir.c_str(), &st) == 0 && S_ISDIR(st.st_mode);
#endif
}

bool isDir(const char *path) {
  struct stat st;
  return stat(path, &st) == 0 && S_ISDIR(st.st_mode);
}

// getVal reads one metadata key with the Go getVal growth protocol:
// 8 KiB, doubling to 1 MiB, past which values fail closed.
int getVal(NvStore *s, const char *key, std::vector<uint8_t> *out,
           bool *found) {
  size_t cap = 8192;
  std::vector<uint8_t> buf(cap);
  for (;;) {
    char err[512];
    size_t n = 0;
    int rc = nv_store_get(s, (const uint8_t *)key, strlen(key), buf.data(),
                          buf.size(), &n, err, sizeof(err));
    if (rc == 1) {
      buf.resize(n);
      *out = std::move(buf);
      *found = true;
      return 0;
    }
    if (rc == 0) {
      *found = false;
      return 0;
    }
    if (rc == -2) {
      if (cap >= kMaxValue) {
        return NV_CTL_CORRUPT;
      }
      cap *= 2;
      buf.resize(cap);
      continue;
    }
    return NV_CTL_IOERR;
  }
}

int putMeta(OpenStore *st, const char *key, const uint8_t *val, size_t len) {
  char err[512];
  int rc = nv_store_put(st->store, (const uint8_t *)key, strlen(key), val,
                        len, st->rocksSync ? 1 : 0, err, sizeof(err));
  return rc == 0 ? NV_CTL_OK : NV_CTL_IOERR;
}

struct MetaProbe {
  int cipher = kCipherAES;
  uint64_t size = 0;
  bool hasSID = false;
  uint8_t sid[kStoreIDLen] = {0};
  std::vector<uint8_t> envelope;
};

// probeMeta ports nativeRecords.load: malformed metadata fails the
// open (Go maps every load error to CANTOPEN at the VFS).
int probeMeta(NvStore *s, MetaProbe *m) {
  std::vector<uint8_t> val;
  bool found = false;
  if (getVal(s, kMetaSize, &val, &found) != 0) {
    return NV_CTL_IOERR;
  }
  if (found) {
    std::string text((const char *)val.data(), val.size());
    uint64_t size = 0;
    // Decimal, no empty (strconv.ParseUint parity: reject empties
    // and non-digits; overflow rejects too).
    if (text.empty() || !parseUint(text.c_str(), &size)) {
      return NV_CTL_IOERR;  // malformed meta:size
    }
    m->size = size;
  }
  if (getVal(s, kMetaCipher, &val, &found) != 0) {
    return NV_CTL_IOERR;
  }
  if (found) {
    std::string text((const char *)val.data(), val.size());
    if (text == "aes256gcm") {
      m->cipher = kCipherAES;
    } else if (text == "aegis256") {
      m->cipher = kCipherAEGIS;
    } else {
      return NV_CTL_IOERR;  // unknown meta:cipher
    }
  }
  if (getVal(s, kMetaStoreID, &val, &found) != 0) {
    return NV_CTL_IOERR;
  }
  if (found) {
    if (val.size() != kStoreIDLen) {
      return NV_CTL_IOERR;  // malformed meta:store_id
    }
    memcpy(m->sid, val.data(), kStoreIDLen);
    m->hasSID = true;
  }
  if (getVal(s, kMetaKeyring, &val, &found) != 0) {
    return NV_CTL_IOERR;
  }
  if (found) {
    m->envelope = std::move(val);
  }
  return NV_CTL_OK;
}

// canonHexVal is defined below (same anonymous namespace).
int canonHexVal(char c);

// cryptoRand fills n bytes from the OS CSPRNG.
bool cryptoRand(uint8_t *out, size_t n) {
  return murmur_os_random(out, n) != 0;
}

// parseHex32 decodes exactly 64 hex chars into 32 bytes.
bool parseHex32(const char *text, uint8_t out[32]) {
  if (!text) {
    return false;
  }
  for (int i = 0; i < 32; i++) {
    int hi = canonHexVal(text[2 * i]);
    int lo = canonHexVal(text[2 * i + 1]);
    if (hi < 0 || lo < 0) {
      return false;
    }
    out[i] = (uint8_t)((hi << 4) | lo);
  }
  return text[64] == '\0';
}

// provisionLocked builds the codec from the staged PRAGMA key.
// Ports openKeysFor: unsealed stores use the master as the page key;
// sealed stores open the retained envelope (direct master, then
// passphrase fallback). The caller holds st->mu.
int provisionLocked(OpenStore *st) {
  if (st->db.load() != nullptr) {
    return NV_CTL_OK;  // already keyed
  }
  if (!st->hasMaster) {
    return NV_CTL_ERROR;
  }
  uint8_t pageKey[32];
  bool sealed = !st->keyringEnv.empty();
  uint8_t active[32] = {0};
  uint32_t current = 0;
  std::vector<uint32_t> retiredIDs;
  std::vector<uint8_t> retiredKeys;
  uint8_t kdf = kKDFDirect;
  uint32_t rtime = 0, rmem = 0;
  uint8_t rthreads = 0;
  if (!sealed) {
    memcpy(pageKey, st->stagedMaster, 32);
  } else {
    uint8_t sid[kStoreIDLen] = {0};
    if (st->hasSID) {
      memcpy(sid, st->storeID, kStoreIDLen);
    }
    KrFlatRing ring;
    int trc = krflat_open_trial(st->keyringEnv.data(), st->keyringEnv.size(),
                              st->stagedMaster, sid, &ring);
    if (trc != 0) {
      // Go maps every ring-open error to CORRUPT on the open path.
      return NV_CTL_CORRUPT;
    }
    memcpy(pageKey, ring.active, 32);
    memcpy(active, ring.active, 32);
    current = ring.current;
    retiredIDs = std::move(ring.retiredIDs);
    retiredKeys = std::move(ring.retiredKeys);
    kdf = ring.kdf;
    rtime = ring.time;
    rmem = ring.mem;
    rthreads = ring.threads;
  }
  size_t cap =
      st->cacheCap > 0 ? (size_t)st->cacheCap : (size_t)kCachePagesDefault;
  const uint8_t *activePtr = sealed ? active : nullptr;
  const uint32_t *rids = retiredIDs.empty() ? nullptr : retiredIDs.data();
  const uint8_t *rkeys = retiredKeys.empty() ? nullptr : retiredKeys.data();
  NvDb *db = nv_db_create(st->store, st->cipher, st->compression, pageKey,
                          sealed ? 1 : 0, activePtr, current, rids, rkeys,
                          retiredIDs.size(), st->stagedMaster, cap,
                          st->committedSize);
  wipe(pageKey, sizeof(pageKey));
  wipe(active, sizeof(active));
  if (!retiredKeys.empty()) {
    wipe(retiredKeys.data(), retiredKeys.size());
  }
  if (!db) {
    return NV_CTL_IOERR;
  }
  st->sealed = sealed;
  st->kdf = kdf;
  st->ringTime = rtime;
  st->ringMem = rmem;
  st->ringThreads = rthreads;
  st->ringCurrent = current;
  st->db.store(db);
  return NV_CTL_OK;
}

// createStore assembles one KEYLESS store outside the registry
// lock: mkdir, RocksDB open, metadata probe. Key provisioning runs
// later, at PRAGMA key (provisionLocked); the envelope is retained
// for it and st->db stays null until then.
OpenStore *createStore(const std::string &canon, bool fileReadOnly,
                       bool create, int cacheCap, unsigned flushMs) {
  if (create) {
    if (!mkdirAll(canon)) {
      return nullptr;
    }
  } else if (!isDir(canon.c_str())) {
    return nullptr;  // not a database directory
  }
  char err[512];
  NvStore *store =
      nv_store_open(canon.c_str(), (create && !fileReadOnly) ? 1 : 0, err,
                    sizeof(err));
  if (!store) {
    return nullptr;
  }
  MetaProbe meta;
  if (probeMeta(store, &meta) != NV_CTL_OK) {
    nv_store_close(store);
    return nullptr;
  }
  OpenStore *st = new (std::nothrow) OpenStore();
  if (!st) {
    nv_store_close(store);
    return nullptr;
  }
  st->canon = canon;
  st->store = store;
  st->cipher = meta.cipher;
  st->flushInterval = flushMs ? flushMs : kFlushMsDefault;
  st->bgThreads = defaultBgThreads();
  st->hasSID = meta.hasSID;
  if (meta.hasSID) {
    memcpy(st->storeID, meta.sid, kStoreIDLen);
  }
  st->committedSize = meta.size;
  st->keyringEnv = std::move(meta.envelope);
  st->cacheCap = cacheCap;
  return st;
}

void flusherLoop(OpenStore *st) {
  for (;;) {
    uint32_t interval;
    {
      std::unique_lock<std::mutex> l(st->mu);
      interval = st->flushInterval ? st->flushInterval : kFlushMsDefault;
      st->cv.wait_for(l, std::chrono::milliseconds(interval),
                      [&] { return st->stop; });
      if (st->stop) {
        return;
      }
    }
    // Sync outside the store lock: seals plus the RocksDB batch
    // take milliseconds, and every control op takes the lock.
    // Keyless stores have nothing to flush.
    NvDb *db = st->db.load();
    if (!db) {
      continue;
    }
    if (nv_db_flush(db) != 0) {
      continue;
    }
    char err[512];
    int rc = nv_store_sync(st->store, err, sizeof(err));
    if (rc == 1) {
      std::lock_guard<std::mutex> l(st->mu);
      st->flushBatches++;
    }
  }
}

void startFlusher(OpenStore *st) {
  std::lock_guard<std::mutex> l(st->mu);
  st->flusherStarted = true;
  st->flusher = std::thread(flusherLoop, st);
}

// destroyStore stops the flusher, runs the final sync, and releases
// the codec and the store. Callers hold no locks.
void destroyStore(OpenStore *st) {
  {
    std::lock_guard<std::mutex> l(st->mu);
    st->stop = true;
    st->cv.notify_all();
  }
  if (st->flusherStarted && st->flusher.joinable()) {
    st->flusher.join();
  }
  NvDb *db = st->db.load();
  if (db) {
    if (nv_db_flush(db) == 0) {
      char err[512];
      if (nv_store_sync(st->store, err, sizeof(err)) == 1) {
        st->flushBatches++;
      }
    }
    nv_db_destroy(db);
  }
  nv_store_close(st->store);
  wipe(st->storeID, sizeof(st->storeID));
  wipe(st->stagedMaster, sizeof(st->stagedMaster));
  delete st;
}

// ---- PRAGMA table (ports pkgs/storage/pragma.go verbatim) ----

struct PragmaOut {
  int code = NV_CTL_NOTFOUND;
  std::string text;
  bool extension = false;  // caller runs the ext callback unlocked
};

bool asciiEqualFold(const std::string &a, const char *b) {
  size_t n = strlen(b);
  if (a.size() != n) {
    return false;
  }
  for (size_t i = 0; i < n; i++) {
    char x = a[i], y = b[i];
    if (x >= 'A' && x <= 'Z') {
      x = (char)(x - 'A' + 'a');
    }
    if (y >= 'A' && y <= 'Z') {
      y = (char)(y - 'A' + 'a');
    }
    if (x != y) {
      return false;
    }
  }
  return true;
}

// sealLocked creates, persists, and installs a fresh keyring,
// fully native (murmur_kr_create + open). The caller holds st->mu.
// The seal master is the explicit per-call master when present,
// else the staged PRAGMA key; keyless stores provision first.
int sealLocked(OpenStore *st, uint8_t kdf, bool hasMaster,
               const uint8_t *master) {
  uint8_t effMaster[32];
  if (hasMaster && master) {
    memcpy(effMaster, master, 32);
  } else if (st->hasMaster) {
    memcpy(effMaster, st->stagedMaster, 32);
  } else {
    return NV_CTL_ERROR;  // Go sealFor without a master: CodeError
  }
  auto wipeEff = [&] { wipe(effMaster, sizeof(effMaster)); };
  if (!st->hasMaster && hasMaster && master) {
    memcpy(st->stagedMaster, master, 32);
    st->hasMaster = true;
  }
  int rc = provisionLocked(st);
  if (rc != NV_CTL_OK) {
    wipeEff();
    return rc;
  }
  uint8_t sid[kStoreIDLen];
  if (st->hasSID) {
    memcpy(sid, st->storeID, kStoreIDLen);
  } else if (!cryptoRand(sid, kStoreIDLen)) {
    wipeEff();
    return NV_CTL_ERROR;
  }
  // Direct-HKDF seals take the master; Argon2 seals take it as
  // passphrase bytes; direct seals stage no Argon2 params (Go
  // zeroes them).
  bool direct = kdf == kKDFDirect;
  uint32_t atime = direct ? 0 : st->stagedTime;
  uint32_t amem = direct ? 0 : st->stagedMemory;
  uint8_t athreads = direct ? 0 : st->stagedThreads;
  const uint8_t *cMaster = direct ? effMaster : nullptr;
  const uint8_t *cPass = direct ? nullptr : effMaster;
  uint8_t *env = nullptr;
  size_t envLen = 0;
  int krc = murmur_kr_create(kdf, atime, amem, athreads, nullptr, 0, sid, sid,
                             cMaster, direct ? 32 : 0, cPass,
                             direct ? 0 : 32, &env, &envLen);
  if (krc != MURMUR_KR_OK || !env) {
    if (env) {
      murmur_kr_free(env);
    }
    wipeEff();
    return NV_CTL_ERROR;  // Go Create failure: CodeError
  }
  KrFlatRing ring;
  rc = krflat_open_trial(env, envLen, effMaster, sid, &ring) == 0
           ? NV_CTL_OK
           : NV_CTL_CORRUPT;
  wipeEff();
  if (rc != NV_CTL_OK) {
    wipe(env, envLen);
    murmur_kr_free(env);
    return NV_CTL_CORRUPT;
  }
  // Order note vs Go: Go persists a minted store id BEFORE creating
  // the envelope; here the envelope exists first, so a failed seal
  // persists nothing. Retry-visible state is identical: the seal
  // flag and the envelope appear together.
  if (!st->hasSID) {
    if (putMeta(st, kMetaStoreID, sid, kStoreIDLen) != NV_CTL_OK) {
      wipe(env, envLen);
      murmur_kr_free(env);
      return NV_CTL_IOERR;
    }
    memcpy(st->storeID, sid, kStoreIDLen);
    st->hasSID = true;
  }
  if (putMeta(st, kMetaKeyring, env, envLen) != NV_CTL_OK) {
    wipe(env, envLen);
    murmur_kr_free(env);
    return NV_CTL_IOERR;
  }
  st->keyringEnv.assign(env, env + envLen);
  wipe(env, envLen);
  murmur_kr_free(env);
  NvDb *db = st->db.load();
  const uint32_t *rids =
      ring.retiredIDs.empty() ? nullptr : ring.retiredIDs.data();
  const uint8_t *rkeys =
      ring.retiredKeys.empty() ? nullptr : ring.retiredKeys.data();
  rc = nv_db_install_ring(db, ring.active, ring.current, rids, rkeys,
                          ring.retiredIDs.size());
  if (rc != 0) {
    return NV_CTL_IOERR;
  }
  st->sealed = true;
  st->kdf = kdf;
  // Direct-HKDF seals stage no Argon2 params (Go zeroes them), so
  // the sealed header reads back zeros, matching reopen decodes.
  st->ringTime = (kdf == kKDFDirect) ? 0 : st->stagedTime;
  st->ringMem = (kdf == kKDFDirect) ? 0 : st->stagedMemory;
  st->ringThreads = (kdf == kKDFDirect) ? 0 : st->stagedThreads;
  st->ringCurrent = ring.current;
  if (hasMaster && master) {
    // The persisted envelope is now the explicit master's: keep the
    // staged master coherent for any later SQL seal attempts.
    memcpy(st->stagedMaster, master, 32);
    st->hasMaster = true;
  }
  return NV_CTL_OK;
}

// setParamLocked ports Engine.SetParam. Stores are alive by
// construction (refs pin them), so the Go closed check has no
// counterpart; Go shells guard use-after-close themselves.
int setParamLocked(OpenStore *st, int param, uint64_t value, bool readOnly,
                   bool hasMaster = false, const uint8_t *master = nullptr) {
  if (readOnly) {
    return NV_CTL_READONLY;
  }
  bool ok = false;
  switch (param) {
    case NV_CTL_PARAM_KDF:
      ok = value <= 1;
      break;
    case NV_CTL_PARAM_TIME:
      ok = value >= 1 && value <= 32;
      break;
    case NV_CTL_PARAM_MEMORY:
      ok = value >= 1024 && value <= 16777216;
      break;
    case NV_CTL_PARAM_THREADS:
      ok = value >= 1 && value <= 32;
      break;
    default:
      return NV_CTL_MISUSE;
  }
  if (!ok) {
    return NV_CTL_ERROR;
  }
  if (st->sealed) {
    return NV_CTL_BUSY;
  }
  switch (param) {
    case NV_CTL_PARAM_TIME:
      st->stagedTime = (uint32_t)value;
      return NV_CTL_OK;
    case NV_CTL_PARAM_MEMORY:
      st->stagedMemory = (uint32_t)value;
      return NV_CTL_OK;
    case NV_CTL_PARAM_THREADS:
      st->stagedThreads = (uint8_t)value;
      return NV_CTL_OK;
    default:
      break;
  }
  return sealLocked(st, (uint8_t)value, hasMaster, master);
}

PragmaOut serveKDFLocked(OpenStore *st, const std::string &name,
                         const char *value, bool hasValue, bool readOnly) {
  PragmaOut r;
  std::string current;
  int param = 0;
  if (name == "murmur_kdf") {
    if (st->sealed) {
      current = (st->kdf == kKDFArgon2ID) ? "argon2id" : "direct";
    } else if (st->stagedKDF == kKDFArgon2ID) {
      current = "argon2id";
    } else {
      current = "direct";
    }
    param = NV_CTL_PARAM_KDF;
  } else if (name == "murmur_kdf_time") {
    current = utoa(st->sealed ? st->ringTime : st->stagedTime);
    param = NV_CTL_PARAM_TIME;
  } else if (name == "murmur_kdf_memory_kib") {
    current = utoa(st->sealed ? st->ringMem : st->stagedMemory);
    param = NV_CTL_PARAM_MEMORY;
  } else {
    current = utoa(st->sealed ? st->ringThreads : st->stagedThreads);
    param = NV_CTL_PARAM_THREADS;
  }
  if (!hasValue) {
    r.code = NV_CTL_OK;
    r.text = current;
    return r;
  }
  if (readOnly) {
    r.code = NV_CTL_READONLY;
    r.text = "cannot set " + name + " on a read-only connection";
    return r;
  }
  if (st->sealed) {
    r.code = NV_CTL_BUSY;
    r.text = name + " cannot change once sealed";
    return r;
  }
  if (param == NV_CTL_PARAM_KDF) {
    uint64_t v;
    std::string low = value ? asciiLower(value) : "";
    if (low == "direct") {
      v = kKDFDirect;
    } else if (low == "argon2id") {
      v = kKDFArgon2ID;
    } else {
      r.code = NV_CTL_ERROR;
      r.text = "murmur_kdf must be direct or argon2id";
      return r;
    }
    int rc = setParamLocked(st, param, v, readOnly);
    if (rc != NV_CTL_OK) {
      r.code = rc;
      return r;
    }
    r.code = NV_CTL_OK;
    r.text = (v == kKDFArgon2ID) ? "argon2id" : "direct";
    return r;
  }
  uint64_t v = 0;
  if (!value || !parseUint(value, &v)) {
    r.code = NV_CTL_ERROR;
    r.text = name + " requires an unsigned integer";
    return r;
  }
  int rc = setParamLocked(st, param, v, readOnly);
  if (rc != NV_CTL_OK) {
    r.code = rc;
    if (rc == NV_CTL_ERROR) {
      r.text = name + " out of range";
    }
    return r;
  }
  r.code = NV_CTL_OK;
  if (param == NV_CTL_PARAM_TIME) {
    r.text = utoa(st->stagedTime);
  } else if (param == NV_CTL_PARAM_MEMORY) {
    r.text = utoa(st->stagedMemory);
  } else {
    r.text = utoa(st->stagedThreads);
  }
  return r;
}

bool rocksIsIOError(const char *msg) {
  return msg && strstr(msg, "IO error") != nullptr;
}

PragmaOut serveRocksDBLocked(OpenStore *st, const std::string &name,
                             const char *value, bool hasValue, bool readOnly) {
  PragmaOut r;
  struct Opt {
    const char *backend;  // live knob, "" for engine-side
    uint64_t min;
    uint64_t max;
  };
  Opt opt = {"", 0, 0};
  int which = -1;  // 0 sync, 1 wbuf, 2 wbufnum, 3 cache, 4 bgjobs
  std::string low = asciiLower(name);
  if (low == "rocksdb_sync") {
    opt = {"", 0, 1};
    which = 0;
  } else if (low == "rocksdb_write_buffer_size") {
    opt = {"write_buffer_size", 65536, 9223372036854775807ull};
    which = 1;
  } else if (low == "rocksdb_max_write_buffer_number") {
    opt = {"max_write_buffer_number", 2, 2147483647};
    which = 2;
  } else if (low == "rocksdb_block_cache_bytes") {
    opt = {"", 0, 9223372036854775807ull};
    which = 3;
  } else if (low == "rocksdb_max_background_jobs") {
    opt = {"max_background_jobs", 1, 2147483647};
    which = 4;
  } else {
    r.code = NV_CTL_NOTFOUND;
    return r;
  }
  // Native-only table: file engines keep the Go table, so the Go
  // hasRocks branch is unreachable here.
  if (hasValue && readOnly) {
    r.code = NV_CTL_READONLY;
    r.text = "cannot set " + name + " on a read-only connection";
    return r;
  }
  uint64_t number = 0;
  if (hasValue) {
    uint64_t n = 0;
    if (!value || !parseUint(value, &n) || n < opt.min || n > opt.max) {
      r.code = NV_CTL_ERROR;
      r.text = name + " requires an integer from " + utoa(opt.min) +
               " through " + utoa(opt.max);
      return r;
    }
    number = n;
  }
  if (hasValue) {
    const char *failed = nullptr;
    char err[512];
    err[0] = '\0';
    switch (which) {
      case 0:
        st->rocksSync = number != 0;
        break;
      case 3:
        nv_store_set_cache_capacity(st->store, (size_t)number);
        break;
      case 1:
      case 2: {
        const char *ks[1] = {opt.backend};
        std::string vs = utoa(number);
        const char *vsa[1] = {vs.c_str()};
        if (nv_store_set_options(st->store, ks, vsa, 1, err, sizeof(err)) !=
            0) {
          failed = err;
        }
        break;
      }
      case 4: {
        std::string vs = utoa(number);
        if (nv_store_set_db_option(st->store, opt.backend, vs.c_str(), err,
                                   sizeof(err)) != 0) {
          failed = err;
        }
        break;
      }
      default:
        break;
    }
    if (failed) {
      r.text = name + ": " + failed;
      r.code = rocksIsIOError(failed) ? NV_CTL_IOERR : NV_CTL_ERROR;
      return r;
    }
  }
  switch (which) {
    case 0:
      number = st->rocksSync ? 1 : 0;
      break;
    case 3:
      number = (uint64_t)nv_store_cache_capacity(st->store);
      break;
    default: {
      char err[512];
      err[0] = '\0';
      uint64_t live = 0;
      if (nv_store_live_option(st->store, opt.backend, &live, err,
                               sizeof(err)) != 0) {
        r.code = NV_CTL_ERROR;
        r.text = name + ": " + err;
        return r;
      }
      number = live;
      break;
    }
  }
  r.code = NV_CTL_OK;
  r.text = utoa(number);
  return r;
}

PragmaOut serveBgThreadsLocked(OpenStore *st, const char *value, bool hasValue,
                               bool readOnly) {
  PragmaOut r;
  if (hasValue && readOnly) {
    r.code = NV_CTL_READONLY;
    return r;
  }
  if (hasValue) {
    uint64_t n = 0;
    if (!value || !parseUint(value, &n) || n == 0 || n > 256) {
      r.code = NV_CTL_ERROR;
      r.text = "background_threads requires an integer from 1 through 256";
      return r;
    }
    st->bgThreads = (uint32_t)n;
  }
  r.code = NV_CTL_OK;
  r.text = utoa(st->bgThreads);
  return r;
}

// keyBytesLocked stages a raw 32-byte master and provisions the
// codec. Shared by PRAGMA key (hex form) and nvStoreKey (the
// explicit shell API): one behavior, two spellings. A different
// master once keyed is MISUSE (rekey is separate).
PragmaOut keyBytesLocked(OpenStore *st, const uint8_t master[32]) {
  PragmaOut r;
  if (st->db.load() != nullptr) {
    if (!st->hasMaster || memcmp(st->stagedMaster, master, 32) != 0) {
      r.code = NV_CTL_MISUSE;
      r.text = "key already set";
    } else {
      r.code = NV_CTL_OK;
    }
    return r;
  }
  memcpy(st->stagedMaster, master, 32);
  st->hasMaster = true;
  int rc = provisionLocked(st);
  if (rc != NV_CTL_OK) {
    wipe(st->stagedMaster, sizeof(st->stagedMaster));
    st->hasMaster = false;
    r.code = rc;
    r.text = (rc == NV_CTL_CORRUPT) ? "key does not unlock the keyring"
                                    : "key provisioning failed";
    return r;
  }
  r.code = NV_CTL_OK;
  return r;
}

// serveKeyLocked stages the PRAGMA key master and provisions the
// codec. Write-only: reads answer empty. Allowed on read-only
// connections (reads need keys).
PragmaOut serveKeyLocked(OpenStore *st, const char *value, bool hasValue) {
  PragmaOut r;
  if (!hasValue) {
    r.code = NV_CTL_OK;
    return r;
  }
  uint8_t master[32];
  if (!parseHex32(value, master)) {
    r.code = NV_CTL_ERROR;
    r.text = "key must be 64 hex characters";
    return r;
  }
  r = keyBytesLocked(st, master);
  wipe(master, sizeof(master));
  return r;
}

// ---- native backup (checkpoint + byte-exact manifest) ----

// backupCipherOK mirrors Go CipherCharsetOK: nonempty [a-z0-9]+.
// The manifest embeds the token raw, so anything else is rejected.
bool backupCipherOK(const char *cipher) {
  if (!cipher || !*cipher) {
    return false;
  }
  for (const char *p = cipher; *p; p++) {
    char c = *p;
    if ((c < 'a' || c > 'z') && (c < '0' || c > '9')) {
      return false;
    }
  }
  return true;
}

void hexLower16(const uint8_t id[16], char out[33]) {
  static const char digits[] = "0123456789abcdef";
  for (int i = 0; i < 16; i++) {
    out[2 * i] = digits[id[i] >> 4];
    out[2 * i + 1] = digits[id[i] & 15];
  }
  out[32] = '\0';
}

#ifdef _WIN32
void removeTree(const char *path) {
  std::error_code ec;
  std::filesystem::remove_all(std::filesystem::u8path(path), ec);
}
void fsyncDirBestEffort(const char *) {}
#else
int removeTreeCb(const char *path, const struct stat *, int,
                 struct FTW *) {
  return remove(path);
}

// removeTree deletes a failed backup artifact best-effort,
// mirroring Go RemoveBackup.
void removeTree(const char *path) {
  nftw(path, removeTreeCb, 16, FTW_DEPTH | FTW_PHYS);
}

void fsyncDirBestEffort(const char *path) {
  int fd = open(path, O_RDONLY | O_DIRECTORY);
  if (fd >= 0) {
    (void)fsync(fd);
    close(fd);
  }
}

#endif

// writeBackupManifest mirrors Go WriteBackupManifest byte-exactly:
// flat object, no spaces, trailing newline, O_EXCL 0600, synced.
int writeBackupManifest(const char *dest, const char *cipher,
                        const uint8_t group[16], const uint8_t node[16],
                        uint64_t seq) {
  char ghex[33], nhex[33];
  hexLower16(group, ghex);
  hexLower16(node, nhex);
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  int64_t ms =
      (int64_t)ts.tv_sec * 1000 + (int64_t)ts.tv_nsec / 1000000;
  if (ms < 0) {
    ms = 0;
  }
  std::string body = "{\"format_version\":1,\"cipher\":\"";
  body += cipher;
  body += "\",\"group_id\":\"";
  body += ghex;
  body += "\",\"node_id\":\"";
  body += nhex;
  body += "\",\"rocksdb_seq\":";
  body += std::to_string(seq);
  body += ",\"created_unix_ms\":";
  body += std::to_string(ms);
  body += "}\n";
  std::string path = std::string(dest) + "/manifest.json";
  int fd = open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL, 0600);
  if (fd < 0) {
    return -1;
  }
  bool ok = false;
  size_t off = 0;
  while (off < body.size()) {
    ssize_t n =
        write(fd, body.data() + off, body.size() - off);
    if (n <= 0) {
      break;
    }
    off += (size_t)n;
  }
  if (off == body.size() && fsync(fd) == 0) {
    ok = true;
  }
  if (close(fd) != 0) {
    ok = false;
  }
  if (!ok) {
    unlink(path.c_str());
    return -1;
  }
  fsyncDirBestEffort(dest);
  // Parent sync mirrors Go filepath.Dir (best-effort either way).
  std::string parent = std::string(dest);
  size_t slash = parent.find_last_of('/');
  if (slash == std::string::npos) {
    fsyncDirBestEffort(".");
  } else if (slash == 0) {
    fsyncDirBestEffort("/");
  } else {
    fsyncDirBestEffort(parent.substr(0, slash).c_str());
  }
  return 0;
}

PragmaOut serveCompressionLocked(OpenStore *st, const char *value,
                                 bool hasValue, bool readOnly) {
  PragmaOut r;
  if (hasValue) {
    if (readOnly) {
      r.code = NV_CTL_READONLY;
      r.text = "cannot set compression on a read-only connection";
      return r;
    }
    int level = -1;
    std::string text = value ? value : "";
    if (asciiEqualFold(text, "none")) {
      level = 0;
    } else if (text.size() >= 4 &&
               asciiEqualFold(text.substr(0, 4), "zstd")) {
      uint64_t n = 0;
      if (parseUint(text.c_str() + 4, &n) && n >= 1 &&
          n <= (uint64_t)kCompressionMax) {
        level = (int)n;
      }
    }
    if (level < 0) {
      r.code = NV_CTL_ERROR;
      r.text = "compression must be none or zstd1 through zstd22";
      return r;
    }
    NvDb *db = st->db.load();
    if (db) {
      if (nv_db_set_level(db, level) != 0) {
        r.code = NV_CTL_ERROR;
        r.text = "could not apply compression setting";
        return r;
      }
    }
    // Keyless stores stage the level; provisionLocked applies it.
    st->compression = level;
  }
  r.code = NV_CTL_OK;
  if (st->compression == 0) {
    r.text = "none";
  } else {
    r.text = "zstd" + utoa((uint64_t)st->compression);
  }
  return r;
}

PragmaOut serveFlushLocked(OpenStore *st, const char *value, bool hasValue) {
  PragmaOut r;
  if (hasValue) {
    uint64_t n = 0;
    if (!value || !parseUint(value, &n)) {
      r.code = NV_CTL_ERROR;
      r.text = "flush_interval_ms requires an unsigned integer";
      return r;
    }
    if (n == 0) {
      n = kFlushMsDefault;
    }
    if (n > 0xFFFFFFFFu) {
      r.code = NV_CTL_ERROR;
      r.text = "flush_interval_ms requires an unsigned integer";
      return r;
    }
    st->flushInterval = (uint32_t)n;
  }
  r.code = NV_CTL_OK;
  r.text = utoa(st->flushInterval);
  return r;
}

const char *cipherName(int c) {
  if (c == kCipherAES) {
    return "aes256gcm";
  }
  if (c == kCipherAEGIS) {
    return "aegis256";
  }
  return "unspecified";
}

PragmaOut serveCipherLocked(OpenStore *st, const char *value, bool hasValue,
                            bool readOnly, bool locked) {
  PragmaOut r;
  if (hasValue) {
    if (readOnly) {
      r.code = NV_CTL_READONLY;
      r.text = "cannot set cipher on a read-only connection";
      return r;
    }
    int c = 0;
    std::string text = value ? value : "";
    if (asciiEqualFold(text, "aes256gcm")) {
      c = kCipherAES;
    } else if (asciiEqualFold(text, "aegis256")) {
      c = kCipherAEGIS;
    } else {
      r.code = NV_CTL_ERROR;
      r.text = "cipher must be aes256gcm or aegis256";
      return r;
    }
    // Engine.SetCipher port (its readOnly pre-check is subsumed by
    // the check above, as in Go where pragmaCipher runs first).
    if (st->cipher != c) {
      NvDb *db = st->db.load();
      uint64_t size = db ? (uint64_t)nv_db_size(db) : st->committedSize;
      if (size != 0 || locked) {
        r.code = NV_CTL_BUSY;
        r.text =
            "cipher can only be changed on an empty database outside a "
            "transaction";
        return r;
      }
      if (db && nv_db_set_cipher(db, c) != 0) {
        r.code = NV_CTL_IOERR;
        r.text = "could not persist cipher setting";
        return r;
      }
      const char *persist = cipherName(c);
      if (putMeta(st, kMetaCipher, (const uint8_t *)persist, strlen(persist)) !=
          NV_CTL_OK) {
        if (db) {
          nv_db_set_cipher(db, st->cipher);
        }
        r.code = NV_CTL_IOERR;
        r.text = "could not persist cipher setting";
        return r;
      }
      st->cipher = c;
    }
  }
  r.code = NV_CTL_OK;
  r.text = cipherName(st->cipher);
  return r;
}

// serveLocked serves the engine PRAGMA table with st->mu held. Names
// outside the engine KDF table but under murmur_ return
// extension=true; the caller drops the lock and runs the Go
// extension callback.
PragmaOut serveLocked(OpenStore *st, const std::string &name,
                      const char *value, bool hasValue, bool readOnly,
                      bool locked) {
  PragmaOut r;
  std::string low = asciiLower(name);
  if (low.compare(0, 7, "murmur_") == 0) {
    if (low == "murmur_kdf" || low == "murmur_kdf_time" ||
        low == "murmur_kdf_memory_kib" || low == "murmur_kdf_threads") {
      return serveKDFLocked(st, low, value, hasValue, readOnly);
    }
    r.extension = true;
    return r;
  }
  if (low == "background_threads") {
    return serveBgThreadsLocked(st, value, hasValue, readOnly);
  }
  if (low == "compression") {
    return serveCompressionLocked(st, value, hasValue, readOnly);
  }
  if (low == "flush_interval_ms") {
    return serveFlushLocked(st, value, hasValue);
  }
  if (low == "cipher") {
    return serveCipherLocked(st, value, hasValue, readOnly, locked);
  }
  if (low == "key") {
    return serveKeyLocked(st, value, hasValue);
  }
  if (low == "journal_mode") {
    std::string text = value ? value : "";
    if (hasValue && !asciiEqualFold(text, "delete")) {
      r.code = NV_CTL_ERROR;
      r.text = "sqlite-murmur requires journal_mode=DELETE";
      return r;
    }
    r.code = NV_CTL_NOTFOUND;
    return r;
  }
  if (low == "mmap_size") {
    r.code = NV_CTL_OK;
    r.text = "0";
    return r;
  }
  if (low.compare(0, 8, "rocksdb_") == 0) {
    return serveRocksDBLocked(st, name, value, hasValue, readOnly);
  }
  r.code = NV_CTL_NOTFOUND;
  return r;
}

// canonCleanInPlace replicates Go filepath.Clean lexically (unix)
// on buf[0,n), returning the cleaned length (0 means ".", which the
// caller substitutes). Output never exceeds consumed input (w<=r at
// every write, proven by the '/' skip preceding each separator
// write), so in-place is exact and allocates nothing.
size_t canonCleanInPlace(char *buf, size_t n) {
  if (n == 0) {
    return 0;
  }
  bool rooted = buf[0] == '/';
  size_t w = 0, dotdot = 0, r = 0;
  if (rooted) {
    buf[w++] = '/';
    r = 1;
    dotdot = 1;
  }
  while (r < n) {
    if (buf[r] == '/') {
      r++;
    } else if (buf[r] == '.' && (r + 1 == n || buf[r + 1] == '/')) {
      r++;
    } else if (buf[r] == '.' && r + 1 < n && buf[r + 1] == '.' &&
               (r + 2 == n || buf[r + 2] == '/')) {
      r += 2;
      if (w > dotdot) {
        w--;
        // Scan back to the separator, which stays excluded (w points
        // at it, exactly Go's lazy-buffer convention).
        while (w > dotdot && buf[w] != '/') {
          w--;
        }
      } else if (!rooted) {
        if (w > 0) {
          buf[w++] = '/';
        }
        buf[w++] = '.';
        buf[w++] = '.';
        dotdot = w;
      }
    } else {
      if ((rooted && w != 1) || (!rooted && w != 0)) {
        buf[w++] = '/';
      }
      for (; r < n && buf[r] != '/'; r++) {
        buf[w++] = buf[r];
      }
    }
  }
  return w;
}

int canonHexVal(char c) {
  if (c >= '0' && c <= '9') {
    return c - '0';
  }
  if (c >= 'a' && c <= 'f') {
    return c - 'a' + 10;
  }
  if (c >= 'A' && c <= 'F') {
    return c - 'A' + 10;
  }
  return -1;
}

}  // namespace

// murmurCanonName replicates Go sqlite.CanonicalPath exactly (URI
// strip, percent-decode, absolute+Clean) so stores unify across
// spellings. Moved here from vfs.cc: the registry is the single
// owner now. TestCanonDifferential pins parity with the Go form.
std::string murmurCanonName(const char *name) {
#ifdef _WIN32
  std::string path = name ? name : "";
  // SQLite has already decoded URI names before passing them to the VFS.
  if (path.compare(0, 5, "file:") == 0) path.erase(0, 5);
  std::error_code ec;
  auto full = std::filesystem::absolute(std::filesystem::u8path(path), ec);
  if (ec) return path;
  std::string result = full.lexically_normal().generic_u8string();
  // Windows paths are case insensitive; use one registry identity.
  for (char &c : result) if (c >= 'A' && c <= 'Z') c += 'a' - 'A';
  return result;
#else
  if (name && name[0] == '/') {
    size_t n = strlen(name);
    if (n < 1024) {
      char buf[1024];
      memcpy(buf, name, n);
      size_t m = canonCleanInPlace(buf, n);
      if (m == 0) {
        return ".";
      }
      return std::string(buf, m);
    }
    std::string s(name, n);
    size_t m = canonCleanInPlace(&s[0], n);
    if (m == 0) {
      return ".";
    }
    s.resize(m);
    return s;
  }
  std::string s = name ? name : "";
  if (s.compare(0, 5, "file:") == 0) {
    s.erase(0, 5);
    size_t q = s.find('?');
    if (q != std::string::npos) {
      s.erase(q);
    }
    if (s.compare(0, 2, "//") == 0) {
      size_t slash = s.find('/', 2);
      if (slash != std::string::npos) {
        s.erase(0, slash);
      } else {
        s.clear();
      }
    }
    if (s.find('%') != std::string::npos) {
      std::string d;
      d.reserve(s.size());
      for (size_t i = 0; i < s.size(); i++) {
        if (s[i] == '%' && i + 2 < s.size()) {
          int hi = canonHexVal(s[i + 1]);
          int lo = canonHexVal(s[i + 2]);
          if (hi >= 0 && lo >= 0) {
            d.push_back((char)(hi << 4 | lo));
            i += 2;
            continue;
          }
        }
        d.push_back(s[i]);
      }
      s.swap(d);
    }
  }
  if (!s.empty() && s[0] == '/') {
    size_t m = canonCleanInPlace(&s[0], s.size());
    if (m == 0) {
      return ".";
    }
    s.resize(m);
    return s;
  }
  char *cwd = getcwd(nullptr, 0);
  if (!cwd) {
    return s;
  }
  std::string abs = std::string(cwd) + "/" + s;
  free(cwd);
  size_t m = canonCleanInPlace(&abs[0], abs.size());
  if (m == 0) {
    return ".";
  }
  abs.resize(m);
  return abs;
#endif
}

namespace {

// openRef runs the shared get-or-create loop (ports nvOpenDbGo,
// including the losing-race recheck): attach to the live store when
// present, else assemble one outside the lock and publish it.
// wantFile mints a file entry (per-file readOnly); otherwise a shell
// entry. Offline mutation tools (rekey/verify/repair) bypass the
// registry with independent LOCK-serialized opens instead.
int openRef(const std::string &canon, bool fileRO, bool create, int cacheCap,
            unsigned flushMs, bool wantFile, uint64_t *dbOut, uint64_t *idOut,
            uint64_t *storeOut) {
  for (;;) {
    std::unique_lock<std::mutex> l(g_mu);
    auto it = g_stores.find(canon);
    if (it != g_stores.end()) {
      OpenStore *live = it->second;
      live->refs++;
      uint64_t id = ++g_nextID;
      g_entries[id] = Entry{live, wantFile, fileRO};
      l.unlock();
      *dbOut = (uint64_t)live->db.load();
      *idOut = id;
      if (storeOut) {
        *storeOut = (uint64_t)live->store;
      }
      return SQLITE_OK;
    }
    l.unlock();
    OpenStore *st = createStore(canon, fileRO, create, cacheCap, flushMs);
    l.lock();
    if (!st) {
      // A racing open may have won while we failed: recheck before
      // reporting CANTOPEN.
      auto won = g_stores.find(canon);
      if (won != g_stores.end()) {
        OpenStore *live = won->second;
        live->refs++;
        uint64_t id = ++g_nextID;
        g_entries[id] = Entry{live, wantFile, fileRO};
        l.unlock();
        *dbOut = (uint64_t)live->db.load();
        *idOut = id;
        if (storeOut) {
          *storeOut = (uint64_t)live->store;
        }
        return SQLITE_OK;
      }
      l.unlock();
      return SQLITE_CANTOPEN;
    }
    if (g_stores.find(canon) != g_stores.end()) {
      // Lost the creation race: release the redundant store.
      l.unlock();
      destroyStore(st);
      continue;
    }
    uint64_t id = ++g_nextID;
    st->refs = 1;
    g_stores[canon] = st;
    Entry e;
    e.store = st;
    e.isFile = wantFile;
    e.readOnly = fileRO;
    g_entries[id] = e;
    l.unlock();
    startFlusher(st);
    *dbOut = (uint64_t)st->db.load();
    *idOut = id;
    if (storeOut) {
      *storeOut = (uint64_t)st->store;
    }
    return SQLITE_OK;
  }
}

// closeEntry drops one file/shell id, destroying its store on last
// close. Go callbacks run outside the registry lock.
int closeEntry(uint64_t id) {
  OpenStore *dropped = nullptr;
  bool isFile = false;
  {
    std::lock_guard<std::mutex> l(g_mu);
    auto it = g_entries.find(id);
    if (it == g_entries.end()) {
      return SQLITE_IOERR;
    }
    OpenStore *st = it->second.store;
    isFile = it->second.isFile;
    g_entries.erase(it);
    if (--st->refs <= 0) {
      g_stores.erase(st->canon);
      dropped = st;
    }
  }
  if (isFile) {
    nvCloseFileGo(id);
  }
  if (dropped) {
    destroyStore(dropped);
  }
  return SQLITE_OK;
}

// runPragma serves one PRAGMA on a known store. Extension names run
// the Go callback with the store lock released.
int runPragma(OpenStore *st, uint64_t id, bool isFile, const char *name,
              const char *value, int hasValue, bool readOnly, char *out,
              size_t cap, size_t *outLen) {
  *outLen = 0;
  if (!name) {
    return SQLITE_NOTFOUND;
  }
  NvDb *lockedDb = st->db.load();
  bool locked = lockedDb && nv_db_locked(lockedDb) != 0;
  std::string nameStr = name;
  const char *vptr = (hasValue && value) ? value : nullptr;
  PragmaOut r;
  {
    std::unique_lock<std::mutex> l(st->mu);
    r = serveLocked(st, nameStr, vptr, hasValue != 0, readOnly, locked);
    if (r.extension) {
      // Extension code may call back into this API: release the
      // store lock first (mirrors Go, which never held e.mu
      // across extension dispatch).
      l.unlock();
      // Per-file slots see the original name (murmur.Register);
      // store-level dispatch sees the lowered name (Engine.Pragma).
      std::string ename = isFile ? nameStr : asciiLower(nameStr);
      const char *ev = (hasValue && value) ? value : nullptr;
      if (isFile) {
        return nvMurmurExtFileGo(id, ename.c_str(), ev, hasValue, out, cap,
                                 outLen);
      }
      return nvMurmurExtStoreGo(id, ename.c_str(), ev, hasValue, out, cap,
                                outLen);
    }
  }
  if (r.text.empty()) {
    return r.code;
  }
  if (r.text.size() + 1 > cap || !out) {
    *outLen = r.text.size() + 1;
    return -2;
  }
  memcpy(out, r.text.data(), r.text.size());
  *outLen = r.text.size();
  return r.code;
}

}  // namespace

extern "C" {

void nvCtlSetDefaults(int cache_pages, unsigned flush_ms) {
  std::lock_guard<std::mutex> l(g_mu);
  g_cachePages = cache_pages;
  g_flushMs = flush_ms;
}

int nvOpenDb(const char *name, int read_only, int create, uint64_t *db,
             uint64_t *file) {
  if (!name || !db || !file) {
    return SQLITE_CANTOPEN;
  }
  int cap;
  unsigned fms;
  {
    std::lock_guard<std::mutex> l(g_mu);
    cap = g_cachePages;
    fms = g_flushMs;
  }
  return openRef(murmurCanonName(name), read_only != 0, create != 0, cap, fms,
                 true, db, file, nullptr);
}

int nvCloseDb(uint64_t file) { return closeEntry(file); }

void *nvEntryDb(uint64_t id) {
  std::lock_guard<std::mutex> l(g_mu);
  auto it = g_entries.find(id);
  if (it == g_entries.end()) {
    return nullptr;
  }
  return it->second.store->db.load();
}

int nvOpenStoreRef(const char *canon, int create, int cache_pages,
                   uint64_t *handle, void **db, void **store) {
  if (!canon || !handle || !db || !store) {
    return SQLITE_MISUSE;
  }
  // Shell opens take the built-in flush default (Go newEngine
  // hardcodes 250 for direct opens; the VFS default only applies to
  // VFS opens).
  uint64_t dbTmp = 0, idTmp = 0, storeTmp = 0;
  int rc = openRef(murmurCanonName(canon), false, create != 0, cache_pages,
                   kFlushMsDefault, false, &dbTmp, &idTmp, &storeTmp);
  if (rc != SQLITE_OK) {
    return rc;
  }
  *handle = idTmp;
  *db = (void *)dbTmp;
  *store = (void *)storeTmp;
  return SQLITE_OK;
}

int nvCloseStoreRef(uint64_t handle) { return closeEntry(handle); }

int nvStoreIsLive(const char *canon) {
  if (!canon) {
    return 0;
  }
  std::lock_guard<std::mutex> l(g_mu);
  return g_stores.find(murmurCanonName(canon)) != g_stores.end() ? 1 : 0;
}

int nvStoreLiveCount() {
  std::lock_guard<std::mutex> l(g_mu);
  return (int)g_stores.size();
}

int nvPragmaDb(uint64_t file, const char *name, const char *value,
               int has_value, char *out, size_t cap, size_t *out_len) {
  if (!out_len) {
    return SQLITE_MISUSE;
  }
  *out_len = 0;
  OpenStore *st = nullptr;
  bool readOnly = false;
  {
    std::lock_guard<std::mutex> l(g_mu);
    auto it = g_entries.find(file);
    if (it == g_entries.end() || !it->second.isFile) {
      return SQLITE_NOTFOUND;
    }
    st = it->second.store;
    readOnly = it->second.readOnly;
  }
  return runPragma(st, file, true, name, value, has_value, readOnly, out, cap,
                   out_len);
}

int nvPragmaStore(uint64_t handle, const char *name, const char *value,
                  int has_value, int read_only, char *out, size_t cap,
                  size_t *out_len) {
  if (!out_len) {
    return SQLITE_MISUSE;
  }
  *out_len = 0;
  OpenStore *st = nullptr;
  {
    std::lock_guard<std::mutex> l(g_mu);
    auto it = g_entries.find(handle);
    if (it == g_entries.end() || it->second.isFile) {
      return SQLITE_NOTFOUND;
    }
    st = it->second.store;
  }
  return runPragma(st, handle, false, name, value, has_value,
                   read_only != 0, out, cap, out_len);
}

int nvStoreKey(uint64_t handle, const uint8_t master[32]) {
  if (!master) {
    return SQLITE_MISUSE;
  }
  OpenStore *st = nullptr;
  {
    std::lock_guard<std::mutex> l(g_mu);
    auto it = g_entries.find(handle);
    if (it == g_entries.end() || it->second.isFile) {
      return SQLITE_NOTFOUND;
    }
    st = it->second.store;
  }
  std::lock_guard<std::mutex> l(st->mu);
  return keyBytesLocked(st, master).code;
}

int nvStoreBackup(uint64_t handle, const char *dest, const char *cipher,
                  const uint8_t group[16], const uint8_t node[16]) {
  if (!dest || !*dest || !cipher || !group || !node) {
    return SQLITE_MISUSE;
  }
  if (!backupCipherOK(cipher)) {
    return NV_CTL_ERROR;  // Go control layer answers CodeError too
  }
  NvStore *store = nullptr;
  {
    std::lock_guard<std::mutex> l(g_mu);
    auto it = g_entries.find(handle);
    if (it == g_entries.end() || it->second.isFile) {
      return SQLITE_NOTFOUND;
    }
    store = it->second.store->store;
  }
  if (!store) {
    return NV_CTL_IOERR;
  }
  // DestFree mirrors Go: anything present (files, dirs, symlinks)
  // refuses with ERROR. Callers flush/sync before this call.
  struct stat sb;
  if (lstat(dest, &sb) == 0) {
    return NV_CTL_ERROR;
  }
  char err[512];
  uint64_t seq = 0;
  // Checkpoint outside the store lock: it walks RocksDB state and
  // can take a while, like the flusher's unlocked sync.
  if (nv_store_checkpoint(store, dest, &seq, err, sizeof(err)) != 0) {
    removeTree(dest);
    return NV_CTL_IOERR;
  }
  if (writeBackupManifest(dest, cipher, group, node, seq) != 0) {
    removeTree(dest);
    return NV_CTL_IOERR;
  }
  return NV_CTL_OK;
}

int nvStoreInventory(uint64_t handle, char *out, size_t cap,
                     size_t *out_len) {
  if (!out_len) {
    return SQLITE_MISUSE;
  }
  *out_len = 0;
  OpenStore *st = nullptr;
  {
    std::lock_guard<std::mutex> l(g_mu);
    auto it = g_entries.find(handle);
    if (it == g_entries.end() || it->second.isFile) {
      return SQLITE_NOTFOUND;
    }
    st = it->second.store;
  }
  std::lock_guard<std::mutex> l(st->mu);
  auto emit = [&](const std::string &js) -> int {
    *out_len = js.size();
    if (js.size() + 1 > cap || !out) {
      return -2;
    }
    memcpy(out, js.data(), js.size());
    return NV_CTL_OK;
  };
  if (st->keyringEnv.empty()) {
    return emit("{\"sealed\":false}");
  }
  if (!st->hasMaster || !st->hasSID) {
    return NV_CTL_IOERR;  // sealed envelope with no usable opener
  }
  KrFlatRing ring;
  int trc = krflat_open_trial(st->keyringEnv.data(), st->keyringEnv.size(),
                              st->stagedMaster, st->storeID, &ring);
  if (trc == MURMUR_KR_AUTH) {
    return NV_CTL_AUTH;
  }
  if (trc != 0) {
    return NV_CTL_CORRUPT;
  }
  std::string js;
  krflat_inventory_json(&ring, &js);
  return emit(js);
}

int nvStoreSetParam(uint64_t handle, int param, uint64_t value,
                    const uint8_t master[32]) {
  OpenStore *st = nullptr;
  {
    std::lock_guard<std::mutex> l(g_mu);
    auto it = g_entries.find(handle);
    if (it == g_entries.end() || it->second.isFile) {
      return SQLITE_NOTFOUND;
    }
    st = it->second.store;
  }
  std::lock_guard<std::mutex> l(st->mu);
  return setParamLocked(st, param, value, false, master != nullptr, master);
}

int nvStoreRotate(uint64_t handle, int read_only, uint32_t *new_id) {
  if (!new_id) {
    return SQLITE_MISUSE;
  }
  *new_id = 0;
  OpenStore *st = nullptr;
  {
    std::lock_guard<std::mutex> l(g_mu);
    auto it = g_entries.find(handle);
    if (it == g_entries.end() || it->second.isFile) {
      return SQLITE_NOTFOUND;
    }
    st = it->second.store;
  }
  std::lock_guard<std::mutex> l(st->mu);
  if (read_only) {
    return SQLITE_READONLY;
  }
  NvDb *db = st->db.load();
  if (!db || !st->sealed || !st->hasMaster || st->keyringEnv.empty() ||
      !st->hasSID) {
    return NV_CTL_ERROR;  // Go: ring == nil → CodeError
  }
  if (st->kdf != kKDFDirect) {
    return NV_CTL_ERROR;
  }
  uint8_t *new_env = nullptr;
  size_t new_len = 0;
  uint32_t next = 0;
  int krc = murmur_kr_rotate_flat(st->keyringEnv.data(), st->keyringEnv.size(),
                                  st->storeID, st->storeID, st->stagedMaster,
                                  32, nullptr, 0, &new_env, &new_len, &next);
  if (krc != MURMUR_KR_OK || !new_env) {
    if (new_env) {
      murmur_kr_free(new_env);
    }
    return NV_CTL_ERROR;  // Go: every Rotate error → CodeError
  }
  if (putMeta(st, kMetaKeyring, new_env, new_len) != NV_CTL_OK) {
    wipe(new_env, new_len);
    murmur_kr_free(new_env);
    return NV_CTL_IOERR;
  }
  KrFlatRing ring;
  int trc =
      krflat_open_trial(new_env, new_len, st->stagedMaster, st->storeID, &ring);
  if (trc != 0 || ring.current == 0 || ring.current != next) {
    wipe(new_env, new_len);
    murmur_kr_free(new_env);
    return NV_CTL_CORRUPT;
  }
  const uint32_t *rids =
      ring.retiredIDs.empty() ? nullptr : ring.retiredIDs.data();
  const uint8_t *rkeys =
      ring.retiredKeys.empty() ? nullptr : ring.retiredKeys.data();
  int rc = nv_db_install_ring(db, ring.active, ring.current, rids, rkeys,
                              ring.retiredIDs.size());
  if (rc != 0) {
    wipe(new_env, new_len);
    murmur_kr_free(new_env);
    return NV_CTL_IOERR;
  }
  st->keyringEnv.assign(new_env, new_env + new_len);
  wipe(new_env, new_len);
  murmur_kr_free(new_env);
  st->ringTime = ring.time;
  st->ringMem = ring.mem;
  st->ringThreads = ring.threads;
  st->ringCurrent = ring.current;
  *new_id = next;
  return NV_CTL_OK;
}

int nvStorePrune(uint64_t handle, int read_only, char *out, size_t cap,
                 size_t *out_len) {
  if (!out_len) {
    return SQLITE_MISUSE;
  }
  *out_len = 0;
  OpenStore *st = nullptr;
  {
    std::lock_guard<std::mutex> l(g_mu);
    auto it = g_entries.find(handle);
    if (it == g_entries.end() || it->second.isFile) {
      return SQLITE_NOTFOUND;
    }
    st = it->second.store;
  }
  std::lock_guard<std::mutex> l(st->mu);
  if (read_only) {
    return SQLITE_READONLY;
  }
  auto emit = [&](const std::string &js) -> int {
    *out_len = js.size();
    if (js.size() + 1 > cap || !out) {
      return -2;
    }
    memcpy(out, js.data(), js.size());
    return NV_CTL_OK;
  };
  if (!st->sealed || st->keyringEnv.empty() || !st->hasMaster ||
      !st->hasSID) {
    return emit(
        "{\"pruned\":[],\"blocked_by_unkeyed\":0,\"retained\":[],"
        "\"unreadable\":0}");
  }
  KrFlatRing ring;
  int trc = krflat_open_trial(st->keyringEnv.data(), st->keyringEnv.size(),
                              st->stagedMaster, st->storeID, &ring);
  if (trc != 0) {
    return NV_CTL_IOERR;  // Go: refreshRingLocked error → CodeIOErr
  }
  std::set<uint32_t> referenced;
  uint64_t unkeyed = 0, unreadable = 0;
  NvScan *sc = nv_scan_open(st->store);
  if (!sc) {
    return NV_CTL_IOERR;
  }
  std::vector<uint8_t> rec(8192);
  int scan_rc = NV_CTL_OK;
  for (;;) {
    uint64_t id = 0;
    size_t vlen = 0;
    int rc = nv_scan_next(sc, &id, rec.data(), rec.size(), &vlen);
    if (rc == 0) {
      break;
    }
    if (rc == -2) {
      if (vlen > (64u << 20)) {
        scan_rc = NV_CTL_IOERR;
        break;
      }
      rec.resize(vlen ? vlen : rec.size() * 2);
      continue;
    }
    if (rc != 1) {
      scan_rc = NV_CTL_IOERR;
      break;
    }
    (void)id;
    uint32_t kid = 0;
    if (murmur_record_key_id(rec.data(), vlen, &kid)) {
      if (kid != 0) {
        referenced.insert(kid);
      } else {
        unreadable++;
      }
      continue;
    }
    bool legacy = false;
    if (vlen >= 4 && memcmp(rec.data(), "EXP1", 4) == 0) {
      legacy = vlen >= (size_t)(4 + 1 + 12 + 16);
    } else if (vlen >= 4 && memcmp(rec.data(), "EXP2", 4) == 0) {
      legacy = vlen >= (size_t)(5 + 32 + 32);
    }
    if (legacy) {
      unkeyed++;
    } else {
      unreadable++;
    }
  }
  nv_scan_close(sc);
  if (scan_rc != NV_CTL_OK) {
    return scan_rc;
  }
  std::vector<uint32_t> drop, retained;
  for (size_t i = 0; i < ring.allIDs.size(); i++) {
    uint32_t id = ring.allIDs[i];
    if (ring.allActive[i] || id == ring.current) {
      retained.push_back(id);
      continue;
    }
    if (unkeyed == 0 && referenced.find(id) == referenced.end()) {
      drop.push_back(id);
    } else {
      retained.push_back(id);
    }
  }
  if (!drop.empty()) {
    if (st->kdf != kKDFDirect) {
      return NV_CTL_ERROR;
    }
    uint8_t *new_env = nullptr;
    size_t new_len = 0;
    int krc = murmur_kr_drop_flat(
        st->keyringEnv.data(), st->keyringEnv.size(), drop.data(), drop.size(),
        st->storeID, st->storeID, st->stagedMaster, 32, nullptr, 0, &new_env,
        &new_len);
    if (krc != MURMUR_KR_OK || !new_env) {
      if (new_env) {
        murmur_kr_free(new_env);
      }
      return NV_CTL_ERROR;
    }
    if (putMeta(st, kMetaKeyring, new_env, new_len) != NV_CTL_OK) {
      wipe(new_env, new_len);
      murmur_kr_free(new_env);
      return NV_CTL_IOERR;
    }
    KrFlatRing fresh;
    int frc = krflat_open_trial(new_env, new_len, st->stagedMaster,
                                st->storeID, &fresh);
    if (frc != 0 || fresh.current == 0) {
      wipe(new_env, new_len);
      murmur_kr_free(new_env);
      return NV_CTL_CORRUPT;
    }
    NvDb *db = st->db.load();
    const uint32_t *rids =
        fresh.retiredIDs.empty() ? nullptr : fresh.retiredIDs.data();
    const uint8_t *rkeys =
        fresh.retiredKeys.empty() ? nullptr : fresh.retiredKeys.data();
    int rc = NV_CTL_IOERR;
    if (db) {
      rc = nv_db_install_ring(db, fresh.active, fresh.current, rids, rkeys,
                              fresh.retiredIDs.size()) == 0
               ? NV_CTL_OK
               : NV_CTL_IOERR;
    }
    if (rc == NV_CTL_OK) {
      st->keyringEnv.assign(new_env, new_env + new_len);
      st->ringTime = fresh.time;
      st->ringMem = fresh.mem;
      st->ringThreads = fresh.threads;
      st->ringCurrent = fresh.current;
    }
    wipe(new_env, new_len);
    murmur_kr_free(new_env);
    if (rc != NV_CTL_OK) {
      return rc;
    }
  }
  std::string js = "{\"pruned\":[";
  for (size_t i = 0; i < drop.size(); i++) {
    if (i > 0) {
      js += ",";
    }
    js += std::to_string(drop[i]);
  }
  js += "],\"blocked_by_unkeyed\":" + std::to_string(unkeyed) +
        ",\"retained\":[";
  for (size_t i = 0; i < retained.size(); i++) {
    if (i > 0) {
      js += ",";
    }
    js += std::to_string(retained[i]);
  }
  js += "],\"unreadable\":" + std::to_string(unreadable) + "}";
  return emit(js);
}

int nvStoreKdf(uint64_t handle, int *sealed, uint8_t *kdf, uint32_t *time_ms,
               uint32_t *mem_kib, uint8_t *threads) {
  if (!sealed || !kdf || !time_ms || !mem_kib || !threads) {
    return SQLITE_MISUSE;
  }
  OpenStore *st = nullptr;
  {
    std::lock_guard<std::mutex> l(g_mu);
    auto it = g_entries.find(handle);
    if (it == g_entries.end() || it->second.isFile) {
      return SQLITE_NOTFOUND;
    }
    st = it->second.store;
  }
  std::lock_guard<std::mutex> l(st->mu);
  if (st->sealed) {
    *sealed = 1;
    *kdf = st->kdf;
    *time_ms = st->ringTime;
    *mem_kib = st->ringMem;
    *threads = st->ringThreads;
  } else {
    *sealed = 0;
    *kdf = st->stagedKDF;
    *time_ms = st->stagedTime;
    *mem_kib = st->stagedMemory;
    *threads = st->stagedThreads;
  }
  return SQLITE_OK;
}

int nvStoreSyncStats(uint64_t handle, uint64_t *committed_size,
                     uint64_t *flush_batches) {
  if (!committed_size || !flush_batches) {
    return SQLITE_MISUSE;
  }
  OpenStore *st = nullptr;
  {
    std::lock_guard<std::mutex> l(g_mu);
    auto it = g_entries.find(handle);
    if (it == g_entries.end() || it->second.isFile) {
      return SQLITE_NOTFOUND;
    }
    st = it->second.store;
  }
  std::lock_guard<std::mutex> l(st->mu);
  *committed_size = st->committedSize;
  *flush_batches = st->flushBatches;
  return SQLITE_OK;
}

int nvStoreFlush(uint64_t handle) {
  OpenStore *st=nullptr;
  {
    std::lock_guard<std::mutex> lock(g_mu);
    auto it=g_entries.find(handle);
    if(it==g_entries.end() || it->second.isFile) return SQLITE_NOTFOUND;
    st=it->second.store;
  }
  NvDb *db=st->db.load();
  if(!db) return SQLITE_AUTH;
  if(nv_db_flush(db)!=0) return SQLITE_IOERR;
  char error[512]; int rc=nv_store_sync(st->store,error,sizeof(error));
  if(rc<0) return SQLITE_IOERR;
  if(rc>0) { std::lock_guard<std::mutex> lock(st->mu); ++st->flushBatches; }
  return SQLITE_OK;
}

int nvCommitDb(const char *canon) {
  if (!canon) {
    return SQLITE_OK;
  }
  // Sole caller (xDelete) pre-canonicalizes, so the Go
  // re-canonicalize-on-miss fallback is dead here: direct lookup.
  size_t n = strlen(canon);
  if (n < 8 || !endsWith(canon, "-journal")) {
    return SQLITE_OK;
  }
  std::string base(canon, n - 8);
  OpenStore *st = nullptr;
  {
    std::lock_guard<std::mutex> l(g_mu);
    auto it = g_stores.find(base);
    if (it == g_stores.end()) {
      return SQLITE_OK;
    }
    st = it->second;
  }
  std::lock_guard<std::mutex> l(st->mu);
  if (NvDb *cdb = st->db.load()) {
    st->committedSize = (uint64_t)nv_db_size(cdb);
  }
  return SQLITE_OK;
}

int nvAccessDb(const char *name, int *out) {
  if (!out) {
    return SQLITE_IOERR;
  }
  if (!name) {
    *out = 0;
    return SQLITE_OK;
  }
  std::string canon = murmurCanonName(name);
  bool mainLive;
  bool suffixed =
      endsWith(canon.c_str(), "-journal") || endsWith(canon.c_str(), "-wal");
  bool ownerLive = false;
  {
    std::lock_guard<std::mutex> l(g_mu);
    mainLive = g_stores.find(canon) != g_stores.end();
    if (suffixed && !mainLive) {
      size_t cut = endsWith(canon.c_str(), "-journal") ? 8 : 4;
      ownerLive =
          g_stores.find(canon.substr(0, canon.size() - cut)) != g_stores.end();
    }
  }
  if (suffixed && !mainLive && ownerLive) {
    *out = 0;
    return SQLITE_OK;
  }
  *out = isDir(canon.c_str()) || access(canon.c_str(), F_OK) == 0 ? 1 : 0;
  return SQLITE_OK;
}

}  // extern "C"
