// Native byte engine: one NvDb serves a main-database store with a
// C++-owned write-back page cache, the page codec, and the RocksDB
// pump. Writes dirty cache pages (no seal, no I/O); nv_db_flush seals
// the dirty set and lands one RocksDB batch. Durability is periodic
// (like Rust): commits stage in cache, the background flusher and the
// sync barriers persist.
//
// Lock discipline (deadlock-free by construction): d->mu is never
// held across a seal (the slow part runs unlocked); the flush
// validate+Write+clear window holds it across one RocksDB Write
// (~50-200us). The codec has its own mutex; the two are never nested.
// Same-page write/write races are excluded by SQLite's own lock
// protocol, which the VFS enforces cross-connection -- the same
// guarantee SQLite's stock VFSes rely on.
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <mutex>
#include <unordered_map>
#include <utility>
#include <vector>

#include "cache.h"
#include "murmur_codec.h"
#include "nv_crypto.h"

#include "../sqlite/sqlite3.h"

typedef struct NvStore NvStore;

extern "C" {
int nv_store_get(NvStore *s, const uint8_t *key, size_t klen, uint8_t *val,
                 size_t vcap, size_t *vlen, char *err, size_t err_cap);
int nv_store_put(NvStore *s, const uint8_t *key, size_t klen,
                 const uint8_t *val, size_t vlen, int sync, char *err,
                 size_t err_cap);
int nv_store_write_batch(NvStore *s, size_t count, const uint8_t **keys,
                         const size_t *klens, const uint8_t **vals,
                         const size_t *vlens, char *err, size_t err_cap);
int nv_store_del_pages_from(NvStore *s, uint64_t first, char *err,
                            size_t err_cap);
void nv_page_key(uint64_t page, uint8_t out[9]);
}

namespace {

struct NvDb {
  NvStore *store;  // borrowed from Go; outlives the db
  PageCache cache;
  std::mutex mu;
  uint64_t size;
  MurmurCodec *codec;  // owned; keys provisioned once, never leaves C++
  // Write-back set: page id -> dirty sequence. A dirty page is always
  // in cache (flush seals+cleans); flush clears entries whose
  // sequence survived the seal.
  std::unordered_map<uint64_t, uint64_t> dirty;
  uint64_t dirty_seq = 0;
  bool size_dirty = false;
  // Cross-connection lock table (xLock/xUnlock/xCheckReserved).
  // One NvDb serves one store, so this replaces the Go ent.locks
  // map 1:1; levels are SQLITE_LOCK_*. A dedicated mutex keeps
  // lock traffic off the page-cache mutex. Entries at NONE are
  // dropped (unobservable: compatible with every want, skipped by
  // the reserved/locked scans).
  std::mutex lock_mu;
  std::unordered_map<uint64_t, int> file_locks;
  // Page-1 header shadow: SQLite reads bytes 24..39 (change counter)
  // straight through the VFS on every read-txn to validate its
  // snapshot. Serving those 16 bytes via a full 4KB page fetch costs
  // ~1.4us; the shadow serves fully-inside-[0,100) reads from memory.
  // Guarded by mu; mirrors logical bytes (single-process store, so
  // only this NvDb writes). hdr_size mirrors size.
  uint8_t hdr[100] = {};
  uint64_t hdr_size = 0;
  bool hdr_valid = false;
  // Counters merged into SnapshotStats.
  uint64_t pages_read = 0;
  uint64_t vfs_read_bytes = 0;
  uint64_t vfs_write_bytes = 0;
  uint64_t pages_sealed = 0;
  uint64_t seal_uncompressed = 0;
  uint64_t seal_payload = 0;
  uint64_t seal_stored = 0;

  NvDb(NvStore *s, MurmurCodec *c, size_t cap, uint64_t size)
      : store(s), cache(cap), size(size), codec(c) {}
  ~NvDb() {
    if (codec) {
      murmur_codec_destroy(codec);
    }
  }
};

void wipe(uint8_t *p, size_t n) {
  // explicit_bzero: vectorized like memset but never elided (see
  // cache.cc: volatile wipes were 7% of benchmark CPU).
#ifdef _WIN32
  volatile uint8_t *v = (volatile uint8_t *)p;
  while (n--) *v++ = 0;
#else
  explicit_bzero(p, n);
#endif
}

const size_t kFlushChunk = 512;
const uint8_t kMetaSize[] = {'m', 'e', 't', 'a', ':', 's', 'i', 'z', 'e'};

struct SealedPage {
  uint64_t id;
  uint64_t seq;
  uint8_t key[9];
  std::vector<uint8_t> rec;
  size_t payload = 0;
};

// loadBlock fetches one plaintext block into blk. I/O and crypto run
// unlocked; cache install uses put-if-absent so a racing write or fill
// always wins over stale bytes. Installs never seal (soft cap: the
// cache grows past cap_ when nothing clean remains; dirties persist
// at flush like the Rust store).
int loadBlock(NvDb *d, uint64_t id, uint8_t *blk) {
  {
    std::lock_guard<std::mutex> l(d->mu);
    if (d->cache.get(id, blk)) {
      return 0;
    }
  }
  uint8_t key[9];
  nv_page_key(id, key);
  uint8_t rec[NV_MAX_RECORD];
  size_t rlen = 0;
  int rc = nv_store_get(d->store, key, 9, rec, sizeof(rec), &rlen, nullptr, 0);
  if (rc == -2) {
    return -2;  // oversized record fails closed as corrupt here; the
                // record path (scan/rekey) handles growth
  }
  if (rc < 0) {
    return -1;
  }
  if (rc == 0) {
    memset(blk, 0, NV_BLOCK);  // sparse hole reads as zeros
    {
      std::lock_guard<std::mutex> l(d->mu);
      d->cache.putIfAbsent(id, blk, blk);
    }
    return 0;
  }
  uint8_t plain[NV_BLOCK];
  int n = murmur_codec_open(d->codec, id, rec, rlen, plain, sizeof(plain));
  wipe(rec, rlen);
  if (n != NV_BLOCK) {
    wipe(plain, sizeof(plain));
    // Auth/corrupt stay the corrupt family (as before); short/misuse
    // are I/O failures.
    return (n == NV_ERR_AUTH || n == NV_ERR_CORRUPT) ? -2 : -1;
  }
  {
    std::lock_guard<std::mutex> l(d->mu);
    if (d->cache.putIfAbsent(id, plain, blk)) {
      memcpy(blk, plain, NV_BLOCK);
    }
  }
  wipe(plain, sizeof(plain));
  return 0;
}

// Compatibility matrix, exactly the retired Go nvLockOK: SHARED
// conflicts with PENDING-or-higher held by others, RESERVED..
// PENDING conflict with RESERVED-or-higher, EXCLUSIVE conflicts
// with anything.
bool nvLockOK(int want, int other) {
  if (want == SQLITE_LOCK_SHARED && other >= SQLITE_LOCK_PENDING) {
    return false;
  }
  if (want >= SQLITE_LOCK_RESERVED && want <= SQLITE_LOCK_PENDING &&
      other >= SQLITE_LOCK_RESERVED) {
    return false;
  }
  if (want == SQLITE_LOCK_EXCLUSIVE && other > SQLITE_LOCK_NONE) {
    return false;
  }
  return true;
}

}  // namespace

extern "C" {

typedef struct NvDb NvDb;

NvDb *nv_db_create(NvStore *store, int cipher, int level,
                   const uint8_t page_key[32], int sealed,
                   const uint8_t active[32], uint32_t current_id,
                   const uint32_t *retired_ids, const uint8_t *retired_keys,
                   size_t retired_count, const uint8_t master[32],
                   size_t cache_cap, uint64_t init_size) {
  if (!store) {
    return nullptr;
  }
  MurmurCodec *codec = murmur_codec_create(
      cipher, level, page_key, sealed, active, current_id, retired_ids,
      retired_keys, retired_count, master);
  if (!codec) {
    return nullptr;
  }
  NvDb *d = new (std::nothrow) NvDb(store, codec, cache_cap, init_size);
  if (!d) {
    murmur_codec_destroy(codec);
    return nullptr;
  }
  return d;
}

// Destroy flushes remaining dirty pages (best effort; the normal
// path already flushed, making this a fast no-op), wipes the cache,
// and frees the db. It never closes the store: Go closes the store
// separately, after destroy.
int nv_db_flush(NvDb *d);  // defined below
void nv_db_destroy(NvDb *d) {
  if (!d) {
    return;
  }
  nv_db_flush(d);
  delete d;
}

/* Reads up to n bytes at off. Returns bytes read (short reads past
 * end are normal) or -1 on error. blocks counts pages touched. */
int64_t nv_db_read(NvDb *d, uint8_t *out, size_t n, int64_t off,
                   uint64_t *blocks) {
  if (!d || !out || !blocks || off < 0) {
    return -1;
  }
  // Header fast path: fully inside [0,100) reads bypass the page
  // fetch. Seeds lazily from page 0 on first use.
  if (off < 100 && n <= (size_t)(100 - off)) {
    {
      std::lock_guard<std::mutex> l(d->mu);
      if (d->hdr_valid) {
        uint64_t cursor = (uint64_t)off;
        size_t avail = (cursor < d->hdr_size) ? (size_t)(d->hdr_size - cursor) : 0;
        if (avail > n) {
          avail = n;
        }
        if (avail > 0) {
          memcpy(out, d->hdr + cursor, avail);
        }
        (*blocks)++;
        d->pages_read++;
        d->vfs_read_bytes += avail;
        return (int64_t)avail;
      }
    }
    uint8_t blk[NV_BLOCK];
    int lrc = loadBlock(d, 0, blk);
    if (lrc != 0) {
      wipe(blk, sizeof(blk));
      return lrc;
    }
    {
      std::lock_guard<std::mutex> l(d->mu);
      if (!d->hdr_valid) {
        memcpy(d->hdr, blk, sizeof(d->hdr));
        d->hdr_size = d->size;
        d->hdr_valid = true;
      }
      uint64_t cursor = (uint64_t)off;
      size_t avail = (cursor < d->hdr_size) ? (size_t)(d->hdr_size - cursor) : 0;
      if (avail > n) {
        avail = n;
      }
      if (avail > 0) {
        memcpy(out, d->hdr + cursor, avail);
      }
      (*blocks)++;
      d->pages_read++;
      d->vfs_read_bytes += avail;
      wipe(blk, sizeof(blk));
      return (int64_t)avail;
    }
  }
  uint64_t size;
  {
    std::lock_guard<std::mutex> l(d->mu);
    size = d->size;
  }
  uint64_t cursor = (uint64_t)off;
  size_t total = 0;
  while (total < n && cursor < size) {
    uint64_t id = cursor / NV_BLOCK;
    size_t within = (size_t)(cursor % NV_BLOCK);
    uint8_t blk[NV_BLOCK];
    int lrc = loadBlock(d, id, blk);
    if (lrc != 0) {
      wipe(blk, sizeof(blk));
      // Partial PagesRead persists (like the staged engine);
      // byte volume only counts on success.
      std::lock_guard<std::mutex> l(d->mu);
      d->pages_read += *blocks;
      return lrc;
    }
    size_t avail = NV_BLOCK - within;
    if (avail > size - cursor) {
      avail = (size_t)(size - cursor);
    }
    if (avail > n - total) {
      avail = n - total;
    }
    memcpy(out + total, blk + within, avail);
    wipe(blk, sizeof(blk));
    total += avail;
    cursor += avail;
    (*blocks)++;
    if (avail == 0) {
      break;
    }
  }
  {
    std::lock_guard<std::mutex> l(d->mu);
    d->pages_read += *blocks;
    d->vfs_read_bytes += total;
  }
  return (int64_t)total;
}

/* Writes len bytes at off (read-modify-write per block, dirtying
 * cache pages; the flush seals and stages). Returns 0 or -1. blocks
 * counts pages written. */
int nv_db_write(NvDb *d, const uint8_t *in, size_t len, int64_t off,
                uint64_t *blocks) {
  if (!d || (!in && len > 0) || !blocks || off < 0) {
    return -1;
  }
  uint64_t cursor = (uint64_t)off;
  size_t done = 0;
  while (done < len) {
    uint64_t id = cursor / NV_BLOCK;
    size_t within = (size_t)(cursor % NV_BLOCK);
    size_t span = NV_BLOCK - within;
    if (span > len - done) {
      span = len - done;
    }
    if (span == 0) {
      return -1;  // short copy, like the staged engine
    }
    // Fast path: the page is cached, so memcpy the span straight
    // into its slot and dirty-mark it. One lock hold, one 4KB-or-
    // less copy, no wipes, no evictions.
    bool fast = false;
    {
      std::lock_guard<std::mutex> l(d->mu);
      uint8_t *slot = d->cache.mutate(id);
      if (slot != nullptr) {
        memcpy(slot + within, in + done, span);
        uint64_t seq = ++d->dirty_seq;
        if (d->cache.commitDirty(id, seq)) {
          d->dirty[id] = seq;
          uint64_t end = cursor + span;
          if (end > d->size) {
            d->size = end;
            d->size_dirty = true;
          }
          // Header shadow follows: seed from the merged slot,
          // overlay the written intersection, zero any sparse gap
          // the write jumps over, and mirror the size.
          if (d->hdr_valid && cursor > d->hdr_size && d->hdr_size < 100) {
            uint64_t z0 = d->hdr_size;
            uint64_t z1 = cursor < 100 ? cursor : 100;
            memset(d->hdr + z0, 0, (size_t)(z1 - z0));
          }
          if (id == 0) {
            if (!d->hdr_valid) {
              memcpy(d->hdr, slot, sizeof(d->hdr));
              d->hdr_valid = true;
            } else if (within < 100) {
              size_t o1 = within + span;
              if (o1 > 100) {
                o1 = 100;
              }
              memcpy(d->hdr + within, slot + within, o1 - within);
            }
          }
          d->hdr_size = d->size;
          fast = true;
        }
      }
    }
    if (!fast) {
      uint8_t blk[NV_BLOCK];
      int lrc = loadBlock(d, id, blk);
      if (lrc != 0) {
        wipe(blk, sizeof(blk));
        return lrc;
      }
      memcpy(blk + within, in + done, span);
      {
        // Install + dirty-mark + size update commit atomically.
        // Never seals (soft cap grows past cap_ when all dirty).
        std::lock_guard<std::mutex> l(d->mu);
        uint64_t seq = ++d->dirty_seq;
        d->cache.put(id, blk, true, seq);
        d->dirty[id] = seq;
        uint64_t end = cursor + span;
        if (end > d->size) {
          d->size = end;
          d->size_dirty = true;
        }
        // Header shadow follows: seed from the merged block, overlay
        // the written intersection, zero any sparse gap the write
        // jumps over, and mirror the size.
        if (d->hdr_valid && cursor > d->hdr_size && d->hdr_size < 100) {
          uint64_t z0 = d->hdr_size;
          uint64_t z1 = cursor < 100 ? cursor : 100;
          memset(d->hdr + z0, 0, (size_t)(z1 - z0));
        }
        if (id == 0) {
          if (!d->hdr_valid) {
            memcpy(d->hdr, blk, sizeof(d->hdr));
            d->hdr_valid = true;
          } else if (within < 100) {
            size_t o1 = within + span;
            if (o1 > 100) {
              o1 = 100;
            }
            memcpy(d->hdr + within, blk + within, o1 - within);
          }
        }
        d->hdr_size = d->size;
      }
      wipe(blk, sizeof(blk));
    }
    done += span;
    cursor += span;
    (*blocks)++;
  }
  {
    std::lock_guard<std::mutex> l(d->mu);
    d->vfs_write_bytes += done;
  }
  return 0;
}

/* Truncate mirrors the staged engine: shrinking to a non-block
 * boundary zeroes the partial tail (dirty rewrite), drops trailing
 * records synchronously, and defers the size to the flush; growing is
 * sparse. */
int nv_db_truncate(NvDb *d, int64_t size) {
  if (!d || size < 0) {
    return -1;
  }
  uint64_t target = (uint64_t)size;
  uint64_t cur;
  {
    std::lock_guard<std::mutex> l(d->mu);
    cur = d->size;
  }
  if (target < cur && target % NV_BLOCK != 0) {
    uint64_t id = target / NV_BLOCK;
    uint8_t blk[NV_BLOCK];
    int lrc = loadBlock(d, id, blk);
    if (lrc != 0) {
      wipe(blk, sizeof(blk));
      return lrc;
    }
    memset(blk + (target % NV_BLOCK), 0, NV_BLOCK - (target % NV_BLOCK));
    {
      std::lock_guard<std::mutex> l(d->mu);
      uint64_t seq = ++d->dirty_seq;
      d->cache.put(id, blk, true, seq);
      d->dirty[id] = seq;
      // Partial-tail zeroing reaches the shadow when page 0's
      // header range is cut.
      if (id == 0 && d->hdr_valid && target < 100) {
        memset(d->hdr + target, 0, (size_t)(100 - target));
      }
    }
    wipe(blk, sizeof(blk));
  }
  {
    std::lock_guard<std::mutex> l(d->mu);
    if (target < d->size) {
      uint64_t firstGone = (target + NV_BLOCK - 1) / NV_BLOCK;
      bool partial = target % NV_BLOCK != 0;
      uint64_t keep = target / NV_BLOCK;
      d->cache.removeFrom(firstGone, keep, partial);
      for (auto it = d->dirty.begin(); it != d->dirty.end();) {
        if (it->first >= firstGone && !(partial && it->first == keep)) {
          it = d->dirty.erase(it);
        } else {
          ++it;
        }
      }
      if (nv_store_del_pages_from(d->store, firstGone, nullptr, 0) != 0) {
        return -1;
      }
    }
    if (target != d->size) {
      // Growth exposes sparse zeros: scrub any stale shadow bytes
      // the new size uncovers.
      if (d->hdr_valid && target > d->hdr_size && d->hdr_size < 100) {
        uint64_t z1 = target < 100 ? target : 100;
        memset(d->hdr + d->hdr_size, 0, (size_t)(z1 - d->hdr_size));
      }
      d->size = target;
      d->hdr_size = target;
      d->size_dirty = true;
    }
  }
  return 0;
}

/* Flush seals the dirty set and lands one RocksDB batch per chunk.
 * Protocol per chunk: snapshot (id,seq) under mu; copy+seal each page
 * unlocked (re-validating seq at copy time); then validate+Write+clear
 * in one mutex window (a single RocksDB Write, ~50-200us). Pages
 * re-dirtied mid-flush keep their dirty mark for the next flush; a
 * failed batch clears nothing. Size stages when unchanged since the
 * snapshot. Returns 0, or -1 when any seal or batch failed (after
 * attempting everything). */
int nv_db_flush(NvDb *d) {
  if (!d) {
    return -1;
  }
  int rc = 0;
  bool size_pending = true;
  std::vector<std::pair<uint64_t, uint64_t>> ids;
  std::vector<SealedPage> sealed;
  std::vector<const uint8_t *> keys;
  std::vector<size_t> klens;
  std::vector<const uint8_t *> vals;
  std::vector<size_t> vlens;
  char sizetext[24];
  for (;;) {
    ids.clear();
    uint64_t fsize = 0;
    bool want_size = false;
    {
      std::lock_guard<std::mutex> l(d->mu);
      if (!d->dirty.empty()) {
        ids.reserve(kFlushChunk);
        for (const auto &kv : d->dirty) {
          ids.push_back(kv);
          if (ids.size() >= kFlushChunk) {
            break;
          }
        }
      }
      if (size_pending) {
        size_pending = false;
        if (d->size_dirty) {
          fsize = d->size;
          want_size = true;
        }
      }
      if (ids.empty() && !want_size) {
        return rc;
      }
    }
    // Copy + seal unlocked, re-validating each sequence at copy time.
    sealed.clear();
    for (const auto &kv : ids) {
      uint8_t blk[NV_BLOCK];
      {
        std::lock_guard<std::mutex> l(d->mu);
        auto it = d->dirty.find(kv.first);
        if (it == d->dirty.end() || it->second != kv.second ||
            !d->cache.get(kv.first, blk)) {
          continue;  // re-dirtied, cleaned, or truncated away
        }
      }
      uint8_t rec[NV_MAX_RECORD];
      size_t payload = 0;
      int n = murmur_codec_seal(d->codec, kv.first, blk, rec, sizeof(rec),
                                &payload);
      wipe(blk, sizeof(blk));
      if (n <= 0 || (size_t)n > NV_MAX_RECORD) {
        rc = -1;  // stays dirty; retried next flush
        continue;
      }
      SealedPage sp;
      sp.id = kv.first;
      sp.seq = kv.second;
      nv_page_key(sp.id, sp.key);
      sp.rec.assign(rec, rec + n);
      sp.payload = payload;
      wipe(rec, sizeof(rec));
      sealed.push_back(std::move(sp));
    }
    // Validate under lock, Write unlocked, then re-validate and
    // clear. Holding d->mu across the synced RocksDB batch stalls
    // every foreground dirty for milliseconds; the re-validation
    // keeps it safe (pages re-dirtied mid-write carry a newer seq,
    // stay dirty, and the next flush overwrites the stale record).
    std::vector<SealedPage *> staged;
    staged.reserve(sealed.size());
    bool stage_size = false;
    bool want_batch = false;
    {
      std::lock_guard<std::mutex> l(d->mu);
      keys.clear();
      klens.clear();
      vals.clear();
      vlens.clear();
      for (auto &sp : sealed) {
        auto it = d->dirty.find(sp.id);
        if (it == d->dirty.end() || it->second != sp.seq) {
          continue;  // changed mid-flush; stays dirty
        }
        staged.push_back(&sp);
        keys.push_back(sp.key);
        klens.push_back(9);
        vals.push_back(sp.rec.data());
        vlens.push_back(sp.rec.size());
      }
      if (want_size && d->size == fsize && d->size_dirty) {
        size_t sizelen = (size_t)snprintf(sizetext, sizeof(sizetext), "%llu",
                                          (unsigned long long)fsize);
        keys.push_back(kMetaSize);
        klens.push_back(sizeof(kMetaSize));
        vals.push_back((const uint8_t *)sizetext);
        vlens.push_back(sizelen);
        stage_size = true;
      }
      want_batch = !keys.empty();
    }
    int wrc = 0;
    if (want_batch) {
      // sealed/sp.rec/sizetext are stable across this call (owned by
      // this frame, wiped only after the clear window).
      wrc = nv_store_write_batch(d->store, keys.size(), keys.data(),
                                 klens.data(), vals.data(), vlens.data(),
                                 nullptr, 0);
    }
    {
      std::lock_guard<std::mutex> l(d->mu);
      if (want_batch && wrc == 0) {
        for (auto *sp : staged) {
          auto it = d->dirty.find(sp->id);
          if (it == d->dirty.end() || it->second != sp->seq) {
            continue;  // re-dirtied mid-write; stays dirty
          }
          d->dirty.erase(sp->id);
          d->cache.markClean(sp->id, sp->seq);
          d->pages_sealed++;
          d->seal_uncompressed += NV_BLOCK;
          d->seal_payload += sp->payload;
          d->seal_stored += sp->rec.size();
        }
        if (stage_size && d->size == fsize && d->size_dirty) {
          d->size_dirty = false;
        }
      } else if (want_batch) {
        rc = -1;  // nothing cleared; retried next flush
      }
    }
    for (auto &sp : sealed) {
      wipe(sp.rec.data(), sp.rec.size());
    }
  }
}

int64_t nv_db_size(NvDb *d) {
  if (!d) {
    return -1;
  }
  std::lock_guard<std::mutex> l(d->mu);
  if (d->size > (uint64_t)INT64_MAX) {
    return (int64_t)INT64_MAX;
  }
  return (int64_t)d->size;
}

/* Lock table: xLock acquires level for file (BUSY on conflict with
 * another file's holding), xUnlock lowers it, xCheckReserved
 * reports any RESERVED-or-higher holding. Same contract as the
 * retired Go registry (TestNativeVFSLocking pins it). */
int nv_db_lock(NvDb *d, uint64_t file, int level) {
  if (!d) {
    return SQLITE_BUSY;
  }
  std::lock_guard<std::mutex> l(d->lock_mu);
  int cur = SQLITE_LOCK_NONE;
  auto it = d->file_locks.find(file);
  if (it != d->file_locks.end()) {
    cur = it->second;
  }
  if (level <= cur) {
    return SQLITE_OK;
  }
  for (auto &kv : d->file_locks) {
    if (kv.first == file) {
      continue;
    }
    if (!nvLockOK(level, kv.second)) {
      return SQLITE_BUSY;
    }
  }
  d->file_locks[file] = level;
  return SQLITE_OK;
}

int nv_db_unlock(NvDb *d, uint64_t file, int level) {
  if (!d) {
    return SQLITE_IOERR;
  }
  std::lock_guard<std::mutex> l(d->lock_mu);
  if (level <= SQLITE_LOCK_NONE) {
    d->file_locks.erase(file);
  } else {
    d->file_locks[file] = level;
  }
  return SQLITE_OK;
}

int nv_db_check_reserved(NvDb *d, int *out) {
  if (!d || !out) {
    return SQLITE_IOERR;
  }
  *out = 0;
  std::lock_guard<std::mutex> l(d->lock_mu);
  for (auto &kv : d->file_locks) {
    if (kv.second >= SQLITE_LOCK_RESERVED) {
      *out = 1;
      break;
    }
  }
  return SQLITE_OK;
}

/* nv_db_locked reports whether any file holds above NONE (the
 * PRAGMA locked signal). */
int nv_db_locked(NvDb *d) {
  if (!d) {
    return 0;
  }
  std::lock_guard<std::mutex> l(d->lock_mu);
  for (auto &kv : d->file_locks) {
    if (kv.second > SQLITE_LOCK_NONE) {
      return 1;
    }
  }
  return 0;
}

/* nv_db_forget_file drops file's lock entry at close. Called before
 * the Go close (which may destroy the NvDb on last close). */
void nv_db_forget_file(NvDb *d, uint64_t file) {
  if (!d) {
    return;
  }
  std::lock_guard<std::mutex> l(d->lock_mu);
  d->file_locks.erase(file);
}

/* Reports byte-path counters for SnapshotStats merging. */
void nv_db_stats(NvDb *d, uint64_t *pages_read, uint64_t *read_bytes,
                 uint64_t *write_bytes) {
  if (!d || !pages_read || !read_bytes || !write_bytes) {
    return;
  }
  std::lock_guard<std::mutex> l(d->mu);
  *pages_read = d->pages_read;
  *read_bytes = d->vfs_read_bytes;
  *write_bytes = d->vfs_write_bytes;
}

/* Reports seal counters for SnapshotStats merging. */
void nv_db_seal_stats(NvDb *d, uint64_t *pages, uint64_t *uncompressed,
                      uint64_t *payload, uint64_t *stored) {
  if (!d || !pages || !uncompressed || !payload || !stored) {
    return;
  }
  std::lock_guard<std::mutex> l(d->mu);
  *pages = d->pages_sealed;
  *uncompressed = d->seal_uncompressed;
  *payload = d->seal_payload;
  *stored = d->seal_stored;
}

/* Cold codec updates (PRAGMA cipher/compression, seal/rotate/prune).
 * Return 0 or -5. */
int nv_db_set_cipher(NvDb *d, int cipher) {
  if (!d) {
    return -5;
  }
  return murmur_codec_set_cipher(d->codec, cipher);
}

int nv_db_set_level(NvDb *d, int level) {
  if (!d) {
    return -5;
  }
  return murmur_codec_set_level(d->codec, level);
}

int nv_db_install_ring(NvDb *d, const uint8_t active[32], uint32_t current_id,
                       const uint32_t *retired_ids, const uint8_t *retired_keys,
                       size_t retired_count) {
  if (!d) {
    return -5;
  }
  return murmur_codec_install_ring(d->codec, active, current_id, retired_ids,
                                   retired_keys, retired_count);
}

}  // extern "C"
