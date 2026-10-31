// Plaintext page cache for the native engine. Write-back: dirty pages
// pin until the db flush seals them; capacity is a soft target and
// inserts only drop clean entries (growing past cap when all dirty).
// Not thread-safe: the owning NvDb serializes access.
#ifndef NV_CACHE_H
#define NV_CACHE_H

#include <cstddef>
#include <cstdint>
#include <list>
#include <unordered_map>
#include <vector>

class PageCache {
 public:
  static const size_t kBlock = 4096;

  explicit PageCache(size_t cap);
  ~PageCache();

  PageCache(const PageCache &) = delete;
  PageCache &operator=(const PageCache &) = delete;

  // get copies the cached block to out on hits.
  bool get(uint64_t id, uint8_t *out);
  // mutate returns a writable pointer to the cached block on hits,
  // or nullptr on misses. It does not touch recency; the caller
  // memcpy's its span into the slot and finishes with commitDirty,
  // all under the db lock (no eviction can intervene). This skips
  // the two 4KB copies + wipes of the load/merge/put path.
  uint8_t *mutate(uint64_t id);
  // commitDirty applies put's present+dirty semantics (unlink clean,
  // dirty mark, generation, recency touch) after a mutate span
  // copy. Returns false when the entry vanished (impossible under
  // the db lock; the caller then falls back to the copy path).
  bool commitDirty(uint64_t id, uint64_t seq);
  // put inserts or replaces a block. dirty pins it for write-back
  // at generation seq (replace never clears a dirty entry). cap_ is
  // a soft target like the Rust store: inserts drop clean entries
  // oldest-first, but dirty entries are never sealed or dropped on
  // the foreground path (they persist at flush); when nothing clean
  // remains the cache grows past cap_ until the next flush cleans.
  void put(uint64_t id, const uint8_t *block, bool dirty, uint64_t seq);
  // putIfAbsent installs block only when id is missing (a concurrent
  // write or miss-fill won the race); on races it copies the current
  // block to out and returns false. Installs are always clean (loads
  // never dirty). Same soft-cap growth as put.
  bool putIfAbsent(uint64_t id, const uint8_t *block, uint8_t *out);
  // markClean clears the dirty mark only when the entry still carries
  // generation seq (a re-dirtied entry keeps its mark).
  void markClean(uint64_t id, uint64_t seq);
  // removeFrom evicts every id >= first, except keep when hasKeep.
  void removeFrom(uint64_t first, uint64_t keep, bool hasKeep);
  void clear();

 private:
  struct Entry;
  using LruList = std::list<Entry>;
  // Clean entries in LRU order (mirrors lru_ recency): the victim
  // pick is O(1) with exact prefer-clean semantics (LRU-most clean).
  using CleanList = std::list<LruList::iterator>;
  struct Entry {
    uint64_t id;
    std::vector<uint8_t> block;  // fixed kBlock bytes
    bool dirty;
    uint64_t seq = 0;  // dirty generation (0 when clean)
    CleanList::iterator cleanIt;
    bool inClean = false;
  };

  std::list<Entry>::iterator pickVictim();
  // linkClean inserts it at the clean MRU front; unlinkClean removes
  // it. Callers must keep lru_/clean_ recency in sync on access.
  void linkClean(std::list<Entry>::iterator it);
  void unlinkClean(std::list<Entry>::iterator it);
  void touch(std::list<Entry>::iterator it);
  void evictOne();
  void evictInto(uint64_t id, const uint8_t *block, bool dirty,
                 uint64_t seq);
  static void wipe(uint8_t *p, size_t n);

  size_t cap_;
  std::list<Entry> lru_;
  std::unordered_map<uint64_t, std::list<Entry>::iterator> map_;
  CleanList clean_;
};

#endif
