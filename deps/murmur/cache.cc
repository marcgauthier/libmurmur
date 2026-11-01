// Plaintext page cache. Evicted and removed blocks are wiped: cache
// contents are decrypted pages. Dirty victims report out for
// synchronous sealing (write-back pressure path). A clean list
// mirrors LRU recency so victim picks are O(1) with exact
// prefer-clean semantics (invariant: inClean == !dirty).
#include "cache.h"

#include <cstring>

PageCache::PageCache(size_t cap) : cap_(cap ? cap : 1) {}

PageCache::~PageCache() { clear(); }

void PageCache::wipe(uint8_t *p, size_t n) {
  // explicit_bzero: vectorized like memset but never elided (7% of
  // benchmark CPU was volatile byte-loop wipes on the seal path).
#ifdef _WIN32
  volatile unsigned char *v = (volatile unsigned char *)p;
  while (n--) *v++ = 0;
#else
  explicit_bzero(p, n);
#endif
}

void PageCache::linkClean(std::list<Entry>::iterator it) {
  it->cleanIt = clean_.insert(clean_.begin(), it);
  it->inClean = true;
}

void PageCache::unlinkClean(std::list<Entry>::iterator it) {
  if (!it->inClean) {
    return;
  }
  clean_.erase(it->cleanIt);
  it->inClean = false;
}

void PageCache::touch(std::list<Entry>::iterator it) {
  lru_.splice(lru_.begin(), lru_, it);
  if (it->inClean) {
    clean_.splice(clean_.begin(), clean_, it->cleanIt);
  }
}

bool PageCache::get(uint64_t id, uint8_t *out) {
  auto it = map_.find(id);
  if (it == map_.end()) {
    return false;
  }
  touch(it->second);
  memcpy(out, it->second->block.data(), kBlock);
  return true;
}

void PageCache::put(uint64_t id, const uint8_t *block, bool dirty,
                    uint64_t seq) {
  auto it = map_.find(id);
  if (it != map_.end()) {
    memcpy(it->second->block.data(), block, kBlock);
    if (dirty) {
      unlinkClean(it->second);
      it->second->dirty = true;
      it->second->seq = seq;
    }
    touch(it->second);
    return;
  }
  if (lru_.size() >= cap_) {
    evictInto(id, block, dirty, seq);
    return;
  }
  lru_.push_front(Entry{id, std::vector<uint8_t>(kBlock), dirty});
  lru_.front().seq = dirty ? seq : 0;
  if (!dirty) {
    linkClean(lru_.begin());
  }
  memcpy(lru_.front().block.data(), block, kBlock);
  map_[id] = lru_.begin();
}

uint8_t *PageCache::mutate(uint64_t id) {
  auto it = map_.find(id);
  if (it == map_.end()) {
    return nullptr;
  }
  return it->second->block.data();
}

bool PageCache::commitDirty(uint64_t id, uint64_t seq) {
  auto it = map_.find(id);
  if (it == map_.end()) {
    return false;
  }
  unlinkClean(it->second);
  it->second->dirty = true;
  it->second->seq = seq;
  touch(it->second);
  return true;
}

bool PageCache::putIfAbsent(uint64_t id, const uint8_t *block, uint8_t *out) {
  auto it = map_.find(id);
  if (it != map_.end()) {
    touch(it->second);
    memcpy(out, it->second->block.data(), kBlock);
    return false;
  }
  if (lru_.size() >= cap_) {
    evictInto(id, block, false, 0);
    return true;
  }
  lru_.push_front(Entry{id, std::vector<uint8_t>(kBlock), false});
  linkClean(lru_.begin());
  memcpy(lru_.front().block.data(), block, kBlock);
  map_[id] = lru_.begin();
  return true;
}

void PageCache::markClean(uint64_t id, uint64_t seq) {
  auto it = map_.find(id);
  if (it == map_.end()) {
    return;
  }
  if (it->second->dirty && it->second->seq == seq) {
    it->second->dirty = false;
    it->second->seq = 0;
    linkClean(it->second);
  }
}

void PageCache::removeFrom(uint64_t first, uint64_t keep, bool hasKeep) {
  for (auto it = map_.begin(); it != map_.end();) {
    uint64_t id = it->first;
    if (id >= first && !(hasKeep && id == keep)) {
      unlinkClean(it->second);
      wipe(it->second->block.data(), kBlock);
      lru_.erase(it->second);
      it = map_.erase(it);
    } else {
      ++it;
    }
  }
}

void PageCache::clear() {
  for (auto &e : lru_) {
    wipe(e.block.data(), kBlock);
  }
  lru_.clear();
  map_.clear();
  clean_.clear();
}

std::list<PageCache::Entry>::iterator PageCache::pickVictim() {
  // LRU-most clean entry, else end (dirty entries are never
  // foreground victims; the cache grows past cap_ instead). O(1).
  if (!clean_.empty()) {
    return clean_.back();
  }
  return lru_.end();
}

void PageCache::evictOne() {
  if (lru_.empty()) {
    return;
  }
  auto it = pickVictim();
  if (it == lru_.end()) {
    return;  // all dirty: grow past cap_, flush will clean
  }
  unlinkClean(it);
  wipe(it->block.data(), kBlock);
  map_.erase(it->id);
  lru_.erase(it);
}

void PageCache::evictInto(uint64_t id, const uint8_t *block, bool dirty,
                          uint64_t seq) {
  // Steady-state insert: recycle the clean victim's node and 4KB
  // storage in place (no malloc/free). The full overwrite leaves no
  // plaintext trace, so no wipe. With nothing clean, insert anyway
  // (soft cap: grow past cap_ until the next flush cleans).
  auto vit = pickVictim();
  if (vit == lru_.end()) {
    lru_.push_front(Entry{id, std::vector<uint8_t>(kBlock), dirty});
    lru_.front().seq = dirty ? seq : 0;
    if (!dirty) {
      linkClean(lru_.begin());
    }
    memcpy(lru_.front().block.data(), block, kBlock);
    map_[id] = lru_.begin();
    return;
  }
  unlinkClean(vit);
  map_.erase(vit->id);
  vit->id = id;
  vit->dirty = dirty;
  vit->seq = dirty ? seq : 0;
  if (!dirty) {
    linkClean(vit);
  }
  memcpy(vit->block.data(), block, kBlock);
  map_[id] = vit;
  lru_.splice(lru_.begin(), lru_, vit);
}
