// Native record pump over the RocksDB C++ API: the only RocksDB
// path. Options: optional create, no compression (pages compress
// before encryption), statistics, 32 MiB LRU block cache. Durability:
// plain puts stage in WAL + memtable, and an empty synced batch is
// the commit barrier.
#include <stdint.h>
#include <string.h>

#include "rocksdb/advanced_cache.h"
#include "rocksdb/cache.h"
#include "rocksdb/db.h"
#include "rocksdb/options.h"
#include "rocksdb/slice.h"
#include "rocksdb/statistics.h"
#include "rocksdb/table.h"
#include "rocksdb/write_batch.h"

#include "nv_crypto.h"

namespace {

struct NvStore {
  rocksdb::DB *db;
  std::shared_ptr<rocksdb::Cache> cache;
  std::shared_ptr<rocksdb::Statistics> stats;
  rocksdb::ReadOptions ro;
  rocksdb::WriteOptions wo;
  rocksdb::WriteOptions wo_sync;
  bool dirty;
  uint64_t batches;
};

void set_err(char *err, size_t cap, const rocksdb::Status &st) {
  if (!err || cap == 0) {
    return;
  }
  std::string msg = st.ToString();
  size_t n = msg.size();
  if (n + 1 > cap) {
    n = cap - 1;
  }
  memcpy(err, msg.data(), n);
  err[n] = '\0';
}

}  // namespace

extern "C" {

typedef struct NvStore NvStore;

NvStore *nv_store_open(const char *dir, int create, char *err, size_t err_cap) {
  rocksdb::Options opts;
  opts.create_if_missing = create != 0;
  opts.compression = rocksdb::kNoCompression;
  NvStore *s = new (std::nothrow) NvStore();
  if (!s) {
    return nullptr;
  }
  s->stats = rocksdb::CreateDBStatistics();
  s->stats->set_stats_level(rocksdb::kExceptHistogramOrTimers);
  opts.statistics = s->stats;
  rocksdb::BlockBasedTableOptions table;
  s->cache = rocksdb::NewLRUCache(32 * 1024 * 1024);
  table.block_cache = s->cache;
  opts.table_factory.reset(rocksdb::NewBlockBasedTableFactory(table));
  s->wo_sync.sync = true;
  s->dirty = false;
  s->batches = 0;
  rocksdb::Status st = rocksdb::DB::Open(opts, dir, &s->db);
  if (!st.ok()) {
    set_err(err, err_cap, st);
    delete s;
    return nullptr;
  }
  return s;
}

void nv_store_close(NvStore *s) {
  if (!s) {
    return;
  }
  delete s->db;
  delete s;
}

/* Returns 1 when found (vlen set), 0 when missing, -1 on error. */
int nv_store_get(NvStore *s, const uint8_t *key, size_t klen, uint8_t *val,
                 size_t vcap, size_t *vlen, char *err, size_t err_cap) {
  if (!s || !s->db) {
    return -1;
  }
  std::string out;
  rocksdb::Status st =
      s->db->Get(s->ro, rocksdb::Slice((const char *)key, klen), &out);
  if (st.IsNotFound()) {
    return 0;
  }
  if (!st.ok()) {
    set_err(err, err_cap, st);
    return -1;
  }
  if (out.size() > vcap) {
    return -2; /* short buffer: caller grows and retries */
  }
  memcpy(val, out.data(), out.size());
  *vlen = out.size();
  return 1;
}

int nv_store_put(NvStore *s, const uint8_t *key, size_t klen,
                 const uint8_t *val, size_t vlen, int sync, char *err,
                 size_t err_cap) {
  if (!s || !s->db) {
    return -1;
  }
  rocksdb::Status st =
      s->db->Put(sync ? s->wo_sync : s->wo,
                 rocksdb::Slice((const char *)key, klen),
                 rocksdb::Slice((const char *)val, vlen));
  if (!st.ok()) {
    set_err(err, err_cap, st);
    return -1;
  }
  if (!sync) {
    s->dirty = true;
  }
  return 0;
}

int nv_store_del(NvStore *s, const uint8_t *key, size_t klen, int sync,
                 char *err, size_t err_cap) {
  if (!s || !s->db) {
    return -1;
  }
  rocksdb::Status st =
      s->db->Delete(sync ? s->wo_sync : s->wo,
                    rocksdb::Slice((const char *)key, klen));
  if (!st.ok()) {
    set_err(err, err_cap, st);
    return -1;
  }
  if (!sync) {
    s->dirty = true;
  }
  return 0;
}

/* Writes count puts in one async batch (flush path). Keys and values
 * are borrowed arrays; klens/vlens hold each entry's length. */
int nv_store_write_batch(NvStore *s, size_t count, const uint8_t **keys,
                         const size_t *klens, const uint8_t **vals,
                         const size_t *vlens, char *err, size_t err_cap) {
  if (!s || !s->db) {
    return -1;
  }
  rocksdb::WriteBatch b;
  for (size_t i = 0; i < count; i++) {
    if (!keys[i] || !vals[i]) {
      return -1;
    }
    rocksdb::Status st = b.Put(rocksdb::Slice((const char *)keys[i], klens[i]),
                               rocksdb::Slice((const char *)vals[i], vlens[i]));
    if (!st.ok()) {
      set_err(err, err_cap, st);
      return -1;
    }
  }
  rocksdb::Status st = s->db->Write(s->wo, &b);
  if (!st.ok()) {
    set_err(err, err_cap, st);
    return -1;
  }
  if (count > 0) {
    s->dirty = true;
  }
  return 0;
}

/* Drops every page id >= first ('p'+u64be range delete to "q"). */
int nv_store_del_pages_from(NvStore *s, uint64_t first, char *err,
                            size_t err_cap) {
  if (!s || !s->db) {
    return -1;
  }
  uint8_t start[9];
  start[0] = 'p';
  for (int i = 0; i < 8; i++) {
    start[1 + i] = (uint8_t)(first >> (56 - 8 * i));
  }
  rocksdb::WriteBatch b;
  rocksdb::Status st =
      b.DeleteRange(rocksdb::Slice((const char *)start, 9),
                    rocksdb::Slice("q", 1));
  if (!st.ok()) {
    set_err(err, err_cap, st);
    return -1;
  }
  st = s->db->Write(s->wo, &b);
  if (!st.ok()) {
    set_err(err, err_cap, st);
    return -1;
  }
  s->dirty = true;
  return 0;
}

/* Commit barrier: an empty synced batch forces a WAL sync. Reports 1
 * when a batch advanced, 0 when clean. */
int nv_store_sync(NvStore *s, char *err, size_t err_cap) {
  if (!s || !s->db) {
    return -1;
  }
  if (!s->dirty) {
    return 0;
  }
  rocksdb::WriteBatch b;
  rocksdb::Status st = s->db->Write(s->wo_sync, &b);
  if (!st.ok()) {
    set_err(err, err_cap, st);
    return -1;
  }
  s->dirty = false;
  s->batches++;
  return 1;
}

/* Builds the 'p' + u64be page key (storage.PageKey layout). */
void nv_page_key(uint64_t page, uint8_t out[9]) {
  out[0] = 'p';
  for (int i = 0; i < 8; i++) {
    out[1 + i] = (uint8_t)(page >> (56 - 8 * i));
  }
}

}  // extern "C"

#include <chrono>
#include <unordered_map>

#include "rocksdb/utilities/checkpoint.h"

namespace {

struct NvScan {
  rocksdb::Iterator *it;
  bool started;
  bool advanced;  // false after a short read: retry re-reads the row
};

}  // namespace

extern "C" {

typedef struct NvScan NvScan;

/* Opens a page-record scan: seeks 'p'+0, visits page keys in id
 * order, stops at the first non-page key, ends silently on iterator
 * errors. */
NvScan *nv_scan_open(NvStore *s) {
  if (!s || !s->db) {
    return nullptr;
  }
  NvScan *sc = new (std::nothrow) NvScan();
  if (!sc) {
    return nullptr;
  }
  sc->it = s->db->NewIterator(s->ro);
  sc->started = false;
  sc->advanced = true;
  if (!sc->it) {
    delete sc;
    return nullptr;
  }
  return sc;
}

/* next: 1 = row (id set, value copied, vlen set), 0 = done,
 * -1 = error, -2 = short buffer (vlen = needed; retry re-reads the
 * same row, it does not advance). */
int nv_scan_next(NvScan *sc, uint64_t *id, uint8_t *vbuf, size_t vcap,
                 size_t *vlen) {
  if (!sc || !sc->it || !id || !vlen) {
    return -1;
  }
  if (!sc->started) {
    uint8_t zero[9] = {'p', 0, 0, 0, 0, 0, 0, 0, 0};
    sc->it->Seek(rocksdb::Slice((const char *)zero, 9));
    sc->started = true;
  } else if (sc->advanced) {
    sc->it->Next();
  }
  if (!sc->it->Valid()) {
    sc->advanced = false;
    return 0; /* done or silent error end, like the Go scan */
  }
  rocksdb::Slice key = sc->it->key();
  if (key.size() != 9 || key[0] != 'p') {
    sc->advanced = false;
    return 0;
  }
  uint64_t page = 0;
  for (size_t i = 1; i < 9; i++) {
    page = (page << 8) | (uint8_t)key[i];
  }
  rocksdb::Slice val = sc->it->value();
  if (val.size() > vcap) {
    *vlen = val.size();
    sc->advanced = false;
    return -2;
  }
  memcpy(vbuf, val.data(), val.size());
  *vlen = val.size();
  *id = page;
  sc->advanced = true;
  return 1;
}

void nv_scan_close(NvScan *sc) {
  if (!sc) {
    return;
  }
  delete sc->it;
  delete sc;
}

/* Flushes memtables, waiting for completion. */
int nv_store_flush(NvStore *s, char *err, size_t err_cap) {
  if (!s || !s->db) {
    return -1;
  }
  rocksdb::FlushOptions opts;
  opts.wait = true;
  rocksdb::Status st = s->db->Flush(opts);
  if (!st.ok()) {
    set_err(err, err_cap, st);
    return -1;
  }
  return 0;
}

/* Waits up to 30s for background compactions (TimedOut on expiry). */
int nv_store_wait_compact_30s(NvStore *s, char *err, size_t err_cap) {
  if (!s || !s->db) {
    return -1;
  }
  rocksdb::WaitForCompactOptions opts;
  opts.timeout = std::chrono::seconds(30);
  rocksdb::Status st = s->db->WaitForCompact(opts);
  if (!st.ok()) {
    set_err(err, err_cap, st);
    return -1;
  }
  return 0;
}

/* Compacts the full key range synchronously. */
int nv_store_compact_full(NvStore *s, char *err, size_t err_cap) {
  if (!s || !s->db) {
    return -1;
  }
  rocksdb::CompactRangeOptions opts;
  rocksdb::Status st = s->db->CompactRange(opts, nullptr, nullptr);
  if (!st.ok()) {
    set_err(err, err_cap, st);
    return -1;
  }
  return 0;
}

/* Writes a consistent checkpoint plus its sequence number. */
int nv_store_checkpoint(NvStore *s, const char *dir, uint64_t *seq, char *err,
                        size_t err_cap) {
  if (!s || !s->db || !dir || !seq) {
    return -1;
  }
  rocksdb::Checkpoint *raw = nullptr;
  rocksdb::Status st = rocksdb::Checkpoint::Create(s->db, &raw);
  if (!st.ok() || !raw) {
    set_err(err, err_cap, st);
    return -1;
  }
  st = raw->CreateCheckpoint(dir, 0, seq);
  delete raw;
  if (!st.ok()) {
    set_err(err, err_cap, st);
    return -1;
  }
  return 0;
}

/* Applies column-family options live (DB::SetOptions). */
int nv_store_set_options(NvStore *s, const char **keys, const char **vals,
                         int n, char *err, size_t err_cap) {
  if (!s || !s->db || n <= 0 || !keys || !vals) {
    return -1;
  }
  std::unordered_map<std::string, std::string> opts;
  for (int i = 0; i < n; i++) {
    if (!keys[i] || !vals[i]) {
      return -1;
    }
    opts[keys[i]] = vals[i];
  }
  rocksdb::Status st = s->db->SetOptions(opts);
  if (!st.ok()) {
    set_err(err, err_cap, st);
    return -1;
  }
  return 0;
}

/* Applies one DB-level option live (DB::SetDBOptions). */
int nv_store_set_db_option(NvStore *s, const char *name, const char *value,
                           char *err, size_t err_cap) {
  if (!s || !s->db || !name || !value) {
    return -1;
  }
  rocksdb::Status st = s->db->SetDBOptions({{name, value}});
  if (!st.ok()) {
    set_err(err, err_cap, st);
    return -1;
  }
  return 0;
}

/* Reads a live option: write_buffer_size, max_write_buffer_number
 * (CF), or max_background_jobs (DB) -- the murmur ext's exact set. */
int nv_store_live_option(NvStore *s, const char *name, uint64_t *out, char *err,
                         size_t err_cap) {
  if (!s || !s->db || !name || !out) {
    return -1;
  }
  if (strcmp(name, "write_buffer_size") == 0) {
    *out = (uint64_t)s->db->GetOptions().write_buffer_size;
    return 0;
  }
  if (strcmp(name, "max_write_buffer_number") == 0) {
    *out = (uint64_t)s->db->GetOptions().max_write_buffer_number;
    return 0;
  }
  if (strcmp(name, "max_background_jobs") == 0) {
    *out = (uint64_t)s->db->GetDBOptions().max_background_jobs;
    return 0;
  }
  if (err && err_cap > 0) {
    const char *msg = "Invalid argument: unknown live option";
    size_t n = strlen(msg);
    if (n + 1 > err_cap) {
      n = err_cap - 1;
    }
    memcpy(err, msg, n);
    err[n] = '\0';
  }
  return -1;
}

/* Reads a RocksDB string property into out (NUL-terminated). */
int nv_store_property(NvStore *s, const char *name, char *out, size_t cap,
                      size_t *out_len, char *err, size_t err_cap) {
  if (!s || !s->db || !name || !out_len) {
    return -1;
  }
  std::string val;
  if (!s->db->GetProperty(rocksdb::Slice(name), &val)) {
    set_err(err, err_cap, rocksdb::Status::InvalidArgument("no such property"));
    return -1;
  }
  *out_len = val.size();
  if (!out || val.size() + 1 > cap) {
    return -2;
  }
  memcpy(out, val.data(), val.size());
  out[val.size()] = '\0';
  return 0;
}

/* Reads a statistics ticker by numeric id (see statistics.h). */
uint64_t nv_store_ticker(NvStore *s, int ticker) {
  if (!s || !s->stats || ticker < 0) {
    return 0;
  }
  return s->stats->getTickerCount((rocksdb::Tickers)ticker);
}

void nv_store_set_cache_capacity(NvStore *s, size_t bytes) {
  if (s && s->cache) {
    s->cache->SetCapacity(bytes);
  }
}

size_t nv_store_cache_capacity(NvStore *s) {
  if (!s || !s->cache) {
    return 0;
  }
  return s->cache->GetCapacity();
}

int nv_repair(const char *dir, char *err, size_t err_cap) {
  rocksdb::Options opts;
  opts.compression = rocksdb::kNoCompression;
  rocksdb::Status st = rocksdb::RepairDB(dir, opts);
  if (!st.ok()) {
    set_err(err, err_cap, st);
    return -1;
  }
  return 0;
}

}  // extern "C"
