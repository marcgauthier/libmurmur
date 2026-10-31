// store.h - native record pump over the RocksDB C++ API (store.cc).
//
// Raw key/value access to a murmur store directory: page records
// ('p' + u64be), metadata (meta:*), scans, flush/compaction,
// checkpoints, and offline repair. The control plane (open.h) owns
// live stores; offline tools (admin, offline.h) use these calls
// directly. Conventions: 0 ok, -1 error (err filled), -2 short
// buffer (vlen/out_len = needed, retry grows once).
#ifndef MURMUR_STORE_H
#define MURMUR_STORE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct NvStore NvStore;
typedef struct NvScan NvScan;

NvStore *nv_store_open(const char *dir, int create, char *err, size_t err_cap);
void nv_store_close(NvStore *s);

/* 1 found (vlen set), 0 missing, -1 error, -2 short buffer. */
int nv_store_get(NvStore *s, const uint8_t *key, size_t klen, uint8_t *val,
                 size_t vcap, size_t *vlen, char *err, size_t err_cap);
int nv_store_put(NvStore *s, const uint8_t *key, size_t klen,
                 const uint8_t *val, size_t vlen, int sync, char *err,
                 size_t err_cap);
int nv_store_del(NvStore *s, const uint8_t *key, size_t klen, int sync,
                 char *err, size_t err_cap);
int nv_store_write_batch(NvStore *s, size_t count, const uint8_t **keys,
                         const size_t *klens, const uint8_t **vals,
                         const size_t *vlens, char *err, size_t err_cap);
int nv_store_del_pages_from(NvStore *s, uint64_t first, char *err,
                            size_t err_cap);
int nv_store_sync(NvStore *s, char *err, size_t err_cap);
void nv_page_key(uint64_t page, uint8_t out[9]);

/* Page-record scan in id order: 1 row, 0 done, -1 error, -2 short
 * buffer (retry re-reads the same row). */
NvScan *nv_scan_open(NvStore *s);
int nv_scan_next(NvScan *sc, uint64_t *id, uint8_t *vbuf, size_t vcap,
                 size_t *vlen);
void nv_scan_close(NvScan *sc);

int nv_store_flush(NvStore *s, char *err, size_t err_cap);
int nv_store_wait_compact_30s(NvStore *s, char *err, size_t err_cap);
int nv_store_compact_full(NvStore *s, char *err, size_t err_cap);
int nv_store_checkpoint(NvStore *s, const char *dir, uint64_t *seq, char *err,
                        size_t err_cap);
int nv_store_set_options(NvStore *s, const char **keys, const char **vals,
                         int n, char *err, size_t err_cap);
int nv_store_set_db_option(NvStore *s, const char *name, const char *value,
                           char *err, size_t err_cap);
int nv_store_live_option(NvStore *s, const char *name, uint64_t *out, char *err,
                         size_t err_cap);
uint64_t nv_store_ticker(NvStore *s, int ticker);
void nv_store_set_cache_capacity(NvStore *s, size_t bytes);
size_t nv_store_cache_capacity(NvStore *s);

/* Reads a RocksDB string property (e.g. rocksdb.estimate-num-keys,
 * rocksdb.estimate-live-data-size, rocksdb.num-snapshots). 0 ok, -1
 * unknown/failed, -2 short buffer (out_len = needed). */
int nv_store_property(NvStore *s, const char *name, char *out, size_t cap,
                      size_t *out_len, char *err, size_t err_cap);

/* Offline repair (rocksdb::RepairDB): rebuilds the store in place,
 * discarding what it cannot parse. 0 ok, -1 failed. */
int nv_repair(const char *dir, char *err, size_t err_cap);

#ifdef __cplusplus
}
#endif

#endif /* MURMUR_STORE_H */
