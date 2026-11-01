// Package nvfs is the native (C++) VFS hot path: page caching, the page
// codec, buffer allocation, and the RocksDB pump live in C++ so the
// SQLite <-> VFS <-> RocksDB data exchange never crosses cgo and never
// copies into Go memory. Key material is provisioned once at database
// open and never leaves C++.
//
// The Go engine stays the reference implementation; the native path
// is proven against it by differential tests before it serves reads.
package nvfs

/*
#cgo CFLAGS: -I../../../../deps/rocksdb/include -I../../../../deps/sqlite -I../../../../deps/codec -I../../../../deps/zstd -I../../../../deps/argon2 -O2
#cgo CXXFLAGS: -std=c++17 -I../../../../deps/rocksdb/include -I../../../../deps/codec -I../../../../deps/aegis/src/include -I../../../../deps/zstd -I../../../../deps/argon2 -I../../../../deps/keyring -O2
#cgo LDFLAGS: ${SRCDIR}/../../../../libmurmur.a -lstdc++ -lpthread -ldl -lm
#include <stdlib.h>
#include <stdint.h>
#include "sqlite3.h"
#include "aesgcm.h"
#include "murmur_codec.h"
// NOTE: nv_crypto.h is intentionally not included here: it declares
// nvCryptGo with a const input pointer while cgo generates the export
// implementation without const, which would conflict. The C++ side
// includes it; the Go side only needs the decls below.

typedef struct NvStore NvStore;
extern NvStore *nv_store_open(const char *dir, int create, char *err, size_t err_cap);
extern void nv_store_close(NvStore *s);
#include "murmur_codec.h"
extern int nv_repair(const char *dir, char *err, size_t err_cap);
extern int nv_store_get(NvStore *s, const uint8_t *key, size_t klen, uint8_t *val, size_t vcap, size_t *vlen, char *err, size_t err_cap);
extern int nv_store_put(NvStore *s, const uint8_t *key, size_t klen, const uint8_t *val, size_t vlen, int sync, char *err, size_t err_cap);
extern int nv_store_del(NvStore *s, const uint8_t *key, size_t klen, int sync, char *err, size_t err_cap);
extern int nv_store_del_pages_from(NvStore *s, uint64_t first, char *err, size_t err_cap);
extern int nv_store_sync(NvStore *s, char *err, size_t err_cap);
extern void nv_page_key(uint64_t page, uint8_t out[9]);
typedef struct NvDb NvDb;
typedef struct NvScan NvScan;
extern NvScan *nv_scan_open(NvStore *s);
extern int nv_scan_next(NvScan *sc, uint64_t *id, uint8_t *vbuf, size_t vcap, size_t *vlen);
extern void nv_scan_close(NvScan *sc);
extern int nv_store_flush(NvStore *s, char *err, size_t err_cap);
extern int nv_store_wait_compact_30s(NvStore *s, char *err, size_t err_cap);
extern int nv_store_compact_full(NvStore *s, char *err, size_t err_cap);
extern int nv_store_checkpoint(NvStore *s, const char *dir, uint64_t *seq, char *err, size_t err_cap);
extern int nv_store_set_options(NvStore *s, const char **keys, const char **vals, int n, char *err, size_t err_cap);
extern int nv_store_set_db_option(NvStore *s, const char *name, const char *value, char *err, size_t err_cap);
extern int nv_store_live_option(NvStore *s, const char *name, uint64_t *out, char *err, size_t err_cap);
extern uint64_t nv_store_ticker(NvStore *s, int ticker);
extern void nv_store_set_cache_capacity(NvStore *s, size_t bytes);
extern size_t nv_store_cache_capacity(NvStore *s);
extern NvDb *nv_db_create(NvStore *s, int cipher, int level, const uint8_t page_key[32], int sealed, const uint8_t active[32], uint32_t current_id, const uint32_t *retired_ids, const uint8_t *retired_keys, size_t retired_count, const uint8_t master[32], size_t cache_cap, uint64_t init_size);
extern void nv_db_destroy(NvDb *d);
extern int nv_db_set_cipher(NvDb *d, int cipher);
extern int nv_db_set_level(NvDb *d, int level);
extern int nv_db_install_ring(NvDb *d, const uint8_t active[32], uint32_t current_id, const uint32_t *retired_ids, const uint8_t *retired_keys, size_t retired_count);
extern int nv_db_flush(NvDb *d);
extern void nv_db_seal_stats(NvDb *d, uint64_t *pages, uint64_t *uncompressed, uint64_t *payload, uint64_t *stored);
extern int64_t nv_db_read(NvDb *d, uint8_t *out, size_t n, int64_t off, uint64_t *blocks);
extern int nv_db_write(NvDb *d, const uint8_t *in, size_t n, int64_t off, uint64_t *blocks);
extern int nv_db_truncate(NvDb *d, int64_t size);
extern int64_t nv_db_size(NvDb *d);
extern int nv_db_locked(NvDb *d);
extern void nv_db_stats(NvDb *d, uint64_t *pages_read, uint64_t *read_bytes, uint64_t *write_bytes);
extern int nvVfsRegister(const char *name);
extern void nvCtlSetDefaults(int cache_pages, unsigned flush_ms);
extern int nvOpenStoreRef(const char *canon, int create, int cache_pages, uint64_t *handle, void **db, void **store);
extern int nvCloseStoreRef(uint64_t handle);
extern int nvStoreIsLive(const char *canon);
extern int nvStoreLiveCount();
extern int nvPragmaStore(uint64_t handle, const char *name, const char *value, int has_value, int read_only, char *out, size_t cap, size_t *out_len);
extern int nvStoreRotate(uint64_t handle, int read_only, uint32_t *new_id);
extern int nvStorePrune(uint64_t handle, int read_only, char *out, size_t cap, size_t *out_len);
extern void *nvEntryDb(uint64_t id);
extern int nvOfflineRekey(const char *dir, const uint8_t *old_master, const uint8_t *new_master, int fault_after);
extern int nvOfflineVerify(const char *dir, const uint8_t *master);
extern int nvOfflineInventory(const char *dir, const uint8_t *master, char *out, size_t cap, size_t *out_len);
extern int nvStoreKey(uint64_t handle, const uint8_t master[32]);
extern int nvStoreInventory(uint64_t handle, char *out, size_t cap, size_t *out_len);
extern int nvStoreBackup(uint64_t handle, const char *dest, const char *cipher, const uint8_t group[16], const uint8_t node[16]);
extern int nvStoreSetParam(uint64_t handle, int param, uint64_t value, const uint8_t master[32]);
extern int nvStoreKdf(uint64_t handle, int *sealed, uint8_t *kdf, uint32_t *time_ms, uint32_t *mem_kib, uint8_t *threads);
extern int nvStoreSyncStats(uint64_t handle, uint64_t *committed_size, uint64_t *flush_batches);
typedef struct { unsigned long long calls; unsigned long long ns; } NvVfsStat;
extern void nvVfsStats(NvVfsStat *out);
extern void nvVfsStatsReset();
*/
import "C"

import (
	"errors"
	"sync"
	"unsafe"

	"github.com/marcgauthier/libmurmur/clients/go/bindings/nvapi"
	"github.com/marcgauthier/libmurmur/clients/go/bindings/sqlite"

	// Symbol homes for the C++ codec: the codec calls ZSTD_* and
	// aegis_* across the final link, and these edges pull those
	// objects into every binary (including this package's tests)
	// instead of relying on incidental imports.
	_ "github.com/marcgauthier/libmurmur/clients/go/bindings/aegis"
	_ "github.com/marcgauthier/libmurmur/clients/go/bindings/zstd"
)

// Block and MaxRecord mirror the nv_crypto.h buffer contract.
const (
	Block     = 4096
	MaxRecord = 8192
)

var ErrMisuse = errors.New("nvfs: crypto misuse")

// Auth and corruption signals are the shared seam errors: service
// failures map back to the same vars the engine raised.
var (
	ErrAuth    = nvapi.ErrAuth
	ErrCorrupt = nvapi.ErrCorrupt
)

// PageKey builds the 9-byte 'p' + u64be record key via the C++ helper,
// proving both sides agree on the layout.
func PageKey(page uint64) [9]byte {
	var out [9]byte
	C.nv_page_key(C.uint64_t(page), (*C.uint8_t)(unsafe.Pointer(&out[0])))
	return out
}

// Store is the native RocksDB record container: the only RocksDB
// path. Keys and values are arbitrary bytes; page records use
// PageKey, metadata the meta:* keys.
type Store struct {
	raw *C.NvStore
}

// Open opens (or creates) a native store on dir.
func Open(dir string, create bool) (*Store, error) {
	cdir := C.CString(dir)
	defer C.free(unsafe.Pointer(cdir))
	var errbuf [512]byte
	cr := 0
	if create {
		cr = 1
	}
	raw := C.nv_store_open(cdir, C.int(cr),
		(*C.char)(unsafe.Pointer(&errbuf[0])), C.size_t(len(errbuf)))
	if raw == nil {
		return nil, errors.New("nvfs: open failed: " + cStr(errbuf[:]))
	}
	return &Store{raw: raw}, nil
}

// Close releases the store.
func (s *Store) Close() {
	if s.raw != nil {
		C.nv_store_close(s.raw)
		s.raw = nil
	}
}

// Repair runs RocksDB offline repair on dir.
func Repair(dir string) error {
	cdir := C.CString(dir)
	defer C.free(unsafe.Pointer(cdir))
	var errbuf [512]byte
	if rc := C.nv_repair(cdir, (*C.char)(unsafe.Pointer(&errbuf[0])), C.size_t(len(errbuf))); rc != 0 {
		return errors.New("nvfs: repair failed: " + cStr(errbuf[:]))
	}
	return nil
}

func cStr(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

func (s *Store) lastErr(errbuf []byte) error {
	return errors.New("nvfs: rocksdb error: " + cStr(errbuf))
}

// Get reads one key. found=false means missing (zero page /
// absent meta).
func (s *Store) Get(key, val []byte) (vlen int, found bool, err error) {
	if len(key) == 0 || len(val) == 0 {
		return 0, false, ErrMisuse
	}
	var errbuf [512]byte
	var n C.size_t
	rc := C.nv_store_get(s.raw,
		(*C.uint8_t)(unsafe.Pointer(&key[0])), C.size_t(len(key)),
		(*C.uint8_t)(unsafe.Pointer(&val[0])), C.size_t(len(val)),
		&n, (*C.char)(unsafe.Pointer(&errbuf[0])), C.size_t(len(errbuf)))
	switch rc {
	case 1:
		return int(n), true, nil
	case 0:
		return 0, false, nil
	case -2:
		return 0, false, nvapi.ErrNativeShort
	default:
		return 0, false, s.lastErr(errbuf[:])
	}
}

// Put writes one key; sync chooses per-call durability (async puts
// stage until Sync).
func (s *Store) Put(key, val []byte, sync bool) error {
	if len(key) == 0 {
		return ErrMisuse
	}
	var vp unsafe.Pointer
	if len(val) > 0 {
		vp = unsafe.Pointer(&val[0])
	}
	var errbuf [512]byte
	sy := 0
	if sync {
		sy = 1
	}
	rc := C.nv_store_put(s.raw,
		(*C.uint8_t)(unsafe.Pointer(&key[0])), C.size_t(len(key)),
		(*C.uint8_t)(vp), C.size_t(len(val)), C.int(sy),
		(*C.char)(unsafe.Pointer(&errbuf[0])), C.size_t(len(errbuf)))
	if rc != 0 {
		return s.lastErr(errbuf[:])
	}
	return nil
}

// Delete removes one key.
func (s *Store) Delete(key []byte, sync bool) error {
	if len(key) == 0 {
		return ErrMisuse
	}
	var errbuf [512]byte
	sy := 0
	if sync {
		sy = 1
	}
	rc := C.nv_store_del(s.raw,
		(*C.uint8_t)(unsafe.Pointer(&key[0])), C.size_t(len(key)),
		C.int(sy), (*C.char)(unsafe.Pointer(&errbuf[0])), C.size_t(len(errbuf)))
	if rc != 0 {
		return s.lastErr(errbuf[:])
	}
	return nil
}

// DeletePagesFrom drops every page id >= first (staged).
func (s *Store) DeletePagesFrom(first uint64) error {
	var errbuf [512]byte
	rc := C.nv_store_del_pages_from(s.raw, C.uint64_t(first),
		(*C.char)(unsafe.Pointer(&errbuf[0])), C.size_t(len(errbuf)))
	if rc != 0 {
		return s.lastErr(errbuf[:])
	}
	return nil
}

// Sync is the commit barrier; it reports whether a batch advanced.
func (s *Store) Sync() (bool, error) {
	var errbuf [512]byte
	rc := C.nv_store_sync(s.raw,
		(*C.char)(unsafe.Pointer(&errbuf[0])), C.size_t(len(errbuf)))
	if rc < 0 {
		return false, s.lastErr(errbuf[:])
	}
	return rc == 1, nil
}

// Statistics tickers mirror rocksdb/statistics.h numeric ids.
const (
	TickerWALFileBytes     = 63
	TickerCompactWriteByte = 68
	TickerFlushWriteBytes  = 69
)

// ScanPages visits stored page records in id order, stopping at the
// first non-page key like the staged scan. Records past 64 MiB fail
// closed (real records peak near 4.3 KiB).
func (s *Store) ScanPages(fn func(id uint64, rec []byte) error) error {
	raw := C.nv_scan_open(s.raw)
	if raw == nil {
		return errors.New("nvfs: scan open failed")
	}
	defer C.nv_scan_close(raw)
	buf := make([]byte, 8192)
	for {
		var id C.uint64_t
		var n C.size_t
		rc := C.nv_scan_next(raw, &id,
			(*C.uint8_t)(unsafe.Pointer(&buf[0])), C.size_t(len(buf)), &n)
		switch rc {
		case 0:
			return nil
		case -2:
			if uint64(n) > 64<<20 {
				return ErrCorrupt
			}
			buf = make([]byte, int(n))
		case 1:
			rec := append([]byte(nil), buf[:int(n)]...)
			if err := fn(uint64(id), rec); err != nil {
				return err
			}
		default:
			return errors.New("nvfs: scan failed")
		}
	}
}

// FlushWait flushes memtables, waiting for completion.
func (s *Store) FlushWait() error {
	var errbuf [512]byte
	if rc := C.nv_store_flush(s.raw,
		(*C.char)(unsafe.Pointer(&errbuf[0])), C.size_t(len(errbuf))); rc != 0 {
		return s.lastErr(errbuf[:])
	}
	return nil
}

// WaitCompact30s waits up to 30s for background compactions.
func (s *Store) WaitCompact30s() error {
	var errbuf [512]byte
	if rc := C.nv_store_wait_compact_30s(s.raw,
		(*C.char)(unsafe.Pointer(&errbuf[0])), C.size_t(len(errbuf))); rc != 0 {
		return s.lastErr(errbuf[:])
	}
	return nil
}

// CompactFullRange compacts the full key range synchronously.
func (s *Store) CompactFullRange() error {
	var errbuf [512]byte
	if rc := C.nv_store_compact_full(s.raw,
		(*C.char)(unsafe.Pointer(&errbuf[0])), C.size_t(len(errbuf))); rc != 0 {
		return s.lastErr(errbuf[:])
	}
	return nil
}

// CheckpointTo writes a consistent checkpoint plus its sequence number.
func (s *Store) CheckpointTo(dir string) (uint64, error) {
	cdir := C.CString(dir)
	defer C.free(unsafe.Pointer(cdir))
	var errbuf [512]byte
	var seq C.uint64_t
	if rc := C.nv_store_checkpoint(s.raw, cdir, &seq,
		(*C.char)(unsafe.Pointer(&errbuf[0])), C.size_t(len(errbuf))); rc != 0 {
		return 0, s.lastErr(errbuf[:])
	}
	return uint64(seq), nil
}

// SetCFOptions applies column-family options live.
func (s *Store) SetCFOptions(opts map[string]string) error {
	if len(opts) == 0 {
		return errors.New("nvfs: no options to set")
	}
	ckeys := make([]*C.char, 0, len(opts))
	cvals := make([]*C.char, 0, len(opts))
	for k, v := range opts {
		ckeys = append(ckeys, C.CString(k))
		cvals = append(cvals, C.CString(v))
	}
	defer func() {
		for _, c := range ckeys {
			C.free(unsafe.Pointer(c))
		}
		for _, c := range cvals {
			C.free(unsafe.Pointer(c))
		}
	}()
	var errbuf [512]byte
	rc := C.nv_store_set_options(s.raw,
		(**C.char)(unsafe.Pointer(&ckeys[0])),
		(**C.char)(unsafe.Pointer(&cvals[0])),
		C.int(len(ckeys)),
		(*C.char)(unsafe.Pointer(&errbuf[0])), C.size_t(len(errbuf)))
	if rc != 0 {
		return s.lastErr(errbuf[:])
	}
	return nil
}

// SetDBOption applies one DB-level option live.
func (s *Store) SetDBOption(name, value string) error {
	cname := C.CString(name)
	defer C.free(unsafe.Pointer(cname))
	cval := C.CString(value)
	defer C.free(unsafe.Pointer(cval))
	var errbuf [512]byte
	if rc := C.nv_store_set_db_option(s.raw, cname, cval,
		(*C.char)(unsafe.Pointer(&errbuf[0])), C.size_t(len(errbuf))); rc != 0 {
		return s.lastErr(errbuf[:])
	}
	return nil
}

// LiveOption reads a live option value.
func (s *Store) LiveOption(name string) (uint64, error) {
	cname := C.CString(name)
	defer C.free(unsafe.Pointer(cname))
	var errbuf [512]byte
	var out C.uint64_t
	if rc := C.nv_store_live_option(s.raw, cname, &out,
		(*C.char)(unsafe.Pointer(&errbuf[0])), C.size_t(len(errbuf))); rc != 0 {
		return 0, s.lastErr(errbuf[:])
	}
	return uint64(out), nil
}

// SetCacheCapacity resizes the block cache live.
func (s *Store) SetCacheCapacity(bytes int) {
	if bytes < 0 {
		bytes = 0
	}
	C.nv_store_set_cache_capacity(s.raw, C.size_t(bytes))
}

// CacheCapacity reports the block cache capacity.
func (s *Store) CacheCapacity() int {
	return int(C.nv_store_cache_capacity(s.raw))
}

// TickerWALBytes reports WAL bytes written.
func (s *Store) TickerWALBytes() uint64 {
	return uint64(C.nv_store_ticker(s.raw, C.int(TickerWALFileBytes)))
}

// TickerFlushBytes reports flush bytes written.
func (s *Store) TickerFlushBytes() uint64 {
	return uint64(C.nv_store_ticker(s.raw, C.int(TickerFlushWriteBytes)))
}

// TickerCompactBytes reports compaction bytes written.
func (s *Store) TickerCompactBytes() uint64 {
	return uint64(C.nv_store_ticker(s.raw, C.int(TickerCompactWriteByte)))
}

var _ nvapi.NativeStoreAPI = (*Store)(nil)

// DB is one native database: the RocksDB store plus the C++ page
// cache. It implements nvapi.NativeDB, backing an Engine's byte
// and record paths. The owning Engine's mutex serializes all Go-side
// use; VFS-direct traffic never touches this object (C++ holds the
// raw NvDb pointer while files are open).
type DB struct {
	store *Store
	raw   *C.NvDb
}

// CreateDB builds the page-cached byte engine over an open store.
// params provisions the C++ codec once (keys never cross again),
// cachePages bounds the page cache, initSize seeds the size. The
// caller owns the DB (Close releases cache, codec, and store).
func CreateDB(store *Store, params nvapi.CodecParams, cachePages int, initSize uint64) (*DB, error) {
	var activePtr, idsPtr, keysPtr unsafe.Pointer
	sealed := 0
	if params.Sealed {
		sealed = 1
		activePtr = unsafe.Pointer(&params.Active[0])
	}
	if len(params.RetiredIDs) > 0 {
		idsPtr = unsafe.Pointer(&params.RetiredIDs[0])
		keysPtr = unsafe.Pointer(&params.RetiredKeys[0])
	}
	raw := C.nv_db_create(store.raw, C.int(params.Cipher), C.int(params.Level),
		(*C.uint8_t)(unsafe.Pointer(&params.PageKey[0])), C.int(sealed),
		(*C.uint8_t)(activePtr), C.uint32_t(params.Current),
		(*C.uint32_t)(idsPtr), (*C.uint8_t)(keysPtr), C.size_t(len(params.RetiredIDs)),
		(*C.uint8_t)(unsafe.Pointer(&params.Master[0])),
		C.size_t(cachePages), C.uint64_t(initSize))
	if raw == nil {
		return nil, errors.New("nvfs: db create failed")
	}
	return &DB{store: store, raw: raw}, nil
}

// Close releases the page cache and the store. Idempotent.
func (d *DB) Close() {
	if d.raw != nil {
		C.nv_db_destroy(d.raw)
		d.raw = nil
	}
	if d.store != nil {
		d.store.Close()
	}
}

// NReadAt serves a page-cached read. It reports short reads past end
// with a nil error and counts pages touched.
func (d *DB) NReadAt(p []byte, off int64) (int, uint64, error) {
	if off < 0 {
		return 0, 0, errors.New("storage: negative read offset")
	}
	if len(p) == 0 {
		return 0, 0, nil
	}
	var blocks C.uint64_t
	n := C.nv_db_read(d.raw, (*C.uint8_t)(unsafe.Pointer(&p[0])),
		C.size_t(len(p)), C.int64_t(off), &blocks)
	if n == -2 {
		return 0, uint64(blocks), nvapi.ErrCorrupt
	}
	if n < 0 {
		return 0, uint64(blocks), errors.New("nvfs: read failed")
	}
	return int(n), uint64(blocks), nil
}

// NWriteAt serves a page-cached write-through write.
func (d *DB) NWriteAt(p []byte, off int64) (uint64, error) {
	if off < 0 {
		return 0, errors.New("storage: negative write offset")
	}
	var ptr *C.uint8_t
	if len(p) > 0 {
		ptr = (*C.uint8_t)(unsafe.Pointer(&p[0]))
	}
	var blocks C.uint64_t
	rc := C.nv_db_write(d.raw, ptr, C.size_t(len(p)), C.int64_t(off), &blocks)
	if rc == -2 {
		return uint64(blocks), nvapi.ErrCorrupt
	}
	if rc != 0 {
		return uint64(blocks), errors.New("nvfs: write failed")
	}
	return uint64(blocks), nil
}

// NTruncate mirrors the staged truncate exactly (partial-tail zero,
// trailing-record drop, sparse grow).
func (d *DB) NTruncate(size int64) error {
	if size < 0 {
		return errors.New("storage: negative truncate")
	}
	switch rc := C.nv_db_truncate(d.raw, C.int64_t(size)); rc {
	case 0:
		return nil
	case -2:
		return nvapi.ErrCorrupt
	default:
		return errors.New("nvfs: truncate failed")
	}
}

// NSize reports the logical size.
func (d *DB) NSize() int64 {
	return int64(C.nv_db_size(d.raw))
}

// NStats reports byte-path counters for SnapshotStats merging.
func (d *DB) NStats() (pagesRead, readBytes, writeBytes uint64) {
	var pr, rb, wb C.uint64_t
	C.nv_db_stats(d.raw, &pr, &rb, &wb)
	return uint64(pr), uint64(rb), uint64(wb)
}

// NSealStats reports seal counters for SnapshotStats merging.
func (d *DB) NSealStats() (pages, uncompressed, payload, stored uint64) {
	var p, u, pl, s C.uint64_t
	C.nv_db_seal_stats(d.raw, &p, &u, &pl, &s)
	return uint64(p), uint64(u), uint64(pl), uint64(s)
}

// NSetCipher swaps the codec cipher (cold: empty databases only).
func (d *DB) NSetCipher(cipher int) error {
	if rc := C.nv_db_set_cipher(d.raw, C.int(cipher)); rc != 0 {
		return errors.New("nvfs: set cipher failed")
	}
	return nil
}

// NSetLevel swaps the codec compression level (cold).
func (d *DB) NSetLevel(level int) error {
	if rc := C.nv_db_set_level(d.raw, C.int(level)); rc != 0 {
		return errors.New("nvfs: set compression failed")
	}
	return nil
}

// NFlush seals the dirty set and lands it in RocksDB. Runs before
// every sync barrier (Sync, Checkpoint, Close, Backup, Compact, and
// the background flusher).
func (d *DB) NFlush() error {
	if rc := C.nv_db_flush(d.raw); rc != 0 {
		return errors.New("nvfs: flush failed")
	}
	return nil
}

// NInstallRing installs a sealed ring trial set (cold: seal/rotate/prune).
func (d *DB) NInstallRing(active [32]byte, current uint32, ids []uint32, keys []byte) error {
	var idsPtr, keysPtr unsafe.Pointer
	if len(ids) > 0 {
		idsPtr = unsafe.Pointer(&ids[0])
		keysPtr = unsafe.Pointer(&keys[0])
	}
	rc := C.nv_db_install_ring(d.raw, (*C.uint8_t)(unsafe.Pointer(&active[0])),
		C.uint32_t(current), (*C.uint32_t)(idsPtr), (*C.uint8_t)(keysPtr), C.size_t(len(ids)))
	if rc != 0 {
		return errors.New("nvfs: install ring failed")
	}
	return nil
}

// Record-container surface: forwarded to the store, except Close,
// which releases the whole database (see above).
func (d *DB) Get(key, val []byte) (int, bool, error) { return d.store.Get(key, val) }
func (d *DB) Put(key, val []byte, sync bool) error   { return d.store.Put(key, val, sync) }
func (d *DB) Delete(key []byte, sync bool) error     { return d.store.Delete(key, sync) }
func (d *DB) DeletePagesFrom(first uint64) error     { return d.store.DeletePagesFrom(first) }
func (d *DB) Sync() (bool, error)                    { return d.store.Sync() }
func (d *DB) ScanPages(fn func(id uint64, rec []byte) error) error {
	return d.store.ScanPages(fn)
}
func (d *DB) FlushWait() error        { return d.store.FlushWait() }
func (d *DB) WaitCompact30s() error   { return d.store.WaitCompact30s() }
func (d *DB) CompactFullRange() error { return d.store.CompactFullRange() }
func (d *DB) CheckpointTo(dir string) (uint64, error) {
	return d.store.CheckpointTo(dir)
}
func (d *DB) SetCFOptions(opts map[string]string) error { return d.store.SetCFOptions(opts) }
func (d *DB) SetDBOption(name, value string) error      { return d.store.SetDBOption(name, value) }
func (d *DB) LiveOption(name string) (uint64, error)    { return d.store.LiveOption(name) }
func (d *DB) SetCacheCapacity(bytes int)                { d.store.SetCacheCapacity(bytes) }
func (d *DB) CacheCapacity() int                        { return d.store.CacheCapacity() }
func (d *DB) TickerWALBytes() uint64                    { return d.store.TickerWALBytes() }
func (d *DB) TickerFlushBytes() uint64                  { return d.store.TickerFlushBytes() }
func (d *DB) TickerCompactBytes() uint64                { return d.store.TickerCompactBytes() }

var _ nvapi.NativeDB = (*DB)(nil)

// Lock levels live in C++ now (db.cc lock table, SQLITE_LOCK_*);
// this package keeps no lock state.

// VFSConfig wires the interim Go hooks into the native VFS. The C++
// control plane owns the registry, lifecycle, keys, and PRAGMA
// table; Go only serves murmur_* extension PRAGMAs (until
// replication moves in) and drops extension slots on close. Keys
// travel as raw bytes through the explicit key APIs; see KeyStore.
type VFSConfig struct {
	// FileExt serves murmur_* extension PRAGMAs on a file.
	FileExt func(file uint64, name string, value *string) (string, int)
	// OnCloseFile drops a file's extension slot.
	OnCloseFile func(file uint64)
	// CachePages bounds the C++ page cache; 0 selects the default.
	CachePages int
	// FlushMS is the background flush interval; 0 selects 250 ms.
	FlushMS uint32
}

var (
	ctlMu         sync.Mutex
	ctlName       string
	fileExtFn     func(file uint64, name string, value *string) (string, int)
	storeExtFn    func(handle uint64, name string, value *string) (string, int)
	onCloseFileFn func(file uint64)
)

// RegisterVFS registers the native murmur VFS under name. Only one
// registration is supported; registering again with the same name
// replaces the config.
func RegisterVFS(name string, cfg VFSConfig) error {
	ctlMu.Lock()
	defer ctlMu.Unlock()
	if ctlName != "" && ctlName != name {
		return &sqlite.Error{Code: int(C.SQLITE_MISUSE), Msg: "vfs already registered"}
	}
	if ctlName == "" {
		cname := C.CString(name)
		// Intentionally retained: SQLite keeps the pointer.
		if rc := C.nvVfsRegister(cname); rc != C.SQLITE_OK {
			C.free(unsafe.Pointer(cname))
			return &sqlite.Error{Code: int(rc), Msg: "vfs register failed"}
		}
		ctlName = name
	}
	fileExtFn = cfg.FileExt
	onCloseFileFn = cfg.OnCloseFile
	C.nvCtlSetDefaults(C.int(cfg.CachePages), C.uint(cfg.FlushMS))
	return nil
}

// VFSOpStat is one VFS method's accumulated calls and nanoseconds.
// Zeros unless built with -tags murmurvfsstats.
type VFSOpStat struct {
	Calls uint64
	Ns    uint64
}

// VFSStatNames orders VFSStats; matches vfs.cc nvVfsStats.
var VFSStatNames = [...]string{
	"open", "close", "readDb", "readAux", "writeDb", "writeAux",
	"truncate", "sync", "fileSize", "lock", "unlock", "checkRes",
	"fileControl", "vfsDelete", "vfsAccess",
}

// VFSStats snapshots the vfs.cc per-op counters.
func VFSStats() [15]VFSOpStat {
	var raw [15]C.NvVfsStat
	C.nvVfsStats(&raw[0])
	var out [15]VFSOpStat
	for i := range raw {
		out[i] = VFSOpStat{Calls: uint64(raw[i].calls), Ns: uint64(raw[i].ns)}
	}
	return out
}

// VFSStatsReset zeroes the vfs.cc per-op counters.
func VFSStatsReset() {
	C.nvVfsStatsReset()
}

// SetFileExt installs the murmur_* file extension slot lookup.
func SetFileExt(fn func(file uint64, name string, value *string) (string, int)) {
	ctlMu.Lock()
	defer ctlMu.Unlock()
	fileExtFn = fn
}

// SetStoreExt installs the store-level murmur_* extension dispatch.
func SetStoreExt(fn func(handle uint64, name string, value *string) (string, int)) {
	ctlMu.Lock()
	defer ctlMu.Unlock()
	storeExtFn = fn
}

// SetOnCloseFile installs the file-close extension-slot drop.
func SetOnCloseFile(fn func(file uint64)) {
	ctlMu.Lock()
	defer ctlMu.Unlock()
	onCloseFileFn = fn
}

// StoreRef is a shell reference on a live C++ store: the opaque
// handle plus a DB wrapping the borrowed raw pointers (valid until
// CloseStoreRef).
type StoreRef struct {
	Handle uint64
	DB     *DB
}

// Store returns the record-container surface over the borrowed store.
func (r StoreRef) Store() *Store { return r.DB.store }

// OpenStoreRef opens a shared shell reference on a store.
func OpenStoreRef(canon string, create bool, cachePages int) (StoreRef, error) {
	var ref StoreRef
	ccanon := C.CString(canon)
	defer C.free(unsafe.Pointer(ccanon))
	cr := 0
	if create {
		cr = 1
	}
	var handle C.uint64_t
	var db, store unsafe.Pointer
	rc := C.nvOpenStoreRef(ccanon, C.int(cr), C.int(cachePages), &handle, &db, &store)
	if rc != C.SQLITE_OK {
		return ref, &sqlite.Error{Code: int(rc), Msg: "nvfs: store open failed"}
	}
	ref.Handle = uint64(handle)
	ref.DB = &DB{
		store: &Store{raw: (*C.NvStore)(store)},
		raw:   (*C.NvDb)(db),
	}
	return ref, nil
}

// CloseStoreRef drops one shell reference.
func CloseStoreRef(handle uint64) {
	C.nvCloseStoreRef(C.uint64_t(handle))
}

// StoreIsLive reports whether canon names a live store (no open).
func StoreIsLive(canon string) bool {
	ccanon := C.CString(canon)
	defer C.free(unsafe.Pointer(ccanon))
	return C.nvStoreIsLive(ccanon) != 0
}

// StoreLiveCount reports how many stores are live.
func StoreLiveCount() int {
	return int(C.nvStoreLiveCount())
}

// PragmaStore serves one PRAGMA on a shell reference. value is nil
// for read-back; readOnly selects the operator context.
func PragmaStore(handle uint64, name string, value *string, readOnly bool) (int, string) {
	cname := C.CString(name)
	defer C.free(unsafe.Pointer(cname))
	var cvalue *C.char
	hasValue := 0
	if value != nil {
		cvalue = C.CString(*value)
		defer C.free(unsafe.Pointer(cvalue))
		hasValue = 1
	}
	ro := 0
	if readOnly {
		ro = 1
	}
	out := make([]byte, 4096)
	for {
		var outLen C.size_t
		rc := C.nvPragmaStore(C.uint64_t(handle), cname, cvalue, C.int(hasValue),
			C.int(ro), (*C.char)(unsafe.Pointer(&out[0])), C.size_t(len(out)), &outLen)
		if rc != -2 {
			return int(rc), string(out[:outLen])
		}
		need := int(outLen)
		if need <= len(out) || need > 1<<20 {
			return int(C.SQLITE_NOMEM), ""
		}
		out = make([]byte, need)
	}
}

// StoreDb re-fetches a shell's live codec pointer. Shells opened
// keyless hold a nil DB until PRAGMA key provisions; call this once
// after keying (KeyStore does it).
func StoreDb(handle uint64) unsafe.Pointer {
	return unsafe.Pointer(C.nvEntryDb(C.uint64_t(handle)))
}

// OfflineRekey rewrites every page of a sealed store under a fresh
// data key sealed by newMaster. faultAfter aborts after N pages
// (test crash hook; 0 disables). Codes mirror storage.RekeyDir.
func OfflineRekey(dir string, oldMaster, newMaster [32]byte, faultAfter int) int {
	cdir := C.CString(dir)
	defer C.free(unsafe.Pointer(cdir))
	return int(C.nvOfflineRekey(cdir,
		(*C.uint8_t)(unsafe.Pointer(&oldMaster[0])),
		(*C.uint8_t)(unsafe.Pointer(&newMaster[0])), C.int(faultAfter)))
}

// OfflineVerify trial-opens every page of a sealed store.
// Read-only. Codes mirror storage.VerifyDir.
func OfflineVerify(dir string, master [32]byte) int {
	cdir := C.CString(dir)
	defer C.free(unsafe.Pointer(cdir))
	return int(C.nvOfflineVerify(cdir,
		(*C.uint8_t)(unsafe.Pointer(&master[0]))))
}

// OfflineInventory serializes a closed store's ring state as JSON,
// byte-identical to Engine.InventoryJSON.
func OfflineInventory(dir string, master [32]byte) (string, int) {
	cdir := C.CString(dir)
	defer C.free(unsafe.Pointer(cdir))
	out := make([]byte, 4096)
	for {
		var outLen C.size_t
		rc := C.nvOfflineInventory(cdir,
			(*C.uint8_t)(unsafe.Pointer(&master[0])),
			(*C.char)(unsafe.Pointer(&out[0])), C.size_t(len(out)), &outLen)
		if rc != -2 {
			return string(out[:outLen]), int(rc)
		}
		need := int(outLen)
		if need <= len(out) || need > 1<<20 {
			return "", int(C.SQLITE_NOMEM)
		}
		out = make([]byte, need)
	}
}

// KeyStore provisions the master on a shell reference through the
// explicit nvStoreKey API and refreshes its borrowed codec pointer.
// It reports the key result code.
func KeyStore(ref *StoreRef, key [32]byte) int {
	rc := int(C.nvStoreKey(C.uint64_t(ref.Handle),
		(*C.uint8_t)(unsafe.Pointer(&key[0]))))
	if rc != 0 {
		return rc
	}
	db := StoreDb(ref.Handle)
	if db == nil {
		return int(C.SQLITE_CANTOPEN)
	}
	ref.DB.raw = (*C.NvDb)(db)
	return 0
}

// StoreRotate mints a fresh data key on a live sealed store.
// Mirrors Engine.Rotate codes.
func StoreRotate(handle uint64, readOnly bool) (int, uint32) {
	ro := 0
	if readOnly {
		ro = 1
	}
	var id C.uint32_t
	rc := C.nvStoreRotate(C.uint64_t(handle), C.int(ro), &id)
	return int(rc), uint32(id)
}

// StorePrune drops retired keys no live page references and reports
// pruneJSON. Mirrors Engine.Prune codes.
func StorePrune(handle uint64, readOnly bool) (int, string) {
	ro := 0
	if readOnly {
		ro = 1
	}
	out := make([]byte, 4096)
	for {
		var outLen C.size_t
		rc := C.nvStorePrune(C.uint64_t(handle), C.int(ro),
			(*C.char)(unsafe.Pointer(&out[0])), C.size_t(len(out)), &outLen)
		if rc != -2 {
			return int(rc), string(out[:outLen])
		}
		need := int(outLen)
		if need <= len(out) || need > 1<<20 {
			return int(C.SQLITE_NOMEM), ""
		}
		out = make([]byte, need)
	}
}

// StoreBackup checkpoints a live store plus its manifest into dest.
// group and node are the 16-byte manifest ids. Codes mirror
// Engine.BackupTo.
func StoreBackup(handle uint64, dest, cipher string, group, node []byte) int {
	if len(group) != 16 || len(node) != 16 {
		return int(C.SQLITE_MISUSE)
	}
	cdest := C.CString(dest)
	defer C.free(unsafe.Pointer(cdest))
	ccipher := C.CString(cipher)
	defer C.free(unsafe.Pointer(ccipher))
	return int(C.nvStoreBackup(C.uint64_t(handle), cdest, ccipher,
		(*C.uint8_t)(unsafe.Pointer(&group[0])),
		(*C.uint8_t)(unsafe.Pointer(&node[0]))))
}

// StoreInventory serializes a live shell's ring state as JSON,
// byte-identical to Engine.InventoryJSON.
func StoreInventory(handle uint64) (string, int) {
	out := make([]byte, 4096)
	for {
		var outLen C.size_t
		rc := C.nvStoreInventory(C.uint64_t(handle),
			(*C.char)(unsafe.Pointer(&out[0])), C.size_t(len(out)), &outLen)
		if rc != -2 {
			return string(out[:outLen]), int(rc)
		}
		need := int(outLen)
		if need <= len(out) || need > 1<<20 {
			return "", int(C.SQLITE_NOMEM)
		}
		out = make([]byte, need)
	}
}

// StoreSetParam tunes one staged seal parameter (or seals) on a
// shell reference. It mirrors Engine.SetParam codes. master travels
// with the call so shells seal with their own key.
func StoreSetParam(handle uint64, param int, value uint64, master [32]byte) int {
	return int(C.nvStoreSetParam(C.uint64_t(handle), C.int(param), C.uint64_t(value),
		(*C.uint8_t)(unsafe.Pointer(&master[0]))))
}

// KdfState is the seal state: the envelope header when sealed, the
// staged seal parameters otherwise.
type KdfState struct {
	Sealed  bool
	KDF     uint8
	Time    uint32
	Memory  uint32
	Threads uint8
}

// StoreKdf reads one shell reference's seal state.
func StoreKdf(handle uint64) (KdfState, int) {
	var st KdfState
	var sealed C.int
	var kdf C.uint8_t
	var timeMs, memKiB C.uint32_t
	var threads C.uint8_t
	rc := C.nvStoreKdf(C.uint64_t(handle), &sealed, &kdf, &timeMs, &memKiB, &threads)
	if rc != C.SQLITE_OK {
		return st, int(rc)
	}
	st.Sealed = sealed != 0
	st.KDF = uint8(kdf)
	st.Time = uint32(timeMs)
	st.Memory = uint32(memKiB)
	st.Threads = uint8(threads)
	return st, int(C.SQLITE_OK)
}

// StoreSyncStats reads the commit-boundary size and the flusher
// batch count.
func StoreSyncStats(handle uint64) (committed, batches uint64, rc int) {
	var c, b C.uint64_t
	rc = int(C.nvStoreSyncStats(C.uint64_t(handle), &c, &b))
	return uint64(c), uint64(b), rc
}

// Locks live in the C++ NvDb lock table (db.cc); the VFS never
// calls into Go for xLock/xUnlock/xCheckReserved.

// extResult marshals an extension PRAGMA result into the C++
// short-buffer protocol.
func extResult(res string, code int, out *C.char, cap C.size_t, outLen *C.size_t) C.int {
	*outLen = 0
	if res == "" {
		return C.int(code)
	}
	if uint64(len(res))+1 > uint64(cap) || out == nil {
		*outLen = C.size_t(len(res) + 1)
		return -2
	}
	copy(unsafe.Slice((*byte)(unsafe.Pointer(out)), len(res)), res)
	*outLen = C.size_t(len(res))
	return C.int(code)
}

// NoExtensionHint names the missing murmur-replication slot, as the
// Go dispatch did.
const NoExtensionHint = "load murmur-replication before using murmur PRAGMAs"

//export nvMurmurExtFileGo
func nvMurmurExtFileGo(file C.uint64_t, cname, cvalue *C.char, hasValue C.int, out *C.char, cap C.size_t, outLen *C.size_t) (rc C.int) {
	defer func() {
		if recover() != nil {
			rc = C.SQLITE_ERROR
		}
	}()
	ctlMu.Lock()
	hook := fileExtFn
	ctlMu.Unlock()
	if hook == nil || cname == nil {
		return extResult(NoExtensionHint, int(C.SQLITE_ERROR), out, cap, outLen)
	}
	var value *string
	if hasValue != 0 && cvalue != nil {
		s := C.GoString(cvalue)
		value = &s
	}
	res, code := hook(uint64(file), C.GoString(cname), value)
	return extResult(res, code, out, cap, outLen)
}

//export nvMurmurExtStoreGo
func nvMurmurExtStoreGo(handle C.uint64_t, cname, cvalue *C.char, hasValue C.int, out *C.char, cap C.size_t, outLen *C.size_t) (rc C.int) {
	defer func() {
		if recover() != nil {
			rc = C.SQLITE_ERROR
		}
	}()
	ctlMu.Lock()
	hook := storeExtFn
	ctlMu.Unlock()
	if hook == nil || cname == nil {
		return extResult(NoExtensionHint, int(C.SQLITE_ERROR), out, cap, outLen)
	}
	var value *string
	if hasValue != 0 && cvalue != nil {
		s := C.GoString(cvalue)
		value = &s
	}
	res, code := hook(uint64(handle), C.GoString(cname), value)
	return extResult(res, code, out, cap, outLen)
}

//export nvCloseFileGo
func nvCloseFileGo(file C.uint64_t) {
	defer func() { _ = recover() }()
	ctlMu.Lock()
	hook := onCloseFileFn
	ctlMu.Unlock()
	if hook != nil {
		hook(uint64(file))
	}
}
