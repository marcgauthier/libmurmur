// Package nvapi is the dependency-free seam between the storage
// engine and the native (C++) VFS hot path.
//
// storage owns Engine and the record protocol; nvfs owns the page
// cache, buffer allocation, the codec, and the RocksDB pump. Key
// material is provisioned once at database open (CodecParams) and
// never crosses into Go again, so neither package may import the
// other: shared interfaces, key-provisioning types, and the errors
// that cross the boundary live here.
package nvapi

import "errors"

var (
	// ErrAuth reports authentication failure (wrong key).
	ErrAuth = errors.New("storage: keyring authentication failed")
	// ErrCorrupt reports undecryptable or malformed records.
	ErrCorrupt = errors.New("storage: corrupt keyring")
	// ErrNativeShort reports an undersized native value buffer.
	// Callers grow and retry; values past the cap fail closed.
	ErrNativeShort = errors.New("storage: native value buffer too small")
)

// CachePagesDefault bounds the page cache (4 KiB pages).
const CachePagesDefault = 16384

// CodecParams provisions the C++ page codec once at database open.
// PageKey seals legacy records (master when unsealed, active data key
// when sealed); the ring trial set is live only when Sealed.
// RetiredKeys is flat (32 bytes per RetiredIDs entry).
type CodecParams struct {
	Cipher      int
	Level       int
	PageKey     [32]byte
	Sealed      bool
	Active      [32]byte
	Current     uint32
	RetiredIDs  []uint32
	RetiredKeys []byte
	Master      [32]byte
}

// NativeStoreAPI is the record-container surface a native database
// implements: metadata plus page records with staged-write and
// sync-barrier semantics.
type NativeStoreAPI interface {
	Get(key, val []byte) (int, bool, error)
	Put(key, val []byte, sync bool) error
	Delete(key []byte, sync bool) error
	DeletePagesFrom(first uint64) error
	Sync() (bool, error)
	ScanPages(fn func(id uint64, rec []byte) error) error
	FlushWait() error
	WaitCompact30s() error
	CompactFullRange() error
	CheckpointTo(dir string) (uint64, error)
	SetCFOptions(opts map[string]string) error
	SetDBOption(name, value string) error
	LiveOption(name string) (uint64, error)
	SetCacheCapacity(bytes int)
	CacheCapacity() int
	TickerWALBytes() uint64
	TickerFlushBytes() uint64
	TickerCompactBytes() uint64
	Close()
}

// NativeByteAPI is the page-cached byte-engine surface. Reads report
// short past end with a nil error.
type NativeByteAPI interface {
	NReadAt(p []byte, off int64) (int, uint64, error)
	NWriteAt(p []byte, off int64) (uint64, error)
	NTruncate(size int64) error
	NSize() int64
	// NStats reports byte-path counters merged into SnapshotStats
	// (pages read, bytes read, bytes written).
	NStats() (pagesRead, readBytes, writeBytes uint64)
	// NSealStats reports seal counters merged into SnapshotStats
	// (pages sealed, uncompressed bytes, payload bytes, stored bytes).
	NSealStats() (pages, uncompressed, payload, stored uint64)
	// NFlush seals the dirty set and lands it in RocksDB.
	NFlush() error
	// Cold codec updates (PRAGMA cipher/compression, seal/rotate/prune).
	NSetCipher(cipher int) error
	NSetLevel(level int) error
	NInstallRing(active [32]byte, current uint32, ids []uint32, keys []byte) error
}

// NativeDB bundles both native surfaces: one object backing an Engine.
type NativeDB interface {
	NativeStoreAPI
	NativeByteAPI
}

// Engine is the storage-engine surface the native VFS assembly
// needs: key provisioning, size, close, byte-engine attach, and the
// sync/commit barriers the file methods drive.
type Engine interface {
	CodecSnapshot() CodecParams
	Size() int64
	Close() error
	AttachNative(db NativeDB)
	Sync() error
	CompleteTransaction() int
}
