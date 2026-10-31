package storage

// Record keys and meta keys mirror the sqlite-murmur RocksDB layout
// byte-for-byte: page records live under 'p' + u64be, metadata under
// the meta:* keys. Both backends (file slots and RocksDB) implement
// recordStore; only the container differs.
const (
	MetaSize         = "meta:size"
	MetaCipher       = "meta:cipher"
	MetaKeyring      = "meta:keyring"
	MetaKeyringRekey = "meta:keyring.REKEY"
	MetaStoreID      = "meta:store_id"

	// EndKey bounds page-range deletes ('p' < 'q').
	EndKey = "q"
)

// PageKey lives in crypto.go ('p' + u64be). recordMeta is the persisted
// store header in backend-neutral form.
type recordMeta struct {
	size     uint64
	cipher   Cipher
	storeID  [16]byte
	hasSID   bool
	envelope []byte // nil/empty when unsealed
}

// recordStore persists page records and metadata. Page writes are
// staged (durable at the next sync barrier, mirroring RocksDB WAL
// semantics); metadata writes choose per-call durability. All methods
// assume the engine holds its mutex unless noted.
type recordStore interface {
	// load reads size, cipher, store id, and envelope.
	load() (recordMeta, error)
	// saveCipher persists the page AEAD selection.
	saveCipher(c Cipher, sync bool) error
	// saveSize stages the logical size (durable at sync).
	saveSize(size uint64) error
	// saveStoreID persists the 16-byte store identity.
	saveStoreID(id [16]byte, sync bool) error
	// saveKeyring persists the envelope (nil clears).
	saveKeyring(env []byte, sync bool) error
	// getPage reads one record; found=false means a zero page.
	getPage(id uint64) (rec []byte, found bool, err error)
	// putPage stages one record.
	putPage(id uint64, rec []byte) error
	// deletePagesFrom drops every page id >= first (staged).
	deletePagesFrom(first uint64) error
	// scanPages visits stored page records in id order, stopping at
	// the first non-page key like the Rust iterator loop.
	scanPages(fn func(id uint64, rec []byte) error) error
	// sync is the durability barrier; it reports batches advanced.
	sync() (batches uint64, err error)
	// backupTo checkpoints the store plus manifest; it reports the
	// checkpoint sequence (0 for backends without one).
	backupTo(dest, cipher string, group, node []byte) (uint64, error)
	// close releases backend resources.
	close() error
}

// rocksBackend is implemented by record stores with a live RocksDB
// handle behind them (PRAGMA and checkpoint surface).
type rocksBackend interface {
	setCFOptions(opts map[string]string) error
	setDBOption(name, value string) error
	liveOption(name string) (uint64, error)
	setCacheCapacity(bytes int)
	cacheCapacity() int
	tickerWALBytes() uint64
	tickerFlushBytes() uint64
	tickerCompactBytes() uint64
	flushWait() error
	waitCompact30s() error
	compactFullRange() error
	checkpointTo(dir string) (uint64, error)
}
