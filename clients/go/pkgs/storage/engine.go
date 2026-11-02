// Package storage implements the murmur encrypted page engine.
//
// The engine is a BlockStore: SQLite's VFS reads and writes plaintext
// bytes, and the engine encrypts each 4096-byte block with the page AEAD
// (AES-256-GCM) before persisting it. Records use the
// EXP1-EXP4 envelopes shared with sqlite-murmur.
//
// Directory engines persist through RocksDB with a byte-identical
// layout ('p'+u64be page keys, meta:* metadata), so databases open in
// either implementation. Memory and single-file engines use a fixed
// slot container behind the same record interface.
//
// Unlike the Rust engine there is no background persist thread: page
// writes stage immediately and a sync barrier (commit) makes them
// durable, which keeps the same commit-boundary guarantee with simpler
// crash behavior.
package storage

import (
	"bytes"
	"container/list"
	"crypto/rand"
	"errors"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/marcgauthier/libmurmur/clients/go/bindings/nvapi"
	"github.com/marcgauthier/libmurmur/clients/go/bindings/nvfs"
	"github.com/marcgauthier/libmurmur/clients/go/bindings/zstd"
)

// SQLite result codes mirrored for the engine and PRAGMA table.
const (
	CodeOK       = 0
	CodeError    = 1
	CodeBusy     = 5
	CodeNoMem    = 7
	CodeReadOnly = 8
	CodeIOErr    = 10
	CodeCorrupt  = 11
	CodeNotFound = 12
	CodeMisuse   = 21
)

// Keyring params mirror sqlite_murmur_keyring_args. KDF selectors and
// scrypt defaults live in keyring.go.
const (
	KeyringParamKDF     = 1
	KeyringParamScryptN = 2
	KeyringParamScryptR = 3
	KeyringParamScryptP = 4
)

// CachePagesDefault bounds the plaintext page cache.
const CachePagesDefault = nvapi.CachePagesDefault

// Errors for engine misuse.
var (
	ErrClosed   = errors.New("storage: engine closed")
	ErrReadOnly = errors.New("storage: read-only engine")
)

// Stats counts engine traffic. Counters only grow.
type Stats struct {
	PagesRead            uint64
	PagesWritten         uint64
	UncompressedBytes    uint64
	StoredBytes          uint64
	CompressedPayloadSum uint64
	VFSReadBytes         uint64
	VFSWriteBytes        uint64
	FlushBatches         uint64
	WALBytes             uint64
	FlushBytes           uint64
	CompactBytes         uint64
}

// Engine is an encrypted BlockStore. The zero value is unusable;
// construct with OpenFile, OpenDir, or OpenMem. All methods are safe
// for concurrent use. Close wipes key material.
type Engine struct {
	rec    recordStore
	native NativeByteAPI // non-nil: byte path served from C++ (see native.go)
	lockF  *os.File      // cross-process lock for single-file engines
	mu     sync.Mutex
	// wg pins in-flight native byte ops. NReadAt/NWriteAt/NTruncate
	// call back into the crypto service, which locks mu for key
	// snapshots — so native calls must run WITHOUT mu held, and
	// Close drains wg before destroying the native database.
	wg sync.WaitGroup
	// flushStop/flushDone bracket the background persistence
	// worker. Commits never sync; the worker persists every
	// flushInterval ms, and Sync/Checkpoint/Close are explicit
	// barriers.
	flushStop      chan struct{}
	flushDone      chan struct{}
	flusherStarted bool

	master  [32]byte
	ring    *Keyring
	active  [32]byte
	storeID [16]byte
	hasSID  bool

	cipher        Cipher
	compression   int32
	flushInterval uint32
	bgThreads     uint32
	rocksSync     bool

	stagedKDF uint8
	stagedN   uint32
	stagedR   uint32
	stagedP   uint8

	size          uint64
	committedSize uint64
	flushBatches  uint64
	cache         map[uint64]*list.Element
	lru           *list.List
	cap           int

	stats  Stats
	closed bool
	// live marks a registry shell: the C++ control plane owns the
	// store (registry, flusher, PRAGMA table) and the shell borrows
	// it via handle until Close. loadedEnv tracks the envelope the
	// ring was opened from, so live Rotate/Prune can refresh after
	// external seals.
	live      bool
	handle    uint64
	canon     string
	loadedEnv []byte
}

type cacheEnt struct {
	id    uint64
	block [Block]byte
}

// OpenFile opens (or creates) a single-file engine. key is the host
// master key. create allows a fresh database; without it the file must
// exist. Single-file engines are a Go-port convenience format; use
// OpenDir for the cross-implementation RocksDB format.
func OpenFile(path string, key [32]byte, create bool) (*Engine, error) {
	lock, err := acquireLockFile(path + ".mlock")
	if err != nil {
		return nil, err
	}
	raw, err := openFileStore(path, create)
	if err != nil {
		lock.Close()
		return nil, err
	}
	rec := &fileRecords{raw: raw, srcPath: path, krPath: path + ".mkeyring"}
	e := newEngine(rec, key, CachePagesDefault)
	e.lockF = lock
	if err := e.load(); err != nil {
		e.Close()
		return nil, err
	}
	e.startFlusher()
	return e, nil
}

// OpenMem opens a memory-backed engine for tests and temp databases.
func OpenMem(key [32]byte) *Engine {
	return newEngine(&fileRecords{raw: &MemBlockStore{}}, key, CachePagesDefault)
}

func newEngine(rec recordStore, key [32]byte, cap int) *Engine {
	if cap <= 0 {
		cap = CachePagesDefault
	}
	return &Engine{
		rec:           rec,
		master:        key,
		cipher:        CipherAES256GCM,
		compression:   zstd.DefaultLevel,
		flushInterval: 250,
		flushStop:     make(chan struct{}),
		flushDone:     make(chan struct{}),
		bgThreads:     uint32(runtime.NumCPU()),
		stagedKDF:     KDFDirectHKDF,
		stagedN:       ScryptNDefault,
		stagedR:       ScryptRDefault,
		stagedP:       ScryptPDefault,
		cache:         map[uint64]*list.Element{},
		lru:           list.New(),
		cap:           cap,
	}
}

// load reads persisted metadata and opens the envelope, if any.
func (e *Engine) load() error {
	meta, err := e.rec.load()
	if err != nil {
		return err
	}
	e.cipher = meta.cipher
	e.size = meta.size
	e.committedSize = meta.size
	e.storeID = meta.storeID
	e.hasSID = meta.hasSID
	e.loadedEnv = append([]byte(nil), meta.envelope...)
	if len(meta.envelope) == 0 {
		return nil
	}
	ring, err := openRekeyRing(meta.envelope, e.master, e.storeID)
	if err != nil {
		return errors.New("storage: keyring open failed")
	}
	cur, ok := ring.ByID(ring.Current)
	if !ok || ring.Current == 0 {
		ring.Wipe()
		return errors.New("storage: keyring has no current key")
	}
	e.ring = ring
	e.active = cur.Key
	e.loadedEnv = append([]byte(nil), meta.envelope...)
	return nil
}

// reloadRingLocked reopens the ring from the current envelope (or
// clears it when unsealed). Live shells call it after a seal and
// before ring mutations, so external seals/rotates are observed.
// Callers hold e.mu.
func (e *Engine) reloadRingLocked() {
	meta, err := e.rec.load()
	if err != nil {
		return
	}
	e.storeID = meta.storeID
	e.hasSID = meta.hasSID
	e.loadedEnv = append([]byte(nil), meta.envelope...)
	if e.ring != nil {
		e.ring.Wipe()
		e.ring = nil
	}
	for i := range e.active {
		e.active[i] = 0
	}
	if len(meta.envelope) == 0 {
		return
	}
	ring, err := openRekeyRing(meta.envelope, e.master, e.storeID)
	if err != nil {
		return
	}
	cur, ok := ring.ByID(ring.Current)
	if !ok || ring.Current == 0 {
		ring.Wipe()
		return
	}
	e.ring = ring
	e.active = cur.Key
}

// refreshRingLocked reloads the ring when the envelope changed under
// a live shell (another connection sealed or rotated). Callers hold
// e.mu.
func (e *Engine) refreshRingLocked() error {
	meta, err := e.rec.load()
	if err != nil {
		return err
	}
	if bytes.Equal(meta.envelope, e.loadedEnv) {
		return nil
	}
	e.reloadRingLocked()
	return nil
}

// Wipe releases key material without closing the backend. Callers that
// only need to drop secrets (failed opens) use this; Close also
// releases files and handles.
func (e *Engine) Wipe() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.wipeLocked()
}

func (e *Engine) wipeLocked() {
	for i := range e.master {
		e.master[i] = 0
	}
	for i := range e.active {
		e.active[i] = 0
	}
	if e.ring != nil {
		e.ring.Wipe()
		e.ring = nil
	}
	for i := range e.loadedEnv {
		e.loadedEnv[i] = 0
	}
	e.loadedEnv = nil
	for _, el := range e.cache {
		ce := el.Value.(*cacheEnt)
		for i := range ce.block {
			ce.block[i] = 0
		}
	}
	e.cache = map[uint64]*list.Element{}
	e.lru.Init()
}

// Close syncs, wipes key material, and releases the backend.
// Registry shells only drop their reference (the last close syncs
// and destroys in C++) and wipe keys.
func (e *Engine) Close() error {
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return nil
	}
	e.closed = true
	live, handle := e.live, e.handle
	started := e.flusherStarted
	e.mu.Unlock()
	// Drain in-flight native byte ops and unlocked flushes before
	// teardown. They only touch mu briefly, so mu must stay free
	// while waiting; teardown re-locks below.
	e.wg.Wait()
	if live {
		nvfs.CloseStoreRef(handle)
		dropShellCanon(handle)
		dropShellKey(handle)
		e.mu.Lock()
		defer e.mu.Unlock()
		e.wipeLocked()
		return nil
	}
	if started {
		close(e.flushStop)
		<-e.flushDone
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	syncErr := e.syncLocked()
	recErr := e.rec.close()
	if e.lockF != nil {
		e.lockF.Close()
		e.lockF = nil
	}
	e.wipeLocked()
	if syncErr != nil {
		return syncErr
	}
	return recErr
}

// pageKeys is a point-in-time key snapshot for one page operation.
type pageKeys struct {
	page    [32]byte
	master  [32]byte
	active  [32]byte
	current uint32
	sealed  bool
	retired []KeyEntry
}

func (e *Engine) snapshotKeys() pageKeys {
	snap := pageKeys{master: e.master, sealed: e.ring != nil}
	if e.ring != nil {
		snap.active = e.active
		snap.page = e.active
		snap.current = e.ring.Current
		for _, ent := range e.ring.Keys {
			if ent.Active {
				continue
			}
			snap.retired = append(snap.retired, ent)
		}
	} else {
		snap.page = e.master
	}
	return snap
}

func (k *pageKeys) wipe() {
	for i := range k.page {
		k.page[i] = 0
	}
	for i := range k.master {
		k.master[i] = 0
	}
	for i := range k.active {
		k.active[i] = 0
	}
	for i := range k.retired {
		for j := range k.retired[i].Key {
			k.retired[i].Key[j] = 0
		}
	}
	k.retired = nil
}

// decryptBlock mirrors the Rust trial chain: keyed (EXP3/EXP4) records
// take the direct-id path with no backstop, and fail closed on unknown
// or zero ids; legacy records try the page key, then retired ring keys,
// then the master.
func decryptBlock(cipher Cipher, keys *pageKeys, id uint64, record []byte) ([Block]byte, error) {
	var out [Block]byte
	if keyID, ok := RecordKeyID(record); ok {
		if keyID == 0 {
			return out, ErrCorrupt
		}
		var direct *[32]byte
		if keys.sealed && keyID == keys.current {
			direct = &keys.active
		}
		if direct == nil {
			for i := range keys.retired {
				if keys.retired[i].ID == keyID {
					direct = &keys.retired[i].Key
					break
				}
			}
		}
		if direct == nil {
			return out, ErrCorrupt
		}
		plain, err := Decrypt(cipher, *direct, id, record)
		if err != nil {
			return out, err
		}
		copy(out[:], plain)
		return out, nil
	}
	if plain, err := Decrypt(cipher, keys.page, id, record); err == nil {
		copy(out[:], plain)
		return out, nil
	}
	if keys.sealed {
		for i := range keys.retired {
			if plain, err := Decrypt(cipher, keys.retired[i].Key, id, record); err == nil {
				copy(out[:], plain)
				return out, nil
			}
		}
		if plain, err := Decrypt(cipher, keys.master, id, record); err == nil {
			copy(out[:], plain)
			return out, nil
		}
	}
	return out, ErrCorrupt
}

// loadBlock returns the plaintext block, from cache or records. Missing
// records read as zeros (sparse); undecryptable records fail closed.
func (e *Engine) loadBlock(id uint64) ([Block]byte, error) {
	var zero [Block]byte
	if el, ok := e.cache[id]; ok {
		e.lru.MoveToFront(el)
		return el.Value.(*cacheEnt).block, nil
	}
	rec, found, err := e.rec.getPage(id)
	if err != nil {
		return zero, err
	}
	block := zero
	if found && len(rec) > 0 {
		keys := e.snapshotKeys()
		block, err = decryptBlock(e.cipher, &keys, id, rec)
		keys.wipe()
		for i := range rec {
			rec[i] = 0
		}
		if err != nil {
			return zero, err
		}
	}
	e.insertCache(id, block)
	return block, nil
}

func (e *Engine) insertCache(id uint64, block [Block]byte) {
	if el, ok := e.cache[id]; ok {
		el.Value.(*cacheEnt).block = block
		e.lru.MoveToFront(el)
		return
	}
	for e.lru.Len() >= e.cap {
		back := e.lru.Back()
		if back == nil {
			break
		}
		ce := back.Value.(*cacheEnt)
		delete(e.cache, ce.id)
		for i := range ce.block {
			ce.block[i] = 0
		}
		e.lru.Remove(back)
	}
	e.cache[id] = e.lru.PushFront(&cacheEnt{id: id, block: block})
}

// persistBlock compresses (when enabled and smaller), encrypts, and
// stages one block.
func (e *Engine) persistBlock(id uint64, block [Block]byte) error {
	keys := e.snapshotKeys()
	defer keys.wipe()
	payload := block[:]
	compressed := false
	if e.compression != 0 {
		if out, err := zstd.Compress(block[:], int(e.compression)); err == nil && len(out) < Block {
			payload = out
			compressed = true
		}
	}
	var keyID uint32
	if keys.sealed {
		keyID = keys.current
	}
	rec, err := Encrypt(e.cipher, keys.page, id, payload, compressed, keyID)
	if err != nil {
		return err
	}
	if err := e.rec.putPage(id, rec); err != nil {
		return err
	}
	e.stats.PagesWritten++
	e.stats.UncompressedBytes += Block
	e.stats.CompressedPayloadSum += uint64(len(payload))
	e.stats.StoredBytes += uint64(len(rec))
	return nil
}

// enterNative pins the native byte engine for one call. The caller
// must run the native call WITHOUT mu held (crypto callbacks lock
// mu) and call Done when finished. It reports false for staged
// engines and closed engines.
func (e *Engine) enterNative() (NativeByteAPI, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed || e.native == nil {
		return nil, false
	}
	e.wg.Add(1)
	return e.native, true
}

// ReadAt implements BlockStore. Short reads return n < len(p) with a
// nil error; corrupt pages report ErrCorrupt.
func (e *Engine) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, errors.New("storage: negative read offset")
	}
	if nat, ok := e.enterNative(); ok {
		defer e.wg.Done()
		// Byte-path counters merge in SnapshotStats; nothing to add here.
		n, _, err := nat.NReadAt(p, off)
		return n, err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return 0, ErrClosed
	}
	cursor := uint64(off)
	var total int
	for total < len(p) {
		if cursor >= e.size {
			break
		}
		id := cursor / Block
		within := int(cursor % Block)
		block, err := e.loadBlock(id)
		if err != nil {
			return total, err
		}
		n := copy(p[total:], block[within:])
		if avail := e.size - cursor; uint64(n) > avail {
			n = int(avail)
		}
		total += n
		cursor += uint64(n)
		e.stats.PagesRead++
		if n == 0 {
			break
		}
	}
	e.stats.VFSReadBytes += uint64(total)
	return total, nil
}

// WriteAt implements BlockStore with staged persistence.
func (e *Engine) WriteAt(p []byte, off int64) error {
	if off < 0 {
		return errors.New("storage: negative write offset")
	}
	if nat, ok := e.enterNative(); ok {
		defer e.wg.Done()
		// SealBlock counts write-side pages; byte volume merges later.
		_, err := nat.NWriteAt(p, off)
		return err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return ErrClosed
	}
	cursor := uint64(off)
	done := 0
	for done < len(p) {
		id := cursor / Block
		within := int(cursor % Block)
		block, err := e.loadBlock(id)
		if err != nil {
			return err
		}
		n := copy(block[within:], p[done:])
		e.insertCache(id, block)
		if err := e.persistBlock(id, block); err != nil {
			return err
		}
		done += n
		cursor += uint64(n)
		if n == 0 {
			return errors.New("storage: short copy")
		}
	}
	if end := uint64(off) + uint64(len(p)); end > e.size {
		e.size = end
		if err := e.rec.saveSize(end); err != nil {
			return err
		}
	}
	e.stats.VFSWriteBytes += uint64(len(p))
	return nil
}

// Truncate implements BlockStore. Shrinking to a non-block boundary
// zeroes the partial tail (mirroring the Rust tail-block rewrite) and
// drops trailing records; growing is sparse.
func (e *Engine) Truncate(size int64) error {
	if size < 0 {
		return errors.New("storage: negative truncate")
	}
	if nat, ok := e.enterNative(); ok {
		defer e.wg.Done()
		return nat.NTruncate(size)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return ErrClosed
	}
	target := uint64(size)
	if target < e.size && target%Block != 0 {
		id := target / Block
		block, err := e.loadBlock(id)
		if err != nil {
			return err
		}
		from := int(target % Block)
		for i := from; i < Block; i++ {
			block[i] = 0
		}
		e.insertCache(id, block)
		if err := e.persistBlock(id, block); err != nil {
			return err
		}
	}
	if target < e.size {
		firstGone := (target + Block - 1) / Block
		for id := range e.cache {
			if id >= firstGone && (target%Block == 0 || id != target/Block) {
				if el, ok := e.cache[id]; ok {
					ce := el.Value.(*cacheEnt)
					for i := range ce.block {
						ce.block[i] = 0
					}
					e.lru.Remove(el)
					delete(e.cache, id)
				}
			}
		}
		if err := e.rec.deletePagesFrom(firstGone); err != nil {
			return err
		}
	}
	if target != e.size {
		e.size = target
		if err := e.rec.saveSize(target); err != nil {
			return err
		}
	}
	return nil
}

// Size implements BlockStore.
func (e *Engine) Size() int64 {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.native != nil {
		return e.native.NSize()
	}
	return int64(e.size)
}

// CommittedSize reports the last commit-boundary size (stats surface).
func (e *Engine) CommittedSize() uint64 {
	e.mu.Lock()
	live, handle := e.live, e.handle
	committed := e.committedSize
	e.mu.Unlock()
	if live {
		if c, _, rc := nvfs.StoreSyncStats(handle); rc == CodeOK {
			return c
		}
		return 0
	}
	return committed
}

// Sync implements BlockStore: the durability barrier.
func (e *Engine) Sync() error {
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return ErrClosed
	}
	nat := e.native
	if nat != nil {
		// Pin the native handle across the unlocked flush below.
		// Close sets closed before wg.Wait, so destroy cannot race
		// a flush that observed closed == false here.
		e.wg.Add(1)
	}
	e.mu.Unlock()
	if nat != nil {
		// Flush outside mu: seals plus the RocksDB batch take
		// milliseconds on large dirty sets, and every VFS op locks
		// mu in enterNative. Holding mu across NFlush would stall
		// all reads and writes for the whole flush.
		err := nat.NFlush()
		e.wg.Done()
		if err != nil {
			return err
		}
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return ErrClosed
	}
	batches, err := e.rec.sync()
	if err != nil {
		return err
	}
	if !e.live {
		e.flushBatches += batches
	}
	// Live shells read the C++-owned batch count in SnapshotStats.
	return nil
}

func (e *Engine) syncLocked() error {
	if e.native != nil {
		if err := e.native.NFlush(); err != nil {
			return err
		}
	}
	batches, err := e.rec.sync()
	if err != nil {
		return err
	}
	if !e.live {
		e.flushBatches += batches
	}
	return nil
}

// startFlusher launches background persistence: the worker syncs
// every flushInterval ms (re-read each tick, so PRAGMA changes
// apply). Disk-backed constructors call it after a successful load;
// memory engines never need it.
func (e *Engine) startFlusher() {
	e.mu.Lock()
	e.flusherStarted = true
	e.mu.Unlock()
	go e.flushLoop()
}

func (e *Engine) flushLoop() {
	defer close(e.flushDone)
	for {
		e.mu.Lock()
		interval := e.flushInterval
		e.mu.Unlock()
		if interval == 0 {
			interval = 250
		}
		t := time.NewTimer(time.Duration(interval) * time.Millisecond)
		select {
		case <-e.flushStop:
			t.Stop()
			return
		case <-t.C:
		}
		_ = e.Sync()
	}
}

// CompleteTransaction marks a commit boundary. Persistence is
// asynchronous — the background worker syncs every flushInterval ms
// — so commits acknowledge without waiting for disk.
func (e *Engine) CompleteTransaction() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return CodeIOErr
	}
	e.committedSize = e.logicalSizeLocked()
	return CodeOK
}

// Checkpoint flushes memtables and waits for compactions (RocksDB) or
// syncs (file). A compaction timeout reports BUSY.
func (e *Engine) Checkpoint() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return CodeIOErr
	}
	if err := e.syncLocked(); err != nil {
		return CodeIOErr
	}
	rb, ok := e.rec.(rocksBackend)
	if !ok {
		return CodeOK
	}
	if err := rb.flushWait(); err != nil {
		return CodeIOErr
	}
	if err := rb.waitCompact30s(); err != nil {
		if isTimeout(err.Error()) {
			return CodeBusy
		}
		return CodeIOErr
	}
	return CodeOK
}

// Compact forces a full-range compaction (RocksDB) or syncs (file).
func (e *Engine) Compact() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return CodeIOErr
	}
	if err := e.syncLocked(); err != nil {
		return CodeIOErr
	}
	if rb, ok := e.rec.(rocksBackend); ok {
		if err := rb.compactFullRange(); err != nil {
			return CodeIOErr
		}
	}
	return CodeOK
}

// BackupTo checkpoints the store plus manifest into dest. Live
// shells run the native backup (checkpoint + byte-exact manifest in
// one call); mem/file engines keep the Go record path.
func (e *Engine) BackupTo(dest string, group, node []byte) int {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return CodeIOErr
	}
	if err := e.syncLocked(); err != nil {
		return CodeIOErr
	}
	if !DestFree(dest) {
		return CodeError
	}
	if e.live {
		return nvfs.StoreBackup(e.handle, dest, e.cipherNameLocked(), group, node)
	}
	if _, err := e.rec.backupTo(dest, e.cipherNameLocked(), group, node); err != nil {
		return CodeIOErr
	}
	return CodeOK
}

func (e *Engine) cipherNameLocked() string { return CipherName(e.cipher) }

// CodecSnapshot provisions the C++ codec: cipher, compression, and
// the key trial set. Mirrors snapshotKeys exactly.
func (e *Engine) CodecSnapshot() nvapi.CodecParams {
	e.mu.Lock()
	defer e.mu.Unlock()
	p := nvapi.CodecParams{
		Cipher: int(e.cipher),
		Level:  int(e.compression),
		Master: e.master,
		Sealed: e.ring != nil,
	}
	if e.ring != nil {
		p.PageKey, p.Active, p.Current = e.active, e.active, e.ring.Current
		for _, ent := range e.ring.Keys {
			if ent.Active {
				continue
			}
			p.RetiredIDs = append(p.RetiredIDs, ent.ID)
			p.RetiredKeys = append(p.RetiredKeys, ent.Key[:]...)
		}
	} else {
		p.PageKey = e.master
	}
	return p
}

// pushCipher swaps the cipher on the native codec, if attached.
// Callers hold e.mu; codec calls never re-enter Go. Staged engines
// read e.cipher directly, so there is nothing to push without native.
func (e *Engine) pushCipher(c Cipher) error {
	if e.native != nil {
		return e.native.NSetCipher(int(c))
	}
	return nil
}

// pushLevel swaps the compression level on the native codec, if attached.
func (e *Engine) pushLevel(level int32) error {
	if e.native != nil {
		return e.native.NSetLevel(int(level))
	}
	return nil
}

// pushRing installs a sealed trial set on the native codec, if attached.
func (e *Engine) pushRing(active [32]byte, current uint32, retired []KeyEntry) error {
	if e.native == nil {
		return nil
	}
	var ids []uint32
	var keys []byte
	for _, ent := range retired {
		ids = append(ids, ent.ID)
		keys = append(keys, ent.Key[:]...)
	}
	return e.native.NInstallRing(active, current, ids, keys)
}

// SnapshotStats copies the traffic counters.
func (e *Engine) SnapshotStats() Stats {
	e.mu.Lock()
	defer e.mu.Unlock()
	st := e.stats
	st.FlushBatches = e.flushBatches
	if e.live {
		if _, b, rc := nvfs.StoreSyncStats(e.handle); rc == CodeOK {
			st.FlushBatches = b
		}
	}
	if e.native != nil {
		pr, rb, wb := e.native.NStats()
		st.PagesRead += pr
		st.VFSReadBytes += rb
		st.VFSWriteBytes += wb
		sp, su, spl, ss := e.native.NSealStats()
		st.PagesWritten += sp
		st.UncompressedBytes += su
		st.CompressedPayloadSum += spl
		st.StoredBytes += ss
	}
	if rb, ok := e.rec.(rocksBackend); ok {
		st.WALBytes = rb.tickerWALBytes()
		st.FlushBytes = rb.tickerFlushBytes()
		st.CompactBytes = rb.tickerCompactBytes()
	}
	return st
}

// Sealed reports whether a keyring is installed.
func (e *Engine) Sealed() bool {
	e.mu.Lock()
	live, handle := e.live, e.handle
	ring := e.ring != nil
	e.mu.Unlock()
	if live {
		if st, rc := nvfs.StoreKdf(handle); rc == CodeOK {
			return st.Sealed
		}
		return false
	}
	return ring
}

// StagedKDF reports the staged seal parameters.
func (e *Engine) StagedKDF() (kdf uint8, time, mem uint32, threads uint8) {
	e.mu.Lock()
	live, handle := e.live, e.handle
	k, t, m, th := e.stagedKDF, e.stagedN, e.stagedR, e.stagedP
	e.mu.Unlock()
	if live {
		if st, rc := nvfs.StoreKdf(handle); rc == CodeOK {
			return st.KDF, st.Time, st.Memory, st.Threads
		}
		return 0, 0, 0, 0
	}
	return k, t, m, th
}

// RingParams reports the live envelope header when sealed.
func (e *Engine) RingParams() (kdf uint8, time, mem uint32, threads uint8, sealed bool) {
	e.mu.Lock()
	live, handle := e.live, e.handle
	ring := e.ring
	e.mu.Unlock()
	if live {
		st, rc := nvfs.StoreKdf(handle)
		if rc != CodeOK || !st.Sealed {
			return 0, 0, 0, 0, false
		}
		return st.KDF, st.Time, st.Memory, st.Threads, true
	}
	if ring == nil {
		return 0, 0, 0, 0, false
	}
	return ring.KDF, ring.ScryptN, ring.ScryptR, ring.ScryptP, true
}

// RocksSync reports the per-batch sync setting.
func (e *Engine) RocksSync() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.rocksSync
}

// SetRocksSync flips the per-batch sync setting.
func (e *Engine) SetRocksSync(sync bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.rocksSync = sync
}

// RocksBackend exposes the RocksDB surface, if any.
func (e *Engine) RocksBackend() (rocksBackend, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	rb, ok := e.rec.(rocksBackend)
	return rb, ok
}

// SetParam stages one KDF parameter; the KDF param seals the keyring.
// It mirrors KEYRING_SET: range-checked, read-only aware, BUSY once
// sealed. Returns an SQLite result code.
func (e *Engine) SetParam(param int, value uint64, readOnly bool) int {
	e.mu.Lock()
	live, handle, closed := e.live, e.handle, e.closed
	e.mu.Unlock()
	if live {
		if closed {
			return CodeIOErr
		}
		if readOnly {
			return CodeReadOnly
		}
		e.mu.Lock()
		master := e.master
		e.mu.Unlock()
		rc := nvfs.StoreSetParam(handle, param, value, master)
		if rc == CodeOK && param == KeyringParamKDF {
			// A seal installed an envelope: reload the ring so
			// subsequent Rotate/Prune observe it.
			e.mu.Lock()
			e.reloadRingLocked()
			e.mu.Unlock()
		}
		return rc
	}
	if readOnly {
		return CodeReadOnly
	}
	var ok bool
	switch param {
	case KeyringParamKDF:
		ok = value == KDFDirectHKDF || value == KDFScrypt
	case KeyringParamScryptN:
		ok = value >= 2 && value <= 1<<20 && value&(value-1) == 0
	case KeyringParamScryptR:
		ok = value >= 1 && value <= 32
	case KeyringParamScryptP:
		ok = value >= 1 && value <= 16
	default:
		return CodeMisuse
	}
	if !ok {
		return CodeError
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return CodeIOErr
	}
	if e.ring != nil {
		return CodeBusy
	}
	switch param {
	case KeyringParamScryptN:
		e.stagedN = uint32(value)
		return CodeOK
	case KeyringParamScryptR:
		e.stagedR = uint32(value)
		return CodeOK
	case KeyringParamScryptP:
		e.stagedP = uint8(value)
		return CodeOK
	}
	return e.sealLocked(uint8(value))
}

// sealLocked creates, persists, and installs a fresh keyring. The store
// id is minted once and reused across retries. Callers hold e.mu.
func (e *Engine) sealLocked(kdf uint8) int {
	if !e.hasSID {
		if _, err := rand.Read(e.storeID[:]); err != nil {
			return CodeError
		}
		if err := e.rec.saveStoreID(e.storeID, e.rocksSync); err != nil {
			return CodeIOErr
		}
		e.hasSID = true
	}
	co := CreateOptions{
		KDF:       kdf,
		ScryptN:   e.stagedN,
		ScryptR:   e.stagedR,
		ScryptP:   e.stagedP,
		StoreID:   e.storeID,
		ContextID: e.storeID,
	}
	if kdf == KDFDirectHKDF {
		co.ScryptN, co.ScryptR, co.ScryptP = 0, 0, 0
		co.Master = e.master[:]
	} else {
		co.Passphrase = e.master[:]
	}
	env, err := Create(co)
	if err != nil {
		return CodeError
	}
	if err := e.rec.saveKeyring(env, e.rocksSync); err != nil {
		wipe(env)
		return CodeIOErr
	}
	ring, err := openRekeyRing(env, e.master, e.storeID)
	fresh := append([]byte(nil), env...)
	wipe(env)
	if err != nil {
		return CodeCorrupt
	}
	cur, ok := ring.ByID(ring.Current)
	if !ok || ring.Current == 0 {
		ring.Wipe()
		return CodeCorrupt
	}
	if err := e.pushRing(cur.Key, ring.Current, retiredOf(ring)); err != nil {
		ring.Wipe()
		return CodeIOErr
	}
	e.ring = ring
	e.active = cur.Key
	e.loadedEnv = fresh
	return CodeOK
}

// retiredOf collects the non-active entries of a ring for codec pushes.
func retiredOf(ring *Keyring) []KeyEntry {
	var out []KeyEntry
	for _, ent := range ring.Keys {
		if ent.Active {
			continue
		}
		out = append(out, ent)
	}
	return out
}

// Rotate seals a successor key and installs it. Only direct-HKDF rings
// rotate (passphrase rings need interactive unlock), mirroring the Rust
// guard. It returns the result code and the new current id.
func (e *Engine) Rotate(readOnly bool) (int, uint32) {
	if readOnly {
		return CodeReadOnly, 0
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return CodeIOErr, 0
	}
	if e.live {
		rc, id := nvfs.StoreRotate(e.handle, false)
		if rc == CodeOK {
			// Re-sync the shell's cached ring for
			// InventoryJSON and later ring reads.
			_ = e.refreshRingLocked()
		}
		return rc, id
	}
	return e.rotateFileLocked()
}

func (e *Engine) rotateFileLocked() (int, uint32) {
	if e.ring == nil || e.ring.KDF != KDFDirectHKDF {
		return CodeError, 0
	}
	env, newID, err := e.ring.Rotate(e.storeID, e.master[:], nil)
	if err != nil {
		return CodeError, 0
	}
	if err := e.rec.saveKeyring(env, e.rocksSync); err != nil {
		wipe(env)
		return CodeIOErr, 0
	}
	ring, err := openRekeyRing(env, e.master, e.storeID)
	fresh := append([]byte(nil), env...)
	wipe(env)
	if err != nil {
		return CodeCorrupt, 0
	}
	if ring.Current != newID {
		ring.Wipe()
		return CodeCorrupt, 0
	}
	cur, ok := ring.ByID(newID)
	if !ok || newID == 0 {
		ring.Wipe()
		return CodeCorrupt, 0
	}
	if err := e.pushRing(cur.Key, ring.Current, retiredOf(ring)); err != nil {
		ring.Wipe()
		return CodeIOErr, 0
	}
	e.ring.Wipe()
	e.ring = ring
	e.active = cur.Key
	e.loadedEnv = fresh
	return CodeOK, newID
}

// Prune drops retired keys no live page references. It scans every
// record, keeps active/current/referenced ids, and reseals. The JSON
// report mirrors the Rust shape. Live shells run the native prune.
func (e *Engine) Prune(readOnly bool) (int, string) {
	if readOnly {
		return CodeReadOnly, ""
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return CodeIOErr, ""
	}
	if e.live {
		rc, report := nvfs.StorePrune(e.handle, false)
		if rc == CodeOK {
			// Re-sync the shell's cached ring for
			// InventoryJSON and later ring reads.
			_ = e.refreshRingLocked()
		}
		return rc, report
	}
	return e.pruneFileLocked()
}

func (e *Engine) pruneFileLocked() (int, string) {
	if e.ring == nil {
		return CodeOK, `{"pruned":[],"blocked_by_unkeyed":0,"retained":[],"unreadable":0}`
	}
	referenced := map[uint32]bool{}
	var unkeyed, unreadable uint64
	err := e.rec.scanPages(func(id uint64, rec []byte) error {
		if keyID, ok := RecordKeyID(rec); ok {
			if keyID != 0 {
				referenced[keyID] = true
			} else {
				unreadable++
			}
			return nil
		}
		if IsLegacyRecord(rec) {
			unkeyed++
		} else {
			unreadable++
		}
		return nil
	})
	if err != nil {
		return CodeIOErr, ""
	}
	var drop, retained []uint32
	for _, ent := range e.ring.Keys {
		if ent.Active || ent.ID == e.ring.Current {
			retained = append(retained, ent.ID)
			continue
		}
		if unkeyed == 0 && !referenced[ent.ID] {
			drop = append(drop, ent.ID)
		} else {
			retained = append(retained, ent.ID)
		}
	}
	if len(drop) > 0 {
		if e.ring.KDF != KDFDirectHKDF {
			return CodeError, ""
		}
		env, err := e.ring.DropKeys(drop, e.storeID, e.master[:], nil)
		if err != nil {
			return CodeError, ""
		}
		if err := e.rec.saveKeyring(env, e.rocksSync); err != nil {
			wipe(env)
			return CodeIOErr, ""
		}
		ring, err := openRekeyRing(env, e.master, e.storeID)
		fresh := append([]byte(nil), env...)
		wipe(env)
		if err != nil {
			return CodeCorrupt, ""
		}
		cur, ok := ring.ByID(ring.Current)
		if !ok || ring.Current == 0 {
			ring.Wipe()
			return CodeCorrupt, ""
		}
		if err := e.pushRing(cur.Key, ring.Current, retiredOf(ring)); err != nil {
			ring.Wipe()
			return CodeIOErr, ""
		}
		e.ring.Wipe()
		e.ring = ring
		e.active = cur.Key
		e.loadedEnv = fresh
	}
	return CodeOK, pruneJSON(drop, unkeyed, retained, unreadable)
}

func pruneJSON(drop []uint32, unkeyed uint64, retained []uint32, unreadable uint64) string {
	return `{"pruned":[` + joinIDs(drop) + `],"blocked_by_unkeyed":` +
		utoa(unkeyed) + `,"retained":[` + joinIDs(retained) + `],"unreadable":` + utoa(unreadable) + `}`
}

func joinIDs(ids []uint32) string {
	out := ""
	for i, id := range ids {
		if i > 0 {
			out += ","
		}
		out += utoa(uint64(id))
	}
	return out
}

func utoa(v uint64) string {
	if v == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	return string(b[i:])
}

// InventoryJSON reports the keyring state; unsealed rings report sealed:false.
// Live shells read the native inventory (the envelope opens under
// the staged master, so external seals/rotates show without a ring
// reload); mem/file engines render the cached ring. A native
// failure falls back to the cached ring rather than lying.
func (e *Engine) InventoryJSON() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.live {
		if js, rc := nvfs.StoreInventory(e.handle); rc == CodeOK {
			return js
		}
	}
	if e.ring == nil {
		return `{"sealed":false}`
	}
	r := e.ring
	kdf := "direct"
	if r.KDF == KDFScrypt {
		kdf = "scrypt"
	}
	out := `{"sealed":true,"seq":` + utoa(r.Seq) + `,"kdf":"` + kdf + `",`
	out += `"scrypt_n":` + utoa(uint64(r.ScryptN)) + `,"scrypt_r":` + utoa(uint64(r.ScryptR)) + `,"scrypt_p":` + utoa(uint64(r.ScryptP)) + `,`
	out += `"wrap_id":"` + jsonEscape(r.WrapID) + `",`
	out += `"current":` + utoa(uint64(r.Current)) + `,"keys":[`
	for i, ent := range r.Keys {
		if i > 0 {
			out += ","
		}
		active := "false"
		if ent.Active {
			active = "true"
		}
		out += `{"id":` + utoa(uint64(ent.ID)) + `,"created_nanos":` + itoa64(ent.CreatedAt) + `,"active":` + active + `}`
	}
	return out + `]}`
}

func itoa64(v int64) string {
	neg := v < 0
	if neg {
		v = -v
	}
	s := utoa(uint64(v))
	if neg {
		return "-" + s
	}
	return s
}

func jsonEscape(input []byte) string {
	const hexd = "0123456789abcdef"
	out := ""
	for _, c := range input {
		switch c {
		case '"':
			out += `\"`
		case '\\':
			out += `\\`
		case '\n':
			out += `\n`
		case '\r':
			out += `\r`
		case '\t':
			out += `\t`
		default:
			if c < 0x20 {
				out += `\u00` + string([]byte{hexd[c>>4], hexd[c&15]})
			} else {
				out += string([]byte{c})
			}
		}
	}
	return out
}

// SetCipher switches the page AEAD. Like the Rust store it only runs on
// an empty database outside a transaction; locked reports whether any
// connection currently holds a lock on this store.
func (e *Engine) SetCipher(c Cipher, readOnly, locked bool) int {
	if c != CipherAES256GCM {
		return CodeMisuse
	}
	if readOnly {
		return CodeReadOnly
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return CodeIOErr
	}
	if e.cipher == c {
		return CodeOK
	}
	if e.logicalSizeLocked() != 0 || locked {
		return CodeBusy
	}
	if err := e.pushCipher(c); err != nil {
		return CodeIOErr
	}
	if err := e.rec.saveCipher(c, e.rocksSync); err != nil {
		_ = e.pushCipher(e.cipher)
		return CodeIOErr
	}
	e.cipher = c
	return CodeOK
}

// CipherName reports the active cipher PRAGMA name.
func (e *Engine) CipherName() string { return CipherName(e.Cipher()) }

// Cipher returns the active page AEAD.
func (e *Engine) Cipher() Cipher {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.cipher
}
