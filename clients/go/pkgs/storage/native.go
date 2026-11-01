package storage

import (
	"errors"
	"strconv"
	"strings"
	"sync"

	"github.com/marcgauthier/libmurmur/clients/go/bindings/nvapi"
	"github.com/marcgauthier/libmurmur/clients/go/bindings/nvfs"
	"github.com/marcgauthier/libmurmur/clients/go/bindings/sqlite"
)

// Native seam for the C++ VFS hot path (bindings/nvfs).
//
// A native-backed engine splits ownership: C++ owns the page cache,
// buffer allocation, the RocksDB pump, and the control plane
// (registry, lifecycle, flusher, PRAGMA table), while Go keeps key
// material plus the record/byte paths over borrowed native handles.
// The nvfs.DB object implements NativeDB (both interfaces below);
// storage imports nvfs for the registry client, and nvfs calls back
// into storage only through the registered interim key/extension
// hooks (no import cycle).

// Native seam types live in bindings/nvapi (shared with the nvfs
// package, which cannot import storage). Aliases keep the storage
// surface unchanged.
type (
	NativeStoreAPI = nvapi.NativeStoreAPI
	NativeByteAPI  = nvapi.NativeByteAPI
	NativeDB       = nvapi.NativeDB
)

// ErrNativeShort reports an undersized native value buffer. Callers
// grow and retry; values past nativeMaxValue fail closed as corrupt.
var ErrNativeShort = nvapi.ErrNativeShort

// nativeMaxValue bounds single record/meta reads through the native
// store. Native reads past 1 MiB fail closed (real records peak near
// 4.3 KiB, envelopes far below 1 MiB).
const nativeMaxValue = 1 << 20

// RocksDB status classifiers over native error strings. Native errors
// wrap the C++ status ("nvfs: ...: <Status>"), so the kind is matched
// by containment rather than prefix.
func rocksKind(msg string) string {
	switch {
	case strings.Contains(msg, "NotFound"):
		return "NotFound"
	case strings.Contains(msg, "IO error"):
		return "IOError"
	case strings.Contains(msg, "TimedOut"):
		return "TimedOut"
	case strings.Contains(msg, "Busy"):
		return "Busy"
	case strings.Contains(msg, "Try again"):
		return "TryAgain"
	default:
		return ""
	}
}

func isTimeout(msg string) bool { return rocksKind(msg) == "TimedOut" }

func isBusyOrRetry(msg string) bool {
	k := rocksKind(msg)
	return k == "Busy" || k == "TryAgain"
}

func isIOError(msg string) bool { return rocksKind(msg) == "IOError" }

// nativeRecords is the recordStore over a native database: the only
// RocksDB record path.
type nativeRecords struct {
	api     NativeStoreAPI
	batches uint64
	closed  bool
}

func (r *nativeRecords) getVal(key []byte) ([]byte, bool, error) {
	buf := make([]byte, 8192)
	for {
		n, found, err := r.api.Get(key, buf)
		if err == nil {
			if !found {
				return nil, false, nil
			}
			return append([]byte(nil), buf[:n]...), true, nil
		}
		if !errors.Is(err, ErrNativeShort) {
			return nil, false, err
		}
		if len(buf) >= nativeMaxValue {
			return nil, false, ErrCorrupt
		}
		buf = make([]byte, len(buf)*2)
	}
}

func (r *nativeRecords) load() (recordMeta, error) {
	var meta recordMeta
	meta.cipher = CipherAES256GCM
	if val, found, err := r.getVal([]byte(MetaSize)); err != nil {
		return meta, err
	} else if found {
		size, err := strconv.ParseUint(string(val), 10, 64)
		if err != nil {
			return meta, errors.New("storage: malformed meta:size")
		}
		meta.size = size
	}
	if val, found, err := r.getVal([]byte(MetaCipher)); err != nil {
		return meta, err
	} else if found {
		switch string(val) {
		case "aes256gcm":
			meta.cipher = CipherAES256GCM
		case "aegis256":
			meta.cipher = CipherAEGIS256
		default:
			return meta, errors.New("storage: unknown meta:cipher")
		}
	}
	if val, found, err := r.getVal([]byte(MetaStoreID)); err != nil {
		return meta, err
	} else if found {
		if len(val) != 16 {
			return meta, errors.New("storage: malformed meta:store_id")
		}
		copy(meta.storeID[:], val)
		meta.hasSID = true
	}
	if val, found, err := r.getVal([]byte(MetaKeyring)); err != nil {
		return meta, err
	} else if found {
		meta.envelope = val
	}
	return meta, nil
}

func (r *nativeRecords) saveCipher(c Cipher, sync bool) error {
	return r.api.Put([]byte(MetaCipher), []byte(CipherName(c)), sync)
}

func (r *nativeRecords) saveSize(size uint64) error {
	return r.api.Put([]byte(MetaSize), []byte(strconv.FormatUint(size, 10)), false)
}

func (r *nativeRecords) saveStoreID(id [16]byte, sync bool) error {
	return r.api.Put([]byte(MetaStoreID), id[:], sync)
}

func (r *nativeRecords) saveKeyring(env []byte, sync bool) error {
	if env == nil {
		return r.api.Delete([]byte(MetaKeyring), sync)
	}
	return r.api.Put([]byte(MetaKeyring), env, sync)
}

func (r *nativeRecords) getPage(id uint64) ([]byte, bool, error) {
	key := PageKey(id)
	return r.getVal(key[:])
}

func (r *nativeRecords) putPage(id uint64, rec []byte) error {
	key := PageKey(id)
	return r.api.Put(key[:], rec, false)
}

func (r *nativeRecords) deletePagesFrom(first uint64) error {
	return r.api.DeletePagesFrom(first)
}

func (r *nativeRecords) scanPages(fn func(id uint64, rec []byte) error) error {
	return r.api.ScanPages(fn)
}

func (r *nativeRecords) sync() (uint64, error) {
	advanced, err := r.api.Sync()
	if err != nil {
		return 0, err
	}
	if !advanced {
		return 0, nil
	}
	r.batches++
	return 1, nil
}

func (r *nativeRecords) backupTo(dest, cipher string, group, node []byte) (uint64, error) {
	if !DestFree(dest) {
		return 0, errors.New("storage: backup destination exists")
	}
	seq, err := r.checkpointTo(dest)
	if err != nil {
		RemoveBackup(dest)
		return 0, err
	}
	if err := WriteBackupManifest(dest, cipher, group, node, seq); err != nil {
		RemoveBackup(dest)
		return 0, err
	}
	return seq, nil
}

func (r *nativeRecords) close() error {
	if r.closed {
		return nil
	}
	r.closed = true
	r.api.Close()
	return nil
}

func (r *nativeRecords) setCFOptions(opts map[string]string) error {
	return r.api.SetCFOptions(opts)
}

func (r *nativeRecords) setDBOption(name, value string) error {
	return r.api.SetDBOption(name, value)
}

func (r *nativeRecords) liveOption(name string) (uint64, error) {
	return r.api.LiveOption(name)
}

func (r *nativeRecords) setCacheCapacity(bytes int) {
	r.api.SetCacheCapacity(bytes)
}

func (r *nativeRecords) cacheCapacity() int {
	return r.api.CacheCapacity()
}

func (r *nativeRecords) tickerWALBytes() uint64 { return r.api.TickerWALBytes() }

func (r *nativeRecords) tickerFlushBytes() uint64 { return r.api.TickerFlushBytes() }

func (r *nativeRecords) tickerCompactBytes() uint64 {
	return r.api.TickerCompactBytes()
}

func (r *nativeRecords) flushWait() error { return r.api.FlushWait() }

func (r *nativeRecords) waitCompact30s() error { return r.api.WaitCompact30s() }

func (r *nativeRecords) compactFullRange() error { return r.api.CompactFullRange() }

func (r *nativeRecords) checkpointTo(dir string) (uint64, error) {
	return r.api.CheckpointTo(dir)
}

var _ nvapi.Engine = (*Engine)(nil)

// Registry shells borrow C++-owned stores (open.cc): the control
// plane owns the registry, lifecycle, flusher, and PRAGMA table,
// while the shell keeps Go key material plus the record/byte paths
// over borrowed raw pointers (valid until Close drops the shell's
// reference).
var (
	shellMu     sync.Mutex
	shellCanons = map[uint64]string{}
	// shellKeys holds each shell's caller-provided master (recorded
	// by openShell, dropped at Close) for ring reloads and the
	// store-level extension path. Unlike the old global stash, keys
	// are scoped to the shell that was opened with them and never
	// consulted by C++.
	shellKeys = map[uint64][32]byte{}
	// openMu serializes direct opens.
	openMu sync.Mutex
)

func recordShellCanon(handle uint64, canon string) {
	shellMu.Lock()
	defer shellMu.Unlock()
	shellCanons[handle] = canon
}

func dropShellCanon(handle uint64) {
	shellMu.Lock()
	defer shellMu.Unlock()
	delete(shellCanons, handle)
}

func shellCanon(handle uint64) (string, bool) {
	shellMu.Lock()
	defer shellMu.Unlock()
	c, ok := shellCanons[handle]
	return c, ok
}

func recordShellKey(handle uint64, key [32]byte) {
	shellMu.Lock()
	defer shellMu.Unlock()
	shellKeys[handle] = key
}

func dropShellKey(handle uint64) {
	shellMu.Lock()
	defer shellMu.Unlock()
	delete(shellKeys, handle)
}

func shellKey(handle uint64) ([32]byte, bool) {
	shellMu.Lock()
	defer shellMu.Unlock()
	k, ok := shellKeys[handle]
	return k, ok
}

// openShell builds a live Engine over a registry reference. The
// reference's raw pointers back both the record path and the byte
// engine; Close drops the reference (no destroy: the registry owns
// the store).
func openShell(ref nvfs.StoreRef, canon string, key [32]byte) (*Engine, error) {
	rec := &nativeRecords{api: ref.DB}
	e := newEngine(rec, key, CachePagesDefault)
	e.live = true
	e.handle = ref.Handle
	e.canon = canon
	recordShellCanon(ref.Handle, canon)
	recordShellKey(ref.Handle, key)
	if err := e.load(); err != nil {
		e.Close()
		return nil, err
	}
	e.AttachNative(ref.DB)
	return e, nil
}

// OpenLive opens a shell on a live store, or nil when the store is
// not live. Callers own the shell and must Close it. The key must
// unlock the envelope; it is used for ring reloads (Rotate/Prune)
// and travels with seal calls.
func OpenLive(path string, key [32]byte) *Engine {
	canon := sqlite.CanonicalPath(path)
	if !nvfs.StoreIsLive(canon) {
		return nil
	}
	ref, err := nvfs.OpenStoreRef(canon, false, CachePagesDefault)
	if err != nil {
		return nil
	}
	// No-op when the live store already holds this key; MISUSE when
	// it holds another (fail fast on the wrong key).
	if rc := nvfs.KeyStore(&ref, key); rc != 0 {
		nvfs.CloseStoreRef(ref.Handle)
		return nil
	}
	e, err := openShell(ref, canon, key)
	if err != nil {
		nvfs.CloseStoreRef(ref.Handle)
		return nil
	}
	return e
}

func init() {
	nvfs.SetStoreExt(storeExtFor)
}

// storeExtFor serves store-level murmur_* extension PRAGMAs. With no
// extension registered it reports the documented hint; otherwise it
// opens a fresh shell for the extension call (the store lock is
// released across extension dispatch, so a re-entrant open is
// safe).
func storeExtFor(handle uint64, name string, value *string) (string, int) {
	if extensionPragma == nil {
		return "load murmur-replication before using murmur PRAGMAs", CodeError
	}
	canon, ok := shellCanon(handle)
	if !ok {
		return "load murmur-replication before using murmur PRAGMAs", CodeError
	}
	// The caller's shell key, or zeros for unsealed stores when the
	// caller opened without one (sealed shells fail closed in load).
	master, _ := shellKey(handle)
	ref, err := nvfs.OpenStoreRef(canon, false, CachePagesDefault)
	if err != nil {
		return "", CodeIOErr
	}
	e, err := openShell(ref, canon, master)
	if err != nil {
		nvfs.CloseStoreRef(ref.Handle)
		return "", CodeIOErr
	}
	defer e.Close()
	rc, out := extensionPragma(e, name, value, false)
	return out, rc
}

// AttachNative binds the byte engine, completing a native-backed
// Engine. The same object backs records from here on, so Close
// releases the whole native database exactly once.
func (e *Engine) AttachNative(db NativeDB) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.native = db
	if nr, ok := e.rec.(*nativeRecords); ok {
		nr.api = db
	}
}

// Native reports whether the byte path is native-backed.
func (e *Engine) Native() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.native != nil
}

// logicalSizeLocked reports the authoritative size: native when
// attached, the staged field otherwise.
func (e *Engine) logicalSizeLocked() uint64 {
	if e.native != nil {
		if n := e.native.NSize(); n >= 0 {
			return uint64(n)
		}
	}
	return e.size
}
