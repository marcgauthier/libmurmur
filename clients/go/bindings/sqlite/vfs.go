package sqlite

/*
#cgo CFLAGS: -DSQLITE_ENABLE_FTS5 -DSQLITE_THREADSAFE=1 -DSQLITE_ENABLE_PREUPDATE_HOOK=1 -O2
#cgo CXXFLAGS: -std=c++17 -DSQLITE_ENABLE_FTS5 -DSQLITE_THREADSAFE=1 -DSQLITE_ENABLE_PREUPDATE_HOOK=1 -O2
#cgo LDFLAGS: ${SRCDIR}/../../../../libmurmur.a -lm -lstdc++
#include <stdlib.h>
#include "../../../../deps/sqlite/sqlite3.h"

extern int murmurVfsRegister(const char *name);
extern char *murmurPragmaStrdup(const char *s);
*/
import "C"

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"unsafe"
)

// Lock levels mirror SQLITE_LOCK_*.
const (
	LockNone      = 0
	LockShared    = 1
	LockReserved  = 2
	LockPending   = 3
	LockExclusive = 4
)

// FileStore is a byte-addressable main-database store behind one VFS path.
// Methods must be safe for concurrent use; the VFS serializes per-file
// SQLite calls but different connections share the store. ReadAt reports
// short reads by returning n < len(p) with a nil error; the VFS
// zero-fills the tail and reports SHORT_READ.
type FileStore interface {
	ReadAt(p []byte, off int64) (int, error)
	WriteAt(p []byte, off int64) error
	Truncate(size int64) error
	Size() int64
	Sync() error
}

// CommitTracker is implemented by stores that track commit completion:
// the VFS calls CompleteTransaction when the main journal is deleted.
type CommitTracker interface {
	CompleteTransaction() int
}

// PragmaFunc handles PRAGMA name[=value] on a main database file. handle
// identifies the file for per-handle state, value is nil for read-back
// form, and locked reports whether any connection currently holds a
// lock on the store. It returns an SQLite result code and an optional
// output string for arguments[0].
type PragmaFunc func(store FileStore, handle uint64, name string, value *string, readOnly, locked bool) (int, string)

// Opener creates (or reuses) the store for a main database path.
type Opener func(path string, readOnly, create bool) (FileStore, error)

// FileControlFunc handles non-PRAGMA file controls on a main database
// file. handle identifies the file for per-handle state (extension
// slots). It reports whether it owned the op and the result code.
type FileControlFunc func(store FileStore, handle uint64, op int, arg unsafe.Pointer, readOnly bool) (bool, int)

// VFSConfig wires stores and pragmas into a registered VFS.
type VFSConfig struct {
	Open   Opener
	Pragma PragmaFunc
	// FileControl, when set, owns custom file-control opcodes
	// (extension/keyring/flush/backup/compact) for main databases.
	FileControl FileControlFunc
	// OnCloseStore runs when the last file on a store closes, right
	// before the store is dropped.
	OnCloseStore func(store FileStore)
	// OnCloseFile runs on every file close with the file handle, so
	// owners can release per-handle state (extension slots).
	OnCloseFile func(handle uint64)
}

type memFile struct {
	mu    sync.Mutex
	bytes []byte
	size  int
}

type vfsFile struct {
	store         FileStore
	mem           *memFile
	name          string
	mainDB        bool
	readOnly      bool
	deleteOnClose bool
	lockLevel     int
}

type vfsStoreEnt struct {
	store FileStore
	mu    sync.Mutex
	locks map[uint64]int
	refs  int
}

var (
	vfsMu     sync.Mutex
	vfsName   string
	vfsCfg    VFSConfig
	vfsFiles  = map[uint64]*vfsFile{}
	vfsStores = map[string]*vfsStoreEnt{}
	vfsMem    = map[string]*memFile{}
	vfsTempID uint64
)

// RegisterVFS registers the murmur VFS under name. Only one registration
// is supported; registering again with the same name replaces the config.
func RegisterVFS(name string, cfg VFSConfig) error {
	vfsMu.Lock()
	defer vfsMu.Unlock()
	if vfsName != "" && vfsName != name {
		return &Error{Code: int(C.SQLITE_MISUSE), Msg: "vfs already registered"}
	}
	if vfsName == "" {
		cname := C.CString(name)
		// Intentionally retained: SQLite keeps the pointer.
		if rc := C.murmurVfsRegister(cname); rc != C.SQLITE_OK {
			C.free(unsafe.Pointer(cname))
			return &Error{Code: int(rc), Msg: "vfs register failed"}
		}
		vfsName = name
	}
	vfsCfg = cfg
	return nil
}

func vfsLookup(handle uint64) *vfsFile {
	vfsMu.Lock()
	defer vfsMu.Unlock()
	return vfsFiles[handle]
}

func isJournal(name string) bool { return strings.HasSuffix(name, "-journal") }

// CanonicalPath canonicalizes the filename SQLite hands to
// xOpen/xDelete/xAccess so main databases, journals, and access probes
// share one key space. URI filenames are reduced to absolute paths,
// matching the parent VFS xFullPathname the pager uses to derive
// journal names. Offline tools use the same mapping to find live stores.
func CanonicalPath(raw string) string {
	return normalizeName(raw)
}

// normalizeName implements CanonicalPath.
func normalizeName(raw string) string {
	s := raw
	if strings.HasPrefix(s, "file:") {
		s = s[len("file:"):]
		if i := strings.IndexByte(s, '?'); i >= 0 {
			s = s[:i]
		}
		if strings.HasPrefix(s, "//") {
			if i := strings.IndexByte(s[2:], '/'); i >= 0 {
				s = s[2+i:]
			} else {
				s = ""
			}
		}
		s = percentDecode(s)
	}
	if abs, err := filepath.Abs(s); err == nil {
		return abs
	}
	return s
}

func percentDecode(s string) string {
	if strings.IndexByte(s, '%') < 0 {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '%' && i+2 < len(s) {
			hi, ok1 := hexVal(s[i+1])
			lo, ok2 := hexVal(s[i+2])
			if ok1 && ok2 {
				b.WriteByte(hi<<4 | lo)
				i += 2
				continue
			}
		}
		b.WriteByte(c)
	}
	return b.String()
}

func hexVal(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

//export goVfsOpen
func goVfsOpen(cname *C.char, handle C.ulonglong, flags C.int, outFlags *C.int) (rc C.int) {
	defer func() {
		if recover() != nil {
			rc = C.SQLITE_NOMEM
		}
	}()
	f := C.int(flags)
	mainDB := f&C.SQLITE_OPEN_MAIN_DB != 0
	var name string
	if cname == nil {
		id := atomic.AddUint64(&vfsTempID, 1)
		name = ":sqlite-murmur-temp:" + itoa(id)
	} else {
		name = normalizeName(C.GoString(cname))
	}
	file := &vfsFile{
		name:          name,
		mainDB:        mainDB,
		deleteOnClose: f&C.SQLITE_OPEN_DELETEONCLOSE != 0,
	}
	if mainDB {
		file.readOnly = f&C.SQLITE_OPEN_READONLY != 0
		var ent *vfsStoreEnt
		for ent == nil {
			vfsMu.Lock()
			ent = vfsStores[name]
			if ent != nil {
				// Pin the entry before releasing the map lock so a
				// concurrent last-close cannot drop it first.
				ent.mu.Lock()
				ent.refs++
				ent.mu.Unlock()
				vfsMu.Unlock()
				break
			}
			opener := vfsCfg.Open
			vfsMu.Unlock()
			if opener == nil {
				return C.SQLITE_CANTOPEN
			}
			store, err := opener(name, file.readOnly, f&C.SQLITE_OPEN_CREATE != 0)
			if err != nil || store == nil {
				return C.SQLITE_CANTOPEN
			}
			vfsMu.Lock()
			if live := vfsStores[name]; live != nil {
				// Lost the creation race: release the redundant store.
				vfsMu.Unlock()
				closeStore(store)
				continue
			}
			ent = &vfsStoreEnt{store: store, locks: map[uint64]int{}, refs: 1}
			vfsStores[name] = ent
			vfsMu.Unlock()
		}
		file.store = ent.store
		vfsMu.Lock()
		vfsFiles[uint64(handle)] = file
		vfsMu.Unlock()
	} else {
		if strings.HasSuffix(name, "-wal") {
			// WAL requires a different recovery design.
			return C.SQLITE_CANTOPEN
		}
		vfsMu.Lock()
		mem, ok := vfsMem[name]
		if !ok {
			mem = &memFile{}
			vfsMem[name] = mem
		}
		file.mem = mem
		vfsFiles[uint64(handle)] = file
		vfsMu.Unlock()
	}
	if outFlags != nil {
		*outFlags = flags
	}
	return C.SQLITE_OK
}

//export goVfsClose
func goVfsClose(handle C.ulonglong) (rc C.int) {
	defer func() {
		if recover() != nil {
			rc = C.SQLITE_IOERR
		}
	}()
	vfsMu.Lock()
	f := vfsFiles[uint64(handle)]
	if f == nil {
		vfsMu.Unlock()
		return C.SQLITE_IOERR
	}
	delete(vfsFiles, uint64(handle))
	var dropped FileStore
	onFile := vfsCfg.OnCloseFile
	if !f.mainDB {
		if f.deleteOnClose {
			delete(vfsMem, f.name)
		}
		vfsMu.Unlock()
		if onFile != nil {
			onFile(uint64(handle))
		}
		return C.SQLITE_OK
	}
	if ent := vfsStores[f.name]; ent != nil && ent.store == f.store {
		ent.mu.Lock()
		delete(ent.locks, uint64(handle))
		ent.refs--
		last := ent.refs <= 0
		ent.mu.Unlock()
		if last {
			// Last file: drop the store like Rust's Weak expiry.
			// Settings reset when the store reopens.
			delete(vfsStores, f.name)
			dropped = ent.store
		}
	}
	onClose := vfsCfg.OnCloseStore
	vfsMu.Unlock()
	if onFile != nil {
		onFile(uint64(handle))
	}
	if dropped != nil {
		if onClose != nil {
			onClose(dropped)
		}
		closeStore(dropped)
	}
	return C.SQLITE_OK
}

// closeStore releases a store dropped from the registry. Stores that
// hold resources (files, key material) implement Close.
func closeStore(store FileStore) {
	if c, ok := store.(interface{ Close() error }); ok {
		c.Close()
	}
}

//export goVfsRead
func goVfsRead(handle C.ulonglong, data unsafe.Pointer, n C.int, off C.longlong) (rc C.int) {
	defer func() {
		if recover() != nil {
			rc = C.SQLITE_IOERR_READ
		}
	}()
	f := vfsLookup(uint64(handle))
	if f == nil || off < 0 || n < 0 {
		return C.SQLITE_IOERR_READ
	}
	dst := unsafe.Slice((*byte)(data), int(n))
	if f.mainDB {
		n, err := f.store.ReadAt(dst, int64(off))
		if err != nil {
			return C.SQLITE_IOERR_READ
		}
		if n < len(dst) {
			for i := n; i < len(dst); i++ {
				dst[i] = 0
			}
			return C.SQLITE_IOERR_SHORT_READ
		}
		return C.SQLITE_OK
	}
	f.mem.mu.Lock()
	defer f.mem.mu.Unlock()
	pos := int(off)
	avail := 0
	if pos < f.mem.size {
		avail = int(n)
		if memAvail := f.mem.size - pos; avail > memAvail {
			avail = memAvail
		}
	}
	// Reads fully past end (avail == 0 with pos > len) must not
	// evaluate the subslice: short-read with zeros instead.
	if avail > 0 {
		copy(dst, f.mem.bytes[pos:pos+avail])
	}
	if avail < int(n) {
		for i := avail; i < int(n); i++ {
			dst[i] = 0
		}
		return C.SQLITE_IOERR_SHORT_READ
	}
	return C.SQLITE_OK
}

//export goVfsWrite
func goVfsWrite(handle C.ulonglong, data unsafe.Pointer, n C.int, off C.longlong) (rc C.int) {
	defer func() {
		if recover() != nil {
			rc = C.SQLITE_IOERR_WRITE
		}
	}()
	f := vfsLookup(uint64(handle))
	if f == nil || off < 0 || n < 0 {
		return C.SQLITE_IOERR_WRITE
	}
	src := unsafe.Slice((*byte)(data), int(n))
	if f.mainDB {
		if err := f.store.WriteAt(src, int64(off)); err != nil {
			return C.SQLITE_IOERR_WRITE
		}
		return C.SQLITE_OK
	}
	f.mem.mu.Lock()
	defer f.mem.mu.Unlock()
	end := int(off) + int(n)
	if end > len(f.mem.bytes) {
		f.mem.bytes = append(f.mem.bytes, make([]byte, end-len(f.mem.bytes))...)
	}
	copy(f.mem.bytes[int(off):], src)
	if end > f.mem.size {
		f.mem.size = end
	}
	return C.SQLITE_OK
}

//export goVfsTruncate
func goVfsTruncate(handle C.ulonglong, n C.longlong) (rc C.int) {
	defer func() {
		if recover() != nil {
			rc = C.SQLITE_IOERR_TRUNCATE
		}
	}()
	f := vfsLookup(uint64(handle))
	if f == nil {
		return C.SQLITE_IOERR_TRUNCATE
	}
	if f.mainDB {
		if err := f.store.Truncate(int64(n)); err != nil {
			return C.SQLITE_IOERR_TRUNCATE
		}
		return C.SQLITE_OK
	}
	if n < 0 {
		return C.SQLITE_IOERR_TRUNCATE
	}
	f.mem.mu.Lock()
	defer f.mem.mu.Unlock()
	target := int(n)
	if target > len(f.mem.bytes) {
		f.mem.bytes = append(f.mem.bytes, make([]byte, target-len(f.mem.bytes))...)
	} else {
		for i := target; i < len(f.mem.bytes); i++ {
			f.mem.bytes[i] = 0
		}
		f.mem.bytes = f.mem.bytes[:target]
	}
	f.mem.size = target
	return C.SQLITE_OK
}

//export goVfsSync
func goVfsSync(handle C.ulonglong, flags C.int) (rc C.int) {
	// Deliberately deferred like the Rust io_sync: commits
	// acknowledge without waiting for disk; the engine's
	// background worker persists every flush_interval_ms, and
	// Sync/Checkpoint/Close are the explicit barriers.
	if vfsLookup(uint64(handle)) == nil {
		return C.SQLITE_IOERR_FSYNC
	}
	return C.SQLITE_OK
}

//export goVfsFileSize
func goVfsFileSize(handle C.ulonglong, out *C.longlong) (rc C.int) {
	defer func() {
		if recover() != nil {
			rc = C.SQLITE_IOERR
		}
	}()
	f := vfsLookup(uint64(handle))
	if f == nil {
		return C.SQLITE_IOERR
	}
	if f.mainDB {
		*out = C.longlong(f.store.Size())
		return C.SQLITE_OK
	}
	f.mem.mu.Lock()
	*out = C.longlong(f.mem.size)
	f.mem.mu.Unlock()
	return C.SQLITE_OK
}

func lockOK(want, other int) bool {
	switch {
	case want == LockShared && other >= LockPending:
		return false
	case want >= LockReserved && want <= LockPending && other >= LockReserved:
		return false
	case want == LockExclusive && other > LockNone:
		return false
	}
	return true
}

//export goVfsLock
func goVfsLock(handle C.ulonglong, level C.int) (rc C.int) {
	defer func() {
		if recover() != nil {
			rc = C.SQLITE_BUSY
		}
	}()
	f := vfsLookup(uint64(handle))
	if f == nil {
		return C.SQLITE_BUSY
	}
	if !f.mainDB {
		return C.SQLITE_OK
	}
	vfsMu.Lock()
	ent := vfsStores[f.name]
	vfsMu.Unlock()
	if ent == nil {
		return C.SQLITE_BUSY
	}
	ent.mu.Lock()
	defer ent.mu.Unlock()
	if int(level) <= f.lockLevel {
		return C.SQLITE_OK
	}
	for otherFile, other := range ent.locks {
		if otherFile == uint64(handle) {
			continue
		}
		if !lockOK(int(level), other) {
			return C.SQLITE_BUSY
		}
	}
	f.lockLevel = int(level)
	ent.locks[uint64(handle)] = int(level)
	return C.SQLITE_OK
}

//export goVfsUnlock
func goVfsUnlock(handle C.ulonglong, level C.int) (rc C.int) {
	defer func() {
		if recover() != nil {
			rc = C.SQLITE_IOERR
		}
	}()
	f := vfsLookup(uint64(handle))
	if f == nil {
		return C.SQLITE_IOERR
	}
	if !f.mainDB {
		return C.SQLITE_OK
	}
	vfsMu.Lock()
	ent := vfsStores[f.name]
	vfsMu.Unlock()
	f.lockLevel = int(level)
	if ent != nil {
		ent.mu.Lock()
		ent.locks[uint64(handle)] = int(level)
		ent.mu.Unlock()
	}
	return C.SQLITE_OK
}

//export goVfsCheckReserved
func goVfsCheckReserved(handle C.ulonglong, out *C.int) (rc C.int) {
	defer func() {
		if recover() != nil {
			rc = C.SQLITE_IOERR
		}
	}()
	*out = 0
	f := vfsLookup(uint64(handle))
	if f == nil {
		return C.SQLITE_IOERR
	}
	if !f.mainDB {
		return C.SQLITE_OK
	}
	vfsMu.Lock()
	ent := vfsStores[f.name]
	vfsMu.Unlock()
	if ent == nil {
		return C.SQLITE_OK
	}
	ent.mu.Lock()
	defer ent.mu.Unlock()
	for _, level := range ent.locks {
		if level >= LockReserved {
			*out = 1
			break
		}
	}
	return C.SQLITE_OK
}

//export goVfsFileControl
func goVfsFileControl(handle C.ulonglong, op C.int, arg unsafe.Pointer) (rc C.int) {
	defer func() {
		if recover() != nil {
			rc = C.SQLITE_ERROR
		}
	}()
	f := vfsLookup(uint64(handle))
	if f == nil {
		return C.SQLITE_NOTFOUND
	}
	if int(op) == int(C.SQLITE_FCNTL_MMAP_SIZE) && arg != nil {
		// Memory-mapped I/O is unsupported; force it off.
		*(*C.sqlite3_int64)(arg) = 0
		return C.SQLITE_OK
	}
	if !f.mainDB {
		return C.SQLITE_NOTFOUND
	}
	if int(op) == int(C.SQLITE_FCNTL_COMMIT_PHASETWO) {
		if tracker, ok := f.store.(CommitTracker); ok {
			return C.int(tracker.CompleteTransaction())
		}
		return C.SQLITE_OK
	}
	if int(op) != int(C.SQLITE_FCNTL_PRAGMA) {
		if arg == nil {
			return C.SQLITE_NOTFOUND
		}
		vfsMu.Lock()
		hook := vfsCfg.FileControl
		vfsMu.Unlock()
		if hook != nil {
			if handled, rc := hook(f.store, uint64(handle), int(op), arg, f.readOnly); handled {
				return C.int(rc)
			}
		}
		return C.SQLITE_NOTFOUND
	}
	if arg == nil {
		return C.SQLITE_NOTFOUND
	}
	// PRAGMA args are char*[4] per the SQLite contract.
	argv := (*[4]*C.char)(arg)
	var name, value *string
	if argv[1] != nil {
		s := C.GoString(argv[1])
		name = &s
	}
	if argv[2] != nil {
		s := C.GoString(argv[2])
		value = &s
	}
	vfsMu.Lock()
	fn := vfsCfg.Pragma
	ent := vfsStores[f.name]
	vfsMu.Unlock()
	if fn == nil || name == nil {
		return C.SQLITE_NOTFOUND
	}
	locked := false
	if ent != nil {
		ent.mu.Lock()
		for _, level := range ent.locks {
			if level > LockNone {
				locked = true
				break
			}
		}
		ent.mu.Unlock()
	}
	code, out := fn(f.store, uint64(handle), *name, value, f.readOnly, locked)
	if out != "" {
		cs := C.CString(out)
		dup := C.murmurPragmaStrdup(cs)
		C.free(unsafe.Pointer(cs))
		argv[0] = dup // SQLite frees arguments[0] with sqlite3_free.
	}
	return C.int(code)
}

//export goVfsDelete
func goVfsDelete(cname *C.char) (rc C.int) {
	defer func() {
		if recover() != nil {
			rc = C.SQLITE_IOERR_DELETE
		}
	}()
	if cname == nil {
		return C.SQLITE_IOERR_DELETE
	}
	name := normalizeName(C.GoString(cname))
	vfsMu.Lock()
	delete(vfsMem, name)
	var tracker CommitTracker
	if isJournal(name) {
		if ent, ok := vfsStores[name[:len(name)-8]]; ok {
			tracker, _ = ent.store.(CommitTracker)
		}
	}
	vfsMu.Unlock()
	if tracker != nil {
		return C.int(tracker.CompleteTransaction())
	}
	// Never delete an open store directory via xDelete.
	return C.SQLITE_OK
}

//export goVfsAccess
func goVfsAccess(cname *C.char, flags C.int, out *C.int) (rc C.int) {
	defer func() {
		if recover() != nil {
			rc = C.SQLITE_IOERR
		}
	}()
	if cname == nil {
		*out = 0
		return C.SQLITE_OK
	}
	name := normalizeName(C.GoString(cname))
	vfsMu.Lock()
	if _, ok := vfsMem[name]; ok {
		vfsMu.Unlock()
		*out = 1
		return C.SQLITE_OK
	}
	_, mainLive := vfsStores[name]
	suffixed := isJournal(name) || strings.HasSuffix(name, "-wal")
	ownerLive := false
	if suffixed && !mainLive {
		base := name
		if isJournal(name) {
			base = name[:len(name)-8]
		} else {
			base = name[:len(name)-4]
		}
		_, ownerLive = vfsStores[base]
	}
	vfsMu.Unlock()
	if suffixed && !mainLive && ownerLive {
		*out = 0
		return C.SQLITE_OK
	}
	_, err := os.Stat(name)
	present := err == nil
	*out = 0
	if present {
		*out = 1
	}
	return C.SQLITE_OK
}

func itoa(v uint64) string {
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
