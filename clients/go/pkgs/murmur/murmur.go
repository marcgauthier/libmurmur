// Package murmur is the Go API for encrypted SQLite databases: VFS
// registration, integrated open/close, offline tools (flush,
// checkpoint, repair, rekey, inventory, stats), and live control
// (backup, compact, keyring). Databases are RocksDB directories
// readable by any implementation of the murmur format.
package murmur

import (
	"sync"

	"github.com/marcgauthier/libmurmur/clients/go/bindings/sqlite"
	"github.com/marcgauthier/libmurmur/clients/go/pkgs/storage"
)

// VFSName is the registered VFS name.
const VFSName = "sqlite-murmur"

// Result codes mirror storage.Code* (SQLite primary codes).
const (
	CodeOK       = storage.CodeOK
	CodeError    = storage.CodeError
	CodeBusy     = storage.CodeBusy
	CodeNoMem    = storage.CodeNoMem
	CodeReadOnly = storage.CodeReadOnly
	CodeIOErr    = storage.CodeIOErr
	CodeCorrupt  = storage.CodeCorrupt
	CodeNotFound = storage.CodeNotFound
	CodeCantOpen = storage.CodeCantOpen
	CodeMisuse   = storage.CodeMisuse
	CodeAuth     = storage.CodeAuth
)

var (
	stateMu    sync.Mutex
	registered bool
	master     [32]byte
	flushMS    uint32 = 250
	cachePages int    = storage.CachePagesDefault

	fileKeyCur, fileKeyPrev   [32]byte
	haveFileCur, haveFilePrev bool

	// handles tracks open integrated connections.
	handles = map[*sqlite.Conn]bool{}
	// extensions tracks per-file extension slots by VFS file handle.
	extensions = map[uint64]Extension{}
)

// Extension serves murmur_* PRAGMAs for one file. The replication
// layer provides the implementation; without one, murmur_* PRAGMAs
// (outside the engine KDF table) report an error naming it.
type Extension interface {
	// Pragma serves one PRAGMA; value is nil for read-back form.
	// It returns the result string and the SQLite result code.
	Pragma(name string, value *string) (string, int)
	// Close releases the slot when its file closes.
	Close()
}

// lookupEngine opens a shell on a live store by the user-supplied
// path, or nil when the store is not live. Callers own the shell and
// must Close it. Callers must not hold stateMu.
func lookupEngine(path string) *storage.Engine {
	stateMu.Lock()
	k := master
	stateMu.Unlock()
	return storage.OpenLive(path, k)
}

func isRegistered() bool {
	stateMu.Lock()
	defer stateMu.Unlock()
	return registered
}

func trackHandle(db *sqlite.Conn) {
	stateMu.Lock()
	defer stateMu.Unlock()
	handles[db] = true
}

func untrackHandle(db *sqlite.Conn) {
	stateMu.Lock()
	defer stateMu.Unlock()
	delete(handles, db)
}
