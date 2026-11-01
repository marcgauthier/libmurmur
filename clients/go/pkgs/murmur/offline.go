package murmur

import (
	"os"

	"github.com/marcgauthier/libmurmur/clients/go/bindings/nvfs"
	"github.com/marcgauthier/libmurmur/clients/go/pkgs/storage"
)

// liveEngine opens a shell on a live store, or nil when the store is
// not live. Callers own the shell and must Close it.
func liveEngine(path string) *storage.Engine {
	return lookupEngine(path)
}

// liveStore reports whether path names a live store (no open). Offline
// tools refuse live stores with BUSY.
func liveStore(path string) bool {
	return nvfs.StoreIsLive(path)
}

// Flush syncs one open store.
func Flush(path string) int {
	eng := liveEngine(path)
	if eng == nil {
		return CodeNotFound
	}
	defer eng.Close()
	if err := eng.Sync(); err != nil {
		return CodeIOErr
	}
	return CodeOK
}

// Checkpoint is the persistence barrier: sync, flush memtables, and
// wait for compactions.
func Checkpoint(path string) int {
	eng := liveEngine(path)
	if eng == nil {
		return CodeNotFound
	}
	defer eng.Close()
	return eng.Checkpoint()
}

// Repair runs RocksDB offline repair on a closed store.
func Repair(path string) int {
	if path == "" {
		return CodeMisuse
	}
	if st, err := os.Stat(path); err != nil || !st.IsDir() {
		return CodeCantOpen
	}
	if liveStore(path) {
		return CodeBusy
	}
	return storage.RepairDir(path)
}

// KeyInventory serializes a closed store's ring through the native
// offline inventory (no open, no shell). Live stores refuse with
// BUSY. Unlock/open failures report CANTOPEN, as before.
func KeyInventory(path string) (string, int) {
	if liveStore(path) {
		return "", CodeBusy
	}
	stateMu.Lock()
	k := master
	ready := registered
	stateMu.Unlock()
	if !ready {
		return "", CodeMisuse
	}
	js, rc := nvfs.OfflineInventory(path, k)
	if rc != CodeOK {
		return "", CodeCantOpen
	}
	return js, CodeOK
}

// Rekey runs the offline full-store rekey. faultAfter aborts after N
// pages (test crash hook; 0 disables). Live stores refuse with BUSY.
func Rekey(path string, oldMaster, newMaster [32]byte, faultAfter int) int {
	if liveStore(path) {
		return CodeBusy
	}
	return storage.RekeyDir(path, oldMaster, newMaster, faultAfter)
}

// Verify trial-opens every page of a closed store. Read-only. Live
// stores refuse with BUSY.
func Verify(path string, master [32]byte) int {
	if liveStore(path) {
		return CodeBusy
	}
	return storage.VerifyDir(path, master)
}

// Stats snapshots one store's traffic counters plus its committed
// logical size.
type Stats struct {
	LogicalSizeBytes       uint64
	VFSWriteBytes          uint64
	VFSBlockWrites         uint64
	FlushBatches           uint64
	PersistedBlocks        uint64
	UncompressedBytes      uint64
	CompressedPayloadBytes uint64
	EncryptedRecordBytes   uint64
	RocksDBWALBytes        uint64
	RocksDBFlushBytes      uint64
	RocksDBCompactionBytes uint64
}

// GetStats fills the stats snapshot from one open store.
func GetStats(path string) (Stats, int) {
	var out Stats
	eng := liveEngine(path)
	if eng == nil {
		return out, CodeNotFound
	}
	defer eng.Close()
	st := eng.SnapshotStats()
	out.LogicalSizeBytes = eng.CommittedSize()
	out.VFSWriteBytes = st.VFSWriteBytes
	out.VFSBlockWrites = st.PagesWritten
	out.FlushBatches = st.FlushBatches
	out.PersistedBlocks = st.PagesWritten
	out.UncompressedBytes = st.UncompressedBytes
	out.CompressedPayloadBytes = st.CompressedPayloadSum
	out.EncryptedRecordBytes = st.StoredBytes
	out.RocksDBWALBytes = st.WALBytes
	out.RocksDBFlushBytes = st.FlushBytes
	out.RocksDBCompactionBytes = st.CompactBytes
	return out, CodeOK
}
