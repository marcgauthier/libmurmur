package murmur

import (
	"github.com/marcgauthier/libmurmur/clients/go/pkgs/storage"
)

// Backup checkpoints a live store plus manifest into dest, which must
// not exist. Any failure removes dest.
func Backup(path, dest, cipher string, group, node []byte) int {
	if dest == "" || cipher == "" {
		return CodeMisuse
	}
	if !storage.CipherCharsetOK(cipher) {
		return CodeError
	}
	if len(group) != 16 || len(node) != 16 {
		return CodeMisuse
	}
	eng := liveEngine(path)
	if eng == nil {
		return CodeNotFound
	}
	defer eng.Close()
	return eng.BackupTo(dest, group, node)
}

// Compact forces a full-range compaction on a live store.
func Compact(path string) int {
	eng := liveEngine(path)
	if eng == nil {
		return CodeNotFound
	}
	defer eng.Close()
	return eng.Compact()
}

// KeyringParams reports the sealed envelope header, or the staged
// seal parameters when unsealed.
type KeyringParams struct {
	KDF       uint8
	Time      uint32
	MemoryKiB uint32
	Threads   uint8
	Sealed    bool
}

// KeyringParamsFor reads one live store's keyring parameters.
func KeyringParamsFor(path string) (KeyringParams, int) {
	var out KeyringParams
	eng := liveEngine(path)
	if eng == nil {
		return out, CodeNotFound
	}
	defer eng.Close()
	if kdf, time, mem, threads, sealed := eng.RingParams(); sealed {
		out = KeyringParams{KDF: kdf, Time: time, MemoryKiB: mem, Threads: threads, Sealed: true}
	} else {
		kdf, time, mem, threads := eng.StagedKDF()
		out = KeyringParams{KDF: kdf, Time: time, MemoryKiB: mem, Threads: threads}
	}
	return out, CodeOK
}

// SetKeyringParam tunes one staged seal parameter on a live store.
// Operator tool: it carries no read-only context (use the murmur_kdf*
// PRAGMAs from read-only connections instead).
func SetKeyringParam(path string, param int, value uint64) int {
	eng := liveEngine(path)
	if eng == nil {
		return CodeNotFound
	}
	defer eng.Close()
	return eng.SetParam(param, value, false)
}

// KeyringRotate rotates a live store's data key, reporting the new id.
func KeyringRotate(path string) (uint32, int) {
	eng := liveEngine(path)
	if eng == nil {
		return 0, CodeNotFound
	}
	defer eng.Close()
	rc, id := eng.Rotate(false)
	if rc != CodeOK {
		return 0, rc
	}
	return id, CodeOK
}

// KeyringPrune drops unreferenced retired keys, reporting the JSON
// prune report.
func KeyringPrune(path string) (string, int) {
	eng := liveEngine(path)
	if eng == nil {
		return "", CodeNotFound
	}
	defer eng.Close()
	rc, report := eng.Prune(false)
	if rc != CodeOK {
		return "", rc
	}
	return report, CodeOK
}
