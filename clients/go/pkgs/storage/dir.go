package storage

import (
	"errors"
	"os"
	"syscall"

	"github.com/marcgauthier/libmurmur/clients/go/bindings/nvfs"
	"github.com/marcgauthier/libmurmur/clients/go/bindings/sqlite"
	"github.com/marcgauthier/libmurmur/clients/go/bindings/zstd"
)

// Directory engines are RocksDB databases with the sqlite-murmur
// layout (page records under PageKey, metadata under meta:*), readable
// by either implementation. RocksDB's LOCK owns cross-process
// exclusion; same-process exclusion is the caller's registry check.

// Extra result codes for offline tools.
const (
	CodeCantOpen = 14
	CodeAuth     = 23
)

// ErrLocked reports a store held by another process (single-file
// engines, which carry their own lock file).
var ErrLocked = errors.New("storage: store locked by another process")

// acquireLockFile opens lockPath and takes a non-blocking exclusive
// flock. The caller holds the returned file until release.
func acquireLockFile(lockPath string) (*os.File, error) {
	f, err := os.OpenFile(lockPath, os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, ErrLocked
	}
	return f, nil
}

// OpenDir opens (or creates) a directory-backed RocksDB engine. The
// store is owned by the C++ control-plane registry; the returned
// Engine is a shell borrowing it (Close drops the reference). The
// key travels as raw bytes via nvStoreKey (staged in C++ only);
// shells keep their own copy for ring reloads. There is no Go-side
// RocksDB path.
func OpenDir(dir string, key [32]byte, create bool) (*Engine, error) {
	openMu.Lock()
	defer openMu.Unlock()
	canon := sqlite.CanonicalPath(dir)
	if create {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return nil, err
		}
	} else if st, err := os.Stat(dir); err != nil || !st.IsDir() {
		return nil, errors.New("storage: not a database directory")
	}
	ref, err := nvfs.OpenStoreRef(canon, create, CachePagesDefault)
	if err != nil {
		return nil, err
	}
	if rc := nvfs.KeyStore(&ref, key); rc != 0 {
		nvfs.CloseStoreRef(ref.Handle)
		return nil, &sqlite.Error{Code: rc, Msg: "storage: key rejected"}
	}
	return openShell(ref, canon, key)
}

func keyringErrCode(err error) int {
	switch {
	case errors.Is(err, ErrAuth):
		return CodeAuth
	case errors.Is(err, ErrCorrupt):
		return CodeCorrupt
	case errors.Is(err, ErrMisuse):
		return CodeMisuse
	default:
		return CodeError
	}
}

// nvGet reads one meta/small key from a native store with buffer
// growth. Records and envelopes stay far below the cap.
func nvGet(db *nvfs.Store, key []byte) (val []byte, found bool, err error) {
	buf := make([]byte, 8192)
	for {
		n, found, err := db.Get(key, buf)
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

// RekeyDir rekeys a sealed store offline through the native
// implementation (offline.cc nvOfflineRekey): every page is
// rewritten under a fresh data key sealed by newMaster. faultAfter
// aborts after N pages (test crash hook; 0 disables).
func RekeyDir(dir string, oldMaster, newMaster [32]byte, faultAfter int) int {
	return nvfs.OfflineRekey(dir, oldMaster, newMaster, faultAfter)
}

// VerifyDir trial-opens every page of a sealed store through the
// native implementation (offline.cc nvOfflineVerify). Read-only.
func VerifyDir(dir string, master [32]byte) int {
	return nvfs.OfflineVerify(dir, master)
}

// rekeyDirGo is the Go oracle for the native rekey (differential
// reference; see TestNativeRekeyDifferential). Protocol: staged
// envelope in META_KEYRING_REKEY, old-first trial decrypt, legacy
// pages stay unkeyed, level-3 compression, 100-page synced chunks,
// atomic flip. The flip's two synced puts resume safely (a crash
// between them leaves the staged envelope for the next run, and
// page rewrites are idempotent under old-first trial decrypt).
func rekeyDirGo(dir string, oldMaster, newMaster [32]byte, faultAfter int) (rc int) {
	defer func() {
		if recover() != nil {
			rc = CodeIOErr
		}
	}()
	if st, err := os.Stat(dir); err != nil || !st.IsDir() {
		return CodeCantOpen
	}
	// Independent raw open (no registry, no codec): RocksDB's LOCK
	// serializes against live same-process stores (BUSY) and
	// cross-process holders, exactly as before the control plane.
	db, err := nvfs.Open(dir, false)
	if err != nil {
		if isBusyOrRetry(err.Error()) {
			return CodeBusy
		}
		return CodeCantOpen
	}
	defer db.Close()

	cipher := CipherAES256GCM
	if val, found, err := nvGet(db, []byte(MetaCipher)); err == nil && found {
		switch string(val) {
		case "aegis256":
			cipher = CipherAEGIS256
		case "aes256gcm":
		default:
			return CodeCorrupt
		}
	}
	currentEnv, found, err := nvGet(db, []byte(MetaKeyring))
	if err != nil || !found {
		return CodeError
	}
	sidRaw, found, err := nvGet(db, []byte(MetaStoreID))
	if err != nil || !found || len(sidRaw) != 16 {
		return CodeCorrupt
	}
	var storeID [16]byte
	copy(storeID[:], sidRaw)
	oldRing, err := openRekeyRing(currentEnv, oldMaster, storeID)
	if err != nil {
		return keyringErrCode(err)
	}
	defer oldRing.Wipe()
	if _, ok := oldRing.ByID(oldRing.Current); !ok || oldRing.Current == 0 {
		return CodeCorrupt
	}
	oldKeys := snapshotRing(oldMaster, oldRing)

	var staged []byte
	if val, found, err := nvGet(db, []byte(MetaKeyringRekey)); err == nil && found && len(val) > 0 {
		staged = val
	} else {
		co := CreateOptions{
			KDF:            oldRing.KDF,
			ArgonTime:      oldRing.ArgonTime,
			ArgonMemoryKiB: oldRing.ArgonMemoryKiB,
			ArgonThreads:   oldRing.ArgonThreads,
			WrapID:         oldRing.WrapID,
			StoreID:        storeID,
			ContextID:      storeID,
		}
		if oldRing.KDF == KDFArgon2ID {
			co.Passphrase = newMaster[:]
		} else {
			co.Master = newMaster[:]
		}
		staged, err = Create(co)
		if err != nil {
			return keyringErrCode(err)
		}
		defer wipe(staged)
		if err := db.Put([]byte(MetaKeyringRekey), staged, true); err != nil {
			return CodeIOErr
		}
	}
	newRing, err := openRekeyRing(staged, newMaster, storeID)
	if err != nil {
		return CodeCorrupt
	}
	defer newRing.Wipe()
	newCur, ok := newRing.ByID(newRing.Current)
	if !ok || newRing.Current == 0 {
		return CodeCorrupt
	}

	chunk, total := 0, 0
	scanErr := db.ScanPages(func(page uint64, record []byte) error {
		plain, err := decryptBlock(cipher, &oldKeys, page, record)
		if err != nil {
			if p, err2 := Decrypt(cipher, newCur.Key, page, record); err2 == nil {
				copy(plain[:], p)
			} else {
				return errCorruptSentinel
			}
		}
		_, wasKeyed := RecordKeyID(record)
		var target uint32
		if wasKeyed {
			target = newRing.Current
		}
		payload := plain[:]
		compressed := false
		if out, err := zstd.Compress(plain[:], 3); err == nil && len(out) < Block {
			payload = out
			compressed = true
		}
		newRec, err := Encrypt(cipher, newCur.Key, page, payload, compressed, target)
		for i := range plain {
			plain[i] = 0
		}
		if err != nil {
			return errIOWriteSentinel
		}
		key := PageKey(page)
		if err := db.Put(key[:], newRec, false); err != nil {
			return errIOWriteSentinel
		}
		chunk++
		total++
		if faultAfter > 0 && total >= faultAfter {
			_, _ = db.Sync()
			return errFaultSentinel
		}
		if chunk >= 100 {
			if _, err := db.Sync(); err != nil {
				return errIOWriteSentinel
			}
			chunk = 0
		}
		return nil
	})
	oldKeys.wipe()
	if scanErr == errCorruptSentinel {
		return CodeCorrupt
	}
	if scanErr == errFaultSentinel {
		return CodeIOErr
	}
	if scanErr != nil {
		return CodeIOErr
	}
	if chunk > 0 {
		if _, err := db.Sync(); err != nil {
			return CodeIOErr
		}
	}
	if err := db.Put([]byte(MetaKeyring), staged, true); err != nil {
		return CodeIOErr
	}
	if err := db.Delete([]byte(MetaKeyringRekey), true); err != nil {
		return CodeIOErr
	}
	return CodeOK
}

var (
	errCorruptSentinel = errors.New("corrupt")
	errIOWriteSentinel = errors.New("io write")
	errFaultSentinel   = errors.New("fault")
)

// snapshotRing builds a decrypt snapshot from a standalone ring.
func snapshotRing(master [32]byte, ring *Keyring) pageKeys {
	snap := pageKeys{master: master, sealed: true, current: ring.Current}
	if cur, ok := ring.ByID(ring.Current); ok {
		snap.active = cur.Key
		snap.page = cur.Key
	}
	for _, ent := range ring.Keys {
		if ent.Active {
			continue
		}
		snap.retired = append(snap.retired, ent)
	}
	return snap
}

// openRekeyRing opens an envelope with a master pair: direct rings use
// it as the master, Argon2 rings as passphrase bytes.
func openRekeyRing(env []byte, master [32]byte, storeID [16]byte) (*Keyring, error) {
	if ring, err := Open(env, master[:], nil, storeID, storeID); err == nil {
		return ring, nil
	}
	return Open(env, nil, master[:], storeID, storeID)
}

// VerifyDir decrypts every page of a store offline and reports the
// first failure. It never mutates the store. Go oracle for the
// native verify (see TestNativeRekeyDifferential).
func verifyDirGo(dir string, master [32]byte) int {
	if st, err := os.Stat(dir); err != nil || !st.IsDir() {
		return CodeCantOpen
	}
	// Independent raw open like RekeyDir (LOCK-serialized).
	db, err := nvfs.Open(dir, false)
	if err != nil {
		if isBusyOrRetry(err.Error()) {
			return CodeBusy
		}
		return CodeCantOpen
	}
	defer db.Close()
	cipher := CipherAES256GCM
	if val, found, err := nvGet(db, []byte(MetaCipher)); err == nil && found {
		switch string(val) {
		case "aegis256":
			cipher = CipherAEGIS256
		case "aes256gcm":
		default:
			return CodeCorrupt
		}
	}
	keys := pageKeys{master: master, page: master}
	if env, found, err := nvGet(db, []byte(MetaKeyring)); err == nil && found && len(env) > 0 {
		sidRaw, found, err := nvGet(db, []byte(MetaStoreID))
		if err != nil || !found || len(sidRaw) != 16 {
			return CodeCorrupt
		}
		var storeID [16]byte
		copy(storeID[:], sidRaw)
		ring, err := openRekeyRing(env, master, storeID)
		if err != nil {
			return keyringErrCode(err)
		}
		defer ring.Wipe()
		keys = snapshotRing(master, ring)
	}
	defer keys.wipe()
	failed := false
	if err := db.ScanPages(func(page uint64, record []byte) error {
		if _, err := decryptBlock(cipher, &keys, page, record); err != nil {
			failed = true
		}
		return nil
	}); err != nil {
		return CodeIOErr
	}
	if failed {
		return CodeCorrupt
	}
	return CodeOK
}

// RepairDir runs RocksDB offline repair. The caller checks liveness
// first (repair refuses live same-process stores with BUSY).
func RepairDir(dir string) int {
	if err := nvfs.Repair(dir); err != nil {
		return CodeIOErr
	}
	return CodeOK
}
