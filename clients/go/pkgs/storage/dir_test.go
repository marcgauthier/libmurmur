package storage

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/marcgauthier/sqlite-murmur-go/clients/go/bindings/nvfs"
)

func dirKey(seed byte) [32]byte {
	var k [32]byte
	for i := range k {
		k[i] = seed + byte(i)
	}
	return k
}

func openRaw(t *testing.T, dir string) *nvfs.Store {
	t.Helper()
	db, err := nvfs.Open(dir, false)
	if err != nil {
		t.Fatalf("raw open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestOpenDirRoundTrip(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "db")
	e, err := OpenDir(dir, dirKey(0x10), true)
	if err != nil {
		t.Fatalf("OpenDir create: %v", err)
	}
	payload := bytes.Repeat([]byte("directory store payload "), 200)
	if err := e.WriteAt(payload, 0); err != nil {
		t.Fatalf("WriteAt: %v", err)
	}
	if err := e.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	// A real RocksDB directory: CURRENT + LOCK + MANIFEST family.
	for _, name := range []string{"CURRENT", "LOCK"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Fatalf("missing rocksdb %s: %v", name, err)
		}
	}
	// The page record sits under the cross-implementation key.
	db := openRaw(t, dir)
	pk := PageKey(0)
	rec, found, err := nvGet(db, pk[:])
	if err != nil || !found {
		t.Fatalf("page record missing: %v,%v", found, err)
	}
	if !IsLegacyRecord(rec) {
		t.Fatalf("record is not a legacy EXP envelope")
	}
	if sz, found, _ := nvGet(db, []byte(MetaSize)); !found || string(sz) != "4800" {
		t.Fatalf("meta:size = %q,%v", sz, found)
	}
	db.Close() // release LOCK before the engine open
	e2, err := OpenDir(dir, dirKey(0x10), false)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer e2.Close()
	back := make([]byte, len(payload))
	if n, err := e2.ReadAt(back, 0); err != nil || n != len(payload) || !bytes.Equal(back, payload) {
		t.Fatalf("read = %d, %v", n, err)
	}
	if _, err := OpenDir(filepath.Join(t.TempDir(), "nope"), dirKey(0x10), false); err == nil {
		t.Fatalf("open missing without create unexpectedly succeeded")
	}
}

func sealDir(t *testing.T, dir string, key [32]byte, payload []byte) {
	t.Helper()
	e, err := OpenDir(dir, key, true)
	if err != nil {
		t.Fatalf("OpenDir: %v", err)
	}
	defer e.Close()
	if err := e.WriteAt(payload, 0); err != nil {
		t.Fatalf("WriteAt: %v", err)
	}
	if rc := e.SetParam(KeyringParamKDF, KDFDirectHKDF, false); rc != CodeOK {
		t.Fatalf("seal = %d", rc)
	}
	if err := e.WriteAt(payload, 0); err != nil {
		t.Fatalf("rewrite: %v", err)
	}
}

func TestRekeyDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "db")
	oldM, newM := dirKey(0x20), dirKey(0x40)
	payload := bytes.Repeat([]byte("rekey me "), 600)
	sealDir(t, dir, oldM, payload)

	if rc := RekeyDir(dir, oldM, newM, 0); rc != CodeOK {
		t.Fatalf("rekey = %d", rc)
	}
	db := openRaw(t, dir)
	if _, found, _ := nvGet(db, []byte(MetaKeyringRekey)); found {
		t.Fatalf("staged rekey envelope left behind")
	}
	db.Close() // release LOCK before the engine opens
	if _, err := OpenDir(dir, oldM, false); err == nil {
		t.Fatalf("old-master open unexpectedly succeeded after rekey")
	}
	e, err := OpenDir(dir, newM, false)
	if err != nil {
		t.Fatalf("new-master open: %v", err)
	}
	defer e.Close()
	if !e.Sealed() {
		t.Fatalf("rekeyed store not sealed")
	}
	back := make([]byte, len(payload))
	if n, err := e.ReadAt(back, 0); err != nil || n != len(payload) || !bytes.Equal(back, payload) {
		t.Fatalf("rekeyed read = %d, %v", n, err)
	}
}

func TestRekeyDirGuards(t *testing.T) {
	oldM, newM := dirKey(0x20), dirKey(0x40)
	if rc := RekeyDir(filepath.Join(t.TempDir(), "nope"), oldM, newM, 0); rc != CodeCantOpen {
		t.Fatalf("missing dir = %d, want CANTOPEN", rc)
	}
	plain := filepath.Join(t.TempDir(), "plain")
	e, err := OpenDir(plain, oldM, true)
	if err != nil {
		t.Fatalf("OpenDir: %v", err)
	}
	if err := e.WriteAt([]byte("x"), 0); err != nil {
		t.Fatalf("WriteAt: %v", err)
	}
	if err := e.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if rc := RekeyDir(plain, oldM, newM, 0); rc != CodeError {
		t.Fatalf("unsealed rekey = %d, want ERROR", rc)
	}
	sealed := filepath.Join(t.TempDir(), "sealed")
	sealDir(t, sealed, oldM, []byte("guard payload"))
	var wrong [32]byte
	if rc := RekeyDir(sealed, wrong, newM, 0); rc != CodeAuth {
		t.Fatalf("wrong master = %d, want AUTH", rc)
	}
}

func TestRekeyDirFaultResume(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "db")
	oldM, newM := dirKey(0x20), dirKey(0x40)
	payload := bytes.Repeat([]byte("fault-injected rekey payload "), 500)
	sealDir(t, dir, oldM, payload)

	if rc := RekeyDir(dir, oldM, newM, 1); rc != CodeIOErr {
		t.Fatalf("faulted rekey = %d, want IOERR", rc)
	}
	db := openRaw(t, dir)
	if _, found, _ := nvGet(db, []byte(MetaKeyringRekey)); !found {
		t.Fatalf("staged envelope missing after fault")
	}
	db.Close() // release LOCK before the resume
	if rc := RekeyDir(dir, oldM, newM, 0); rc != CodeOK {
		t.Fatalf("resume = %d", rc)
	}
	e, err := OpenDir(dir, newM, false)
	if err != nil {
		t.Fatalf("open after resume: %v", err)
	}
	defer e.Close()
	back := make([]byte, len(payload))
	if n, err := e.ReadAt(back, 0); err != nil || n != len(payload) || !bytes.Equal(back, payload) {
		t.Fatalf("resumed read = %d, %v", n, err)
	}
}

func TestRekeyDirArgon2(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "db")
	oldM, newM := dirKey(0x20), dirKey(0x40)
	e, err := OpenDir(dir, oldM, true)
	if err != nil {
		t.Fatalf("OpenDir: %v", err)
	}
	payload := bytes.Repeat([]byte("argon2 rekey payload "), 200)
	if err := e.WriteAt(payload, 0); err != nil {
		t.Fatalf("WriteAt: %v", err)
	}
	if rc := e.SetParam(KeyringParamTime, 1, false); rc != CodeOK {
		t.Fatalf("stage time: %d", rc)
	}
	if rc := e.SetParam(KeyringParamMemory, 1024, false); rc != CodeOK {
		t.Fatalf("stage memory: %d", rc)
	}
	if rc := e.SetParam(KeyringParamThreads, 1, false); rc != CodeOK {
		t.Fatalf("stage threads: %d", rc)
	}
	if rc := e.SetParam(KeyringParamKDF, KDFArgon2ID, false); rc != CodeOK {
		t.Fatalf("seal argon2: %d", rc)
	}
	if err := e.WriteAt(payload, 0); err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	if err := e.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if rc := RekeyDir(dir, oldM, newM, 0); rc != CodeOK {
		t.Fatalf("argon2 rekey = %d", rc)
	}
	e2, err := OpenDir(dir, newM, false)
	if err != nil {
		t.Fatalf("open rekeyed argon2: %v", err)
	}
	defer e2.Close()
	back := make([]byte, len(payload))
	if n, err := e2.ReadAt(back, 0); err != nil || n != len(payload) || !bytes.Equal(back, payload) {
		t.Fatalf("argon2 rekeyed read = %d, %v", n, err)
	}
}

func TestVerifyDir(t *testing.T) {
	oldM := dirKey(0x20)
	if rc := VerifyDir(filepath.Join(t.TempDir(), "nope"), oldM); rc != CodeCantOpen {
		t.Fatalf("missing = %d, want CANTOPEN", rc)
	}
	dir := filepath.Join(t.TempDir(), "db")
	payload := bytes.Repeat([]byte("verify me "), 500)
	sealDir(t, dir, oldM, payload)
	if rc := VerifyDir(dir, oldM); rc != CodeOK {
		t.Fatalf("verify = %d", rc)
	}
	var wrong [32]byte
	if rc := VerifyDir(dir, wrong); rc != CodeAuth {
		t.Fatalf("wrong master = %d, want AUTH", rc)
	}
	// Tamper with one record byte through the raw handle.
	db := openRaw(t, dir)
	pk := PageKey(0)
	rec, found, err := nvGet(db, pk[:])
	if err != nil || !found {
		t.Fatalf("page record missing: %v", err)
	}
	rec[20] ^= 0xff
	if err := db.Put(pk[:], rec, true); err != nil {
		t.Fatalf("tamper put: %v", err)
	}
	db.Close()
	if rc := VerifyDir(dir, oldM); rc != CodeCorrupt {
		t.Fatalf("tampered verify = %d, want CORRUPT", rc)
	}
}

func TestRocksPragmaLive(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "db")
	e, err := OpenDir(dir, dirKey(0x10), true)
	if err != nil {
		t.Fatalf("OpenDir: %v", err)
	}
	defer e.Close()
	str := func(s string) *string { return &s }
	if code, out := e.Pragma("rocksdb_sync", nil, false, false); code != CodeOK || out != "0" {
		t.Fatalf("sync read = %d %q", code, out)
	}
	if code, out := e.Pragma("rocksdb_sync", str("1"), false, false); code != CodeOK || out != "1" {
		t.Fatalf("sync set = %d %q", code, out)
	}
	if code, _ := e.Pragma("rocksdb_sync", str("7"), false, false); code != CodeError {
		t.Fatalf("sync bad = %d, want ERROR", code)
	}
	if code, out := e.Pragma("rocksdb_block_cache_bytes", str("4194304"), false, false); code != CodeOK || out != "4194304" {
		t.Fatalf("cache set = %d %q", code, out)
	}
	if code, out := e.Pragma("rocksdb_write_buffer_size", str("134217728"), false, false); code != CodeOK || out != "134217728" {
		t.Fatalf("wbuf set = %d %q", code, out)
	}
	if code, _ := e.Pragma("rocksdb_write_buffer_size", str("1"), false, false); code != CodeError {
		t.Fatalf("wbuf small = %d, want ERROR", code)
	}
	if code, out := e.Pragma("rocksdb_max_background_jobs", str("2"), false, false); code != CodeOK || out != "2" {
		t.Fatalf("bgjobs set = %d %q", code, out)
	}
	if code, _ := e.Pragma("rocksdb_sync", str("1"), true, false); code != CodeReadOnly {
		t.Fatalf("sync ro = %d, want READONLY", code)
	}
	if code, _ := e.Pragma("rocksdb_nope", nil, false, false); code != CodeNotFound {
		t.Fatalf("unknown = %d, want NOTFOUND", code)
	}
	// File engines own no RocksDB knobs.
	f := OpenMem(dirKey(0x10))
	defer f.Close()
	if code, _ := f.Pragma("rocksdb_sync", nil, false, false); code != CodeNotFound {
		t.Fatalf("file rocksdb_sync = %d, want NOTFOUND", code)
	}
}

// copyDir duplicates a closed store directory (RocksDB files only;
// the copy must not run while the source is open).
func copyDir(t *testing.T, src, dst string) {
	t.Helper()
	if err := os.MkdirAll(dst, 0700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	entries, err := os.ReadDir(src)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	for _, e := range entries {
		sp, dp := filepath.Join(src, e.Name()), filepath.Join(dst, e.Name())
		if e.IsDir() {
			copyDir(t, sp, dp)
			continue
		}
		in, err := os.Open(sp)
		if err != nil {
			t.Fatalf("open: %v", err)
		}
		out, err := os.OpenFile(dp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
		if err != nil {
			in.Close()
			t.Fatalf("create: %v", err)
		}
		if _, err := io.Copy(out, in); err != nil {
			t.Fatalf("copy: %v", err)
		}
		in.Close()
		out.Close()
	}
}

// keyedShape scans page records and reports each page's keyed-ness.
// Rekey preserves the shape (keyed pages stay keyed under the new
// id, legacy stay legacy) while randomizing record bytes.
func keyedShape(t *testing.T, dir string) map[uint64]bool {
	t.Helper()
	db, err := nvfs.Open(dir, false)
	if err != nil {
		t.Fatalf("raw open: %v", err)
	}
	defer db.Close()
	shape := map[uint64]bool{}
	if err := db.ScanPages(func(page uint64, rec []byte) error {
		_, keyed := RecordKeyID(rec)
		shape[page] = keyed
		return nil
	}); err != nil {
		t.Fatalf("scan: %v", err)
	}
	return shape
}

func readPayload(t *testing.T, dir string, key [32]byte, n int) []byte {
	t.Helper()
	e, err := OpenDir(dir, key, false)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer e.Close()
	out := make([]byte, n)
	if _, err := e.ReadAt(out, 0); err != nil {
		t.Fatalf("read: %v", err)
	}
	return out
}

// TestNativeRekeyDifferential runs the Go rekey/verify oracles and
// the native implementations on identical sealed fixtures and
// requires identical behavior: codes, readability under old/new
// masters, and the per-page keyed/legacy shape.
func TestNativeRekeyDifferential(t *testing.T) {
	oldM, newM, wrongM := dirKey(0x20), dirKey(0x40), dirKey(0x60)
	payload := bytes.Repeat([]byte("diff me please "), 500)
	base := filepath.Join(t.TempDir(), "base")
	sealDir(t, base, oldM, payload)

	dirGo := filepath.Join(t.TempDir(), "go")
	dirNat := filepath.Join(t.TempDir(), "nat")
	copyDir(t, base, dirGo)
	copyDir(t, base, dirNat)

	if rc := rekeyDirGo(dirGo, oldM, newM, 0); rc != CodeOK {
		t.Fatalf("go rekey = %d", rc)
	}
	if rc := RekeyDir(dirNat, oldM, newM, 0); rc != CodeOK {
		t.Fatalf("native rekey = %d", rc)
	}
	// Behavior after rekey must match on both sides.
	for name, dir := range map[string]string{"go": dirGo, "nat": dirNat} {
		if rc := VerifyDir(dir, newM); rc != CodeOK {
			t.Fatalf("%s verify new = %d", name, rc)
		}
		if rc := VerifyDir(dir, oldM); rc != CodeAuth {
			t.Fatalf("%s verify old = %d, want AUTH", name, rc)
		}
		if got := readPayload(t, dir, newM, len(payload)); !bytes.Equal(got, payload) {
			t.Fatalf("%s payload mismatch", name)
		}
	}
	shapeGo, shapeNat := keyedShape(t, dirGo), keyedShape(t, dirNat)
	if len(shapeGo) == 0 || len(shapeGo) != len(shapeNat) {
		t.Fatalf("shape sizes go=%d nat=%d", len(shapeGo), len(shapeNat))
	}
	for page, keyed := range shapeGo {
		if shapeNat[page] != keyed {
			t.Fatalf("page %d keyed: go=%v nat=%v", page, keyed, shapeNat[page])
		}
	}
	// Verify oracles agree on the sealed fixture, wrong key, and a
	// tampered copy.
	if rc := verifyDirGo(base, oldM); rc != CodeOK {
		t.Fatalf("go verify = %d", rc)
	}
	if rc := VerifyDir(base, oldM); rc != CodeOK {
		t.Fatalf("native verify = %d", rc)
	}
	if rc := verifyDirGo(base, wrongM); rc != CodeAuth {
		t.Fatalf("go verify wrong = %d", rc)
	}
	if rc := VerifyDir(base, wrongM); rc != CodeAuth {
		t.Fatalf("native verify wrong = %d", rc)
	}
	tamp := filepath.Join(t.TempDir(), "tamp")
	copyDir(t, base, tamp)
	raw, err := nvfs.Open(tamp, false)
	if err != nil {
		t.Fatalf("raw open: %v", err)
	}
	if err := raw.ScanPages(func(page uint64, rec []byte) error {
		rec[len(rec)-1] ^= 0xFF
		k := PageKey(page)
		return raw.Put(k[:], rec, true)
	}); err != nil {
		t.Fatalf("tamper scan: %v", err)
	}
	raw.Close()
	if rc := verifyDirGo(tamp, oldM); rc != CodeCorrupt {
		t.Fatalf("go verify tampered = %d", rc)
	}
	if rc := VerifyDir(tamp, oldM); rc != CodeCorrupt {
		t.Fatalf("native verify tampered = %d", rc)
	}
}
