package nvfs_test

import (
	"bytes"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/marcgauthier/sqlite-murmur-go/clients/go/bindings/nvfs"
	"github.com/marcgauthier/sqlite-murmur-go/clients/go/bindings/sqlite"
	"github.com/marcgauthier/sqlite-murmur-go/clients/go/pkgs/storage"
)

type nvHarness struct {
	mu     sync.Mutex
	key    [32]byte
	closes []string
}

func nvKey() [32]byte {
	var k [32]byte
	for i := range k {
		k[i] = byte(0xC0 + i)
	}
	return k
}

func registerNative(t *testing.T) *nvHarness {
	t.Helper()
	h := &nvHarness{key: nvKey()}
	cfg := nvfs.VFSConfig{
		OnCloseFile: func(file uint64) {
			h.mu.Lock()
			h.closes = append(h.closes, "file")
			h.mu.Unlock()
		},
	}
	if err := nvfs.RegisterVFS("nativetest", cfg); err != nil {
		t.Fatalf("RegisterVFS: %v", err)
	}
	return h
}

// shell opens a control-plane shell on path's live store. The shell
// closes at test cleanup.
func (h *nvHarness) shell(t *testing.T, path string) *storage.Engine {
	t.Helper()
	eng := storage.OpenLive(path, h.key)
	if eng == nil {
		t.Fatalf("no live store for %s", path)
	}
	t.Cleanup(func() { eng.Close() })
	return eng
}

func openNative(t *testing.T, path string) *sqlite.Conn {
	t.Helper()
	db, err := sqlite.Open("file:"+path+"?vfs=nativetest", sqlite.OpenReadWrite|sqlite.OpenCreate|sqlite.OpenURI)
	if err != nil {
		t.Fatalf("open %s via nativetest VFS: %v", path, err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// openKeyed opens through the native VFS and provisions with the
// harness key through the public key API, like any ordinary client.
func (h *nvHarness) openKeyed(t *testing.T, path string) *sqlite.Conn {
	t.Helper()
	db := openNative(t, path)
	if rc := db.SetKey(h.key); rc != 0 {
		t.Fatalf("SetKey: %d", rc)
	}
	return db
}

func queryOne(t *testing.T, db *sqlite.Conn, sql string) string {
	t.Helper()
	st, err := db.Prepare(sql)
	if err != nil {
		t.Fatalf("prepare %q: %v", sql, err)
	}
	defer st.Close()
	done, err := st.Step()
	if err != nil || done {
		t.Fatalf("step %q: done=%v err=%v", sql, done, err)
	}
	return st.ColumnText(0)
}

// TestNativeVFSRoundTrip runs SQL through the native VFS against real
// encrypted engines: PRAGMAs round-trip, file bytes stay ciphertext,
// and data survives close/reopen.
func TestNativeVFSRoundTrip(t *testing.T) {
	h := registerNative(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "e2e")
	db := h.openKeyed(t, path)
	if got := queryOne(t, db, "PRAGMA cipher"); got != "aes256gcm" {
		t.Fatalf("PRAGMA cipher = %q", got)
	}
	if got := queryOne(t, db, "PRAGMA compression"); got != "zstd3" {
		t.Fatalf("PRAGMA compression = %q", got)
	}
	if got := queryOne(t, db, "PRAGMA flush_interval_ms"); got != "250" {
		t.Fatalf("PRAGMA flush_interval_ms = %q", got)
	}
	if got := queryOne(t, db, "PRAGMA mmap_size"); got != "0" {
		t.Fatalf("PRAGMA mmap_size = %q", got)
	}
	if got := queryOne(t, db, "PRAGMA murmur_kdf"); got != "direct" {
		t.Fatalf("PRAGMA murmur_kdf = %q", got)
	}
	if err := db.Exec("CREATE TABLE t(a INTEGER PRIMARY KEY, b TEXT); INSERT INTO t(b) VALUES('alpha'),('beta'),('gamma');"); err != nil {
		t.Fatalf("setup: %v", err)
	}
	if got := queryOne(t, db, "SELECT count(*) FROM t"); got != "3" {
		t.Fatalf("count = %q", got)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	// The store directory holds ciphertext only.
	needles := []string{"alpha", "beta", "gamma", "CREATE TABLE"}
	err := filepath.Walk(path, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		if info.Name() == "LOCK" {
			return nil
		}
		raw, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		for _, n := range needles {
			if strings.Contains(string(raw), n) {
				t.Fatalf("plaintext %q visible in %s", n, p)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// Last close destroyed the store: the file hook fired and the
	// registry is empty.
	h.mu.Lock()
	closes := len(h.closes)
	h.mu.Unlock()
	if closes < 1 {
		t.Fatalf("file close hooks fired %d times, want >= 1", closes)
	}
	if nvfs.StoreLiveCount() != 0 {
		t.Fatalf("live stores after last close = %d, want 0", nvfs.StoreLiveCount())
	}
	// Reopen: the store decrypts and the rows survive.
	db2, err := sqlite.Open("file:"+path+"?vfs=nativetest", sqlite.OpenReadWrite|sqlite.OpenURI)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer db2.Close()
	if err := db2.Exec("PRAGMA key='" + hex.EncodeToString(h.key[:]) + "'"); err != nil {
		t.Fatalf("reopen key: %v", err)
	}
	st, err := db2.Prepare("SELECT b FROM t ORDER BY a")
	if err != nil {
		t.Fatalf("prepare reopen: %v", err)
	}
	defer st.Close()
	var got []string
	for {
		done, err := st.Step()
		if err != nil {
			t.Fatalf("step: %v", err)
		}
		if done {
			break
		}
		got = append(got, st.ColumnText(0))
	}
	if len(got) != 3 || got[0] != "alpha" || got[1] != "beta" || got[2] != "gamma" {
		t.Fatalf("rows after reopen = %q", got)
	}
}

func TestNativeVFSLocking(t *testing.T) {
	h := registerNative(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "lock")
	a := h.openKeyed(t, path)
	b := h.openKeyed(t, path)
	if err := a.Exec("CREATE TABLE t(a); INSERT INTO t VALUES(1);"); err != nil {
		t.Fatalf("setup: %v", err)
	}
	if err := a.Exec("BEGIN IMMEDIATE; INSERT INTO t VALUES(2);"); err != nil {
		t.Fatalf("begin+write a: %v", err)
	}
	if err := b.Exec("INSERT INTO t VALUES(3)"); err == nil {
		t.Fatal("concurrent write through second connection unexpectedly succeeded")
	} else {
		var se *sqlite.Error
		if !errors.As(err, &se) || se.Code != 5 {
			t.Fatalf("second-connection write error = %v, want SQLITE_BUSY", err)
		}
	}
	if err := a.Exec("COMMIT"); err != nil {
		t.Fatalf("commit a: %v", err)
	}
	if err := b.Exec("INSERT INTO t VALUES(3)"); err != nil {
		t.Fatalf("write after commit: %v", err)
	}
}

func TestNativeVFSJournalIsEphemeral(t *testing.T) {
	h := registerNative(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "jnl")
	db := h.openKeyed(t, path)
	if err := db.Exec("CREATE TABLE t(a); INSERT INTO t VALUES(1);"); err != nil {
		t.Fatalf("setup: %v", err)
	}
	if err := db.Exec("BEGIN; INSERT INTO t VALUES(2); ROLLBACK;"); err != nil {
		t.Fatalf("rollback txn (journal read-back): %v", err)
	}
	if got := queryOne(t, db, "SELECT count(*) FROM t"); got != "1" {
		t.Fatalf("count after rollback = %q, want 1", got)
	}
	if nvfs.StoreIsLive(path + "-journal") {
		t.Fatalf("journal materialized a main store: %q", path+"-journal")
	}
	if !nvfs.StoreIsLive(path) {
		t.Fatalf("main store not live: %q", path)
	}
}

func TestNativeVFSStatsMerge(t *testing.T) {
	h := registerNative(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "stats")
	db := h.openKeyed(t, path)
	// Pin the flusher off the test window: the pre-flush assertions
	// below must not race a background seal.
	if err := db.Exec("PRAGMA flush_interval_ms=3600000"); err != nil {
		t.Fatalf("pin flusher: %v", err)
	}
	rows := strings.Repeat("('payload-row-data'),", 200)
	if err := db.Exec("CREATE TABLE t(a INTEGER PRIMARY KEY, b TEXT); INSERT INTO t(b) VALUES " + rows[:len(rows)-1] + ";"); err != nil {
		t.Fatalf("setup: %v", err)
	}
	if got := queryOne(t, db, "SELECT count(*) FROM t"); got != "200" {
		t.Fatalf("count = %q", got)
	}
	eng := h.shell(t, path)
	// Write-back: commits stage in cache, so seals accrue at flush,
	// while VFS byte volume counts at write time.
	st := eng.SnapshotStats()
	if st.PagesRead == 0 || st.VFSReadBytes == 0 {
		t.Fatalf("read stats not merged: %+v", st)
	}
	if st.VFSWriteBytes == 0 {
		t.Fatalf("write bytes missing: %+v", st)
	}
	if st.PagesWritten != 0 || st.StoredBytes != 0 {
		t.Fatalf("seals accrued before flush: %+v", st)
	}
	if err := eng.Sync(); err != nil {
		t.Fatalf("sync: %v", err)
	}
	st = eng.SnapshotStats()
	if st.PagesWritten == 0 || st.StoredBytes == 0 {
		t.Fatalf("write stats missing after flush: %+v", st)
	}
	if st.UncompressedBytes == 0 || st.CompressedPayloadSum == 0 {
		t.Fatalf("payload stats missing after flush: %+v", st)
	}
}

// workload exercises DDL, bulk and single-row DML inside and outside
// transactions, updates, deletes, rollback, and explicit commits.
func workload(t *testing.T, db *sqlite.Conn) {
	t.Helper()
	if err := db.Exec("CREATE TABLE t(a INTEGER PRIMARY KEY, b TEXT, c REAL); CREATE INDEX ti ON t(b);"); err != nil {
		t.Fatalf("ddl: %v", err)
	}
	if err := db.Exec("BEGIN;"); err != nil {
		t.Fatalf("begin: %v", err)
	}
	for i := 0; i < 300; i++ {
		if err := db.Exec("INSERT INTO t(b,c) VALUES('name-" + strings.Repeat("x", i%40) + "', 1.5);"); err != nil {
			t.Fatalf("insert %d: %v", i, err)
		}
	}
	if err := db.Exec("COMMIT;"); err != nil {
		t.Fatalf("commit: %v", err)
	}
	if err := db.Exec("UPDATE t SET c = c + 1 WHERE a % 3 = 0; DELETE FROM t WHERE a % 7 = 0;"); err != nil {
		t.Fatalf("update/delete: %v", err)
	}
	if err := db.Exec("BEGIN; INSERT INTO t(b) VALUES('doomed'); ROLLBACK;"); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	if err := db.Exec("INSERT INTO t(b) VALUES('single-1'),('single-2');"); err != nil {
		t.Fatalf("singles: %v", err)
	}
}

func dumpAll(t *testing.T, db *sqlite.Conn) []string {
	t.Helper()
	st, err := db.Prepare("SELECT a, b, c FROM t ORDER BY a")
	if err != nil {
		t.Fatalf("dump prepare: %v", err)
	}
	defer st.Close()
	var out []string
	for {
		done, err := st.Step()
		if err != nil {
			t.Fatalf("dump step: %v", err)
		}
		if done {
			break
		}
		out = append(out, st.ColumnText(0)+"|"+st.ColumnText(1)+"|"+st.ColumnText(2))
	}
	return out
}

// TestNativeVsStagedDifferential runs an identical workload through
// the native and staged engines and requires decrypted-byte equality:
// same logical rows and same plaintext bytes at every offset.
func TestNativeVsStagedDifferential(t *testing.T) {
	h := registerNative(t)
	dir := t.TempDir()
	nativePath := filepath.Join(dir, "native")
	stagedPath := filepath.Join(dir, "staged")

	// Native run.
	ndb := h.openKeyed(t, nativePath)
	workload(t, ndb)
	nativeRows := dumpAll(t, ndb)
	if err := ndb.Close(); err != nil {
		t.Fatalf("native close: %v", err)
	}

	// Staged run through the Go VFS with the same key.
	key := h.key
	stagedOpener := func(path string, readOnly, create bool) (sqlite.FileStore, error) {
		return storage.OpenDir(path, key, create && !readOnly)
	}
	stagedPragma := func(store sqlite.FileStore, handle uint64, name string, value *string, readOnly, locked bool) (int, string) {
		eng, ok := store.(*storage.Engine)
		if !ok {
			return 12, ""
		}
		return eng.Pragma(name, value, readOnly, locked)
	}
	if err := sqlite.RegisterVFS("stagedtest", sqlite.VFSConfig{Open: stagedOpener, Pragma: stagedPragma}); err != nil {
		t.Fatalf("RegisterVFS staged: %v", err)
	}
	sdb, err := sqlite.Open("file:"+stagedPath+"?vfs=stagedtest", sqlite.OpenReadWrite|sqlite.OpenCreate|sqlite.OpenURI)
	if err != nil {
		t.Fatalf("staged open: %v", err)
	}
	workload(t, sdb)
	stagedRows := dumpAll(t, sdb)
	if err := sdb.Close(); err != nil {
		t.Fatalf("staged close: %v", err)
	}

	if len(nativeRows) != len(stagedRows) {
		t.Fatalf("row counts: native=%d staged=%d", len(nativeRows), len(stagedRows))
	}
	for i := range nativeRows {
		if nativeRows[i] != stagedRows[i] {
			t.Fatalf("row %d: native=%q staged=%q", i, nativeRows[i], stagedRows[i])
		}
	}

	// Decrypted bytes must match at every offset. Both stores open
	// with the staged reader (format interop), so any divergence is a
	// native byte-path bug, not a format difference.
	neng, err := storage.OpenDir(nativePath, key, false)
	if err != nil {
		t.Fatalf("open native store staged: %v", err)
	}
	defer neng.Close()
	seng, err := storage.OpenDir(stagedPath, key, false)
	if err != nil {
		t.Fatalf("open staged store staged: %v", err)
	}
	defer seng.Close()
	if neng.Size() != seng.Size() {
		t.Fatalf("sizes: native=%d staged=%d", neng.Size(), seng.Size())
	}
	size := neng.Size()
	nbuf := make([]byte, size)
	sbuf := make([]byte, size)
	if _, err := neng.ReadAt(nbuf, 0); err != nil {
		t.Fatalf("native ReadAt: %v", err)
	}
	if _, err := seng.ReadAt(sbuf, 0); err != nil {
		t.Fatalf("staged ReadAt: %v", err)
	}
	if !bytes.Equal(nbuf, sbuf) {
		t.Fatal("decrypted bytes differ between native and staged engines")
	}
}
