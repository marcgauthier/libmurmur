package nvfs_test

import (
	"encoding/hex"
	"errors"
	"path/filepath"
	"testing"

	"github.com/marcgauthier/libmurmur/clients/go/bindings/sqlite"
)

// execCode runs sql and returns the SQLite result code (0 on success).
func execCode(t *testing.T, db *sqlite.Conn, sql string) int {
	t.Helper()
	if err := db.Exec(sql); err == nil {
		return 0
	} else {
		var se *sqlite.Error
		if !errors.As(err, &se) {
			t.Fatalf("exec %q: non-sqlite error %v", sql, err)
		}
		return se.Code
	}
}

// TestControlPlaneSealViaSQL pins the C++ seal path end to end:
// stage params, seal over SQL, sealed reads, sealed writes, and
// persistence across reopen.
func TestControlPlaneSealViaSQL(t *testing.T) {
	h := registerNative(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "seal")
	db := h.openKeyed(t, path)
	if got := queryOne(t, db, "PRAGMA murmur_scrypt_n='16'"); got != "16" {
		t.Fatalf("stage time = %q", got)
	}
	if got := queryOne(t, db, "PRAGMA murmur_kdf='direct'"); got != "direct" {
		t.Fatalf("seal = %q", got)
	}
	if got := queryOne(t, db, "PRAGMA murmur_kdf"); got != "direct" {
		t.Fatalf("sealed kdf = %q", got)
	}
	// Direct-HKDF seals stage no scrypt params: the sealed header
	// reads back zeros, matching reopen decodes.
	if got := queryOne(t, db, "PRAGMA murmur_scrypt_n"); got != "0" {
		t.Fatalf("sealed time = %q, want 0", got)
	}
	if code := execCode(t, db, "PRAGMA murmur_scrypt_n='6'"); code != 5 {
		t.Fatalf("sealed stage = %d, want BUSY", code)
	}
	if err := db.Exec("CREATE TABLE t(a); INSERT INTO t VALUES(42);"); err != nil {
		t.Fatalf("sealed write: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	// Reopen sealed: envelope persists, rows survive.
	db2 := h.openKeyed(t, path)
	if got := queryOne(t, db2, "PRAGMA murmur_kdf"); got != "direct" {
		t.Fatalf("reopened kdf = %q", got)
	}
	if got := queryOne(t, db2, "SELECT a FROM t"); got != "42" {
		t.Fatalf("reopened row = %q", got)
	}
	_ = h
}

// TestControlPlaneWrongKey pins PRAGMA key authentication: a sealed
// store refuses the wrong master (CORRUPT), accepts the right one,
// and rejects a second, different key (MISUSE).
func TestControlPlaneWrongKey(t *testing.T) {
	h := registerNative(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "auth")
	db := h.openKeyed(t, path)
	if got := queryOne(t, db, "PRAGMA murmur_kdf='direct'"); got != "direct" {
		t.Fatalf("seal = %q", got)
	}
	if err := db.Exec("CREATE TABLE t(a); INSERT INTO t VALUES(7);"); err != nil {
		t.Fatalf("setup: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	// Reopen keyless: the open succeeds, reads fail, and the wrong
	// key is refused.
	db2, err := sqlite.Open("file:"+path+"?vfs=nativetest", sqlite.OpenReadWrite|sqlite.OpenURI)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer db2.Close()
	var wrong [32]byte
	wrong[0] = 0xFF
	if code := execCode(t, db2, "PRAGMA key='"+hex.EncodeToString(wrong[:])+"'"); code != 11 {
		t.Fatalf("wrong key = %d, want CORRUPT", code)
	}
	if err := db2.Exec("SELECT a FROM t"); err == nil {
		t.Fatal("keyless read unexpectedly succeeded")
	}
	if err := db2.Exec("PRAGMA key='" + hex.EncodeToString(h.key[:]) + "'"); err != nil {
		t.Fatalf("right key: %v", err)
	}
	if got := queryOne(t, db2, "SELECT a FROM t"); got != "7" {
		t.Fatalf("row after key = %q", got)
	}
	if code := execCode(t, db2, "PRAGMA key='"+hex.EncodeToString(wrong[:])+"'"); code != 21 {
		t.Fatalf("second key = %d, want MISUSE", code)
	}
	if code := execCode(t, db2, "PRAGMA key='zzzz'"); code == 0 {
		t.Fatal("malformed key accepted")
	}
}

// TestPublicKeyAPI pins the murmur_db_key path end to end: the
// public function provisions, authenticates, and single-keys exactly
// like PRAGMA key, and refuses connections without a murmur store.
func TestPublicKeyAPI(t *testing.T) {
	h := registerNative(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "pubkey")
	db := openNative(t, path)
	if rc := db.SetKey(h.key); rc != 0 {
		t.Fatalf("SetKey = %d", rc)
	}
	if got := queryOne(t, db, "PRAGMA murmur_kdf='direct'"); got != "direct" {
		t.Fatalf("seal = %q", got)
	}
	if err := db.Exec("CREATE TABLE t(a); INSERT INTO t VALUES(9);"); err != nil {
		t.Fatalf("setup: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	db2, err := sqlite.Open("file:"+path+"?vfs=nativetest", sqlite.OpenReadWrite|sqlite.OpenURI)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer db2.Close()
	var wrong [32]byte
	wrong[0] = 0xFF
	if rc := db2.SetKey(wrong); rc != 11 {
		t.Fatalf("wrong key = %d, want CORRUPT", rc)
	}
	if rc := db2.SetKey(h.key); rc != 0 {
		t.Fatalf("right key = %d", rc)
	}
	if got := queryOne(t, db2, "SELECT a FROM t"); got != "9" {
		t.Fatalf("row after key = %q", got)
	}
	if rc := db2.SetKey(wrong); rc != 21 {
		t.Fatalf("second key = %d, want MISUSE", rc)
	}
	// No murmur store behind main: NOTFOUND, not a silent no-op.
	mem, err := sqlite.Open(":memory:", sqlite.OpenReadWrite)
	if err != nil {
		t.Fatalf("memory open: %v", err)
	}
	defer mem.Close()
	if rc := mem.SetKey(h.key); rc != 12 {
		t.Fatalf("memory SetKey = %d, want NOTFOUND", rc)
	}
	var nilConn *sqlite.Conn
	if rc := nilConn.SetKey(h.key); rc != 21 {
		t.Fatalf("nil SetKey = %d, want MISUSE", rc)
	}
}

// TestControlPlaneReadOnlyGuardsViaSQL pins the per-file readOnly
// context through SQL: cold PRAGMAs refuse on read-only
// connections, except flush_interval_ms (no guard, as in Go).
func TestControlPlaneReadOnlyGuardsViaSQL(t *testing.T) {
	h := registerNative(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "ro")
	db := h.openKeyed(t, path)
	if err := db.Exec("CREATE TABLE t(a); INSERT INTO t VALUES(1);"); err != nil {
		t.Fatalf("setup: %v", err)
	}
	ro, err := sqlite.Open("file:"+path+"?vfs=nativetest", sqlite.OpenReadOnly|sqlite.OpenURI)
	if err != nil {
		t.Fatalf("read-only open: %v", err)
	}
	defer ro.Close()
	if code := execCode(t, ro, "PRAGMA cipher='aes256gcm'"); code != 8 {
		t.Fatalf("ro cipher = %d, want READONLY", code)
	}
	if code := execCode(t, ro, "PRAGMA compression='none'"); code != 8 {
		t.Fatalf("ro compression = %d, want READONLY", code)
	}
	if code := execCode(t, ro, "PRAGMA murmur_scrypt_n='7'"); code != 8 {
		t.Fatalf("ro scrypt_n = %d, want READONLY", code)
	}
	if code := execCode(t, ro, "PRAGMA rocksdb_sync='1'"); code != 8 {
		t.Fatalf("ro rocksdb_sync = %d, want READONLY", code)
	}
	if code := execCode(t, ro, "PRAGMA flush_interval_ms='100'"); code != 0 {
		t.Fatalf("ro flush_interval_ms = %d, want OK", code)
	}
	if got := queryOne(t, ro, "SELECT count(*) FROM t"); got != "1" {
		t.Fatalf("ro count = %q", got)
	}
}

// TestControlPlaneRocksDBViaSQL pins the live RocksDB knobs through
// SQL, including range validation.
func TestControlPlaneRocksDBViaSQL(t *testing.T) {
	h := registerNative(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "rocks")
	db := h.openKeyed(t, path)
	if got := queryOne(t, db, "PRAGMA rocksdb_sync"); got != "0" {
		t.Fatalf("sync = %q", got)
	}
	if got := queryOne(t, db, "PRAGMA rocksdb_sync='1'"); got != "1" {
		t.Fatalf("sync set = %q", got)
	}
	if code := execCode(t, db, "PRAGMA rocksdb_sync='2'"); code != 1 {
		t.Fatalf("sync range = %d, want ERROR", code)
	}
	if got := queryOne(t, db, "PRAGMA rocksdb_max_background_jobs='4'"); got != "4" {
		t.Fatalf("bgjobs set = %q", got)
	}
	// Unknown names report NOTFOUND to SQLite, which swallows it
	// (silent OK); SQLite-owned names fall through to SQLite.
	if code := execCode(t, db, "PRAGMA rocksdb_bogus='1'"); code != 0 {
		t.Fatalf("bogus rocks pragma = %d, want silent OK", code)
	}
	if got := queryOne(t, db, "PRAGMA journal_mode"); got != "delete" {
		t.Fatalf("journal_mode passthrough = %q", got)
	}
	if code := execCode(t, db, "PRAGMA journal_mode='wal'"); code != 1 {
		t.Fatalf("journal_mode wal = %d, want ERROR", code)
	}
}
