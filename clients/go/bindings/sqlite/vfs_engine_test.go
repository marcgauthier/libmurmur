package sqlite_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marcgauthier/sqlite-murmur-go/clients/go/bindings/sqlite"
	"github.com/marcgauthier/sqlite-murmur-go/clients/go/pkgs/storage"
)

func engineKey() [32]byte {
	var k [32]byte
	for i := range k {
		k[i] = byte(0x51 + i)
	}
	return k
}

// TestVFSEngineEndToEnd runs SQL through the VFS against real encrypted
// engines: file bytes stay ciphertext, PRAGMAs round-trip, and data
// survives close/reopen.
func TestVFSEngineEndToEnd(t *testing.T) {
	key := engineKey()
	opener := func(path string, readOnly, create bool) (sqlite.FileStore, error) {
		return storage.OpenFile(path, key, create)
	}
	pragma := func(store sqlite.FileStore, handle uint64, name string, value *string, readOnly, locked bool) (int, string) {
		eng, ok := store.(*storage.Engine)
		if !ok {
			return 12, ""
		}
		return eng.Pragma(name, value, readOnly, locked)
	}
	if err := sqlite.RegisterVFS("murmurtest", sqlite.VFSConfig{Open: opener, Pragma: pragma}); err != nil {
		t.Fatalf("RegisterVFS: %v", err)
	}
	dir := t.TempDir()
	uri := "file:" + filepath.Join(dir, "e2e.db") + "?vfs=murmurtest"
	db, err := sqlite.Open(uri, sqlite.OpenReadWrite|sqlite.OpenCreate|sqlite.OpenURI)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	query := func(sql string) string {
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
	if got := query("PRAGMA cipher"); got != "aes256gcm" {
		t.Fatalf("PRAGMA cipher = %q", got)
	}
	if got := query("PRAGMA compression"); got != "zstd3" {
		t.Fatalf("PRAGMA compression = %q", got)
	}
	if got := query("PRAGMA flush_interval_ms"); got != "250" {
		t.Fatalf("PRAGMA flush_interval_ms = %q", got)
	}
	if got := query("PRAGMA mmap_size"); got != "0" {
		t.Fatalf("PRAGMA mmap_size = %q", got)
	}
	if got := query("PRAGMA murmur_kdf"); got != "direct" {
		t.Fatalf("PRAGMA murmur_kdf = %q", got)
	}
	if err := db.Exec("CREATE TABLE t(a INTEGER PRIMARY KEY, b TEXT); INSERT INTO t(b) VALUES('alpha'),('beta'),('gamma');"); err != nil {
		t.Fatalf("setup: %v", err)
	}
	if got := query("SELECT count(*) FROM t"); got != "3" {
		t.Fatalf("count = %q", got)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "e2e.db"))
	if err != nil {
		t.Fatalf("read raw: %v", err)
	}
	for _, needle := range []string{"alpha", "beta", "gamma", "CREATE TABLE"} {
		if strings.Contains(string(raw), needle) {
			t.Fatalf("plaintext %q visible in database file", needle)
		}
	}
	// Reopen: the file decrypts and the rows survive.
	db2, err := sqlite.Open(uri, sqlite.OpenReadWrite|sqlite.OpenURI)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer db2.Close()
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
