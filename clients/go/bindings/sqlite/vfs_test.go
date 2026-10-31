package sqlite_test

import (
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/marcgauthier/sqlite-murmur-go/clients/go/bindings/sqlite"
	"github.com/marcgauthier/sqlite-murmur-go/clients/go/pkgs/storage"
)

type vfsHarness struct {
	mu      sync.Mutex
	stores  map[string]*storage.MemBlockStore
	pragmas []string
}

func (h *vfsHarness) opener(path string, readOnly, create bool) (sqlite.FileStore, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	st, ok := h.stores[path]
	if !ok {
		st = &storage.MemBlockStore{}
		h.stores[path] = st
	}
	return st, nil
}

func (h *vfsHarness) pragma(store sqlite.FileStore, handle uint64, name string, value *string, readOnly, locked bool) (int, string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	rec := name
	if value != nil {
		rec += "=" + *value
	}
	h.pragmas = append(h.pragmas, rec)
	if strings.EqualFold(name, "cipher") && value == nil {
		return 0, "aes256-gcm"
	}
	if strings.EqualFold(name, "cipher") {
		return 0, ""
	}
	return 12, "" // SQLITE_NOTFOUND
}

func keys(h *vfsHarness) []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []string
	for k := range h.stores {
		out = append(out, k)
	}
	return out
}

func openVFS(t *testing.T, path string) *sqlite.Conn {
	t.Helper()
	db, err := sqlite.Open("file:"+path+"?vfs=murmurtest", sqlite.OpenReadWrite|sqlite.OpenCreate|sqlite.OpenURI)
	if err != nil {
		t.Fatalf("open %s via murmurtest VFS: %v", path, err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestVFSRoundTrip(t *testing.T) {
	h := &vfsHarness{stores: map[string]*storage.MemBlockStore{}}
	if err := sqlite.RegisterVFS("murmurtest", sqlite.VFSConfig{Open: h.opener, Pragma: h.pragma}); err != nil {
		t.Fatalf("RegisterVFS: %v", err)
	}
	db := openVFS(t, "vfs1")
	if err := db.Exec("CREATE TABLE t(a INTEGER PRIMARY KEY, b TEXT); INSERT INTO t(b) VALUES('one'),('two');"); err != nil {
		t.Fatalf("setup: %v", err)
	}
	st, err := db.Prepare("SELECT b FROM t ORDER BY a")
	if err != nil {
		t.Fatalf("prepare: %v", err)
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
	if len(got) != 2 || got[0] != "one" || got[1] != "two" {
		t.Fatalf("rows = %q", got)
	}
	h.mu.Lock()
	abs, _ := filepath.Abs("vfs1")
	store, ok := h.stores[abs]
	h.mu.Unlock()
	if !ok {
		t.Fatalf("no store for %q (have %v)", abs, keys(h))
	}
	size := store.Size()
	if size <= 0 || size%4096 != 0 {
		t.Fatalf("store size = %d, want positive page multiple", size)
	}
}

func TestVFSLocking(t *testing.T) {
	h := &vfsHarness{stores: map[string]*storage.MemBlockStore{}}
	if err := sqlite.RegisterVFS("murmurtest", sqlite.VFSConfig{Open: h.opener, Pragma: h.pragma}); err != nil {
		t.Fatalf("RegisterVFS: %v", err)
	}
	a := openVFS(t, "vfs2")
	b := openVFS(t, "vfs2")
	if err := a.Exec("CREATE TABLE t(a); INSERT INTO t VALUES(1);"); err != nil {
		t.Fatalf("setup: %v", err)
	}
	if err := a.Exec("BEGIN IMMEDIATE; INSERT INTO t VALUES(2);"); err != nil {
		t.Fatalf("begin+write a: %v", err)
	}
	if err := b.Exec("INSERT INTO t VALUES(3)"); err == nil {
		t.Fatalf("concurrent write through second connection unexpectedly succeeded")
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

func TestVFSPragmaDispatch(t *testing.T) {
	h := &vfsHarness{stores: map[string]*storage.MemBlockStore{}}
	if err := sqlite.RegisterVFS("murmurtest", sqlite.VFSConfig{Open: h.opener, Pragma: h.pragma}); err != nil {
		t.Fatalf("RegisterVFS: %v", err)
	}
	db := openVFS(t, "vfs3")
	if err := db.Exec("CREATE TABLE t(a)"); err != nil {
		t.Fatalf("setup: %v", err)
	}
	st, err := db.Prepare("PRAGMA cipher")
	if err != nil {
		t.Fatalf("prepare pragma: %v", err)
	}
	defer st.Close()
	done, err := st.Step()
	if err != nil || done {
		t.Fatalf("pragma step: done=%v err=%v", done, err)
	}
	if got := st.ColumnText(0); got != "aes256-gcm" {
		t.Fatalf("PRAGMA cipher = %q", got)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	found := false
	for _, p := range h.pragmas {
		if p == "cipher" {
			found = true
		}
	}
	if !found {
		t.Fatalf("pragma handler saw %q, want cipher read", h.pragmas)
	}
}

func TestVFSJournalIsEphemeral(t *testing.T) {
	h := &vfsHarness{stores: map[string]*storage.MemBlockStore{}}
	if err := sqlite.RegisterVFS("murmurtest", sqlite.VFSConfig{Open: h.opener, Pragma: h.pragma}); err != nil {
		t.Fatalf("RegisterVFS: %v", err)
	}
	db := openVFS(t, "vfs4")
	if err := db.Exec("CREATE TABLE t(a); INSERT INTO t VALUES(1);"); err != nil {
		t.Fatalf("setup: %v", err)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	for name := range h.stores {
		if strings.HasSuffix(name, "-journal") {
			t.Fatalf("journal materialized a main store: %q", name)
		}
	}
}
