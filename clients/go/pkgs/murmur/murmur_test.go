package murmur

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marcgauthier/libmurmur/clients/go/bindings/sqlite"
	"github.com/marcgauthier/libmurmur/clients/go/pkgs/storage"
)

func murmurKey() []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = byte(0x77 + i)
	}
	return k
}

func execSQL(t *testing.T, db *sqlite.Conn, sql string) {
	t.Helper()
	if err := db.Exec(sql); err != nil {
		t.Fatalf("exec %q: %v", sql, err)
	}
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

func TestRegisterOpenCloseCycle(t *testing.T) {
	if rc := Register(murmurKey(), 0, 0); rc != CodeOK {
		t.Fatalf("register: %d", rc)
	}
	dir := filepath.Join(t.TempDir(), "db1")
	db, rc := Open(dir, nil)
	if rc != CodeOK {
		t.Fatalf("open: %d", rc)
	}
	if queryOne(t, db, "PRAGMA cipher") != "aes256gcm" {
		t.Fatalf("cipher pragma wrong")
	}
	execSQL(t, db, "CREATE TABLE t(a INTEGER PRIMARY KEY, b TEXT); INSERT INTO t(b) VALUES('x');")
	if got := queryOne(t, db, "SELECT count(*) FROM t"); got != "1" {
		t.Fatalf("count = %q", got)
	}
	if rc := Flush(dir); rc != CodeOK {
		t.Fatalf("flush: %d", rc)
	}
	if rc := Checkpoint(dir); rc != CodeOK {
		t.Fatalf("checkpoint: %d", rc)
	}
	if st, rc := GetStats(dir); rc != CodeOK || st.VFSWriteBytes == 0 {
		t.Fatalf("stats = %+v rc=%d", st, rc)
	}
	if rc := Close(db); rc != CodeOK {
		t.Fatalf("close: %d", rc)
	}
	if rc := Unregister(); rc != CodeOK {
		t.Fatalf("unregister: %d", rc)
	}
}

func TestUnregisterBusy(t *testing.T) {
	if rc := Register(murmurKey(), 0, 0); rc != CodeOK {
		t.Fatalf("register: %d", rc)
	}
	dir := filepath.Join(t.TempDir(), "busy")
	db, rc := Open(dir, nil)
	if rc != CodeOK {
		t.Fatalf("open: %d", rc)
	}
	if rc := Unregister(); rc != CodeBusy {
		t.Fatalf("unregister with open db = %d, want BUSY", rc)
	}
	if rc := Close(db); rc != CodeOK {
		t.Fatalf("close: %d", rc)
	}
	if rc := Unregister(); rc != CodeOK {
		t.Fatalf("unregister after close: %d", rc)
	}
	if rc := Register(murmurKey(), 100, 64); rc != CodeOK {
		t.Fatalf("re-register: %d", rc)
	}
	if rc := Unregister(); rc != CodeOK {
		t.Fatalf("final unregister: %d", rc)
	}
}

func TestOpenOptions(t *testing.T) {
	if rc := Register(murmurKey(), 0, 0); rc != CodeOK {
		t.Fatalf("register: %d", rc)
	}
	defer Unregister()
	dir := filepath.Join(t.TempDir(), "opts")
	db, rc := Open(dir, &OpenOptions{Cipher: "aegis256", Compression: "zstd6"})
	if rc != CodeOK {
		t.Fatalf("open with options: %d", rc)
	}
	defer Close(db)
	if got := queryOne(t, db, "PRAGMA cipher"); got != "aegis256" {
		t.Fatalf("cipher = %q", got)
	}
	if got := queryOne(t, db, "PRAGMA compression"); got != "zstd6" {
		t.Fatalf("compression = %q", got)
	}
	execSQL(t, db, "CREATE TABLE t(a); INSERT INTO t VALUES(1),(2);")
	if got := queryOne(t, db, "SELECT count(*) FROM t"); got != "2" {
		t.Fatalf("count = %q", got)
	}
	// Read-only open of the same store.
	ro, rc := Open(dir, &OpenOptions{ReadOnly: true})
	if rc != CodeOK {
		t.Fatalf("read-only open: %d", rc)
	}
	defer Close(ro)
	if got := queryOne(t, ro, "SELECT count(*) FROM t"); got != "2" {
		t.Fatalf("ro count = %q", got)
	}
}

func TestOfflineTools(t *testing.T) {
	if rc := Register(murmurKey(), 0, 0); rc != CodeOK {
		t.Fatalf("register: %d", rc)
	}
	defer Unregister()
	dir := filepath.Join(t.TempDir(), "off")
	db, rc := Open(dir, nil)
	if rc != CodeOK {
		t.Fatalf("open: %d", rc)
	}
	execSQL(t, db, "CREATE TABLE t(a); INSERT INTO t VALUES(1);")
	if rc := Repair(dir); rc != CodeBusy {
		t.Fatalf("repair live = %d, want BUSY", rc)
	}
	if _, rc := KeyInventory(dir); rc != CodeBusy {
		t.Fatalf("inventory live = %d, want BUSY", rc)
	}
	var z [32]byte
	if rc := Rekey(dir, z, z, 0); rc != CodeBusy {
		t.Fatalf("rekey live = %d, want BUSY", rc)
	}
	if rc := Close(db); rc != CodeOK {
		t.Fatalf("close: %d", rc)
	}
	if rc := Repair(dir); rc != CodeOK {
		t.Fatalf("repair closed: %d", rc)
	}
	if js, rc := KeyInventory(dir); rc != CodeOK || js != `{"sealed":false}` {
		t.Fatalf("inventory = %d %q", rc, js)
	}
	if rc := Flush(filepath.Join(t.TempDir(), "missing")); rc != CodeNotFound {
		t.Fatalf("flush missing = %d, want NOTFOUND", rc)
	}
}

func TestFileKeyAPI(t *testing.T) {
	if rc := Register(murmurKey(), 0, 0); rc != CodeOK {
		t.Fatalf("register: %d", rc)
	}
	defer Unregister()
	cur := murmurKey()
	prev := append([]byte(nil), cur...)
	prev[0] ^= 0xFF
	if rc := RegisterFileKey(cur, prev); rc != CodeOK {
		t.Fatalf("register file key: %d", rc)
	}
	if rc := RegisterFileKey(cur, nil); rc != CodeMisuse {
		t.Fatalf("second install = %d, want MISUSE", rc)
	}
	got, ok := FileKeyCurrent()
	if !ok || string(got) != string(cur) {
		t.Fatalf("current key mismatch")
	}
	got, ok = FileKeyPrevious()
	if !ok || string(got) != string(prev) {
		t.Fatalf("previous key mismatch")
	}
	if rc := RegisterFileKey([]byte("short"), nil); rc != CodeMisuse {
		t.Fatalf("short key = %d, want MISUSE", rc)
	}
}

func TestFileKeySlotWiped(t *testing.T) {
	if rc := Register(murmurKey(), 0, 0); rc != CodeOK {
		t.Fatalf("register: %d", rc)
	}
	cur := murmurKey()
	for i := range cur {
		cur[i] = 0xAA
	}
	if rc := RegisterFileKey(cur, nil); rc != CodeOK {
		t.Fatalf("register file key: %d", rc)
	}
	if rc := Unregister(); rc != CodeOK {
		t.Fatalf("unregister: %d", rc)
	}
	stateMu.Lock()
	defer stateMu.Unlock()
	if haveFileCur || haveFilePrev {
		t.Fatalf("slot survived unregister")
	}
	for i := range fileKeyCur {
		if fileKeyCur[i] != 0 || fileKeyPrev[i] != 0 {
			t.Fatalf("slot not wiped")
		}
	}
}

type fakeExtension struct {
	calls  int
	closed int
}

func (f *fakeExtension) Pragma(name string, value *string) (string, int) {
	f.calls++
	if value == nil {
		return "read:" + name, CodeOK
	}
	return "set:" + name + "=" + *value, CodeOK
}

func (f *fakeExtension) Close() { f.closed++ }

func TestExtensionSlot(t *testing.T) {
	fx := &fakeExtension{}
	if rc := InstallExtension(7, fx); rc != CodeOK {
		t.Fatalf("install: %d", rc)
	}
	if rc := InstallExtension(7, fx); rc != CodeMisuse {
		t.Fatalf("second install = %d, want MISUSE", rc)
	}
	out, rc, ok := runExtension(7, "murmur_demo", nil)
	if !ok || rc != CodeOK || out != "read:murmur_demo" {
		t.Fatalf("run read = %q,%d,%v", out, rc, ok)
	}
	v := "1"
	out, rc, ok = runExtension(7, "murmur_demo", &v)
	if !ok || rc != CodeOK || out != "set:murmur_demo=1" {
		t.Fatalf("run set = %q,%d,%v", out, rc, ok)
	}
	dropExtension(7)
	if _, _, ok := runExtension(7, "murmur_demo", nil); ok {
		t.Fatalf("run after drop unexpectedly hit")
	}
	if fx.calls != 2 || fx.closed != 1 {
		t.Fatalf("calls=%d closed=%d", fx.calls, fx.closed)
	}
}

func TestBackupRoundTrip(t *testing.T) {
	if rc := Register(murmurKey(), 0, 0); rc != CodeOK {
		t.Fatalf("register: %d", rc)
	}
	defer Unregister()
	dir := filepath.Join(t.TempDir(), "src")
	db, rc := Open(dir, nil)
	if rc != CodeOK {
		t.Fatalf("open: %d", rc)
	}
	execSQL(t, db, "CREATE TABLE t(a); INSERT INTO t VALUES(42);")
	if rc := Close(db); rc != CodeOK {
		t.Fatalf("close: %d", rc)
	}
	dest := filepath.Join(t.TempDir(), "bak")
	group := make([]byte, 16)
	node := make([]byte, 16)
	node[0] = 7
	// Reopen so the backup runs against a live engine.
	dbLive, rc := Open(dir, &OpenOptions{ReadOnly: true})
	if rc != CodeOK {
		t.Fatalf("reopen for backup: %d", rc)
	}
	if rc := Backup(dir, dest, "aes256gcm", group, node); rc != CodeOK {
		t.Fatalf("backup: %d", rc)
	}
	if rc := Close(dbLive); rc != CodeOK {
		t.Fatalf("close live: %d", rc)
	}
	manifest, err := os.ReadFile(filepath.Join(dest, "manifest.json"))
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	// The native manifest is byte-exact: flat object, no spaces,
	// trailing newline, exact schema.
	if !strings.HasSuffix(string(manifest), "}\n") || strings.Contains(string(manifest), " ") {
		t.Fatalf("manifest not byte-exact: %q", manifest)
	}
	var m struct {
		Format  int    `json:"format_version"`
		Cipher  string `json:"cipher"`
		Group   string `json:"group_id"`
		Node    string `json:"node_id"`
		Seq     uint64 `json:"rocksdb_seq"`
		Created int64  `json:"created_unix_ms"`
	}
	if err := json.Unmarshal(manifest, &m); err != nil {
		t.Fatalf("manifest json: %v", err)
	}
	if m.Format != 1 || m.Cipher != "aes256gcm" || m.Created <= 0 {
		t.Fatalf("manifest fields = %+v", m)
	}
	if m.Group != "00000000000000000000000000000000" || m.Node != "07000000000000000000000000000000" {
		t.Fatalf("manifest ids = %q %q", m.Group, m.Node)
	}
	db2, rc := Open(dest, &OpenOptions{ReadOnly: true})
	if rc != CodeOK {
		t.Fatalf("open backup: %d", rc)
	}
	defer Close(db2)
	if got := queryOne(t, db2, "SELECT a FROM t"); got != "42" {
		t.Fatalf("backup row = %q", got)
	}
	if rc := Backup(dest, dest, "aes256gcm", group, node); rc != CodeError {
		t.Fatalf("backup over existing = %d, want ERROR", rc)
	}
	if rc := Backup(dest, filepath.Join(t.TempDir(), "bad"), "AES!", group, node); rc != CodeError {
		t.Fatalf("backup bad cipher = %d, want ERROR", rc)
	}
}

func TestControlPaths(t *testing.T) {
	if rc := Register(murmurKey(), 0, 0); rc != CodeOK {
		t.Fatalf("register: %d", rc)
	}
	defer Unregister()
	missing := filepath.Join(t.TempDir(), "missing")
	if rc := Compact(missing); rc != CodeNotFound {
		t.Fatalf("compact missing = %d, want NOTFOUND", rc)
	}
	if _, rc := KeyringParamsFor(missing); rc != CodeNotFound {
		t.Fatalf("keyring params missing = %d, want NOTFOUND", rc)
	}
	if rc := SetKeyringParam(missing, 1, 0); rc != CodeNotFound {
		t.Fatalf("keyring set missing = %d, want NOTFOUND", rc)
	}
	if _, rc := KeyringRotate(missing); rc != CodeNotFound {
		t.Fatalf("rotate missing = %d, want NOTFOUND", rc)
	}
	if _, rc := KeyringPrune(missing); rc != CodeNotFound {
		t.Fatalf("prune missing = %d, want NOTFOUND", rc)
	}
	group := make([]byte, 16)
	node := make([]byte, 16)
	if rc := Backup(missing, filepath.Join(t.TempDir(), "b"), "aes256gcm", group, node); rc != CodeNotFound {
		t.Fatalf("backup missing = %d, want NOTFOUND", rc)
	}
	if rc := Backup(missing, "", "aes256gcm", group, node); rc != CodeMisuse {
		t.Fatalf("backup empty dest = %d, want MISUSE", rc)
	}
	dir := filepath.Join(t.TempDir(), "ctl")
	db, rc := Open(dir, nil)
	if rc != CodeOK {
		t.Fatalf("open: %d", rc)
	}
	defer Close(db)
	execSQL(t, db, "CREATE TABLE t(a); INSERT INTO t VALUES(1);")
	if rc := Compact(dir); rc != CodeOK {
		t.Fatalf("compact: %d", rc)
	}
	kp, rc := KeyringParamsFor(dir)
	if rc != CodeOK || kp.Sealed {
		t.Fatalf("keyring params = %+v rc=%d, want unsealed", kp, rc)
	}
	if rc := SetKeyringParam(dir, 2, 5); rc != CodeOK {
		t.Fatalf("keyring set kdf_time: %d", rc)
	}
	kp, rc = KeyringParamsFor(dir)
	if rc != CodeOK || kp.Time != 5 {
		t.Fatalf("staged time = %+v rc=%d", kp, rc)
	}
	if id, rc := KeyringRotate(dir); rc == CodeOK || id != 0 {
		t.Fatalf("rotate on unsealed = %d,%d, want ERROR", id, rc)
	}
	if rc := SetKeyringParam(dir, 1, 0); rc != CodeOK {
		t.Fatalf("seal via kdf param: %d", rc)
	}
	kp, rc = KeyringParamsFor(dir)
	if rc != CodeOK || !kp.Sealed {
		t.Fatalf("sealed params = %+v rc=%d", kp, rc)
	}
	if id, rc := KeyringRotate(dir); rc != CodeOK || id == 0 {
		t.Fatalf("rotate sealed = %d,%d", id, rc)
	}
	report, rc := KeyringPrune(dir)
	if rc != CodeOK || report == "" {
		t.Fatalf("prune = %q rc=%d", report, rc)
	}
	// Pre-rotate pages still reference key 1: nothing pruned.
	if !strings.Contains(report, `"pruned":[]`) {
		t.Fatalf("prune report = %q, want empty pruned", report)
	}
}

func TestKeyInventoryNative(t *testing.T) {
	if rc := Register(murmurKey(), 0, 0); rc != CodeOK {
		t.Fatalf("register: %d", rc)
	}
	defer Unregister()
	dir := filepath.Join(t.TempDir(), "inv")
	db, rc := Open(dir, nil)
	if rc != CodeOK {
		t.Fatalf("open: %d", rc)
	}
	execSQL(t, db, "CREATE TABLE t(a); INSERT INTO t VALUES(1);")
	execSQL(t, db, "PRAGMA murmur_kdf='direct'")
	if id, rc := KeyringRotate(dir); rc != CodeOK || id == 0 {
		t.Fatalf("rotate = %d id %d", rc, id)
	}
	if rc := Close(db); rc != CodeOK {
		t.Fatalf("close: %d", rc)
	}
	jsNat, rc := KeyInventory(dir)
	if rc != CodeOK {
		t.Fatalf("native inventory: %d", rc)
	}
	var k [32]byte
	copy(k[:], murmurKey())
	eng, err := storage.OpenDir(dir, k, false)
	if err != nil {
		t.Fatalf("openDir: %v", err)
	}
	jsGo := eng.InventoryJSON()
	eng.Close()
	if jsNat != jsGo {
		t.Fatalf("inventory mismatch:\nnat: %s\ngo:  %s", jsNat, jsGo)
	}
}
