package storage

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEngineMemRoundTrip(t *testing.T) {
	e := OpenMem(testKey())
	defer e.Close()
	msg := bytes.Repeat([]byte("murmur-go engine test pattern "), 200) // > 1 block
	if err := e.WriteAt(msg, 100); err != nil {
		t.Fatalf("WriteAt: %v", err)
	}
	if got := e.Size(); got != int64(100+len(msg)) {
		t.Fatalf("Size = %d, want %d", got, 100+len(msg))
	}
	back := make([]byte, len(msg))
	n, err := e.ReadAt(back, 100)
	if err != nil || n != len(msg) {
		t.Fatalf("ReadAt = %d, %v", n, err)
	}
	if !bytes.Equal(back, msg) {
		t.Fatalf("round-trip mismatch")
	}
	// Sparse head reads as zeros with a full-length read.
	head := make([]byte, 100)
	if n, err := e.ReadAt(head, 0); err != nil || n != 100 {
		t.Fatalf("head ReadAt = %d, %v", n, err)
	}
	if !bytes.Equal(head, make([]byte, 100)) {
		t.Fatalf("sparse head is not zero")
	}
	// Short read past the end.
	tail := make([]byte, 16)
	n, err = e.ReadAt(tail, e.Size()-4)
	if err != nil || n != 4 {
		t.Fatalf("tail ReadAt = %d, %v; want 4, nil", n, err)
	}
	st := e.SnapshotStats()
	if st.PagesWritten == 0 || st.PagesRead == 0 {
		t.Fatalf("stats not tracked: %+v", st)
	}
}

func TestEngineFileCiphertext(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "enc.db")
	key := testKey()
	e, err := OpenFile(path, key, true)
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	secret := bytes.Repeat([]byte("TOP-SECRET-ROW-DATA-"), 300)
	if err := e.WriteAt(secret, 0); err != nil {
		t.Fatalf("WriteAt: %v", err)
	}
	if err := e.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read raw: %v", err)
	}
	if string(raw[:4]) != "MMG1" {
		t.Fatalf("header magic = %q", raw[:4])
	}
	if bytes.Contains(raw, []byte("TOP-SECRET")) {
		t.Fatalf("plaintext visible in database file")
	}
	// Reopen with the right key.
	e2, err := OpenFile(path, key, false)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	back := make([]byte, len(secret))
	if n, err := e2.ReadAt(back, 0); err != nil || n != len(secret) || !bytes.Equal(back, secret) {
		t.Fatalf("reopen read = %d, %v, equal=%v", n, err, bytes.Equal(back, secret))
	}
	if err := e2.Close(); err != nil {
		t.Fatalf("close e2: %v", err)
	}
	// Reopen with the wrong key: header parses, page reads fail closed.
	var wrong [32]byte
	e3, err := OpenFile(path, wrong, false)
	if err != nil {
		t.Fatalf("wrong-key open: %v", err)
	}
	defer e3.Close()
	if _, err := e3.ReadAt(back, 0); err == nil {
		t.Fatalf("wrong-key read unexpectedly succeeded")
	}
}

func TestEngineCipherSwitch(t *testing.T) {
	e := OpenMem(testKey())
	defer e.Close()
	if got := e.CipherName(); got != "aes256gcm" {
		t.Fatalf("default cipher = %q", got)
	}
	if rc := e.SetCipher(CipherAEGIS256, false, false); rc != CodeOK {
		t.Fatalf("switch on empty db = %d", rc)
	}
	if got := e.CipherName(); got != "aegis256" {
		t.Fatalf("cipher = %q", got)
	}
	payload := bytes.Repeat([]byte("aegis page payload "), 256)
	if err := e.WriteAt(payload, 0); err != nil {
		t.Fatalf("WriteAt: %v", err)
	}
	back := make([]byte, len(payload))
	if n, err := e.ReadAt(back, 0); err != nil || n != len(payload) || !bytes.Equal(back, payload) {
		t.Fatalf("aegis round-trip = %d, %v", n, err)
	}
	// Non-empty database refuses the switch.
	if rc := e.SetCipher(CipherAES256GCM, false, false); rc != CodeBusy {
		t.Fatalf("switch on data = %d, want BUSY", rc)
	}
	// Locks refuse the switch even when empty.
	e2 := OpenMem(testKey())
	defer e2.Close()
	if rc := e2.SetCipher(CipherAEGIS256, false, true); rc != CodeBusy {
		t.Fatalf("switch under lock = %d, want BUSY", rc)
	}
	if rc := e2.SetCipher(CipherAES256GCM, false, true); rc != CodeOK {
		t.Fatalf("no-op switch under lock = %d, want OK", rc)
	}
}

func TestEngineTruncate(t *testing.T) {
	e := OpenMem(testKey())
	defer e.Close()
	data := bytes.Repeat([]byte("truncate me "), 1000) // ~12KB, 3 blocks
	if err := e.WriteAt(data, 0); err != nil {
		t.Fatalf("WriteAt: %v", err)
	}
	// Shrink to a non-block boundary: tail zeroes, head intact.
	if err := e.Truncate(5000); err != nil {
		t.Fatalf("Truncate: %v", err)
	}
	if got := e.Size(); got != 5000 {
		t.Fatalf("Size = %d", got)
	}
	back := make([]byte, 5000)
	if n, err := e.ReadAt(back, 0); err != nil || n != 5000 {
		t.Fatalf("read = %d, %v", n, err)
	}
	if !bytes.Equal(back[:4096], data[:4096]) {
		t.Fatalf("first block changed by truncate")
	}
	if !bytes.Equal(back[4096:], data[4096:5000]) {
		t.Fatalf("partial tail mismatch")
	}
	// The rest of block 1 must read as zeros now (via regrow).
	if err := e.Truncate(8192); err != nil {
		t.Fatalf("regrow: %v", err)
	}
	gap := make([]byte, 8192-5000)
	if n, err := e.ReadAt(gap, 5000); err != nil || n != len(gap) {
		t.Fatalf("gap read = %d, %v", n, err)
	}
	if !bytes.Equal(gap, make([]byte, len(gap))) {
		t.Fatalf("truncated tail not zeroed")
	}
	// Shrink to zero drops everything.
	if err := e.Truncate(0); err != nil {
		t.Fatalf("truncate 0: %v", err)
	}
	if got := e.Size(); got != 0 {
		t.Fatalf("Size = %d", got)
	}
	if n, err := e.ReadAt(make([]byte, 8), 0); n != 0 || err != nil {
		t.Fatalf("empty read = %d, %v", n, err)
	}
}

func TestEngineKeyringSealRotatePrune(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sealed.db")
	key := testKey()
	e, err := OpenFile(path, key, true)
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	// Pages written before the seal use legacy (unkeyed) records.
	legacy := bytes.Repeat([]byte("legacy plaintext block "), 200)
	if err := e.WriteAt(legacy, 0); err != nil {
		t.Fatalf("WriteAt: %v", err)
	}
	if e.Sealed() {
		t.Fatalf("fresh engine reports sealed")
	}
	if inv := e.InventoryJSON(); inv != `{"sealed":false}` {
		t.Fatalf("unsealed inventory = %s", inv)
	}
	// Stage KDF params, then seal.
	if rc := e.SetParam(KeyringParamTime, 2, false); rc != CodeOK {
		t.Fatalf("stage time = %d", rc)
	}
	if rc := e.SetParam(KeyringParamTime, 99, false); rc != CodeError {
		t.Fatalf("bad time = %d, want ERROR", rc)
	}
	if rc := e.SetParam(KeyringParamKDF, KDFDirectHKDF, false); rc != CodeOK {
		t.Fatalf("seal = %d", rc)
	}
	if !e.Sealed() {
		t.Fatalf("engine not sealed after seal")
	}
	if rc := e.SetParam(KeyringParamKDF, KDFDirectHKDF, false); rc != CodeBusy {
		t.Fatalf("second seal = %d, want BUSY", rc)
	}
	inv := e.InventoryJSON()
	for _, want := range []string{`"sealed":true`, `"current":1`, `"kdf":"direct"`} {
		if !strings.Contains(inv, want) {
			t.Fatalf("inventory %s missing %s", inv, want)
		}
	}
	// Legacy page still readable after the seal (trial chain).
	back := make([]byte, len(legacy))
	if n, err := e.ReadAt(back, 0); err != nil || n != len(legacy) || !bytes.Equal(back, legacy) {
		t.Fatalf("legacy read after seal = %d, %v", n, err)
	}
	// New pages use keyed records under the current id.
	sealed := bytes.Repeat([]byte("sealed page content "), 220)
	if err := e.WriteAt(sealed, 8192); err != nil {
		t.Fatalf("WriteAt sealed: %v", err)
	}
	if rc, id := e.Rotate(false); rc != CodeOK || id != 2 {
		t.Fatalf("rotate = %d, id %d", rc, id)
	}
	// Rewrite every page so nothing references key 1, then prune.
	rewrite := bytes.Repeat([]byte("post-rotate rewrite "), 230)
	if err := e.WriteAt(rewrite, 0); err != nil {
		t.Fatalf("rewrite 0: %v", err)
	}
	if err := e.WriteAt(rewrite, 4096); err != nil {
		t.Fatalf("rewrite 1: %v", err)
	}
	if err := e.WriteAt(rewrite, 8192); err != nil {
		t.Fatalf("rewrite 2: %v", err)
	}
	rc, report := e.Prune(false)
	if rc != CodeOK {
		t.Fatalf("prune = %d", rc)
	}
	if !strings.Contains(report, `"pruned":[1]`) {
		t.Fatalf("prune report = %s, want key 1 pruned", report)
	}
	if err := e.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	// Reopen sealed: envelope sidecar loads, data intact.
	e2, err := OpenFile(path, key, false)
	if err != nil {
		t.Fatalf("reopen sealed: %v", err)
	}
	if !e2.Sealed() {
		t.Fatalf("reopened engine not sealed")
	}
	back2 := make([]byte, len(rewrite))
	if n, err := e2.ReadAt(back2, 8192); err != nil || n != len(rewrite) || !bytes.Equal(back2, rewrite) {
		t.Fatalf("sealed reopen read = %d, %v", n, err)
	}
	if err := e2.Close(); err != nil {
		t.Fatalf("close e2: %v", err)
	}
	// Wrong master fails the envelope open.
	var wrong [32]byte
	if _, err := OpenFile(path, wrong, false); err == nil {
		t.Fatalf("wrong-master reopen unexpectedly succeeded")
	}
}

// TestLiveShellSealRotatePrune mirrors the file-engine
// seal/rotate/prune flow on a live registry shell, exercising the
// native nvStoreRotate/nvStorePrune through Engine.Rotate/Prune.
func TestLiveShellSealRotatePrune(t *testing.T) {
	dir := t.TempDir()
	key := testKey()
	e, err := OpenDir(dir, key, true)
	if err != nil {
		t.Fatalf("OpenDir: %v", err)
	}
	defer e.Close()
	legacy := bytes.Repeat([]byte("live legacy block "), 200)
	if err := e.WriteAt(legacy, 0); err != nil {
		t.Fatalf("WriteAt: %v", err)
	}
	if rc := e.SetParam(KeyringParamKDF, KDFDirectHKDF, false); rc != CodeOK {
		t.Fatalf("seal = %d", rc)
	}
	if rc, id := e.Rotate(false); rc != CodeOK || id != 2 {
		t.Fatalf("rotate = %d, id %d", rc, id)
	}
	// Rewrite every page so nothing references key 1, then prune.
	rewrite := bytes.Repeat([]byte("live post-rotate rewrite "), 200)
	if err := e.WriteAt(rewrite, 0); err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	rc, report := e.Prune(false)
	if rc != CodeOK {
		t.Fatalf("prune = %d", rc)
	}
	if !strings.Contains(report, `"pruned":[1]`) {
		t.Fatalf("prune report = %s, want key 1 pruned", report)
	}
	// The shell's cached ring re-synced: inventory shows the
	// rotation and current data still reads.
	if inv := e.InventoryJSON(); !strings.Contains(inv, `"current":2`) {
		t.Fatalf("inventory after rotate = %s", inv)
	}
	back := make([]byte, len(rewrite))
	if n, err := e.ReadAt(back, 0); err != nil || n != len(rewrite) || !bytes.Equal(back, rewrite) {
		t.Fatalf("read after prune = %d, %v", n, err)
	}
}

// TestLiveShellInventoryUnsealed pins the native live inventory on
// an unsealed store: exactly {"sealed":false}.
func TestLiveShellInventoryUnsealed(t *testing.T) {
	e, err := OpenDir(t.TempDir(), testKey(), true)
	if err != nil {
		t.Fatalf("OpenDir: %v", err)
	}
	defer e.Close()
	if inv := e.InventoryJSON(); inv != `{"sealed":false}` {
		t.Fatalf("inventory = %s", inv)
	}
}

// TestLiveShellInventoryExternalSeal pins cross-shell visibility:
// a shell opened unsealed observes a seal made through a second
// shell, with no ring reload on its side. The native inventory
// opens the envelope under the staged master; the Go cached ring
// would still report unsealed.
func TestLiveShellInventoryExternalSeal(t *testing.T) {
	dir := t.TempDir()
	key := testKey()
	e1, err := OpenDir(dir, key, true)
	if err != nil {
		t.Fatalf("OpenDir e1: %v", err)
	}
	defer e1.Close()
	if inv := e1.InventoryJSON(); inv != `{"sealed":false}` {
		t.Fatalf("e1 pre-seal = %s", inv)
	}
	e2, err := OpenDir(dir, key, false)
	if err != nil {
		t.Fatalf("OpenDir e2: %v", err)
	}
	defer e2.Close()
	if rc := e2.SetParam(KeyringParamKDF, KDFDirectHKDF, false); rc != CodeOK {
		t.Fatalf("seal via e2 = %d", rc)
	}
	inv := e1.InventoryJSON()
	for _, want := range []string{`"sealed":true`, `"current":1`, `"kdf":"direct"`} {
		if !strings.Contains(inv, want) {
			t.Fatalf("e1 post-seal %s missing %s", inv, want)
		}
	}
}

func TestEnginePragmaTable(t *testing.T) {
	e := OpenMem(testKey())
	defer e.Close()
	str := func(s string) *string { return &s }
	cases := []struct {
		name       string
		value      *string
		readOnly   bool
		locked     bool
		wantCode   int
		wantSubstr string
	}{
		{"cipher", nil, false, false, CodeOK, "aes256gcm"},
		{"cipher", str("aegis256"), false, false, CodeOK, "aegis256"},
		{"cipher", str("bogus"), false, false, CodeError, "must be"},
		{"cipher", str("aes256gcm"), true, false, CodeReadOnly, "read-only"},
		{"compression", nil, false, false, CodeOK, "zstd3"},
		{"compression", str("none"), false, false, CodeOK, "none"},
		{"compression", str("zstd6"), false, false, CodeOK, "zstd6"},
		{"compression", str("zstd99"), false, false, CodeError, "zstd1"},
		{"compression", str("none"), true, false, CodeReadOnly, "read-only"},
		{"flush_interval_ms", nil, false, false, CodeOK, "250"},
		{"flush_interval_ms", str("0"), false, false, CodeOK, "250"},
		{"flush_interval_ms", str("100"), false, false, CodeOK, "100"},
		{"flush_interval_ms", str("abc"), false, false, CodeError, "unsigned"},
		{"background_threads", nil, false, false, CodeOK, ""},
		{"background_threads", str("4"), false, false, CodeOK, "4"},
		{"background_threads", str("0"), false, false, CodeError, "1 through 256"},
		{"background_threads", str("4"), true, false, CodeReadOnly, ""},
		{"journal_mode", nil, false, false, CodeNotFound, ""},
		{"journal_mode", str("delete"), false, false, CodeNotFound, ""},
		{"journal_mode", str("wal"), false, false, CodeError, "DELETE"},
		{"mmap_size", str("999"), false, false, CodeOK, "0"},
		{"murmur_kdf", nil, false, false, CodeOK, "direct"},
		{"murmur_kdf_time", nil, false, false, CodeOK, "3"},
		{"murmur_kdf_time", str("2"), false, false, CodeOK, "2"},
		{"murmur_kdf_time", str("99"), false, false, CodeError, "range"},
		{"murmur_nope", nil, false, false, CodeError, "replication"},
		{"rocksdb_sync", nil, false, false, CodeNotFound, ""},
		{"unknown_pragma_xyz", nil, false, false, CodeNotFound, ""},
	}
	for _, tc := range cases {
		code, out := e.Pragma(tc.name, tc.value, tc.readOnly, tc.locked)
		if code != tc.wantCode || (tc.wantSubstr != "" && !strings.Contains(out, tc.wantSubstr)) {
			t.Errorf("PRAGMA %s=%v ro=%v -> (%d,%q), want (%d, sub %q)",
				tc.name, deref(tc.value), tc.readOnly, code, out, tc.wantCode, tc.wantSubstr)
		}
	}
}

func deref(s *string) string {
	if s == nil {
		return "<read>"
	}
	return *s
}

func TestEngineHeaderLayout(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hdr.db")
	e, err := OpenFile(path, testKey(), true)
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	payload := []byte("header layout probe")
	if err := e.WriteAt(payload, 0); err != nil {
		t.Fatalf("WriteAt: %v", err)
	}
	if err := e.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read raw: %v", err)
	}
	if len(raw) != headerSize+SlotSize {
		t.Fatalf("file size = %d, want %d", len(raw), headerSize+SlotSize)
	}
	if binary.LittleEndian.Uint64(raw[offSize:]) != uint64(len(payload)) {
		t.Fatalf("header size field wrong")
	}
	slotLen := binary.LittleEndian.Uint32(raw[headerSize:])
	if slotLen == 0 || slotLen > SlotSize-4 {
		t.Fatalf("slot length = %d", slotLen)
	}
	magic := string(raw[headerSize+4 : headerSize+8])
	if magic != "EXP1" && magic != "EXP3" {
		t.Fatalf("record magic = %q", magic)
	}
}
