package nvfs_test

import (
	"bytes"
	"crypto/rand"
	"path/filepath"
	"testing"

	"github.com/marcgauthier/libmurmur/clients/go/bindings/nvfs"
	"github.com/marcgauthier/libmurmur/clients/go/pkgs/storage"
)

func testKey() [32]byte {
	var k [32]byte
	for i := range k {
		k[i] = byte(0xA0 + i)
	}
	return k
}

func TestPageKeyMatchesGo(t *testing.T) {
	for _, page := range []uint64{0, 1, 42, 1 << 32, 1<<64 - 1} {
		want := storage.PageKey(page)
		got := nvfs.PageKey(page)
		if got != want {
			t.Fatalf("page %d: C++ key %x != Go key %x", page, got, want)
		}
	}
}

func TestNativeStoreRoundTrip(t *testing.T) {
	dir := t.TempDir()
	s, err := nvfs.Open(dir, true)
	if err != nil {
		t.Fatal(err)
	}
	pk := nvfs.PageKey(7)
	val := make([]byte, nvfs.MaxRecord)
	if _, found, err := s.Get(pk[:], val); err != nil || found {
		t.Fatalf("missing key: found=%v err=%v", found, err)
	}
	rec := bytes.Repeat([]byte{0x3C}, 100)
	if err := s.Put(pk[:], rec, false); err != nil {
		t.Fatal(err)
	}
	if err := s.Put([]byte("meta:cipher"), []byte("aes256gcm"), true); err != nil {
		t.Fatal(err)
	}
	if adv, err := s.Sync(); err != nil || !adv {
		t.Fatalf("sync: advanced=%v err=%v", adv, err)
	}
	if adv, err := s.Sync(); err != nil || adv {
		t.Fatalf("clean sync: advanced=%v err=%v", adv, err)
	}
	s.Close()

	s2, err := nvfs.Open(dir, false)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	n, found, err := s2.Get(pk[:], val)
	if err != nil || !found {
		t.Fatalf("reopen get: found=%v err=%v", found, err)
	}
	if !bytes.Equal(val[:n], rec) {
		t.Fatal("record mismatch after reopen")
	}
	mk := []byte("meta:cipher")
	n, found, err = s2.Get(mk, val)
	if err != nil || !found || string(val[:n]) != "aes256gcm" {
		t.Fatalf("meta get: found=%v err=%v val=%q", found, err, val[:n])
	}
	if err := s2.DeletePagesFrom(7); err != nil {
		t.Fatal(err)
	}
	if _, found, err := s2.Get(pk[:], val); err != nil || found {
		t.Fatalf("after range delete: found=%v err=%v", found, err)
	}
	// Meta keys survive the page-range delete ('q' bound).
	if _, found, err := s2.Get(mk, val); err != nil || !found {
		t.Fatalf("meta after range delete: found=%v err=%v", found, err)
	}
}

func TestCodecSealRoundTrip(t *testing.T) {
	for _, cipher := range []storage.Cipher{storage.CipherAES256GCM, storage.CipherAEGIS256} {
		key := testKey()
		h := nvfs.CodecCreate(int(cipher), 3, key[:], false, nil, 0, nil, nil, key[:])
		if h == nil {
			t.Fatalf("cipher %v: create failed", cipher)
		}
		// Compressible block exercises the zstd path.
		zeros := make([]byte, nvfs.Block)
		for i := range zeros {
			zeros[i] = byte(i >> 4)
		}
		// Random block exercises the raw path (incompressible).
		high := make([]byte, nvfs.Block)
		if _, err := rand.Read(high); err != nil {
			t.Fatal(err)
		}
		for pi, pt := range [][]byte{zeros, high} {
			rec, rc := nvfs.CodecSeal(h, uint64(100+pi), pt)
			if rc != 0 {
				t.Fatalf("cipher %v page %d seal rc=%d", cipher, pi, rc)
			}
			if len(rec) >= nvfs.MaxRecord {
				t.Fatalf("cipher %v page %d: record too large: %d", cipher, pi, len(rec))
			}
			back, rc := nvfs.CodecOpen(h, uint64(100+pi), rec)
			if rc != 0 {
				t.Fatalf("cipher %v page %d open rc=%d", cipher, pi, rc)
			}
			if !bytes.Equal(back, pt) {
				t.Fatalf("cipher %v page %d: round-trip mismatch", cipher, pi)
			}
			// Wrong page in AAD fails closed.
			if _, rc := nvfs.CodecOpen(h, uint64(999), rec); rc == 0 {
				t.Fatalf("cipher %v page %d: wrong-page open accepted", cipher, pi)
			}
			// Bit flip fails closed.
			bad := append([]byte(nil), rec...)
			bad[len(bad)/2] ^= 0x80
			if _, rc := nvfs.CodecOpen(h, uint64(100+pi), bad); rc == 0 {
				t.Fatalf("cipher %v page %d: tampered open accepted", cipher, pi)
			}
		}
		nvfs.CodecDestroy(h)
	}
}

func TestCodecNilHandle(t *testing.T) {
	block := make([]byte, nvfs.Block)
	if _, rc := nvfs.CodecSeal(nil, 0, block); rc == 0 {
		t.Fatal("nil-handle seal accepted")
	}
	if _, rc := nvfs.CodecOpen(nil, 0, []byte("x")); rc == 0 {
		t.Fatal("nil-handle open accepted")
	}
}

// TestNativeMatchesGoFormat proves byte-level interop: records sealed
// through the native crypto boundary open in the Go engine, and
// records the engine persists open through the boundary.
func TestNativeMatchesGoFormat(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "db")
	key := testKey()

	goEng, err := storage.OpenDir(dir, key, true)
	if err != nil {
		t.Fatal(err)
	}
	pt0 := bytes.Repeat([]byte{0x11}, nvfs.Block)
	pt1 := bytes.Repeat([]byte{0x22}, nvfs.Block)
	if err := goEng.WriteAt(pt0, 0); err != nil {
		t.Fatal(err)
	}
	if err := goEng.WriteAt(pt1, nvfs.Block); err != nil {
		t.Fatal(err)
	}
	if err := goEng.Sync(); err != nil {
		t.Fatal(err)
	}
	if err := goEng.Close(); err != nil {
		t.Fatal(err)
	}

	// Native side reads the engine-sealed records and opens page 0.
	s, err := nvfs.Open(dir, false)
	if err != nil {
		t.Fatal(err)
	}
	pk0 := nvfs.PageKey(0)
	val := make([]byte, nvfs.MaxRecord)
	n, found, err := s.Get(pk0[:], val)
	if err != nil || !found {
		t.Fatalf("native get page 0: found=%v err=%v", found, err)
	}
	goRec := append([]byte(nil), val[:n]...)

	e := storage.OpenMem(key)
	h := nvfs.CodecCreate(1, 3, key[:], false, nil, 0, nil, nil, key[:])
	if h == nil {
		t.Fatal("codec create failed")
	}
	defer nvfs.CodecDestroy(h)
	back, rc := nvfs.CodecOpen(h, 0, goRec)
	if rc != 0 {
		t.Fatalf("open engine-sealed record rc=%d", rc)
	}
	if !bytes.Equal(back, pt0) {
		t.Fatal("engine-sealed record mismatch through native boundary")
	}

	// Native side seals page 2 and stages it; the engine reads it.
	pt2 := bytes.Repeat([]byte{0x33}, nvfs.Block)
	rec2, rc := nvfs.CodecSeal(h, 2, pt2)
	if rc != 0 {
		t.Fatalf("seal rc=%d", rc)
	}
	pk2 := nvfs.PageKey(2)
	if err := s.Put(pk2[:], rec2, false); err != nil {
		t.Fatal(err)
	}
	// The engine sizes by meta:size; stage 3 pages.
	if err := s.Put([]byte("meta:size"), []byte("12288"), false); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Sync(); err != nil {
		t.Fatal(err)
	}
	s.Close()
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}

	goEng2, err := storage.OpenDir(dir, key, false)
	if err != nil {
		t.Fatal(err)
	}
	defer goEng2.Close()
	got := make([]byte, nvfs.Block)
	if n, err := goEng2.ReadAt(got, 2*nvfs.Block); err != nil || n != nvfs.Block {
		t.Fatalf("engine read native-sealed page: n=%d err=%v", n, err)
	}
	if !bytes.Equal(got, pt2) {
		t.Fatal("native-sealed record mismatch in engine")
	}
}
