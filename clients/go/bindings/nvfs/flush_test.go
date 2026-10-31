package nvfs_test

import (
	"bytes"
	"math/rand"
	"sync"
	"testing"

	"github.com/marcgauthier/sqlite-murmur-go/clients/go/bindings/nvapi"
	"github.com/marcgauthier/sqlite-murmur-go/clients/go/bindings/nvfs"
)

func testCodecParams() nvapi.CodecParams {
	key := testKey()
	return nvapi.CodecParams{Cipher: 1, Level: 3, PageKey: key, Master: key}
}

// Eviction pressure: a 4-page cache over 64 dirty pages must seal
// evicted victims and flush the rest; everything survives reopen.
func TestFlushEvictionPressure(t *testing.T) {
	dir := t.TempDir()
	s, err := nvfs.Open(dir, true)
	if err != nil {
		t.Fatal(err)
	}
	db, err := nvfs.CreateDB(s, testCodecParams(), 4, 0)
	if err != nil {
		t.Fatal(err)
	}
	rng := rand.New(rand.NewSource(0xF145))
	want := make([]byte, 64*nvfs.Block)
	rng.Read(want)
	if _, err := db.NWriteAt(want, 0); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(want))
	if _, _, err := db.NReadAt(got, 0); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("pre-flush read mismatch")
	}
	if err := db.NFlush(); err != nil {
		t.Fatal(err)
	}
	pages, _, _, _ := db.NSealStats()
	if pages == 0 {
		t.Fatal("no seals recorded")
	}
	db.Close()

	s2, err := nvfs.Open(dir, false)
	if err != nil {
		t.Fatal(err)
	}
	db2, err := nvfs.CreateDB(s2, testCodecParams(), 4, uint64(len(want)))
	if err != nil {
		t.Fatal(err)
	}
	back := make([]byte, len(want))
	if _, _, err := db2.NReadAt(back, 0); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(back, want) {
		t.Fatal("post-reopen mismatch")
	}
	db2.Close()
}

// Flush marks entries clean: evicting flushed pages seals nothing.
// Without generation-tracked cleaning, each eviction below would
// re-seal an already-persisted page (12 seals instead of 8).
func TestFlushMarksClean(t *testing.T) {
	dir := t.TempDir()
	s, err := nvfs.Open(dir, true)
	if err != nil {
		t.Fatal(err)
	}
	db, err := nvfs.CreateDB(s, testCodecParams(), 4, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.NWriteAt(bytes.Repeat([]byte{0x11}, 4*nvfs.Block), 0); err != nil {
		t.Fatal(err)
	}
	if err := db.NFlush(); err != nil {
		t.Fatal(err)
	}
	pages, _, _, _ := db.NSealStats()
	if pages != 4 {
		t.Fatalf("seals after flush = %d, want 4", pages)
	}
	// Displace the flushed pages; clean victims seal nothing.
	if _, err := db.NWriteAt(bytes.Repeat([]byte{0x22}, 4*nvfs.Block), 4*nvfs.Block); err != nil {
		t.Fatal(err)
	}
	pages, _, _, _ = db.NSealStats()
	if pages != 4 {
		t.Fatalf("seals after clean evictions = %d, want 4", pages)
	}
	if err := db.NFlush(); err != nil {
		t.Fatal(err)
	}
	pages, _, _, _ = db.NSealStats()
	if pages != 8 {
		t.Fatalf("seals after second flush = %d, want 8", pages)
	}
	// All eight pages round-trip.
	back := make([]byte, 8*nvfs.Block)
	if _, _, err := db.NReadAt(back, 0); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(back[:4*nvfs.Block], bytes.Repeat([]byte{0x11}, 4*nvfs.Block)) {
		t.Fatal("first span mismatch")
	}
	if !bytes.Equal(back[4*nvfs.Block:], bytes.Repeat([]byte{0x22}, 4*nvfs.Block)) {
		t.Fatal("second span mismatch")
	}
	db.Close()
}

// Truncate (including a partial tail) then flush, close, reopen.
func TestFlushTruncate(t *testing.T) {
	dir := t.TempDir()
	s, err := nvfs.Open(dir, true)
	if err != nil {
		t.Fatal(err)
	}
	db, err := nvfs.CreateDB(s, testCodecParams(), 16, 0)
	if err != nil {
		t.Fatal(err)
	}
	data := bytes.Repeat([]byte{0xAB}, 16*nvfs.Block)
	if _, err := db.NWriteAt(data, 0); err != nil {
		t.Fatal(err)
	}
	cut := int64(3*nvfs.Block + 100)
	if err := db.NTruncate(cut); err != nil {
		t.Fatal(err)
	}
	if err := db.NFlush(); err != nil {
		t.Fatal(err)
	}
	if got := db.NSize(); got != cut {
		t.Fatalf("size = %d, want %d", got, cut)
	}
	db.Close()

	s2, err := nvfs.Open(dir, false)
	if err != nil {
		t.Fatal(err)
	}
	// Size stages through the flush; reopen seeds from meta.
	db2, err := nvfs.CreateDB(s2, testCodecParams(), 16, uint64(cut))
	if err != nil {
		t.Fatal(err)
	}
	back := make([]byte, cut)
	if _, _, err := db2.NReadAt(back, 0); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(back[:3*nvfs.Block], data[:3*nvfs.Block]) {
		t.Fatal("surviving prefix mismatch")
	}
	if !bytes.Equal(back[3*nvfs.Block:cut], bytes.Repeat([]byte{0xAB}, 100)) {
		t.Fatal("partial tail mismatch")
	}
	db2.Close()
}

// Concurrent flush convergence: writers hammer disjoint ranges
// while a flusher loops (the flush writes its batch unlocked, so
// pages re-dirtied mid-write must stay dirty via the seq
// re-validation). Final flush + reopen must equal the model
// exactly: no lost writes, no stale records surviving.
func TestFlushConcurrentConverges(t *testing.T) {
	dir := t.TempDir()
	s, err := nvfs.Open(dir, true)
	if err != nil {
		t.Fatal(err)
	}
	const writers = 4
	const pagesPer = 8
	const rounds = 20
	total := int64(writers * pagesPer * nvfs.Block)
	db, err := nvfs.CreateDB(s, testCodecParams(), 16, 0)
	if err != nil {
		t.Fatal(err)
	}
	model := make([]byte, total)
	var modelMu sync.Mutex
	stopFlush := make(chan struct{})
	var flushWg sync.WaitGroup
	flushWg.Add(1)
	go func() {
		defer flushWg.Done()
		for {
			select {
			case <-stopFlush:
				return
			default:
				if err := db.NFlush(); err != nil {
					t.Error(err)
					return
				}
			}
		}
	}()
	var wg sync.WaitGroup
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			rng := rand.New(rand.NewSource(int64(0xF100 + w)))
			base := int64(w * pagesPer * nvfs.Block)
			buf := make([]byte, pagesPer*nvfs.Block)
			for r := 0; r < rounds; r++ {
				rng.Read(buf)
				if _, err := db.NWriteAt(buf, base); err != nil {
					t.Error(err)
					return
				}
				modelMu.Lock()
				copy(model[base:], buf)
				modelMu.Unlock()
			}
		}(w)
	}
	wg.Wait()
	close(stopFlush)
	flushWg.Wait()
	if err := db.NFlush(); err != nil {
		t.Fatal(err)
	}
	if got := db.NSize(); got != total {
		t.Fatalf("size = %d, want %d", got, total)
	}
	db.Close()

	s2, err := nvfs.Open(dir, false)
	if err != nil {
		t.Fatal(err)
	}
	db2, err := nvfs.CreateDB(s2, testCodecParams(), 16, uint64(total))
	if err != nil {
		t.Fatal(err)
	}
	back := make([]byte, total)
	if _, _, err := db2.NReadAt(back, 0); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(back, model) {
		t.Fatal("post-reopen bytes differ from final model")
	}
	db2.Close()
}
