package nvfs_test

import (
	"bytes"
	"math/rand"
	"testing"

	"github.com/marcgauthier/sqlite-murmur-go/clients/go/bindings/nvfs"
)

// Header-shadow equivalence: every byte in [0,100) served by the
// fast path must match the logical model across writes, sparse
// gaps, truncates, flushes, and reopen (lazy seed).
func TestHeaderShadowEquivalence(t *testing.T) {
	dir := t.TempDir()
	s, err := nvfs.Open(dir, true)
	if err != nil {
		t.Fatal(err)
	}
	db, err := nvfs.CreateDB(s, testCodecParams(), 4, 0)
	if err != nil {
		t.Fatal(err)
	}

	model := map[int64]byte{}
	var size int64
	rng := rand.New(rand.NewSource(0xBEA0))

	check := func() {
		t.Helper()
		if got := db.NSize(); got != size {
			t.Fatalf("size: got %d want %d", got, size)
		}
		fast := make([]byte, 100)
		if _, _, err := db.NReadAt(fast, 0); err != nil {
			t.Fatalf("fast header read: %v", err)
		}
		// Slow path: one straddling read forces the page-fetch
		// path; its [0,100) prefix must agree with the fast path
		// and the model.
		slow := make([]byte, 200)
		if _, _, err := db.NReadAt(slow, 0); err != nil {
			t.Fatalf("slow header read: %v", err)
		}
		for i := 0; i < 100; i++ {
			want := byte(0)
			if int64(i) < size {
				want = model[int64(i)]
			}
			if fast[i] != want {
				t.Fatalf("fast byte %d: got %02x want %02x (size %d)", i, fast[i], want, size)
			}
			if slow[i] != want {
				t.Fatalf("slow byte %d: got %02x want %02x (size %d)", i, slow[i], want, size)
			}
		}
		// The hot change-counter read shape.
		cc := make([]byte, 16)
		if _, _, err := db.NReadAt(cc, 24); err != nil {
			t.Fatalf("counter read: %v", err)
		}
		if !bytes.Equal(cc, fast[24:40]) {
			t.Fatalf("counter mismatch: %x vs %x", cc, fast[24:40])
		}
	}

	for step := 0; step < 120; step++ {
		switch step % 7 {
		case 0, 1, 2:
			// Writes: page-0 partials, full pages, sparse jumps.
			off := int64(rng.Intn(9000))
			if rng.Intn(2) == 0 {
				off = int64(rng.Intn(100))
			}
			ln := 1 + rng.Intn(300)
			buf := make([]byte, ln)
			rng.Read(buf)
			if _, err := db.NWriteAt(buf, off); err != nil {
				t.Fatal(err)
			}
			for i, b := range buf {
				model[off+int64(i)] = b
			}
			if end := off + int64(ln); end > size {
				size = end
			}
		case 3:
			// Truncate: shrink/grow, block-aligned or not.
			target := int64(rng.Intn(9000))
			if err := db.NTruncate(target); err != nil {
				t.Fatal(err)
			}
			if target < size {
				for k := range model {
					if k >= target {
						delete(model, k)
					}
				}
			}
			size = target
		case 4:
			if err := db.NFlush(); err != nil {
				t.Fatal(err)
			}
		case 5:
			// Reopen: fresh store + NvDb over the same dir;
			// the shadow must re-seed from sealed page 0.
			if err := db.NFlush(); err != nil {
				t.Fatal(err)
			}
			db.Close() // also closes the store
			s, err = nvfs.Open(dir, false)
			if err != nil {
				t.Fatal(err)
			}
			db, err = nvfs.CreateDB(s, testCodecParams(), 4, uint64(size))
			if err != nil {
				t.Fatal(err)
			}
		case 6:
			// Full page-1 rewrite, the commit shape.
			blk := make([]byte, nvfs.Block)
			rng.Read(blk)
			if _, err := db.NWriteAt(blk, 0); err != nil {
				t.Fatal(err)
			}
			for i, b := range blk {
				model[int64(i)] = b
			}
			if size < nvfs.Block {
				size = nvfs.Block
			}
		}
		check()
	}
	db.Close()
}
