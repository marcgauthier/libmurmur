package storage

import (
	"bytes"
	"errors"
	"math/rand"
	"testing"

	"github.com/marcgauthier/libmurmur/clients/go/bindings/nvfs"
	"github.com/marcgauthier/libmurmur/clients/go/bindings/zstd"
)

// Differential proof: the C++ page codec must agree with the Go record
// layer bit-for-bit on success (plaintext, record length) and
// class-for-class on every failure (auth vs corrupt). Deterministic.
func goClass(err error) int {
	if err == nil {
		return 0
	}
	if errors.Is(err, ErrAuth) {
		return -2
	}
	return -3
}

func TestCodecRecordDifferential(t *testing.T) {
	rng := rand.New(rand.NewSource(0xC0DEC))
	pages := []uint64{0, 1, 7, 1 << 32, ^uint64(0)}
	payloads := map[string]func() []byte{
		"zeros": func() []byte { return make([]byte, Block) },
		"text": func() []byte {
			b := make([]byte, Block)
			for i := range b {
				b[i] = "abcdefghijklmnopqrstuvwxyz0123456789"[i%36]
			}
			return b
		},
		"random": func() []byte {
			b := make([]byte, Block)
			rng.Read(b)
			return b
		},
	}
	for _, cipher := range []Cipher{CipherAES256GCM} {
		for _, sealed := range []bool{false, true} {
			for _, level := range []int32{0, 3} {
				var master, page, active, k5, k6 [32]byte
				rng.Read(master[:])
				rng.Read(active[:])
				rng.Read(k5[:])
				rng.Read(k6[:])
				page = master
				var current uint32
				var rids []uint32
				var rkeys []byte
				if sealed {
					page = active
					current = 7
					rids = []uint32{5, 6}
					rkeys = append(append([]byte(nil), k5[:]...), k6[:]...)
				}
				h := nvfs.CodecCreate(int(cipher), int(level), page[:], sealed,
					active[:], current, rids, rkeys, master[:])
				if h == nil {
					t.Fatalf("create cipher=%d sealed=%v", cipher, sealed)
				}
				// Trial-chain snapshot matching the C codec's keys.
				keys := pageKeys{page: page, master: master, sealed: sealed}
				if sealed {
					keys.active = active
					keys.current = current
					keys.retired = []KeyEntry{{ID: 5, Key: k5}, {ID: 6, Key: k6}}
				}
				goOpen := func(pg uint64, rec []byte) ([]byte, error) {
					blk, err := decryptBlock(cipher, &keys, pg, rec)
					if err != nil {
						return nil, err
					}
					return append([]byte(nil), blk[:]...), nil
				}
				keyID := uint32(0)
				if sealed {
					keyID = current
				}
				for pname, mk := range payloads {
					block := mk()
					for _, pg := range pages {
						// Go seal -> C open.
						rec, err := goSeal(cipher, page, pg, block, int(level), keyID)
						if err != nil {
							t.Fatalf("go seal: %v", err)
						}
						got, rc := nvfs.CodecOpen(h, pg, rec)
						if rc != 0 || !bytes.Equal(got, block) {
							t.Fatalf("go->C cipher=%d sealed=%v lvl=%d %s pg=%d rc=%d",
								cipher, sealed, level, pname, pg, rc)
						}
						// C seal -> Go open; record lengths must match
						// (same zstd bytes + envelope; only nonces differ).
						crec, crc := nvfs.CodecSeal(h, pg, block)
						if crc != 0 {
							t.Fatalf("C seal: rc=%d", crc)
						}
						plain, err := goOpen(pg, crec)
						if err != nil || !bytes.Equal(plain, block) {
							t.Fatalf("C->go cipher=%d sealed=%v lvl=%d %s pg=%d err=%v",
								cipher, sealed, level, pname, pg, err)
						}
						if len(crec) != len(rec) {
							t.Fatalf("record length: C=%d go=%d", len(crec), len(rec))
						}
						// Wrong page must fail identically.
						_, gerr := goOpen(pg+1, rec)
						_, crc = nvfs.CodecOpen(h, pg+1, rec)
						if goClass(gerr) != crc {
							t.Fatalf("wrong page: go=%v C=%d", gerr, crc)
						}
						// Tamper matrix: exact error-class agreement.
						for ti, mutate := range tampers(len(rec)) {
							bad := append([]byte(nil), rec...)
							mutate(bad)
							_, gerr := goOpen(pg, bad)
							_, crc := nvfs.CodecOpen(h, pg, bad)
							if goClass(gerr) != crc {
								t.Fatalf("tamper %d cipher=%d sealed=%v %s pg=%d: go=%v C=%d",
									ti, cipher, sealed, pname, pg, gerr, crc)
							}
						}
					}
				}
				// Retired-key records open on sealed stores.
				if sealed {
					tblock := payloads["text"]()
					rrec, err := goSeal(cipher, k5, 9, tblock, int(level), 5)
					if err != nil {
						t.Fatalf("retired seal: %v", err)
					}
					if got, rc := nvfs.CodecOpen(h, 9, rrec); rc != 0 || !bytes.Equal(got, tblock) {
						t.Fatalf("retired open rc=%d", rc)
					}
					urec, err := goSeal(cipher, k6, 10, tblock, int(level), 99)
					if err != nil {
						t.Fatalf("unknown-id seal: %v", err)
					}
					if _, rc := nvfs.CodecOpen(h, 10, urec); rc == 0 {
						t.Fatalf("unknown key id opened")
					}
				}
				nvfs.CodecDestroy(h)
			}
		}
	}
}

// goSeal mirrors SealBlock: compress when smaller, then seal.
func goSeal(cipher Cipher, key [32]byte, page uint64, block []byte, level int, keyID uint32) ([]byte, error) {
	payload, compressed := block, false
	if level != 0 {
		if out, err := zstd.Compress(block, level); err == nil && len(out) < Block {
			payload, compressed = out, true
		}
	}
	return Encrypt(cipher, key, page, payload, compressed, keyID)
}

func tampers(reclen int) []func([]byte) {
	return []func([]byte){
		func(b []byte) { b[0] ^= 0x01 },                           // magic
		func(b []byte) { b[3] ^= 0xFF },                           // magic/keyed bit
		func(b []byte) { b[4] = 2 },                               // bad flag
		func(b []byte) { b[4] ^= 1 },                              // flag flip
		func(b []byte) { b[5] ^= 0x80 },                           // keyid/nonce
		func(b []byte) { b[len(b)/2] ^= 0x40 },                    // ciphertext
		func(b []byte) { b[len(b)-1] ^= 0x01 },                    // tag
		func(b []byte) { b[len(b)-17] ^= 0x02 },                   // tag edge
		func(b []byte) { copy(b, bytes.Repeat([]byte{0xFF}, 4)) }, // header wipe
	}
}

func TestCodecReconfigure(t *testing.T) {
	var master, active [32]byte
	for i := range master {
		master[i], active[i] = byte(i+1), byte(i+0x40)
	}
	h := nvfs.CodecCreate(1, 0, master[:], false, active[:], 0, nil, nil, master[:])
	if h == nil {
		t.Fatal("create")
	}
	defer nvfs.CodecDestroy(h)
	block := bytes.Repeat([]byte("reconfigure me! "), 256)[:Block]
	rec, rc := nvfs.CodecSeal(h, 3, block)
	if rc != 0 || string(rec[:4]) != "EXP1" || rec[4] != 0 {
		t.Fatalf("plain seal: rc=%d", rc)
	}
	if nvfs.CodecSetLevel(h, 3) != 0 {
		t.Fatal("set level")
	}
	rec, rc = nvfs.CodecSeal(h, 3, block)
	if rc != 0 || rec[4] != 1 {
		t.Fatalf("compressed seal: rc=%d", rc)
	}
	if nvfs.CodecSetCipher(h, 2) == 0 {
		t.Fatal("removed cipher accepted")
	}
	rec, rc = nvfs.CodecSeal(h, 3, block)
	if rc != 0 || string(rec[:4]) != "EXP1" {
		t.Fatalf("AES seal: rc=%d", rc)
	}
	if nvfs.CodecInstallRing(h, active[:], 11, nil, nil) != 0 {
		t.Fatal("install ring")
	}
	rec, rc = nvfs.CodecSeal(h, 3, block)
	if rc != 0 || string(rec[:4]) != "EXP3" {
		t.Fatalf("keyed seal: rc=%d", rc)
	}
	plain, err := Decrypt(CipherAES256GCM, active, 3, rec)
	if err != nil || !bytes.Equal(plain, block) {
		t.Fatalf("keyed round-trip: %v", err)
	}
}
