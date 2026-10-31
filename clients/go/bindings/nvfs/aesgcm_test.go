package nvfs

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"math/rand"
	"testing"
)

// Deterministic differentials vs Go stdlib (independent AES-GCM
// implementation): fixed seed, edge-biased lengths.

func TestAESNIPresent(t *testing.T) {
	if !aesAvailable() {
		t.Skip("no AES-GCM backend")
	}
}

func TestAESBlockVsStdlib(t *testing.T) {
	if !aesAvailable() {
		t.Skip("no AES-GCM backend")
	}
	rng := rand.New(rand.NewSource(0xA5A5))
	for i := 0; i < 2000; i++ {
		var key [32]byte
		var in [16]byte
		rng.Read(key[:])
		rng.Read(in[:])
		blk, err := aes.NewCipher(key[:])
		if err != nil {
			t.Fatal(err)
		}
		var want [16]byte
		blk.Encrypt(want[:], in[:])
		var got [16]byte
		if rc := aesBlock(key[:], in[:], got[:]); rc != 0 || got != want {
			t.Fatalf("case %d: rc=%d got=%x want=%x", i, rc, got, want)
		}
	}
}

func TestAESGCMVsStdlib(t *testing.T) {
	if !aesAvailable() {
		t.Skip("no AES-GCM backend")
	}
	rng := rand.New(rand.NewSource(0x1EDC0DE))
	ptLens := []int{0, 1, 2, 5, 12, 15, 16, 17, 24, 31, 32, 33, 63, 64, 65, 100, 127, 128, 129, 143, 144, 255, 256, 257, 1000, 4095, 4096}
	aadLens := []int{0, 1, 5, 13, 16, 17, 32, 48, 64}
	n := 0
	for _, ptLen := range ptLens {
		for _, aadLen := range aadLens {
			var key [32]byte
			var nonce [12]byte
			rng.Read(key[:])
			rng.Read(nonce[:])
			pt := make([]byte, ptLen)
			aad := make([]byte, aadLen)
			rng.Read(pt)
			rng.Read(aad)
			blk, err := aes.NewCipher(key[:])
			if err != nil {
				t.Fatal(err)
			}
			aead, err := cipher.NewGCM(blk)
			if err != nil {
				t.Fatal(err)
			}
			sealed := aead.Seal(nil, nonce[:], pt, aad)
			ct, tag := sealed[:ptLen], sealed[ptLen:]
			gotCT, gotTag, rc := aesGCMEncrypt(key[:], nonce[:], pt, aad)
			if rc != 0 || !bytes.Equal(gotCT, ct) || !bytes.Equal(gotTag, tag) {
				t.Fatalf("enc pt=%d aad=%d: rc=%d", ptLen, aadLen, rc)
			}
			gotPT, rc := aesGCMDecrypt(key[:], nonce[:], gotCT, gotTag, aad)
			if rc != 0 || !bytes.Equal(gotPT, pt) {
				t.Fatalf("dec pt=%d aad=%d: rc=%d", ptLen, aadLen, rc)
			}
			bad := append([]byte(nil), tag...)
			bad[len(bad)-1] ^= 0x01
			gotPT, rc = aesGCMDecrypt(key[:], nonce[:], gotCT, bad, aad)
			if rc != -2 {
				t.Fatalf("tampered tag pt=%d aad=%d: rc=%d, want -2", ptLen, aadLen, rc)
			}
			for i, b := range gotPT {
				if b != 0 {
					t.Fatalf("tampered tag released plaintext at %d", i)
				}
			}
			n++
		}
	}
	t.Logf("%d cases", n)
}
