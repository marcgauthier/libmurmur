package storage

import (
	"bytes"
	"testing"

	"github.com/marcgauthier/libmurmur/clients/go/bindings/zstd"
)

func testPage() []byte {
	p := make([]byte, Block)
	for i := range p {
		p[i] = byte(i*31 + 7)
	}
	copy(p, "SQLITE-MURMUR-GO-PAGE")
	return p
}

func testKey() (key [32]byte) {
	for i := range key {
		key[i] = byte(0x20 + i)
	}
	return key
}

func roundTrip(t *testing.T, c Cipher, keyID uint32, compressed bool) {
	t.Helper()
	key := testKey()
	page := testPage()
	data := page
	if compressed {
		c, err := zstd.Compress(page, zstd.DefaultLevel)
		if err != nil {
			t.Fatalf("compress: %v", err)
		}
		data = c
	}
	rec, err := Encrypt(c, key, 4242, data, compressed, keyID)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	plain, err := Decrypt(c, key, 4242, rec)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(plain, page) {
		t.Fatal("round trip mismatch")
	}
	// Routing must agree with the seal.
	id, ok := RecordKeyID(rec)
	if keyID == 0 && ok {
		t.Fatalf("unkeyed record routed keyed: %d", id)
	}
	if keyID != 0 && (!ok || id != keyID) {
		t.Fatalf("key id=%d ok=%v, want %d", id, ok, keyID)
	}
	if IsLegacyRecord(rec) != (keyID == 0) {
		t.Fatalf("legacy routing wrong for keyID=%d", keyID)
	}
}

func TestRoundTrips(t *testing.T) {
	roundTrip(t, CipherAES256GCM, 0, false)
	roundTrip(t, CipherAES256GCM, 0, true)
	roundTrip(t, CipherAES256GCM, 9, false)
	roundTrip(t, CipherAES256GCM, 9, true)
}

func TestCorruptRecordsFailClosed(t *testing.T) {
	key := testKey()
	records := [][]byte{
		{},
		[]byte("EX"),
		[]byte("BAD!"),
		[]byte("EXP1"),
		[]byte("EXP1\x02"),
		make([]byte, 4+1+AESGCMNonceLen+AESGCMTagLen-1),
		[]byte("EXP9\x00AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
	}
	for i, rec := range records {
		if _, err := Decrypt(CipherAES256GCM, key, 3, rec); err == nil {
			t.Fatalf("record %d opened", i)
		}
		if _, ok := RecordKeyID(rec); ok {
			t.Fatalf("record %d routed keyed", i)
		}
	}
	if IsLegacyRecord([]byte("EXP1")) {
		t.Fatal("short EXP1 must not route legacy")
	}
	if IsLegacyRecord([]byte("EXP3\x00\x01\x00\x00\x00AAAAAAAAAAAAAAAAAAAAAAAA")) {
		t.Fatal("EXP3 must not route legacy")
	}
}

func TestTamperMatrix(t *testing.T) {
	key := testKey()
	page := testPage()
	// Keyed AES record layout: EXP3 | flag | keyID[4] | page? no: nonce | sealed.
	// Offsets: flag(4), key id(5), nonce(9), payload(21), tag(last).
	rec, err := Encrypt(CipherAES256GCM, key, 100, page, false, 3)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if string(rec[:4]) != HeaderAESKeyed {
		t.Fatalf("magic=%q", rec[:4])
	}
	for _, off := range []int{4, 5, 9, 21, len(rec) - 1} {
		mut := bytes.Clone(rec)
		mut[off] ^= 0x01
		if _, err := Decrypt(CipherAES256GCM, key, 100, mut); err == nil {
			t.Fatalf("offset %d opened", off)
		}
	}
	var bad [32]byte
	if _, err := Decrypt(CipherAES256GCM, bad, 100, rec); err != ErrAuth {
		t.Fatalf("wrong key err=%v, want ErrAuth", err)
	}
	if _, err := Decrypt(CipherAES256GCM, key, 101, rec); err != ErrAuth {
		t.Fatalf("wrong page err=%v, want ErrAuth", err)
	}
	// Cross-cipher records fail closed.
	if _, err := Decrypt(Cipher(2), key, 100, rec); err == nil {
		t.Fatal("cross-cipher opened")
	}
	// Unkeyed AES tamper.
	rec2, err := Encrypt(CipherAES256GCM, key, 7, page, false, 0)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if string(rec2[:4]) != HeaderAES {
		t.Fatalf("magic=%q", rec2[:4])
	}
	mut := bytes.Clone(rec2)
	mut[len(mut)-1] ^= 0x01
	if _, err := Decrypt(CipherAES256GCM, key, 7, mut); err == nil {
		t.Fatal("AES tag tamper opened")
	}
}

func TestHelpers(t *testing.T) {
	k := PageKey(0x0102030405060708)
	if k[0] != 'p' || k[1] != 0x01 || k[8] != 0x08 {
		t.Fatalf("page key=%x", k)
	}
	if CipherName(CipherAES256GCM) != "aes256gcm" || CipherName(Cipher(2)) != "unspecified" {
		t.Fatal("cipher names")
	}
	if _, err := Encrypt(CipherUnspecified, testKey(), 1, testPage(), false, 0); err != ErrMisuse {
		t.Fatal("unspecified cipher must be misuse")
	}
}
