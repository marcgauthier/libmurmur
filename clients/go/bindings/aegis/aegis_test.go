package aegis

import (
	"bytes"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	if err := Init(); err != nil {
		t.Fatalf("init: %v", err)
	}
	var key [32]byte
	for i := range key {
		key[i] = byte(0x40 + i)
	}
	var nonce [NonceLen]byte
	for i := range nonce {
		nonce[i] = byte(0xc0 + i)
	}
	aad := []byte("aegis-go-aad")
	msg := bytes.Repeat([]byte{0xab}, 100)
	sealed := make([]byte, len(msg)+TagLen)
	out, err := Encrypt(sealed, msg, aad, nonce, key)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if len(out) != len(msg)+TagLen {
		t.Fatalf("sealed len=%d", len(out))
	}
	plain := make([]byte, len(msg))
	got, err := Decrypt(plain, out, aad, nonce, key)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatal("round trip mismatch")
	}
}

func TestTamperMatrix(t *testing.T) {
	var key [32]byte
	var nonce [NonceLen]byte
	aad := []byte("aad")
	msg := []byte("0123456789abcdef")
	sealed := make([]byte, len(msg)+TagLen)
	out, err := Encrypt(sealed, msg, aad, nonce, key)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	// Flip each region: body, tag, aad, nonce, key.
	mut := bytes.Clone(out)
	mut[0] ^= 0x01
	if _, err := Decrypt(make([]byte, len(msg)), mut, aad, nonce, key); err != ErrAuth {
		t.Fatalf("body tamper err=%v, want ErrAuth", err)
	}
	mut = bytes.Clone(out)
	mut[len(mut)-1] ^= 0x01
	if _, err := Decrypt(make([]byte, len(msg)), mut, aad, nonce, key); err != ErrAuth {
		t.Fatalf("tag tamper err=%v, want ErrAuth", err)
	}
	if _, err := Decrypt(make([]byte, len(msg)), out, []byte("aax"), nonce, key); err != ErrAuth {
		t.Fatalf("aad tamper err=%v, want ErrAuth", err)
	}
	var nonce2 [NonceLen]byte
	nonce2[0] = 1
	if _, err := Decrypt(make([]byte, len(msg)), out, aad, nonce2, key); err != ErrAuth {
		t.Fatalf("nonce tamper err=%v, want ErrAuth", err)
	}
	var key2 [32]byte
	key2[0] = 1
	if _, err := Decrypt(make([]byte, len(msg)), out, aad, nonce, key2); err != ErrAuth {
		t.Fatalf("key tamper err=%v, want ErrAuth", err)
	}
	if _, err := Decrypt(make([]byte, 1), out[:10], aad, nonce, key); err != ErrAuth {
		t.Fatalf("truncated err=%v, want ErrAuth", err)
	}
}
