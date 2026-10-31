package zstd

import (
	"bytes"
	"testing"
)

func TestLevels(t *testing.T) {
	// The vendored library version rides go.mod; sweep the level
	// range the PRAGMA surface accepts instead.
	msg := bytes.Repeat([]byte("level sweep payload. "), 200)
	for _, level := range []int{1, 3, 6, 19, MaxLevel} {
		c, err := Compress(msg, level)
		if err != nil {
			t.Fatalf("compress level %d: %v", level, err)
		}
		plain, err := Decompress(c, len(msg))
		if err != nil || !bytes.Equal(plain, msg) {
			t.Fatalf("level %d round trip: %v", level, err)
		}
	}
}

func TestRoundTrip(t *testing.T) {
	msg := bytes.Repeat([]byte("sqlite-murmur page payload. "), 160)
	c, err := Compress(msg, DefaultLevel)
	if err != nil {
		t.Fatalf("compress: %v", err)
	}
	if len(c) >= len(msg) {
		t.Fatalf("incompressible? %d -> %d", len(msg), len(c))
	}
	plain, err := Decompress(c, len(msg))
	if err != nil {
		t.Fatalf("decompress: %v", err)
	}
	if !bytes.Equal(plain, msg) {
		t.Fatal("round trip mismatch")
	}
	if _, err := Decompress(c, len(msg)-1); err == nil {
		t.Fatal("short output must fail")
	}
}

func TestCorruptFails(t *testing.T) {
	msg := bytes.Repeat([]byte("x"), 4096)
	c, err := Compress(msg, DefaultLevel)
	if err != nil {
		t.Fatalf("compress: %v", err)
	}
	c[len(c)/2] ^= 0x01
	if _, err := Decompress(c, len(msg)); err == nil {
		t.Fatal("corrupt frame must fail")
	}
	if _, err := Decompress([]byte{0x28, 0xb5, 0x2f, 0xfd}, 4096); err == nil {
		t.Fatal("truncated frame must fail")
	}
	if _, err := Compress(msg, 0); err == nil {
		t.Fatal("level 0 must fail")
	}
	if _, err := Compress(msg, MaxLevel+1); err == nil {
		t.Fatal("level 23 must fail")
	}
}
