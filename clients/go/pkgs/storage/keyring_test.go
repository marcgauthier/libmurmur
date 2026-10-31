package storage

import (
	"bytes"
	"encoding/hex"
	"hash/crc32"
	"testing"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex: %v", err)
	}
	return b
}

func vecIDs(t *testing.T) (store, context [16]byte, master, key1, key2 [32]byte) {
	t.Helper()
	copy(store[:], mustHex(t, vecStoreHex))
	copy(context[:], mustHex(t, vecContextHex))
	copy(master[:], mustHex(t, vecMasterHex))
	copy(key1[:], mustHex(t, vecKey1Hex))
	copy(key2[:], mustHex(t, vecKey2Hex))
	return store, context, master, key1, key2
}

func TestCRC32CSelfCheck(t *testing.T) {
	// Same self-check as the Python vector generator.
	if got := crc32.Checksum([]byte("123456789"), castagnoli); got != 0xE3069283 {
		t.Fatalf("crc32c=%08x, want e3069283", got)
	}
}

func TestVectorDirectOne(t *testing.T) {
	store, context, master, key1, _ := vecIDs(t)
	raw := mustHex(t, vec_direct_oneHex)
	ring, err := Open(raw, master[:], nil, store, context)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer ring.Wipe()
	if ring.Seq != 9 || ring.KDF != KDFDirectHKDF || ring.Current != 1 {
		t.Fatalf("header: seq=%d kdf=%d current=%d", ring.Seq, ring.KDF, ring.Current)
	}
	if string(ring.WrapID) != "wrap-hint" {
		t.Fatalf("wrap=%q", ring.WrapID)
	}
	if len(ring.Keys) != 1 {
		t.Fatalf("keys=%d, want 1", len(ring.Keys))
	}
	k := ring.Keys[0]
	if k.ID != 1 || !k.Active || k.Key != key1 {
		t.Fatalf("key1 mismatch: %+v", k.ID)
	}
}

func TestVectorDirectTwo(t *testing.T) {
	store, context, master, key1, key2 := vecIDs(t)
	raw := mustHex(t, vec_direct_twoHex)
	ring, err := Open(raw, master[:], nil, store, context)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer ring.Wipe()
	if ring.Seq != 41 || ring.Current != 2 || len(ring.Keys) != 2 {
		t.Fatalf("header: seq=%d current=%d keys=%d", ring.Seq, ring.Current, len(ring.Keys))
	}
	if ring.Keys[0].ID != 1 || ring.Keys[0].Active || ring.Keys[0].Key != key1 {
		t.Fatalf("key1 must be retired with vector bytes")
	}
	if ring.Keys[1].ID != 2 || !ring.Keys[1].Active || ring.Keys[1].Key != key2 {
		t.Fatalf("key2 must be active with vector bytes")
	}
}

func TestVectorWrongMasterFailsAuth(t *testing.T) {
	store, context, _, _, _ := vecIDs(t)
	raw := mustHex(t, vec_direct_oneHex)
	bad := bytes.Repeat([]byte{0xee}, 32)
	if _, err := Open(raw, bad, nil, store, context); err != ErrAuth {
		t.Fatalf("err=%v, want ErrAuth", err)
	}
}

func TestVectorTamperMatrix(t *testing.T) {
	store, context, master, _, _ := vecIDs(t)
	raw := mustHex(t, vec_direct_oneHex)
	// Offsets: magic(0), version(4), kdf(6), salt(20), crc(70), nonce(74), sealed(90).
	for _, off := range []int{0, 4, 6, 20, 70, 74, 90, len(raw) - 1} {
		mut := bytes.Clone(raw)
		mut[off] ^= 0x01
		if _, err := Open(mut, master[:], nil, store, context); err == nil {
			t.Fatalf("offset %d: tampered envelope opened", off)
		}
	}
	if _, err := Open(raw[:60], master[:], nil, store, context); err == nil {
		t.Fatal("truncated envelope opened")
	}
}

func TestVectorArgon2HeaderFailsAuth(t *testing.T) {
	store, context, _, _, _ := vecIDs(t)
	raw := mustHex(t, vec_argon2_hdrHex)
	// Valid argon2id header, garbage body: real Argon2id runs, then the
	// tag check fails. Any passphrase exercises the same path.
	if _, err := Open(raw, nil, []byte("pass"), store, context); err != ErrAuth {
		t.Fatalf("err=%v, want ErrAuth", err)
	}
	// Empty passphrase never reaches Argon2.
	if _, err := Open(raw, nil, nil, store, context); err != ErrAuth {
		t.Fatalf("err=%v, want ErrAuth", err)
	}
}

func TestVectorArgon2ZeroParamsFailsFast(t *testing.T) {
	store, context, _, _, _ := vecIDs(t)
	raw := mustHex(t, vec_argon2_zeroparamsHex)
	if _, err := Open(raw, nil, []byte("pass"), store, context); err != ErrCorrupt {
		t.Fatalf("err=%v, want ErrCorrupt", err)
	}
}

func TestCreateRotateDropRoundTrip(t *testing.T) {
	var store, context [16]byte
	for i := range store {
		store[i] = byte(i)
		context[i] = byte(0x80 + i)
	}
	master := bytes.Repeat([]byte{0x40}, 32)
	env, err := Create(CreateOptions{
		KDF: KDFDirectHKDF, WrapID: []byte("w1"), StoreID: store, ContextID: context, Master: master,
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	ring, err := Open(env, master, nil, store, context)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if ring.Seq != 1 || ring.Current != 1 || len(ring.Keys) != 1 {
		t.Fatalf("fresh ring: %+v", ring.Seq)
	}
	env2, id2, err := ring.Rotate(store, master, nil)
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if id2 != 2 {
		t.Fatalf("id2=%d", id2)
	}
	ring2, err := Open(env2, master, nil, store, context)
	if err != nil {
		t.Fatalf("open rotated: %v", err)
	}
	if ring2.Seq != 2 || ring2.Current != 2 || len(ring2.Keys) != 2 {
		t.Fatalf("rotated ring: seq=%d current=%d keys=%d", ring2.Seq, ring2.Current, len(ring2.Keys))
	}
	if ring2.Keys[0].Active || !ring2.Keys[1].Active {
		t.Fatal("rotation must retire key 1 and activate key 2")
	}
	env3, err := ring2.DropKeys([]uint32{1}, store, master, nil)
	if err != nil {
		t.Fatalf("drop: %v", err)
	}
	ring3, err := Open(env3, master, nil, store, context)
	if err != nil {
		t.Fatalf("open dropped: %v", err)
	}
	if len(ring3.Keys) != 1 || ring3.Keys[0].ID != 2 || ring3.Seq != 3 {
		t.Fatalf("dropped ring: %+v", ring3.Keys)
	}
	if _, err := ring3.DropKeys([]uint32{2}, store, master, nil); err != ErrMisuse {
		t.Fatalf("dropping current must be misuse, got %v", err)
	}
}

func TestArgon2RoundTrip(t *testing.T) {
	var store, context [16]byte
	env, err := Create(CreateOptions{
		KDF: KDFArgon2ID, ArgonTime: 1, ArgonMemoryKiB: 8192, ArgonThreads: 1,
		StoreID: store, ContextID: context, Passphrase: []byte("s3cret"),
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	ring, err := Open(env, nil, []byte("s3cret"), store, context)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if ring.KDF != KDFArgon2ID || ring.Current != 1 {
		t.Fatalf("argon ring: %+v", ring.KDF)
	}
	if _, err := Open(env, nil, []byte("wrong"), store, context); err != ErrAuth {
		t.Fatalf("wrong passphrase err=%v, want ErrAuth", err)
	}
}
