package nvfs_test

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"testing"

	"github.com/marcgauthier/libmurmur/clients/go/bindings/nvfs"
	"github.com/marcgauthier/libmurmur/clients/go/pkgs/storage"
)

// Frozen vectors duplicated from pkgs/storage/keyring_vectors_test.go
// (generated from the sqlite-murmur vectors header; DO NOT EDIT
// there — this copy pins the C++ port to the same bytes).
const (
	vec_direct_oneHex        = "53504c4b0300000900000000000000202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f00000000000000000009777261702d68696e7479107b80c0c1c2c3c4c5c6c7c8c9cacb5b000000b180ae6f71731793130990bbc90d95e9dee94eb765bfdeb1ac37f14da5259ecf8d01d9075eb0726b0eec08480c6bc3d0309eb5bc6a27020d2b07514d299006ac338044dd330acf56a80dd6503ac27c9a1fce7ea8be32634449773c"
	vec_direct_twoHex        = "53504c4b0300002900000000000000606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f0000000000000000000051329d26c0c1c2c3c4c5c6c7c8c9cacb7f0000008d452cbb1bd5e82fbcef3c78b7685850d9ede4fb83ea0f5152aabc49982029d3dc5120d9c3fa9bebe53c7cbc288a8b3d3a1f96de2e0eb7a5940b0a88865eedc6a8d615eb7c2a7d83a78d6b05ae11c23b8e8bd4ee0bddd352844dc6fa022700a11c9e16c4f2e677299dd58514d58a3ad074ceae392543222aa980364f838526"
	vec_argon2_hdrHex        = "53504c4b0300010300000000000000202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f030000000000010004056172676f6e7d765c56c0c1c2c3c4c5c6c7c8c9cacb30000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
	vec_argon2_zeroparamsHex = "53504c4b0300010500000000000000202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f00000000000000000000df248108c0c1c2c3c4c5c6c7c8c9cacb30000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
	vecStoreHex              = "000102030405060708090a0b0c0d0e0f"
	vecContextHex            = "808182838485868788898a8b8c8d8e8f"
	vecMasterHex             = "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f"
	vecKey1Hex               = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
	vecKey2Hex               = "e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
)

const (
	krOK      = 0
	krAuth    = 1
	krCorrupt = 2
	krMisuse  = 3
)

type krFlatKey struct {
	id      uint32
	created int64
	active  bool
	key     [32]byte
}

type krFlat struct {
	seq      uint64
	kdf      uint8
	atime    uint32
	amem     uint32
	athreads uint8
	current  uint32
	wrap     []byte
	keys     []krFlatKey
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex: %v", err)
	}
	return b
}

func parseFlat(t *testing.T, flat []byte) krFlat {
	t.Helper()
	var f krFlat
	if len(flat) < 8+1+4+4+1+4+4+1 {
		t.Fatalf("flat too short: %d", len(flat))
	}
	o := 0
	f.seq = binary.LittleEndian.Uint64(flat[o:])
	o += 8
	f.kdf = flat[o]
	o++
	f.atime = binary.LittleEndian.Uint32(flat[o:])
	o += 4
	f.amem = binary.LittleEndian.Uint32(flat[o:])
	o += 4
	f.athreads = flat[o]
	o++
	f.current = binary.LittleEndian.Uint32(flat[o:])
	o += 4
	nkeys := binary.LittleEndian.Uint32(flat[o:])
	o += 4
	wlen := int(flat[o])
	o++
	if len(flat) < o+wlen+int(nkeys)*45 {
		t.Fatalf("flat truncated: %d", len(flat))
	}
	f.wrap = append([]byte(nil), flat[o:o+wlen]...)
	o += wlen
	for i := uint32(0); i < nkeys; i++ {
		var k krFlatKey
		k.id = binary.LittleEndian.Uint32(flat[o:])
		k.created = int64(binary.LittleEndian.Uint64(flat[o+4:]))
		k.active = flat[o+12] != 0
		copy(k.key[:], flat[o+13:o+45])
		o += 45
		f.keys = append(f.keys, k)
	}
	return f
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

// requireAESNI skips when the C++ AES-GCM backend is unavailable.
func requireAESNI(t *testing.T) {
	t.Helper()
	if !nvfs.KrTestAESAvailable() {
		t.Skip("no AES-GCM backend")
	}
}

func TestKeyringDiffVectors(t *testing.T) {
	requireAESNI(t)
	store, context, master, key1, key2 := vecIDs(t)
	masterB := master[:]

	// Direct-one: hardcoded pins plus Go cross-check.
	raw := mustHex(t, vec_direct_oneHex)
	flat, rc := nvfs.KrTestOpen(raw, masterB, nil, store[:], context[:])
	if rc != krOK {
		t.Fatalf("cpp open one = %d", rc)
	}
	f := parseFlat(t, flat)
	if f.seq != 9 || f.kdf != 0 || f.current != 1 {
		t.Fatalf("one header: %+v", f)
	}
	if string(f.wrap) != "wrap-hint" || len(f.keys) != 1 {
		t.Fatalf("one wrap/keys: %q %d", f.wrap, len(f.keys))
	}
	if k := f.keys[0]; k.id != 1 || !k.active || k.key != key1 {
		t.Fatalf("one key mismatch")
	}
	g, err := storage.Open(raw, masterB, nil, store, context)
	if err != nil {
		t.Fatalf("go open one: %v", err)
	}
	defer g.Wipe()
	if g.Seq != f.seq || g.KDF != f.kdf || g.Current != f.current ||
		!bytes.Equal(g.WrapID, f.wrap) || len(g.Keys) != len(f.keys) ||
		g.Keys[0].Key != f.keys[0].key {
		t.Fatalf("go/cpp one diverge")
	}

	// Direct-two: retired + active.
	raw = mustHex(t, vec_direct_twoHex)
	flat, rc = nvfs.KrTestOpen(raw, masterB, nil, store[:], context[:])
	if rc != krOK {
		t.Fatalf("cpp open two = %d", rc)
	}
	f = parseFlat(t, flat)
	if f.seq != 41 || f.current != 2 || len(f.keys) != 2 {
		t.Fatalf("two header: %+v", f)
	}
	if k := f.keys[0]; k.id != 1 || k.active || k.key != key1 {
		t.Fatalf("two key1 mismatch")
	}
	if k := f.keys[1]; k.id != 2 || !k.active || k.key != key2 {
		t.Fatalf("two key2 mismatch")
	}
}

func goErrClass(err error) int {
	switch err {
	case nil:
		return krOK
	case storage.ErrAuth:
		return krAuth
	case storage.ErrCorrupt:
		return krCorrupt
	case storage.ErrMisuse:
		return krMisuse
	default:
		return -1
	}
}

func TestKeyringDiffErrors(t *testing.T) {
	requireAESNI(t)
	store, context, master, _, _ := vecIDs(t)
	raw := mustHex(t, vec_direct_oneHex)

	// Wrong master: Auth on both sides.
	wrong := append([]byte(nil), master[:]...)
	wrong[0] ^= 0xFF
	if _, rc := nvfs.KrTestOpen(raw, wrong, nil, store[:], context[:]); rc != krAuth {
		t.Fatalf("cpp wrong master = %d, want AUTH", rc)
	}
	if _, err := storage.Open(raw, wrong, nil, store, context); err != storage.ErrAuth {
		t.Fatalf("go wrong master = %v, want ErrAuth", err)
	}

	// Tamper matrix: exact error-class match per offset.
	for _, off := range []int{0, 4, 6, 20, 70, 74, 90, len(raw) - 1} {
		mut := append([]byte(nil), raw...)
		mut[off] ^= 0x01
		_, crc := nvfs.KrTestOpen(mut, master[:], nil, store[:], context[:])
		_, gerr := storage.Open(mut, master[:], nil, store, context)
		grc := goErrClass(gerr)
		if crc == krOK || grc == krOK {
			t.Fatalf("offset %d unexpectedly opened (cpp=%d go=%v)", off, crc, gerr)
		}
		if crc != grc {
			t.Fatalf("offset %d: cpp=%d go=%d (%v)", off, crc, grc, gerr)
		}
	}

	// Truncation: Corrupt on both sides.
	short := raw[:60]
	if _, rc := nvfs.KrTestOpen(short, master[:], nil, store[:], context[:]); rc != krCorrupt {
		t.Fatalf("cpp truncated = %d, want CORRUPT", rc)
	}
	if _, err := storage.Open(short, master[:], nil, store, context); err != storage.ErrCorrupt {
		t.Fatalf("go truncated = %v, want ErrCorrupt", err)
	}

	// Legacy Argon2id headers are rejected before password derivation.
	ahdr := mustHex(t, vec_argon2_hdrHex)
	if _, rc := nvfs.KrTestOpen(ahdr, nil, []byte("pass"), store[:], context[:]); rc != krCorrupt {
		t.Fatalf("cpp legacy Argon2id = %d, want CORRUPT", rc)
	}

	// Zero scrypt params: fail fast with Corrupt (no KDF).
	azero := mustHex(t, vec_argon2_zeroparamsHex)
	if _, rc := nvfs.KrTestOpen(azero, nil, []byte("pass"), store[:], context[:]); rc != krCorrupt {
		t.Fatalf("cpp argon2 zero params = %d, want CORRUPT", rc)
	}
}

func krSealKeys(t *testing.T, kdf uint8, seq uint64, sid, ctx, wrap, master, pass []byte,
	atime, amem uint32, athreads uint8, keys []krFlatKey) []byte {
	t.Helper()
	var flat []byte
	for _, k := range keys {
		var e [45]byte
		binary.LittleEndian.PutUint32(e[0:], k.id)
		binary.LittleEndian.PutUint64(e[4:], uint64(k.created))
		if k.active {
			e[12] = 1
		}
		copy(e[13:], k.key[:])
		flat = append(flat, e[:]...)
	}
	env, rc := nvfs.KrTestSeal(kdf, seq, sid, ctx, wrap, master, pass, atime, amem, athreads, flat, len(keys))
	if rc != krOK {
		t.Fatalf("cpp seal = %d", rc)
	}
	return env
}

func compareRings(t *testing.T, what string, g *storage.Keyring, f krFlat) {
	t.Helper()
	if g.Seq != f.seq || g.KDF != f.kdf || g.Current != f.current ||
		g.ScryptN != f.atime || g.ScryptR != f.amem || g.ScryptP != f.athreads ||
		!bytes.Equal(g.WrapID, f.wrap) || len(g.Keys) != len(f.keys) {
		t.Fatalf("%s: header diverge (go=%+v cpp=%+v)", what, g, f)
	}
	for i := range g.Keys {
		if g.Keys[i].ID != f.keys[i].id || g.Keys[i].Active != f.keys[i].active ||
			g.Keys[i].Key != f.keys[i].key || g.Keys[i].CreatedAt != f.keys[i].created {
			t.Fatalf("%s: key %d diverge", what, i)
		}
	}
}

func TestKeyringDiffRoundTrip(t *testing.T) {
	requireAESNI(t)
	var sid, ctx [16]byte
	for i := range sid {
		sid[i], ctx[i] = byte(i), byte(0x80+i)
	}
	var master [32]byte
	for i := range master {
		master[i] = byte(0x40 + i)
	}
	var k1, k2 [32]byte
	for i := range k1 {
		k1[i], k2[i] = byte(1+i), byte(0xE0+i)
	}

	// Go Create (direct) -> C++ open == Go open.
	env, err := storage.Create(storage.CreateOptions{
		KDF: 0, StoreID: sid, ContextID: ctx, Master: master[:],
	})
	if err != nil {
		t.Fatalf("go create: %v", err)
	}
	g, err := storage.Open(env, master[:], nil, sid, ctx)
	if err != nil {
		t.Fatalf("go open: %v", err)
	}
	flat, rc := nvfs.KrTestOpen(env, master[:], nil, sid[:], ctx[:])
	if rc != krOK {
		t.Fatalf("cpp open go-created = %d", rc)
	}
	compareRings(t, "go-create", g, parseFlat(t, flat))
	g.Wipe()

	// C++ seal (two keys, nonzero CreatedAt) -> Go open == C++ open.
	keys := []krFlatKey{{id: 7, created: 12345, active: false, key: k1}, {id: 9, created: 67890, active: true, key: k2}}
	cenv := krSealKeys(t, 0, 3, sid[:], ctx[:], []byte("hint"), master[:], nil, 0, 0, 0, keys)
	g2, err := storage.Open(cenv, master[:], nil, sid, ctx)
	if err != nil {
		t.Fatalf("go open cpp-sealed: %v", err)
	}
	flat2, rc := nvfs.KrTestOpen(cenv, master[:], nil, sid[:], ctx[:])
	if rc != krOK {
		t.Fatalf("cpp open cpp-sealed = %d", rc)
	}
	compareRings(t, "cpp-seal", g2, parseFlat(t, flat2))
	if g2.Keys[1].CreatedAt != 67890 {
		t.Fatalf("created passthrough = %d", g2.Keys[1].CreatedAt)
	}
	g2.Wipe()

	// scrypt both directions (small params: N=16, r=8, p=2).
	pass := []byte("correct horse battery staple")
	aenv, err := storage.Create(storage.CreateOptions{
		KDF: storage.KDFScrypt, ScryptN: 16, ScryptR: 8, ScryptP: 2,
		StoreID: sid, ContextID: ctx, Passphrase: pass,
	})
	if err != nil {
		t.Fatalf("go scrypt create: %v", err)
	}
	ga, err := storage.Open(aenv, nil, pass, sid, ctx)
	if err != nil {
		t.Fatalf("go scrypt open: %v", err)
	}
	flata, rc := nvfs.KrTestOpen(aenv, nil, pass, sid[:], ctx[:])
	if rc != krOK {
		t.Fatalf("cpp open go-scrypt = %d", rc)
	}
	compareRings(t, "go-scrypt", ga, parseFlat(t, flata))
	ga.Wipe()
	cenvA := krSealKeys(t, storage.KDFScrypt, 1, sid[:], ctx[:], nil, nil, pass, 16, 8, 2,
		[]krFlatKey{{id: 1, active: true, key: k1}})
	ga2, err := storage.Open(cenvA, nil, pass, sid, ctx)
	if err != nil {
		t.Fatalf("go open cpp-scrypt: %v", err)
	}
	flatA2, rc := nvfs.KrTestOpen(cenvA, nil, pass, sid[:], ctx[:])
	if rc != krOK {
		t.Fatalf("cpp open cpp-scrypt = %d", rc)
	}
	compareRings(t, "cpp-scrypt", ga2, parseFlat(t, flatA2))
	ga2.Wipe()
}

func TestKeyringDiffRotateDrop(t *testing.T) {
	requireAESNI(t)
	store, context, master, _, _ := vecIDs(t)
	masterB := master[:]

	base, err := storage.Create(storage.CreateOptions{
		KDF: 0, StoreID: store, ContextID: context, Master: masterB,
	})
	if err != nil {
		t.Fatalf("go create: %v", err)
	}

	// C++ rotate of a Go envelope -> Go open verifies.
	renv, next, rc := nvfs.KrTestRotate(base, store[:], context[:], masterB, nil)
	if rc != krOK {
		t.Fatalf("cpp rotate = %d", rc)
	}
	if next != 2 {
		t.Fatalf("cpp rotate next = %d", next)
	}
	gr, err := storage.Open(renv, masterB, nil, store, context)
	if err != nil {
		t.Fatalf("go open cpp-rotated: %v", err)
	}
	if gr.Current != 2 || len(gr.Keys) != 2 || gr.Keys[0].Active || !gr.Keys[1].Active {
		t.Fatalf("cpp-rotated ring wrong: %+v", gr)
	}
	gr.Wipe()

	// Go rotate of a C++ envelope -> C++ open verifies.
	cenv2 := krSealKeys(t, 0, 5, store[:], context[:], nil, masterB, nil, 0, 0, 0,
		[]krFlatKey{{id: 3, active: true, key: [32]byte{9}}})
	g3, err := storage.Open(cenv2, masterB, nil, store, context)
	if err != nil {
		t.Fatalf("go open: %v", err)
	}
	renv2, next2, err := g3.Rotate(store, masterB, nil)
	g3.Wipe()
	if err != nil || next2 != 4 {
		t.Fatalf("go rotate: %v %d", err, next2)
	}
	flat3, rcode := nvfs.KrTestOpen(renv2, masterB, nil, store[:], context[:])
	if rcode != krOK {
		t.Fatalf("cpp open go-rotated = %d", rcode)
	}
	f3 := parseFlat(t, flat3)
	if f3.current != 4 || len(f3.keys) != 2 || f3.seq != 6 {
		t.Fatalf("go-rotated ring wrong: %+v", f3)
	}

	// C++ drop of key 1 in the rotated envelope -> Go open verifies.
	denv, rc := nvfs.KrTestDrop(renv, []uint32{1}, store[:], context[:], masterB, nil)
	if rc != krOK {
		t.Fatalf("cpp drop = %d", rc)
	}
	gd, err := storage.Open(denv, masterB, nil, store, context)
	if err != nil {
		t.Fatalf("go open cpp-dropped: %v", err)
	}
	if gd.Current != 2 || len(gd.Keys) != 1 || gd.Keys[0].ID != 2 {
		t.Fatalf("cpp-dropped ring wrong: %+v", gd)
	}
	gd.Wipe()

	// Misuse matrix matches both sides.
	if _, err := storage.Seal(storage.SealOptions{KDF: 9, StoreID: store, ContextID: context,
		Master: masterB, Keys: []storage.KeyEntry{{ID: 1, Active: true}}}); err != storage.ErrMisuse {
		t.Fatalf("go bad-kdf seal = %v, want ErrMisuse", err)
	}
	if _, rc := nvfs.KrTestDrop(renv, []uint32{2}, store[:], context[:], masterB, nil); rc != krMisuse {
		t.Fatalf("cpp drop-active = %d, want MISUSE", rc)
	}
}
