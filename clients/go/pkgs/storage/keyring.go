// Package storage implements the murmur storage engine: the keys.enc v3
// keyring envelope, page encryption, and persistence.
package storage

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"io"
	"sort"

	"github.com/marcgauthier/libmurmur/clients/go/bindings/nvapi"
	"golang.org/x/crypto/argon2"
)

// Keyring errors. Authentication failures never expose key material.
// Auth and Corrupt cross into the native package, so they live in
// bindings/nvapi; aliases keep every call site working.
var (
	ErrCorrupt = nvapi.ErrCorrupt
	ErrAuth    = nvapi.ErrAuth
	ErrMisuse  = errors.New("storage: keyring misuse")
)

// KDF ids and Argon2id defaults. They match the sqlite-murmur C ABI
// (SQLITE_MURMUR_KDF_*, SQLITE_MURMUR_ARGON_*).
const (
	KDFDirectHKDF = 0
	KDFArgon2ID   = 1

	ArgonTimeDefault      = 3
	ArgonMemoryKiBDefault = 65536
	ArgonThreadsDefault   = 4
)

const (
	keysMagic   = "SPLK"
	keysVersion = 3
	keysNonce   = 12
	keyLen      = 32
	id16Len     = 16

	maxWrapIDLen = 128
	maxDataKeys  = 1 << 16
	maxSealed    = 1 << 24

	// keysEncInfo binds the protector to this exact use, store, and
	// database context. The full HKDF info is prefix || storeID ||
	// contextID.
	keysEncInfo = "spool/keys-enc/v3/"
)

var castagnoli = crc32.MakeTable(crc32.Castagnoli)

// KeyEntry is one unlocked data key: 256 bits for AES-256-GCM.
type KeyEntry struct {
	ID        uint32
	Key       [32]byte
	CreatedAt int64 // unix nanos
	Active    bool
}

// Keyring is an unlocked keys.enc v3 envelope. Keys is id-sorted and
// Current is the highest active id. Key material should be released
// with Wipe once installed or copied elsewhere.
type Keyring struct {
	Seq            uint64
	KDF            uint8
	ArgonTime      uint32
	ArgonMemoryKiB uint32
	ArgonThreads   uint8
	Context        [16]byte
	WrapID         []byte
	Keys           []KeyEntry
	Current        uint32
}

// ByID returns a copy of the key entry with the given id.
func (r *Keyring) ByID(id uint32) (KeyEntry, bool) {
	for _, k := range r.Keys {
		if k.ID == id {
			return k, true
		}
	}
	return KeyEntry{}, false
}

// Wipe best-effort zeroes unlocked key material. Go offers no pinning,
// so copies made by the runtime or AES-GCM cannot be reached; callers
// must still avoid retaining or logging Key slices.
func (r *Keyring) Wipe() {
	for i := range r.Keys {
		for j := range r.Keys[i].Key {
			r.Keys[i].Key[j] = 0
		}
	}
	for i := range r.Context {
		r.Context[i] = 0
	}
	for i := range r.WrapID {
		r.WrapID[i] = 0
	}
	r.Keys = nil
	r.WrapID = nil
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// deriveProtector derives the 32-byte envelope protector. Exactly one of
// master (direct-HKDF) or passphrase (Argon2id) must unlock the header KDF.
func deriveProtector(kdf uint8, master []byte, passphrase []byte, salt []byte, aTime, aMem uint32, aThreads uint8, storeID, contextID [16]byte) ([32]byte, error) {
	var out [32]byte
	info := make([]byte, 0, len(keysEncInfo)+32)
	info = append(info, keysEncInfo...)
	info = append(info, storeID[:]...)
	info = append(info, contextID[:]...)
	switch kdf {
	case KDFDirectHKDF:
		if len(master) != keyLen {
			return out, ErrAuth
		}
		dk, err := hkdf.Key(sha256.New, master, salt, string(info), keyLen)
		if err != nil {
			return out, ErrCorrupt
		}
		copy(out[:], dk)
		wipe(dk)
		return out, nil
	case KDFArgon2ID:
		if len(passphrase) == 0 {
			return out, ErrAuth
		}
		if aThreads == 0 || aTime == 0 || aMem == 0 {
			return out, ErrCorrupt
		}
		stretched := argon2.IDKey(passphrase, salt, aTime, aMem, aThreads, keyLen)
		dk, err := hkdf.Key(sha256.New, stretched, salt, string(info), keyLen)
		wipe(stretched)
		if err != nil {
			return out, ErrCorrupt
		}
		copy(out[:], dk)
		wipe(dk)
		return out, nil
	default:
		return out, ErrCorrupt
	}
}

func aesGCM(key [32]byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// SealOptions seals one envelope revision with fresh salt and nonce.
type SealOptions struct {
	KDF            uint8
	Seq            uint64
	StoreID        [16]byte
	ContextID      [16]byte
	WrapID         []byte
	ArgonTime      uint32
	ArgonMemoryKiB uint32
	ArgonThreads   uint8
	Master         []byte // exactly one of Master / Passphrase
	Passphrase     []byte
	Keys           []KeyEntry
}

// Seal encodes keys into a keys.enc v3 envelope. Keys are id-sorted on
// the wire; duplicate ids are rejected.
func Seal(o SealOptions) ([]byte, error) {
	if o.KDF != KDFDirectHKDF && o.KDF != KDFArgon2ID {
		return nil, ErrMisuse
	}
	if len(o.WrapID) > maxWrapIDLen || len(o.Keys) == 0 || len(o.Keys) > maxDataKeys {
		return nil, ErrMisuse
	}
	keys := append([]KeyEntry(nil), o.Keys...)
	sort.Slice(keys, func(i, j int) bool { return keys[i].ID < keys[j].ID })
	for i := 1; i < len(keys); i++ {
		if keys[i].ID == keys[i-1].ID {
			return nil, ErrMisuse
		}
	}
	var salt [32]byte
	if _, err := io.ReadFull(rand.Reader, salt[:]); err != nil {
		return nil, err
	}
	protector, err := deriveProtector(o.KDF, o.Master, o.Passphrase, salt[:], o.ArgonTime, o.ArgonMemoryKiB, o.ArgonThreads, o.StoreID, o.ContextID)
	if err != nil {
		return nil, err
	}
	defer wipe(protector[:])

	body := make([]byte, 0, 4+16+1+len(o.WrapID)+len(keys)*(4+8+1+32))
	var tmp [8]byte
	binary.LittleEndian.PutUint32(tmp[:4], uint32(len(keys)))
	body = append(body, tmp[:4]...)
	body = append(body, o.ContextID[:]...)
	body = append(body, byte(len(o.WrapID)))
	body = append(body, o.WrapID...)
	for _, k := range keys {
		binary.LittleEndian.PutUint32(tmp[:4], k.ID)
		body = append(body, tmp[:4]...)
		binary.LittleEndian.PutUint64(tmp[:], uint64(k.CreatedAt))
		body = append(body, tmp[:]...)
		if k.Active {
			body = append(body, 0)
		} else {
			body = append(body, 1)
		}
		body = append(body, k.Key[:]...)
	}
	defer wipe(body)

	hdr := make([]byte, 0, 61+len(o.WrapID))
	hdr = append(hdr, keysMagic...)
	hdr = append(hdr, 0, 0)
	binary.LittleEndian.PutUint16(hdr[4:6], keysVersion)
	hdr = append(hdr, o.KDF)
	hdr = append(hdr, 0, 0, 0, 0, 0, 0, 0, 0)
	binary.LittleEndian.PutUint64(hdr[7:15], o.Seq)
	hdr = append(hdr, salt[:]...)
	hdr = append(hdr, 0, 0, 0, 0)
	binary.LittleEndian.PutUint32(hdr[47:51], o.ArgonTime)
	hdr = append(hdr, 0, 0, 0, 0)
	binary.LittleEndian.PutUint32(hdr[51:55], o.ArgonMemoryKiB)
	hdr = append(hdr, o.ArgonThreads)
	hdr = append(hdr, byte(len(o.WrapID)))
	hdr = append(hdr, o.WrapID...)
	var crc [4]byte
	binary.LittleEndian.PutUint32(crc[:], crc32.Checksum(hdr, castagnoli))
	hdr = append(hdr, crc[:]...)

	var nonce [12]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return nil, err
	}
	aad := make([]byte, 0, len(hdr)+id16Len)
	aad = append(aad, hdr...)
	aad = append(aad, o.StoreID[:]...)
	aead, err := aesGCM(protector)
	if err != nil {
		return nil, err
	}
	sealed := aead.Seal(nil, nonce[:], body, aad)

	envelope := make([]byte, 0, len(hdr)+keysNonce+4+len(sealed))
	envelope = append(envelope, hdr...)
	envelope = append(envelope, nonce[:]...)
	var slen [4]byte
	binary.LittleEndian.PutUint32(slen[:], uint32(len(sealed)))
	envelope = append(envelope, slen[:]...)
	envelope = append(envelope, sealed...)
	return envelope, nil
}

// Open authenticates a keys.enc v3 envelope and returns the unlocked ring.
// Exactly one protector must match the header KDF: a 32-byte master for
// direct-HKDF envelopes or a non-empty passphrase for Argon2id ones.
func Open(envelope, master, passphrase []byte, storeID, contextID [16]byte) (*Keyring, error) {
	if len(envelope) < 61 {
		return nil, ErrCorrupt
	}
	if string(envelope[0:4]) != keysMagic {
		return nil, ErrCorrupt
	}
	if binary.LittleEndian.Uint16(envelope[4:6]) != keysVersion {
		return nil, ErrCorrupt
	}
	kdf := envelope[6]
	if kdf != KDFDirectHKDF && kdf != KDFArgon2ID {
		return nil, ErrCorrupt
	}
	wrapLen := int(envelope[56])
	if wrapLen > maxWrapIDLen || len(envelope) < 61+wrapLen {
		return nil, ErrCorrupt
	}
	hdrLen := 61 + wrapLen
	want := binary.LittleEndian.Uint32(envelope[57+wrapLen : hdrLen])
	if crc32.Checksum(envelope[:57+wrapLen], castagnoli) != want {
		return nil, ErrCorrupt
	}
	if len(envelope) < hdrLen+keysNonce+4 {
		return nil, ErrCorrupt
	}
	seq := binary.LittleEndian.Uint64(envelope[7:15])
	salt := envelope[15:47]
	aTime := binary.LittleEndian.Uint32(envelope[47:51])
	aMem := binary.LittleEndian.Uint32(envelope[51:55])
	aThreads := envelope[55]
	protector, err := deriveProtector(kdf, master, passphrase, salt, aTime, aMem, aThreads, storeID, contextID)
	if err != nil {
		return nil, err
	}
	defer wipe(protector[:])

	off := hdrLen
	nonce := envelope[off : off+keysNonce]
	off += keysNonce
	sealedLen := binary.LittleEndian.Uint32(envelope[off : off+4])
	off += 4
	if sealedLen > maxSealed || uint64(len(envelope[off:])) != uint64(sealedLen) {
		return nil, ErrCorrupt
	}
	aad := make([]byte, 0, hdrLen+id16Len)
	aad = append(aad, envelope[:hdrLen]...)
	aad = append(aad, storeID[:]...)
	aead, err := aesGCM(protector)
	if err != nil {
		return nil, ErrCorrupt
	}
	body, err := aead.Open(nil, nonce, envelope[off:], aad)
	if err != nil {
		return nil, ErrAuth
	}
	defer wipe(body)
	if len(body) < 4+16+1 {
		return nil, ErrCorrupt
	}
	count := binary.LittleEndian.Uint32(body[:4])
	if count == 0 || count > maxDataKeys {
		return nil, ErrCorrupt
	}
	var context [16]byte
	copy(context[:], body[4:20])
	if context != contextID {
		return nil, ErrCorrupt
	}
	w := int(body[20])
	if w > maxWrapIDLen || len(body) < 21+w {
		return nil, ErrCorrupt
	}
	const entryLen = 4 + 8 + 1 + 32
	if uint64(len(body[21+w:])) != uint64(count)*entryLen {
		return nil, ErrCorrupt
	}
	ring := &Keyring{
		Seq:            seq,
		KDF:            kdf,
		ArgonTime:      aTime,
		ArgonMemoryKiB: aMem,
		ArgonThreads:   aThreads,
		Context:        context,
		WrapID:         append([]byte(nil), body[21:21+w]...),
		Keys:           make([]KeyEntry, 0, count),
	}
	pos := 21 + w
	seen := make(map[uint32]bool, count)
	for i := uint32(0); i < count; i++ {
		e := body[pos : pos+entryLen]
		pos += entryLen
		id := binary.LittleEndian.Uint32(e[0:4])
		var active bool
		switch e[12] {
		case 0:
			active = true
		case 1:
			active = false
		default:
			return nil, ErrCorrupt
		}
		if id == 0 || seen[id] {
			return nil, ErrCorrupt
		}
		seen[id] = true
		var key [32]byte
		copy(key[:], e[13:45])
		if active && id > ring.Current {
			ring.Current = id
		}
		ring.Keys = append(ring.Keys, KeyEntry{
			ID:        id,
			Key:       key,
			CreatedAt: int64(binary.LittleEndian.Uint64(e[4:12])),
			Active:    active,
		})
	}
	if ring.Current == 0 {
		return nil, ErrCorrupt
	}
	sort.Slice(ring.Keys, func(i, j int) bool { return ring.Keys[i].ID < ring.Keys[j].ID })
	return ring, nil
}

// CreateOptions seals a fresh envelope: single active key id 1, sequence 1.
type CreateOptions struct {
	KDF            uint8
	ArgonTime      uint32
	ArgonMemoryKiB uint32
	ArgonThreads   uint8
	WrapID         []byte
	StoreID        [16]byte
	ContextID      [16]byte
	Master         []byte
	Passphrase     []byte
}

// Create seals a fresh single-key envelope.
func Create(o CreateOptions) ([]byte, error) {
	if o.KDF != KDFDirectHKDF && o.KDF != KDFArgon2ID {
		return nil, ErrMisuse
	}
	if o.KDF == KDFDirectHKDF && (o.ArgonTime != 0 || o.ArgonMemoryKiB != 0 || o.ArgonThreads != 0) {
		return nil, ErrMisuse
	}
	if o.KDF == KDFArgon2ID && (o.ArgonTime == 0 || o.ArgonMemoryKiB == 0 || o.ArgonThreads == 0) {
		return nil, ErrMisuse
	}
	var first [32]byte
	if _, err := io.ReadFull(rand.Reader, first[:]); err != nil {
		return nil, err
	}
	defer wipe(first[:])
	return Seal(SealOptions{
		KDF:            o.KDF,
		Seq:            1,
		StoreID:        o.StoreID,
		ContextID:      o.ContextID,
		WrapID:         o.WrapID,
		ArgonTime:      o.ArgonTime,
		ArgonMemoryKiB: o.ArgonMemoryKiB,
		ArgonThreads:   o.ArgonThreads,
		Master:         o.Master,
		Passphrase:     o.Passphrase,
		Keys:           []KeyEntry{{ID: 1, Key: first, Active: true}},
	})
}

// Rotate stages a successor key and seals the new envelope WITHOUT
// installing it. The current key retires; the fresh key id is returned
// alongside the envelope bytes.
func (r *Keyring) Rotate(storeID [16]byte, master, passphrase []byte) ([]byte, uint32, error) {
	if len(r.Keys) == 0 || r.Current == 0 {
		return nil, 0, ErrMisuse
	}
	var next uint32 = 1
	for _, k := range r.Keys {
		if k.ID >= next {
			next = k.ID + 1
		}
	}
	if next == 0 {
		return nil, 0, errors.New("storage: key id space exhausted")
	}
	if len(r.Keys)+1 > maxDataKeys {
		return nil, 0, ErrCorrupt
	}
	staged := append([]KeyEntry(nil), r.Keys...)
	for i := range staged {
		if staged[i].ID == r.Current {
			staged[i].Active = false
		}
	}
	var fresh [32]byte
	if _, err := io.ReadFull(rand.Reader, fresh[:]); err != nil {
		return nil, 0, err
	}
	defer wipe(fresh[:])
	staged = append(staged, KeyEntry{ID: next, Key: fresh, Active: true})
	env, err := Seal(SealOptions{
		KDF:            r.KDF,
		Seq:            r.Seq + 1,
		StoreID:        storeID,
		ContextID:      r.Context,
		WrapID:         r.WrapID,
		ArgonTime:      r.ArgonTime,
		ArgonMemoryKiB: r.ArgonMemoryKiB,
		ArgonThreads:   r.ArgonThreads,
		Master:         master,
		Passphrase:     passphrase,
		Keys:           staged,
	})
	if err != nil {
		return nil, 0, err
	}
	return env, next, nil
}

// DropKeys seals a new envelope without the listed retired ids. Active
// keys and the current key are refused.
func (r *Keyring) DropKeys(drop []uint32, storeID [16]byte, master, passphrase []byte) ([]byte, error) {
	if len(drop) == 0 || len(r.Keys) == 0 || r.Current == 0 {
		return nil, ErrMisuse
	}
	kept := make([]KeyEntry, 0, len(r.Keys))
	for _, k := range r.Keys {
		dropped := false
		for _, id := range drop {
			if id != k.ID {
				continue
			}
			if k.Active || k.ID == r.Current {
				return nil, ErrMisuse
			}
			dropped = true
			break
		}
		if !dropped {
			kept = append(kept, k)
		}
	}
	return Seal(SealOptions{
		KDF:            r.KDF,
		Seq:            r.Seq + 1,
		StoreID:        storeID,
		ContextID:      r.Context,
		WrapID:         r.WrapID,
		ArgonTime:      r.ArgonTime,
		ArgonMemoryKiB: r.ArgonMemoryKiB,
		ArgonThreads:   r.ArgonThreads,
		Master:         master,
		Passphrase:     passphrase,
		Keys:           kept,
	})
}
