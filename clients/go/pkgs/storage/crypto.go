package storage

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"io"

	"github.com/marcgauthier/libmurmur/clients/go/bindings/zstd"
)

// Page-record formats. Layouts mirror the sqlite-murmur wire bytes:
//
//	Unkeyed (EXP1): magic[4] | flag[1] | nonce | ciphertext
//	Keyed   (EXP3): magic[4] | flag[1] | key id u32le | nonce | ciphertext
//
// flag 0x00 marks a raw page, 0x01 a zstd-compressed page. The page number
// is covered by the AEAD associated data but is not carried in the record;
// callers supply it. Nonces are random per seal (12 bytes AES-GCM,
// 32 bytes AES-256-GCM).
const (
	HeaderAES      = "EXP1"
	HeaderAESKeyed = "EXP3"

	FlagRaw        = 0x00
	FlagCompressed = 0x01

	AESGCMNonceLen = 12
	AESGCMTagLen   = 16

	// Block is the decrypted page size every record must produce.
	Block = 4096
	// Scratch bounds accepted plaintext like the Rust decoder.
	ScratchSize = 4175
)

// Cipher selects the page AEAD. Ids match the C ABI (murmur_cipher_t);
// Unspecified keeps plaintext pages and never seals.
type Cipher uint8

const (
	CipherAES256GCM   Cipher = 1
	CipherUnspecified Cipher = 255
)

// CipherName reports the PRAGMA cipher name.
func CipherName(c Cipher) string {
	switch c {
	case CipherAES256GCM:
		return "aes256gcm"
	default:
		return "unspecified"
	}
}

// PageKey builds the RocksDB key for a page: 'p' + big-endian u64.
func PageKey(page uint64) [9]byte {
	var out [9]byte
	out[0] = 'p'
	binary.BigEndian.PutUint64(out[1:], page)
	return out
}

// RecordKeyID peeks the data-key id of a keyed (EXP3) record. It
// reports false for legacy and corrupt records; callers route those
// through the legacy trial chain.
func RecordKeyID(record []byte) (uint32, bool) {
	if len(record) < 4 {
		return 0, false
	}
	exp3 := string(record[:4]) == HeaderAESKeyed
	if !exp3 {
		return 0, false
	}
	if exp3 && len(record) < 4+1+4+AESGCMNonceLen+AESGCMTagLen {
		return 0, false
	}
	return binary.LittleEndian.Uint32(record[5:9]), true
}

// IsLegacyRecord positively identifies unkeyed (EXP1) records.
func IsLegacyRecord(record []byte) bool {
	if len(record) < 4 {
		return false
	}
	if string(record[:4]) == HeaderAES {
		return len(record) >= 4+1+AESGCMNonceLen+AESGCMTagLen
	}
	return false
}

func aesAAD(flag byte, page uint64, keyID *uint32) []byte {
	aad := make([]byte, 0, 13)
	aad = append(aad, flag)
	var p [8]byte
	binary.BigEndian.PutUint64(p[:], page)
	aad = append(aad, p[:]...)
	if keyID != nil {
		var id [4]byte
		binary.LittleEndian.PutUint32(id[:], *keyID)
		aad = append(aad, id[:]...)
	}
	return aad
}

// Encrypt seals one page payload. keyID 0 selects the legacy unkeyed
// formats (EXP1); nonzero selects the sealed formats (EXP3).
// data must already be compressed when compressed is set.
func Encrypt(c Cipher, key [32]byte, page uint64, data []byte, compressed bool, keyID uint32) ([]byte, error) {
	if len(data) > 0x7fffffff {
		return nil, ErrMisuse
	}
	if keyID == 0 {
		return encryptUnkeyed(c, key, page, data, compressed)
	}
	return encryptKeyed(c, key, page, data, compressed, keyID)
}

func encryptUnkeyed(c Cipher, key [32]byte, page uint64, data []byte, compressed bool) ([]byte, error) {
	var flag byte
	if compressed {
		flag = FlagCompressed
	}
	switch c {
	case CipherAES256GCM:
		var nonce [AESGCMNonceLen]byte
		if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
			return nil, err
		}
		block, err := aes.NewCipher(key[:])
		if err != nil {
			return nil, err
		}
		aead, err := cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}
		sealed := aead.Seal(nil, nonce[:], data, aesAAD(flag, page, nil))
		out := make([]byte, 0, 5+AESGCMNonceLen+len(sealed))
		out = append(out, HeaderAES...)
		out = append(out, flag)
		out = append(out, nonce[:]...)
		out = append(out, sealed...)
		return out, nil
	default:
		return nil, ErrMisuse
	}
}

func encryptKeyed(c Cipher, key [32]byte, page uint64, data []byte, compressed bool, keyID uint32) ([]byte, error) {
	var flag byte
	if compressed {
		flag = FlagCompressed
	}
	switch c {
	case CipherAES256GCM:
		var nonce [AESGCMNonceLen]byte
		if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
			return nil, err
		}
		block, err := aes.NewCipher(key[:])
		if err != nil {
			return nil, err
		}
		aead, err := cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}
		sealed := aead.Seal(nil, nonce[:], data, aesAAD(flag, page, &keyID))
		out := make([]byte, 0, 9+AESGCMNonceLen+len(sealed))
		var id [4]byte
		binary.LittleEndian.PutUint32(id[:], keyID)
		out = append(out, HeaderAESKeyed...)
		out = append(out, flag)
		out = append(out, id[:]...)
		out = append(out, nonce[:]...)
		out = append(out, sealed...)
		return out, nil
	default:
		return nil, ErrMisuse
	}
}

func finishDecrypt(compressed bool, plain []byte) ([]byte, error) {
	if !compressed {
		if len(plain) != Block {
			return nil, ErrCorrupt
		}
		return append([]byte(nil), plain...), nil
	}
	out, err := zstd.Decompress(plain, Block)
	if err != nil {
		return nil, ErrCorrupt
	}
	if len(out) != Block {
		return nil, ErrCorrupt
	}
	return out, nil
}

func decryptAESToPlain(key [32]byte, keyed bool, page uint64, record []byte) (bool, []byte, error) {
	headerLen := 5
	magic := HeaderAES
	if keyed {
		headerLen = 9
		magic = HeaderAESKeyed
	}
	if len(record) < headerLen+AESGCMNonceLen+AESGCMTagLen || string(record[:4]) != magic {
		return false, nil, ErrCorrupt
	}
	flag := record[4]
	if flag > 1 {
		return false, nil, ErrCorrupt
	}
	var keyID *uint32
	if keyed {
		id := binary.LittleEndian.Uint32(record[5:9])
		keyID = &id
	}
	payloadSize := len(record) - headerLen - AESGCMNonceLen - AESGCMTagLen
	if payloadSize > zstd.CompressBound(Block) {
		return false, nil, ErrCorrupt
	}
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return false, nil, ErrCorrupt
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return false, nil, ErrCorrupt
	}
	plain, err := aead.Open(nil, record[headerLen:headerLen+AESGCMNonceLen], record[headerLen+AESGCMNonceLen:], aesAAD(flag, page, keyID))
	if err != nil {
		return false, nil, ErrAuth
	}
	if len(plain) > ScratchSize {
		return false, nil, ErrCorrupt
	}
	return flag != 0, plain, nil
}

// Decrypt opens one page record into a fresh block. It dispatches on magic
// (EXP3 go keyed); unknown magic fails closed. Authentication,
// bounds, flag, size, and decompression failures all fail closed.
func Decrypt(c Cipher, key [32]byte, page uint64, record []byte) ([]byte, error) {
	switch c {
	case CipherAES256GCM:
		keyed := len(record) >= 4 && string(record[:4]) == HeaderAESKeyed
		compressed, plain, err := decryptAESToPlain(key, keyed, page, record)
		if err != nil {
			return nil, err
		}
		return finishDecrypt(compressed, plain)
	default:
		return nil, ErrMisuse
	}
}
