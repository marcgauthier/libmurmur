// Package aegis binds the vendored libaegis AEGIS-256 AEAD. Only the
// standard library is used besides the vendored C sources.
package aegis

/*
#cgo CFLAGS: -O2 -I../../../../deps/aegis/src/include
#cgo LDFLAGS: ${SRCDIR}/../../../../libmurmur.a
#include <stdlib.h>
#include "aegis.h"
#include "aegis256.h"

static int goAegisInit(void) { return aegis_init(); }
static int goAegis256Encrypt(unsigned char *c, unsigned long long maclen,
    const unsigned char *m, unsigned long long mlen,
    const unsigned char *ad, unsigned long long adlen,
    const unsigned char *npub, const unsigned char *k) {
  return aegis256_encrypt(c, (size_t)maclen, m, (size_t)mlen, ad,
      (size_t)adlen, npub, k);
}
static int goAegis256Decrypt(unsigned char *m, const unsigned char *c,
    unsigned long long clen, unsigned long long maclen,
    const unsigned char *ad, unsigned long long adlen,
    const unsigned char *npub, const unsigned char *k) {
  return aegis256_decrypt(m, c, (size_t)clen, (size_t)maclen, ad,
      (size_t)adlen, npub, k);
}
*/
import "C"

import (
	"errors"
	"sync"
	"unsafe"
)

// NonceLen and TagLen are the AEGIS-256 nonce and maximum tag sizes.
const (
	NonceLen = 32
	TagLen   = 32
)

// ErrAuth reports authentication failure. It never carries plaintext.
var ErrAuth = errors.New("aegis: authentication failed")

var initOnce sync.Once
var initErr error

// Init initializes libaegis. It is idempotent and safe for concurrent use.
func Init() error {
	initOnce.Do(func() {
		if rc := C.goAegisInit(); rc != 0 {
			initErr = errors.New("aegis: init failed")
		}
	})
	return initErr
}

func ptr(b []byte) *C.uchar {
	if len(b) == 0 {
		return nil
	}
	return (*C.uchar)(unsafe.Pointer(&b[0]))
}

// Encrypt seals plaintext with AAD into out, appending a 32-byte tag.
// out must have room for len(plaintext)+TagLen; it returns the sealed slice.
func Encrypt(out, plaintext, aad []byte, nonce [NonceLen]byte, key [32]byte) ([]byte, error) {
	if err := Init(); err != nil {
		return nil, err
	}
	if len(out) < len(plaintext)+TagLen {
		return nil, errors.New("aegis: output too small")
	}
	rc := C.goAegis256Encrypt(ptr(out), TagLen, ptr(plaintext), C.ulonglong(len(plaintext)),
		ptr(aad), C.ulonglong(len(aad)), (*C.uchar)(unsafe.Pointer(&nonce[0])), (*C.uchar)(unsafe.Pointer(&key[0])))
	if rc != 0 {
		return nil, errors.New("aegis: encrypt failed")
	}
	return out[:len(plaintext)+TagLen], nil
}

// Decrypt opens sealed with AAD into out. out must have room for
// len(sealed)-TagLen; it returns the plaintext slice.
func Decrypt(out, sealed, aad []byte, nonce [NonceLen]byte, key [32]byte) ([]byte, error) {
	if err := Init(); err != nil {
		return nil, err
	}
	if len(sealed) < TagLen || len(out) < len(sealed)-TagLen {
		return nil, ErrAuth
	}
	rc := C.goAegis256Decrypt(ptr(out), ptr(sealed), C.ulonglong(len(sealed)), TagLen,
		ptr(aad), C.ulonglong(len(aad)), (*C.uchar)(unsafe.Pointer(&nonce[0])), (*C.uchar)(unsafe.Pointer(&key[0])))
	if rc != 0 {
		return nil, ErrAuth
	}
	return out[:len(sealed)-TagLen], nil
}
