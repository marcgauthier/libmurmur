// Package scrypt derives password keys using libmurmur's AWS-LC backend.
package scrypt

/*
#cgo CFLAGS: -I../../../../deps/keyring
#cgo LDFLAGS: ${SRCDIR}/../../../../libmurmur.a -lstdc++ -lpthread -ldl -lm
#include "scrypt.h"
*/
import "C"
import (
	"errors"
	"unsafe"
)

func bytesPtr(b []byte) *C.uint8_t {
	if len(b) == 0 {
		return nil
	}
	return (*C.uint8_t)(unsafe.Pointer(&b[0]))
}
func Key(pass, salt []byte, n, r, p, length int) ([]byte, error) {
	if n < 2 || uint64(n) > 0xffffffff || r < 1 || r > 32 || p < 1 || p > 16 || length < 1 || length > 1024 {
		return nil, errors.New("scrypt: invalid parameters")
	}
	out := make([]byte, length)
	if C.murmur_scrypt_derive(bytesPtr(pass), C.size_t(len(pass)), bytesPtr(salt), C.size_t(len(salt)), C.uint32_t(n), C.uint32_t(r), C.uint8_t(p), bytesPtr(out), C.size_t(length)) != 0 {
		return nil, errors.New("scrypt: invalid parameters or derivation failed")
	}
	return out, nil
}
