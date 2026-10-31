package nvfs

// Test seam for the native C++ page codec: thin Go wrappers over the
// codec C API so maintained tests (which cannot use cgo directly) can
// drive it. Production code never calls these; the engine talks to the
// codec from C++ only.

/*
#include <stdlib.h>
#include <stdint.h>
#include "aesgcm.h"
#include "murmur_codec.h"
const char *nvCanonTest(const char *name);
void nvCanonTestFree(const char *p);
*/
import "C"

import (
	"unsafe"
)

func aesAvailable() bool { return C.murmur_aes_available() != 0 }

func aesBlock(key, in, out []byte) int {
	return int(C.murmur_aes256_block(
		(*C.uint8_t)(unsafe.Pointer(&key[0])),
		(*C.uint8_t)(unsafe.Pointer(&in[0])),
		(*C.uint8_t)(unsafe.Pointer(&out[0]))))
}

func aesGCMEncrypt(key, nonce, pt, aad []byte) (ct, tag []byte, rc int) {
	ct = make([]byte, len(pt))
	tag = make([]byte, 16)
	var ptPtr, ctPtr, aadPtr unsafe.Pointer
	if len(pt) > 0 {
		ptPtr = unsafe.Pointer(&pt[0])
		ctPtr = unsafe.Pointer(&ct[0])
	}
	if len(aad) > 0 {
		aadPtr = unsafe.Pointer(&aad[0])
	}
	rc = int(C.murmur_aes256gcm_encrypt(
		(*C.uint8_t)(unsafe.Pointer(&key[0])),
		(*C.uint8_t)(unsafe.Pointer(&nonce[0])),
		(*C.uint8_t)(ptPtr), C.size_t(len(pt)),
		(*C.uint8_t)(aadPtr), C.size_t(len(aad)),
		(*C.uint8_t)(ctPtr),
		(*C.uint8_t)(unsafe.Pointer(&tag[0]))))
	return ct, tag, rc
}

// Codec* wrappers drive the C++ page codec from maintained tests in
// other packages (storage differential tests). Test-only: production
// code talks to the codec from C++.

func CodecCreate(cipher, level int, pageKey []byte, sealed bool, active []byte,
	current uint32, retiredIDs []uint32, retiredKeys []byte, master []byte) unsafe.Pointer {
	var activePtr, idsPtr, keysPtr unsafe.Pointer
	sealedInt := 0
	if sealed {
		sealedInt = 1
		activePtr = unsafe.Pointer(&active[0])
	}
	if len(retiredIDs) > 0 {
		idsPtr = unsafe.Pointer(&retiredIDs[0])
		keysPtr = unsafe.Pointer(&retiredKeys[0])
	}
	return unsafe.Pointer(C.murmur_codec_create(C.int(cipher), C.int(level),
		(*C.uint8_t)(unsafe.Pointer(&pageKey[0])), C.int(sealedInt),
		(*C.uint8_t)(activePtr), C.uint32_t(current),
		(*C.uint32_t)(idsPtr), (*C.uint8_t)(keysPtr), C.size_t(len(retiredIDs)),
		(*C.uint8_t)(unsafe.Pointer(&master[0]))))
}

func CodecDestroy(h unsafe.Pointer) {
	C.murmur_codec_destroy((*C.struct_MurmurCodec)(h))
}

func CodecSeal(h unsafe.Pointer, page uint64, block []byte) ([]byte, int) {
	out := make([]byte, 8192)
	n := C.murmur_codec_seal((*C.struct_MurmurCodec)(h), C.uint64_t(page),
		(*C.uint8_t)(unsafe.Pointer(&block[0])),
		(*C.uint8_t)(unsafe.Pointer(&out[0])), C.size_t(len(out)), nil)
	if n < 0 {
		return nil, int(n)
	}
	return out[:int(n)], 0
}

func CodecOpen(h unsafe.Pointer, page uint64, rec []byte) ([]byte, int) {
	out := make([]byte, 4096)
	var recPtr unsafe.Pointer
	if len(rec) > 0 {
		recPtr = unsafe.Pointer(&rec[0])
	}
	n := C.murmur_codec_open((*C.struct_MurmurCodec)(h), C.uint64_t(page),
		(*C.uint8_t)(recPtr), C.size_t(len(rec)),
		(*C.uint8_t)(unsafe.Pointer(&out[0])), C.size_t(len(out)))
	if n < 0 {
		return nil, int(n)
	}
	return out[:int(n)], 0
}

func CodecSetCipher(h unsafe.Pointer, cipher int) int {
	return int(C.murmur_codec_set_cipher((*C.struct_MurmurCodec)(h), C.int(cipher)))
}

func CodecSetLevel(h unsafe.Pointer, level int) int {
	return int(C.murmur_codec_set_level((*C.struct_MurmurCodec)(h), C.int(level)))
}

func CodecInstallRing(h unsafe.Pointer, active []byte, current uint32,
	retiredIDs []uint32, retiredKeys []byte) int {
	var idsPtr, keysPtr unsafe.Pointer
	if len(retiredIDs) > 0 {
		idsPtr = unsafe.Pointer(&retiredIDs[0])
		keysPtr = unsafe.Pointer(&retiredKeys[0])
	}
	return int(C.murmur_codec_install_ring((*C.struct_MurmurCodec)(h),
		(*C.uint8_t)(unsafe.Pointer(&active[0])), C.uint32_t(current),
		(*C.uint32_t)(idsPtr), (*C.uint8_t)(keysPtr), C.size_t(len(retiredIDs))))
}

func aesGCMDecrypt(key, nonce, ct, tag, aad []byte) (pt []byte, rc int) {
	pt = make([]byte, len(ct))
	var ctPtr, ptPtr, aadPtr unsafe.Pointer
	if len(ct) > 0 {
		ctPtr = unsafe.Pointer(&ct[0])
		ptPtr = unsafe.Pointer(&pt[0])
	}
	if len(aad) > 0 {
		aadPtr = unsafe.Pointer(&aad[0])
	}
	rc = int(C.murmur_aes256gcm_decrypt(
		(*C.uint8_t)(unsafe.Pointer(&key[0])),
		(*C.uint8_t)(unsafe.Pointer(&nonce[0])),
		(*C.uint8_t)(ctPtr), C.size_t(len(ct)),
		(*C.uint8_t)(unsafe.Pointer(&tag[0])),
		(*C.uint8_t)(aadPtr), C.size_t(len(aad)),
		(*C.uint8_t)(ptPtr)))
	return pt, rc
}

// canonTestCPP canonicalizes one path through the C++ VFS
// canonicalizer (vfs.cc), for TestCanonDifferential. Empty return
// with ok=false means the C++ side returned nil.
func canonTestCPP(s string) (out string, ok bool) {
	cname := C.CString(s)
	defer C.free(unsafe.Pointer(cname))
	cout := C.nvCanonTest(cname)
	if cout == nil {
		return "", false
	}
	defer C.nvCanonTestFree(cout)
	return C.GoString(cout), true
}
