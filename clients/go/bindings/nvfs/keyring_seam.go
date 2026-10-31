package nvfs

/*
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

int murmur_kr_open_flat(const uint8_t *env, size_t env_len,
                        const uint8_t *master, size_t master_len,
                        const uint8_t *pass, size_t pass_len,
                        const uint8_t store_id[16], const uint8_t context_id[16],
                        uint8_t **out_flat, size_t *out_len);
int murmur_kr_seal_flat(uint8_t kdf, uint64_t seq, const uint8_t store_id[16],
                        const uint8_t context_id[16], const uint8_t *wrap_id,
                        size_t wrap_len, uint32_t argon_time,
                        uint32_t argon_mem_kib, uint8_t argon_threads,
                        const uint8_t *master, size_t master_len,
                        const uint8_t *pass, size_t pass_len,
                        const uint8_t *flat_keys, size_t nkeys,
                        uint8_t **out_env, size_t *out_len);
int murmur_kr_rotate_flat(const uint8_t *env, size_t env_len,
                          const uint8_t store_id[16],
                          const uint8_t context_id[16], const uint8_t *master,
                          size_t master_len, const uint8_t *pass,
                          size_t pass_len, uint8_t **out_env, size_t *out_len,
                          uint32_t *out_next);
int murmur_kr_drop_flat(const uint8_t *env, size_t env_len,
                        const uint32_t *drop_ids, size_t ndrop,
                        const uint8_t store_id[16], const uint8_t context_id[16],
                        const uint8_t *master, size_t master_len,
                        const uint8_t *pass, size_t pass_len,
                        uint8_t **out_env, size_t *out_len);
void murmur_kr_free(void *p);
*/
import "C"

import "unsafe"

// Keyring test seam: thin wrappers over the C++ keys.enc v3 flat
// test API, used only by keyring_diff_test.go (like canonTestCPP).
// Production code paths call the C++ keyring directly (open.cc).
// Exported only because the external test package needs them.

// KrTestAESAvailable reports whether the C++ AES-GCM backend is
// usable (always true: AWS-LC is linked unconditionally).
func KrTestAESAvailable() bool { return aesAvailable() }

func krCBytes(b []byte) (unsafe.Pointer, C.size_t) {
	if len(b) == 0 {
		return nil, 0
	}
	return C.CBytes(b), C.size_t(len(b))
}

func KrTestOpen(env, master, pass, sid, ctx []byte) (flat []byte, rc int) {
	cenv, cen := krCBytes(env)
	if cenv != nil {
		defer C.free(cenv)
	}
	cm, cml := krCBytes(master)
	if cm != nil {
		defer C.free(cm)
	}
	cp, cpl := krCBytes(pass)
	if cp != nil {
		defer C.free(cp)
	}
	csid, _ := krCBytes(sid)
	if csid != nil {
		defer C.free(csid)
	}
	cctx, _ := krCBytes(ctx)
	if cctx != nil {
		defer C.free(cctx)
	}
	var out *C.uint8_t
	var outLen C.size_t
	rc = int(C.murmur_kr_open_flat((*C.uint8_t)(cenv), cen, (*C.uint8_t)(cm), cml,
		(*C.uint8_t)(cp), cpl, (*C.uint8_t)(csid), (*C.uint8_t)(cctx), &out, &outLen))
	if rc != 0 || out == nil {
		return nil, rc
	}
	defer C.murmur_kr_free(unsafe.Pointer(out))
	return C.GoBytes(unsafe.Pointer(out), C.int(outLen)), rc
}

func KrTestSeal(kdf uint8, seq uint64, sid, ctx, wrap, master, pass []byte, atime, amem uint32, athreads uint8, flatKeys []byte, nkeys int) (env []byte, rc int) {
	cf, _ := krCBytes(flatKeys)
	if cf != nil {
		defer C.free(cf)
	}
	cw, cwl := krCBytes(wrap)
	if cw != nil {
		defer C.free(cw)
	}
	cm, cml := krCBytes(master)
	if cm != nil {
		defer C.free(cm)
	}
	cp, cpl := krCBytes(pass)
	if cp != nil {
		defer C.free(cp)
	}
	csid := C.CBytes(sid)
	defer C.free(csid)
	cctx := C.CBytes(ctx)
	defer C.free(cctx)
	var out *C.uint8_t
	var outLen C.size_t
	rc = int(C.murmur_kr_seal_flat(C.uint8_t(kdf), C.uint64_t(seq), (*C.uint8_t)(csid),
		(*C.uint8_t)(cctx), (*C.uint8_t)(cw), cwl, C.uint32_t(atime), C.uint32_t(amem),
		C.uint8_t(athreads), (*C.uint8_t)(cm), cml, (*C.uint8_t)(cp), cpl,
		(*C.uint8_t)(cf), C.size_t(nkeys), &out, &outLen))
	if rc != 0 || out == nil {
		return nil, rc
	}
	defer C.murmur_kr_free(unsafe.Pointer(out))
	return C.GoBytes(unsafe.Pointer(out), C.int(outLen)), rc
}

func KrTestRotate(env, sid, ctx, master, pass []byte) (out []byte, next uint32, rc int) {
	cenv := C.CBytes(env)
	defer C.free(cenv)
	csid := C.CBytes(sid)
	defer C.free(csid)
	cctx := C.CBytes(ctx)
	defer C.free(cctx)
	cm, cml := krCBytes(master)
	if cm != nil {
		defer C.free(cm)
	}
	cp, cpl := krCBytes(pass)
	if cp != nil {
		defer C.free(cp)
	}
	var cout *C.uint8_t
	var outLen C.size_t
	var cnext C.uint32_t
	rc = int(C.murmur_kr_rotate_flat((*C.uint8_t)(cenv), C.size_t(len(env)),
		(*C.uint8_t)(csid), (*C.uint8_t)(cctx), (*C.uint8_t)(cm), cml,
		(*C.uint8_t)(cp), cpl, &cout, &outLen, &cnext))
	if rc != 0 || cout == nil {
		return nil, 0, rc
	}
	defer C.murmur_kr_free(unsafe.Pointer(cout))
	return C.GoBytes(unsafe.Pointer(cout), C.int(outLen)), uint32(cnext), rc
}

func KrTestDrop(env []byte, drop []uint32, sid, ctx, master, pass []byte) (out []byte, rc int) {
	cenv := C.CBytes(env)
	defer C.free(cenv)
	csid := C.CBytes(sid)
	defer C.free(csid)
	cctx := C.CBytes(ctx)
	defer C.free(cctx)
	cm, cml := krCBytes(master)
	if cm != nil {
		defer C.free(cm)
	}
	cp, cpl := krCBytes(pass)
	if cp != nil {
		defer C.free(cp)
	}
	var cdrop *C.uint32_t
	if len(drop) > 0 {
		cdrop = (*C.uint32_t)(C.CBytes(unsafe.Slice((*byte)(unsafe.Pointer(&drop[0])), len(drop)*4)))
		defer C.free(unsafe.Pointer(cdrop))
	}
	var cout *C.uint8_t
	var outLen C.size_t
	rc = int(C.murmur_kr_drop_flat((*C.uint8_t)(cenv), C.size_t(len(env)), cdrop, C.size_t(len(drop)),
		(*C.uint8_t)(csid), (*C.uint8_t)(cctx), (*C.uint8_t)(cm), cml,
		(*C.uint8_t)(cp), cpl, &cout, &outLen))
	if rc != 0 || cout == nil {
		return nil, rc
	}
	defer C.murmur_kr_free(unsafe.Pointer(cout))
	return C.GoBytes(unsafe.Pointer(cout), C.int(outLen)), rc
}
