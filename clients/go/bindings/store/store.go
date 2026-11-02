// Package store binds live store operations (backup) for Go
// orchestration.
package store

/*
#cgo CFLAGS: -I../../../.. -I../../../../deps/murmur -O2
#cgo LDFLAGS: ${SRCDIR}/../../../../libmurmur.a -lstdc++ -lpthread -ldl -lm
#include <stdlib.h>
#include "open.h"
*/
import "C"

import (
	"fmt"
	"github.com/marcgauthier/libmurmur/clients/go/bindings/nvfs"
	"unsafe"
)

// Backup checkpoints the live store at dir (keyed) plus a manifest
// into dest. group/node are the 16-byte replication identities.
func Backup(dir string, key [32]byte, dest string, group, node [16]byte) error {
	defer clear(key[:])
	return backup(dir, &key, dest, group, node)
}

// BackupLive checkpoints an authenticated store already open in this process.
// No password copy is needed: the retained native store owns its active keys.
func BackupLive(dir, dest string, group, node [16]byte) error {
	if !nvfs.StoreIsLive(dir) {
		return fmt.Errorf("backup requires a live authenticated store")
	}
	return backup(dir, nil, dest, group, node)
}

func backup(dir string, key *[32]byte, dest string, group, node [16]byte) error {
	cdir := C.CString(dir)
	defer C.free(unsafe.Pointer(cdir))
	var h C.uint64_t
	var db, store unsafe.Pointer
	if rc := C.nvOpenStoreRef(cdir, 0, 0, &h, &db, &store); rc != 0 {
		return fmt.Errorf("backup open %s: rc=%d", dir, int(rc))
	}
	defer C.nvCloseStoreRef(h)
	if key != nil {
		if rc := C.nvStoreKey(h, (*C.uint8_t)(unsafe.Pointer(&key[0]))); rc != 0 {
			return fmt.Errorf("backup key: rc=%d", int(rc))
		}
	}
	if rc := C.nvStoreFlush(h); rc != 0 {
		return fmt.Errorf("backup flush: rc=%d", int(rc))
	}
	// Cipher token from the live store (falls back to aes256gcm).
	cipher := "aes256gcm"
	var cbuf [64]C.char
	var clen C.size_t
	cname := C.CString("cipher")
	if rc := C.nvPragmaStore(h, cname, nil, 0, 0, &cbuf[0], 64, &clen); rc == 0 && clen > 0 && clen < 64 {
		cbuf[clen] = 0
		cipher = C.GoString(&cbuf[0])
	}
	C.free(unsafe.Pointer(cname))
	cdest := C.CString(dest)
	defer C.free(unsafe.Pointer(cdest))
	ccipher := C.CString(cipher)
	defer C.free(unsafe.Pointer(ccipher))
	rc := C.nvStoreBackup(h, cdest, ccipher,
		(*C.uint8_t)(unsafe.Pointer(&group[0])),
		(*C.uint8_t)(unsafe.Pointer(&node[0])))
	if rc != 0 {
		return fmt.Errorf("backup %s -> %s: rc=%d", dir, dest, int(rc))
	}
	return nil
}

// Flush synchronizes all committed pages of an already open native store.
// Callers must hold writer admission while establishing the commit boundary.
func Flush(dir string) error {
	cdir := C.CString(dir)
	defer C.free(unsafe.Pointer(cdir))
	var h C.uint64_t
	var db, nativeStore unsafe.Pointer
	if rc := C.nvOpenStoreRef(cdir, 0, 0, &h, &db, &nativeStore); rc != 0 {
		return fmt.Errorf("flush open %s: rc=%d", dir, int(rc))
	}
	defer C.nvCloseStoreRef(h)
	if rc := C.nvStoreFlush(h); rc != 0 {
		return fmt.Errorf("flush %s: rc=%d", dir, int(rc))
	}
	return nil
}

// EnsureSealed creates a direct keyring only if the authenticated live store
// has none. Reopening an already sealed store leaves its keyring unchanged.
func EnsureSealed(path string, key [32]byte) error {
	defer clear(key[:])
	ref, err := nvfs.OpenStoreRef(path, false, 0)
	if err != nil {
		return err
	}
	defer nvfs.CloseStoreRef(ref.Handle)
	if rc := nvfs.KeyStore(&ref, key); rc != 0 {
		return fmt.Errorf("key native store: rc=%d", rc)
	}
	state, rc := nvfs.StoreKdf(ref.Handle)
	if rc != 0 {
		return fmt.Errorf("read keyring: rc=%d", rc)
	}
	if state.Sealed {
		return nil
	}
	value := "direct"
	rc, _ = nvfs.PragmaStore(ref.Handle, "murmur_kdf", &value, false)
	if rc != 0 {
		return fmt.Errorf("seal native keyring: rc=%d", rc)
	}
	return nil
}
