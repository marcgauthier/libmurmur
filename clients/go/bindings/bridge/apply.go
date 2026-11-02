package bridge

/*
#include <stdlib.h>
#include "bridge_store.h"
#include "sqlite3.h"
extern int goBridgeApply(uintptr_t,murmur_bridge_header_t *,void *,size_t);
static int bridgeGoApply(sqlite3 *db,const murmur_bridge_header_t *h,const void *data,size_t len,void *ctx) {
  (void)db;
  return goBridgeApply((uintptr_t)ctx,(murmur_bridge_header_t *)h,(void *)data,len);
}
static int bridgeApply(sqlite3 *db,const uint8_t *source,const char *stream,
    const uint8_t *signer,const uint8_t *receiver,const uint8_t *schema,
    size_t mb,size_t mp,uintptr_t handle) {
  return murmur_bridge_store_apply(db,source,stream,signer,receiver,schema,
      mb,mp,bridgeGoApply,(void *)handle);
}
*/
import "C"

import (
	"errors"
	"runtime/cgo"
	"unsafe"

	"github.com/marcgauthier/libmurmur/clients/go/bindings/sqlite"
)

type applyCall struct {
	fn  func(Header, []byte) error
	err error
}

//export goBridgeApply
func goBridgeApply(handle C.uintptr_t, h *C.murmur_bridge_header_t, data unsafe.Pointer, size C.size_t) (rc C.int) {
	call := cgo.Handle(handle).Value().(*applyCall)
	rc = C.SQLITE_ABORT
	defer func() {
		if recover() != nil {
			call.err = errors.New("bridge: apply callback panicked")
			rc = C.SQLITE_ABORT
		}
	}()
	call.err = call.fn(header(h), C.GoBytes(data, C.int(size)))
	if call.err == nil {
		return C.SQLITE_OK
	}
	return C.SQLITE_ABORT
}

// Apply imports the next contiguous artifact under a native transaction. The
// callback may execute SQL on the borrowed connection, but must not change
// transaction state, call back into the SQL pool, or retain the connection.
// Callback errors roll back imported effects and replay receipts together.
// SQLITE_NOTFOUND means no contiguous artifact; SQLITE_SCHEMA means held work.
func Apply(db *sqlite.Conn, source [16]byte, stream string, signer, receiver, schema [32]byte, fn func(Header, []byte) error) error {
	if _, err := native(Header{Stream: stream}); err != nil {
		return err
	}
	if db == nil || fn == nil {
		return &Error{Code: int(C.SQLITE_MISUSE)}
	}
	s := C.CString(stream)
	defer C.free(unsafe.Pointer(s))
	call := &applyCall{fn: fn}
	handle := cgo.NewHandle(call)
	defer handle.Delete()
	rc := C.bridgeApply((*C.sqlite3)(db.NativeDB()), (*C.uint8_t)(unsafe.Pointer(&source[0])), s,
		(*C.uint8_t)(unsafe.Pointer(&signer[0])), (*C.uint8_t)(unsafe.Pointer(&receiver[0])),
		(*C.uint8_t)(unsafe.Pointer(&schema[0])), MaxBundle, MaxPayload, C.uintptr_t(handle))
	if call.err != nil {
		return call.err
	}
	return result(rc)
}
