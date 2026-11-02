// Package bridge binds the native HighLow envelope and transactional queue.
// It also exposes typed ownership, automatic capture and native ferry workers.
package bridge

/*
#cgo CFLAGS: -I../../../../deps/murmur -I../../../../deps/sqlite
#cgo LDFLAGS: ${SRCDIR}/../../../../libmurmur.a -lstdc++ -lpthread -ldl -lm
#include <stdlib.h>
#include "bridge_codec.h"
#include "bridge_store.h"
#include "bridge_publish.h"
#include "sqlite3.h"
*/
import "C"

import (
	"fmt"
	"strings"
	"unsafe"

	"github.com/marcgauthier/libmurmur/clients/go/bindings/sqlite"
)

const (
	MaxBundle      = 16 << 20
	MaxPayload     = 64 << 20
	DefaultStaging = 1 << 30
)

type Header struct {
	Database, Node, Transaction [16]byte
	Sequence                    uint64
	Stream                      string
	Schema                      [32]byte
}

// Error contains the native SQLite result code. No keys or payloads are
// included in errors.
type Error struct{ Code int }

func (e *Error) Error() string { return fmt.Sprintf("bridge: native result %d", e.Code) }
func result(rc C.int) error {
	if rc == C.SQLITE_OK {
		return nil
	}
	return &Error{Code: int(rc)}
}
func pointer(b []byte) unsafe.Pointer {
	if len(b) == 0 {
		return nil
	}
	return unsafe.Pointer(&b[0])
}
func native(h Header) (C.murmur_bridge_header_t, error) {
	var out C.murmur_bridge_header_t
	if len(h.Stream) == 0 || len(h.Stream) > 64 || strings.IndexByte(h.Stream, 0) >= 0 {
		return out, &Error{Code: int(C.SQLITE_MISUSE)}
	}
	copy(unsafe.Slice((*byte)(unsafe.Pointer(&out.database[0])), 16), h.Database[:])
	copy(unsafe.Slice((*byte)(unsafe.Pointer(&out.node[0])), 16), h.Node[:])
	copy(unsafe.Slice((*byte)(unsafe.Pointer(&out.transaction[0])), 16), h.Transaction[:])
	copy(unsafe.Slice((*byte)(unsafe.Pointer(&out.schema[0])), 32), h.Schema[:])
	copy(unsafe.Slice((*byte)(unsafe.Pointer(&out.stream[0])), 65), h.Stream)
	out.sequence = C.uint64_t(h.Sequence)
	return out, nil
}
func header(h *C.murmur_bridge_header_t) Header {
	var out Header
	copy(out.Database[:], unsafe.Slice((*byte)(unsafe.Pointer(&h.database[0])), 16))
	copy(out.Node[:], unsafe.Slice((*byte)(unsafe.Pointer(&h.node[0])), 16))
	copy(out.Transaction[:], unsafe.Slice((*byte)(unsafe.Pointer(&h.transaction[0])), 16))
	copy(out.Schema[:], unsafe.Slice((*byte)(unsafe.Pointer(&h.schema[0])), 32))
	out.Sequence = uint64(h.sequence)
	out.Stream = C.GoString(&h.stream[0])
	return out
}
func bytes(b *C.murmur_bridge_bytes_t) []byte {
	defer C.murmur_bridge_bytes_free(b)
	return C.GoBytes(unsafe.Pointer(b.data), C.int(b.len))
}
func RecipientPublic(secret [32]byte) ([32]byte, error) {
	var out [32]byte
	err := result(C.murmur_bridge_recipient_public((*C.uint8_t)(unsafe.Pointer(&secret[0])), (*C.uint8_t)(unsafe.Pointer(&out[0]))))
	return out, err
}
func Seal(h Header, signer, recipient [32]byte, payload []byte) ([]byte, error) {
	n, err := native(h)
	if err != nil {
		return nil, err
	}
	var out C.murmur_bridge_bytes_t
	err = result(C.murmur_bridge_seal(&n, (*C.uint8_t)(unsafe.Pointer(&signer[0])), (*C.uint8_t)(unsafe.Pointer(&recipient[0])), pointer(payload), C.size_t(len(payload)), MaxBundle, MaxPayload, &out))
	if err != nil {
		return nil, err
	}
	return bytes(&out), nil
}
func Unseal(bundle []byte, source [16]byte, stream string, signer, receiver [32]byte) (Header, []byte, error) {
	if _, err := native(Header{Stream: stream}); err != nil {
		return Header{}, nil, err
	}
	s := C.CString(stream)
	defer C.free(unsafe.Pointer(s))
	var out C.murmur_bridge_bytes_t
	var h C.murmur_bridge_header_t
	err := result(C.murmur_bridge_unseal(pointer(bundle), C.size_t(len(bundle)), (*C.uint8_t)(unsafe.Pointer(&source[0])), s, (*C.uint8_t)(unsafe.Pointer(&signer[0])), (*C.uint8_t)(unsafe.Pointer(&receiver[0])), MaxBundle, MaxPayload, &h, &out))
	if err != nil {
		return Header{}, nil, err
	}
	return header(&h), bytes(&out), nil
}
func Init(db *sqlite.Conn) error {
	if db == nil {
		return &Error{Code: int(C.SQLITE_MISUSE)}
	}
	return result(C.murmur_bridge_store_init((*C.sqlite3)(db.NativeDB())))
}

// Queue runs inside the caller's source transaction; it never commits it.
// The caller must reserve the connection across the complete transaction.
func Queue(db *sqlite.Conn, h Header, signer, recipient [32]byte, payload []byte, capacity uint64) (Header, error) {
	n, err := native(h)
	if err != nil {
		return Header{}, err
	}
	if db == nil {
		return Header{}, &Error{Code: int(C.SQLITE_MISUSE)}
	}
	err = result(C.murmur_bridge_store_queue((*C.sqlite3)(db.NativeDB()), &n, (*C.uint8_t)(unsafe.Pointer(&signer[0])), (*C.uint8_t)(unsafe.Pointer(&recipient[0])), pointer(payload), C.size_t(len(payload)), MaxBundle, MaxPayload, C.uint64_t(capacity)))
	if err != nil {
		return Header{}, err
	}
	return header(&n), nil
}

// Next returns a stable queued artifact. SQLITE_NOTFOUND (12) means no work.
func Next(db *sqlite.Conn, source [16]byte, stream string) (uint64, []byte, error) {
	if _, err := native(Header{Stream: stream}); err != nil {
		return 0, nil, err
	}
	if db == nil {
		return 0, nil, &Error{Code: int(C.SQLITE_MISUSE)}
	}
	s := C.CString(stream)
	defer C.free(unsafe.Pointer(s))
	var seq C.uint64_t
	var out C.murmur_bridge_bytes_t
	err := result(C.murmur_bridge_store_next((*C.sqlite3)(db.NativeDB()), (*C.uint8_t)(unsafe.Pointer(&source[0])), s, &seq, &out))
	if err != nil {
		return 0, nil, err
	}
	return uint64(seq), bytes(&out), nil
}

// Ack is called only after the artifact has been durably published.
func Ack(db *sqlite.Conn, source [16]byte, stream string, sequence uint64) error {
	if _, err := native(Header{Stream: stream}); err != nil {
		return err
	}
	if db == nil {
		return &Error{Code: int(C.SQLITE_MISUSE)}
	}
	s := C.CString(stream)
	defer C.free(unsafe.Pointer(s))
	return result(C.murmur_bridge_store_ack((*C.sqlite3)(db.NativeDB()), (*C.uint8_t)(unsafe.Pointer(&source[0])), s, C.uint64_t(sequence)))
}
func Stage(db *sqlite.Conn, bundle []byte, source [16]byte, stream string, signer, receiver [32]byte, capacity uint64) error {
	if _, err := native(Header{Stream: stream}); err != nil {
		return err
	}
	if db == nil {
		return &Error{Code: int(C.SQLITE_MISUSE)}
	}
	s := C.CString(stream)
	defer C.free(unsafe.Pointer(s))
	return result(C.murmur_bridge_store_stage((*C.sqlite3)(db.NativeDB()), pointer(bundle), C.size_t(len(bundle)), (*C.uint8_t)(unsafe.Pointer(&source[0])), s, (*C.uint8_t)(unsafe.Pointer(&signer[0])), (*C.uint8_t)(unsafe.Pointer(&receiver[0])), MaxBundle, MaxPayload, C.uint64_t(capacity)))
}

// Publish durably writes one immutable artifact before acknowledging its queue
// entry. The operator-owned destination directory must already exist.
func Publish(db *sqlite.Conn, source [16]byte, stream, directory string) error {
	if _, err := native(Header{Stream: stream}); err != nil {
		return err
	}
	if db == nil || directory == "" || strings.IndexByte(directory, 0) >= 0 {
		return &Error{Code: int(C.SQLITE_MISUSE)}
	}
	s, d := C.CString(stream), C.CString(directory)
	defer C.free(unsafe.Pointer(s))
	defer C.free(unsafe.Pointer(d))
	return result(C.murmur_bridge_publish((*C.sqlite3)(db.NativeDB()), (*C.uint8_t)(unsafe.Pointer(&source[0])), s, d))
}
