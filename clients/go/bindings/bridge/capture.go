package bridge

/*
#include <stdlib.h>
#include "bridge_capture.h"
#include "sqlite3.h"
extern int goBridgeWrite(uintptr_t);
static int bridgeWriteCallback(sqlite3 *db,void *handle) {
  (void)db;
  return goBridgeWrite((uintptr_t)handle);
}
static int bridgeWrite(sqlite3 *db,uintptr_t handle) {
  return murmur_bridge_write(db,bridgeWriteCallback,(void *)handle);
}
*/
import "C"

import (
	"errors"
	"runtime/cgo"
	"strings"
	"unsafe"

	"github.com/marcgauthier/libmurmur/clients/go/bindings/sqlite"
)

type Role int

const (
	Low  Role = 1
	High Role = 2
)

type CaptureConfig struct {
	Role              Role
	Database, Node    [16]byte
	Signer, Recipient [32]byte
	Stream            string
	StagingBytes      uint64
}

// AttachCapture enables native transaction capture for registered tables.
// Only operations executed with Write are captured. Attach again after opening
// a new connection; durable ownership and capture state survive reopening.
func AttachCapture(db *sqlite.Conn, config CaptureConfig) error {
	if _, err := native(Header{Stream: config.Stream}); err != nil {
		return err
	}
	if db == nil {
		return &Error{Code: int(C.SQLITE_MISUSE)}
	}
	if config.StagingBytes == 0 {
		config.StagingBytes = DefaultStaging
	}
	var options C.murmur_bridge_capture_options_t
	options.role = C.murmur_bridge_role_t(config.Role)
	options.staging_bytes = C.uint64_t(config.StagingBytes)
	copy(unsafe.Slice((*byte)(unsafe.Pointer(&options.database[0])), 16), config.Database[:])
	copy(unsafe.Slice((*byte)(unsafe.Pointer(&options.node[0])), 16), config.Node[:])
	copy(unsafe.Slice((*byte)(unsafe.Pointer(&options.signer[0])), 32), config.Signer[:])
	copy(unsafe.Slice((*byte)(unsafe.Pointer(&options.recipient[0])), 32), config.Recipient[:])
	copy(unsafe.Slice((*byte)(unsafe.Pointer(&options.stream[0])), 65), config.Stream)
	defer clear(config.Signer[:])
	defer clear(unsafe.Slice((*byte)(unsafe.Pointer(&options.signer[0])), 32))
	return result(C.murmur_bridge_capture_attach((*C.sqlite3)(db.NativeDB()), &options))
}

func DetachCapture(db *sqlite.Conn) error {
	if db == nil {
		return &Error{Code: int(C.SQLITE_MISUSE)}
	}
	return result(C.murmur_bridge_capture_detach((*C.sqlite3)(db.NativeDB())))
}

func Attached(db *sqlite.Conn) bool {
	return db != nil && C.murmur_bridge_capture_attached((*C.sqlite3)(db.NativeDB())) != 0
}

// BeginTransaction, CommitTransaction and RollbackTransaction are SQL-driver
// integration primitives. The caller must reserve the connection, pin its OS
// thread and hold sqlite.LockWriter across the complete transaction. Most
// clients should use Write instead.
func BeginTransaction(db *sqlite.Conn) error {
	if db == nil {
		return &Error{Code: int(C.SQLITE_MISUSE)}
	}
	return result(C.murmur_bridge_capture_begin((*C.sqlite3)(db.NativeDB())))
}
func CommitTransaction(db *sqlite.Conn) error {
	if db == nil {
		return &Error{Code: int(C.SQLITE_MISUSE)}
	}
	return result(C.murmur_bridge_capture_commit((*C.sqlite3)(db.NativeDB())))
}
func RollbackTransaction(db *sqlite.Conn) error {
	if db == nil {
		return &Error{Code: int(C.SQLITE_MISUSE)}
	}
	return result(C.murmur_bridge_capture_rollback((*C.sqlite3)(db.NativeDB())))
}

type writeCall struct {
	fn  func() error
	err error
}

//export goBridgeWrite
func goBridgeWrite(handle C.uintptr_t) (rc C.int) {
	call := cgo.Handle(handle).Value().(*writeCall)
	rc = C.SQLITE_ABORT
	defer func() {
		if recover() != nil {
			call.err = errors.New("bridge: write callback panicked")
			rc = C.SQLITE_ABORT
		}
	}()
	call.err = call.fn()
	if call.err == nil {
		return C.SQLITE_OK
	}
	return C.SQLITE_ABORT
}

// Write holds native writer admission for the entire synchronous transaction.
// The callback may execute ordinary DML on c; it must not execute DDL, change
// transaction state, retain c, or call back into the database/sql pool. Native
// capture, ownership, outbox and user writes commit or roll back together.
// Call through murmurdb.WithConnection to reserve the SQL pool's connection.
func Write(db *sqlite.Conn, fn func(*sqlite.Conn) error) error {
	if db == nil || fn == nil {
		return &Error{Code: int(C.SQLITE_MISUSE)}
	}
	call := &writeCall{fn: func() error { return fn(db) }}
	handle := cgo.NewHandle(call)
	defer handle.Delete()
	rc := C.bridgeWrite((*C.sqlite3)(db.NativeDB()), C.uintptr_t(handle))
	if call.err != nil {
		return call.err
	}
	return result(rc)
}

// Prepare exports one resumable baseline batch of existing Low rows without
// rewriting them. maxRows defaults to 256 and cannot exceed 1024. Once complete,
// a durable schema marker avoids rescanning the tables on subsequent opens.
func Prepare(db *sqlite.Conn, maxRows int) (captured int, complete bool, err error) {
	if db == nil || maxRows < 0 || maxRows > 1024 {
		return 0, false, &Error{Code: int(C.SQLITE_MISUSE)}
	}
	if maxRows == 0 {
		maxRows = 256
	}
	var count C.size_t
	rc := C.murmur_bridge_capture_prepare((*C.sqlite3)(db.NativeDB()), C.size_t(maxRows), &count)
	if rc == C.SQLITE_NOTFOUND {
		return int(count), true, nil
	}
	return int(count), false, result(rc)
}

// ReleaseOwnership releases an attached High claim in a standalone native
// transaction. The native clock orders the release after every retained local
// claim. A nil column releases a row-delete claim. False means already released
// or never owned. Call with an exclusive borrowed connection in autocommit.
func ReleaseOwnership(db *sqlite.Conn, table string, key []any, column *string) (bool, error) {
	if db == nil || table == "" || strings.IndexByte(table, 0) >= 0 {
		return false, &Error{Code: int(C.SQLITE_MISUSE)}
	}
	keys, cleanup, err := nativeKey(key)
	if err != nil {
		return false, err
	}
	defer cleanup()
	name := C.CString(table)
	defer C.free(unsafe.Pointer(name))
	var col *C.char
	if column != nil {
		if *column == "" || strings.IndexByte(*column, 0) >= 0 {
			return false, &Error{Code: int(C.SQLITE_MISUSE)}
		}
		col = C.CString(*column)
		defer C.free(unsafe.Pointer(col))
	}
	rc := C.murmur_bridge_capture_release((*C.sqlite3)(db.NativeDB()), name, keys, C.size_t(len(key)), col)
	if rc == C.SQLITE_NOTFOUND {
		return false, nil
	}
	if err := result(rc); err != nil {
		return false, err
	}
	return true, nil
}

// ReleaseOwnershipEncoded releases a High claim using canonical native
// Vec<Value> primary-key bytes. Decoding and clock allocation stay native.
func ReleaseOwnershipEncoded(db *sqlite.Conn, table string, key []byte, column *string) (bool, error) {
	if db == nil || table == "" || strings.IndexByte(table, 0) >= 0 || len(key) == 0 || len(key) > MaxPayload {
		return false, &Error{Code: int(C.SQLITE_MISUSE)}
	}
	name := C.CString(table)
	defer C.free(unsafe.Pointer(name))
	var col *C.char
	if column != nil {
		if *column == "" || strings.IndexByte(*column, 0) >= 0 {
			return false, &Error{Code: int(C.SQLITE_MISUSE)}
		}
		col = C.CString(*column)
		defer C.free(unsafe.Pointer(col))
	}
	rc := C.murmur_bridge_capture_release_encoded((*C.sqlite3)(db.NativeDB()), name, pointer(key), C.size_t(len(key)), col)
	if rc == C.SQLITE_NOTFOUND {
		return false, nil
	}
	if err := result(rc); err != nil {
		return false, err
	}
	return true, nil
}
