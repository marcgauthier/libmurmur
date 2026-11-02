package bridge

/*
#include <stdlib.h>
#include "bridge_rows.h"
#include "sqlite3.h"
*/
import "C"

import (
	"database/sql/driver"
	"fmt"
	"strings"
	"unsafe"

	"github.com/marcgauthier/libmurmur/clients/go/bindings/sqlite"
)

type TableID [16]byte

type Version struct {
	Millis  uint64
	Logical uint32
	Origin  [16]byte
}

func nativeVersion(v Version) C.murmur_bridge_version_t {
	var out C.murmur_bridge_version_t
	out.millis, out.logical = C.uint64_t(v.Millis), C.uint32_t(v.Logical)
	copy(unsafe.Slice((*byte)(unsafe.Pointer(&out.origin[0])), 16), v.Origin[:])
	return out
}

// RegisterTable explicitly allows an ordinary SQL table to participate in typed
// bridging. This does not start replication or install automatic capture.
func RegisterTable(db *sqlite.Conn, name string) (TableID, error) {
	var id TableID
	if db == nil || name == "" || strings.IndexByte(name, 0) >= 0 {
		return id, &Error{Code: int(C.SQLITE_MISUSE)}
	}
	s := C.CString(name)
	defer C.free(unsafe.Pointer(s))
	err := result(C.murmur_bridge_rows_register((*C.sqlite3)(db.NativeDB()), s, (*C.uint8_t)(unsafe.Pointer(&id[0]))))
	return id, err
}

// Schema returns the digest of the current registered replicated declarations.
func Schema(db *sqlite.Conn) ([32]byte, error) {
	var digest [32]byte
	if db == nil {
		return digest, &Error{Code: int(C.SQLITE_MISUSE)}
	}
	err := result(C.murmur_bridge_rows_schema((*C.sqlite3)(db.NativeDB()), (*C.uint8_t)(unsafe.Pointer(&digest[0]))))
	return digest, err
}

func nativeKey(key []any) (*C.murmur_value_t, func(), error) {
	if len(key) == 0 || len(key) > 32766 {
		return nil, func() {}, &Error{Code: int(C.SQLITE_MISUSE)}
	}
	p := C.calloc(C.size_t(len(key)), C.size_t(C.sizeof_murmur_value_t))
	if p == nil {
		return nil, func() {}, &Error{Code: int(C.SQLITE_NOMEM)}
	}
	allocations := []unsafe.Pointer{p}
	cleanup := func() {
		for _, p := range allocations {
			C.free(p)
		}
	}
	values := unsafe.Slice((*C.murmur_value_t)(p), len(key))
	total := 0
	for i, raw := range key {
		v, err := driver.DefaultParameterConverter.ConvertValue(raw)
		if err != nil {
			cleanup()
			return nil, func() {}, fmt.Errorf("bridge key %d: %w", i, err)
		}
		switch v := v.(type) {
		case nil:
			values[i]._type = C.MURMUR_NULL
		case int64:
			values[i]._type = C.MURMUR_INTEGER
			values[i].integer = C.int64_t(v)
		case bool:
			values[i]._type = C.MURMUR_INTEGER
			if v {
				values[i].integer = 1
			}
		case float64:
			values[i]._type = C.MURMUR_REAL
			values[i].real = C.double(v)
		case string:
			if len(v) > MaxPayload-total {
				cleanup()
				return nil, func() {}, &Error{Code: int(C.SQLITE_TOOBIG)}
			}
			total += len(v)
			values[i]._type = C.MURMUR_TEXT
			data := C.CBytes([]byte(v))
			if len(v) > 0 && data == nil {
				cleanup()
				return nil, func() {}, &Error{Code: int(C.SQLITE_NOMEM)}
			}
			allocations = append(allocations, data)
			values[i].data = data
			values[i].bytes = C.size_t(len(v))
		case []byte:
			if len(v) > MaxPayload-total {
				cleanup()
				return nil, func() {}, &Error{Code: int(C.SQLITE_TOOBIG)}
			}
			total += len(v)
			values[i]._type = C.MURMUR_BLOB
			data := C.CBytes(v)
			if len(v) > 0 && data == nil {
				cleanup()
				return nil, func() {}, &Error{Code: int(C.SQLITE_NOMEM)}
			}
			allocations = append(allocations, data)
			values[i].data = data
			values[i].bytes = C.size_t(len(v))
		default:
			cleanup()
			return nil, func() {}, fmt.Errorf("bridge key %d has unsupported type %T", i, v)
		}
	}
	return (*C.murmur_value_t)(p), cleanup, nil
}

// CaptureRow runs inside the caller's source write transaction. It retains row
// generations and unchanged cell versions; a delete captures a tombstone.
// The connection and native writer guard must cover the complete transaction.
func CaptureRow(db *sqlite.Conn, table TableID, key []any, deleted bool, version Version) ([]byte, error) {
	if db == nil {
		return nil, &Error{Code: int(C.SQLITE_MISUSE)}
	}
	keys, cleanup, err := nativeKey(key)
	if err != nil {
		return nil, err
	}
	defer cleanup()
	v := nativeVersion(version)
	var out C.murmur_bridge_bytes_t
	var del C.int
	if deleted {
		del = 1
	}
	err = result(C.murmur_bridge_rows_capture((*C.sqlite3)(db.NativeDB()), (*C.uint8_t)(unsafe.Pointer(&table[0])), keys, C.size_t(len(key)), del, &v, &out))
	if err != nil {
		return nil, err
	}
	return bytes(&out), nil
}

func PackRows(records ...[]byte) ([]byte, error) {
	if len(records) == 0 || len(records) > 1024 {
		return nil, &Error{Code: int(C.SQLITE_MISUSE)}
	}
	total := 5 + 10*len(records)
	for _, record := range records {
		if len(record) > MaxPayload-total {
			return nil, &Error{Code: int(C.SQLITE_TOOBIG)}
		}
		total += len(record)
	}
	p := C.calloc(C.size_t(len(records)), C.size_t(C.sizeof_murmur_bridge_bytes_t))
	if p == nil {
		return nil, &Error{Code: int(C.SQLITE_NOMEM)}
	}
	defer C.free(p)
	native := unsafe.Slice((*C.murmur_bridge_bytes_t)(p), len(records))
	defer func() {
		for i := range native {
			C.free(unsafe.Pointer(native[i].data))
		}
	}()
	for i, record := range records {
		if len(record) == 0 || len(record) > MaxPayload {
			return nil, &Error{Code: int(C.SQLITE_TOOBIG)}
		}
		native[i].data = (*C.uint8_t)(C.CBytes(record))
		if native[i].data == nil {
			return nil, &Error{Code: int(C.SQLITE_NOMEM)}
		}
		native[i].len = C.size_t(len(record))
	}
	var out C.murmur_bridge_bytes_t
	if err := result(C.murmur_bridge_rows_pack((*C.murmur_bridge_bytes_t)(p), C.size_t(len(records)), &out)); err != nil {
		return nil, err
	}
	return bytes(&out), nil
}

// ApplyRows atomically projects the next authenticated typed bundle and its
// replay receipt using the local registered schema and persisted ownership.
func ApplyRows(db *sqlite.Conn, source [16]byte, stream string, signer, receiver [32]byte) error {
	if _, err := native(Header{Stream: stream}); err != nil {
		return err
	}
	if db == nil {
		return &Error{Code: int(C.SQLITE_MISUSE)}
	}
	s := C.CString(stream)
	defer C.free(unsafe.Pointer(s))
	return result(C.murmur_bridge_rows_apply((*C.sqlite3)(db.NativeDB()), (*C.uint8_t)(unsafe.Pointer(&source[0])), s, (*C.uint8_t)(unsafe.Pointer(&signer[0])), (*C.uint8_t)(unsafe.Pointer(&receiver[0])), MaxBundle, MaxPayload))
}

func changeOwner(db *sqlite.Conn, table TableID, key []any, column *string, version Version, release bool) error {
	if db == nil {
		return &Error{Code: int(C.SQLITE_MISUSE)}
	}
	keys, cleanup, err := nativeKey(key)
	if err != nil {
		return err
	}
	defer cleanup()
	var name *C.char
	if column != nil {
		if *column == "" || strings.IndexByte(*column, 0) >= 0 {
			return &Error{Code: int(C.SQLITE_MISUSE)}
		}
		name = C.CString(*column)
		defer C.free(unsafe.Pointer(name))
	}
	v := nativeVersion(version)
	if release {
		return result(C.murmur_bridge_rows_release((*C.sqlite3)(db.NativeDB()), (*C.uint8_t)(unsafe.Pointer(&table[0])), keys, C.size_t(len(key)), name, &v))
	}
	return result(C.murmur_bridge_rows_claim((*C.sqlite3)(db.NativeDB()), (*C.uint8_t)(unsafe.Pointer(&table[0])), keys, C.size_t(len(key)), name, &v))
}

// Claim follows the corresponding High write in its transaction. A nil column
// claims a deleted row. Primary keys cannot be claimed as individual fields.
func Claim(db *sqlite.Conn, table TableID, key []any, column *string, version Version) error {
	return changeOwner(db, table, key, column, version, false)
}

// Release reprojects the latest Low state in the caller's High transaction.
func Release(db *sqlite.Conn, table TableID, key []any, column *string, version Version) error {
	return changeOwner(db, table, key, column, version, true)
}
