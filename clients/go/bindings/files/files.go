// Package files binds the native file-object store for Go
// orchestration: upload/download/availability over a staged driver.
package files

/*
#cgo CFLAGS: -I../../../.. -I../../../../deps/murmur -I../../../../deps/sqlite -O2
#cgo LDFLAGS: ${SRCDIR}/../../../../libmurmur.a -lstdc++ -lpthread -ldl -lm
#include <stdlib.h>
#include <string.h>
#include "files.h"
#include "driver.h"
*/
import "C"

import (
	"fmt"
	"unsafe"
)

// Status mirrors murmur_files_status_t.
type Status int

const (
	StatusOK          Status = 0
	StatusInvalid     Status = 1
	StatusAuth        Status = 2
	StatusIO          Status = 3
	StatusUnavailable Status = 4
	StatusOverloaded  Status = 5
	StatusSQLite      Status = 6
	StatusProtocol    Status = 7
)

// Stage stages the file store on a native driver (call before Start).
// fetchPort is the uniform cluster fetch port; bindIP is this node's
// loopback IP (nodes share the port via distinct 127.0.0.x).
func Stage(drv unsafe.Pointer, dir string, key [32]byte, bindIP string, fetchPort uint16) error {
	cdir := C.CString(dir)
	defer C.free(unsafe.Pointer(cdir))
	cip := C.CString(bindIP)
	defer C.free(unsafe.Pointer(cip))
	var cfg C.murmur_driver_files_config_t
	C.memset(unsafe.Pointer(&cfg), 0, C.size_t(unsafe.Sizeof(cfg)))
	cfg.directory = cdir
	C.memcpy(unsafe.Pointer(&cfg.key[0]), unsafe.Pointer(&key[0]), 32)
	cfg.fetch_bind_ip = cip
	cfg.fetch_port = C.uint16_t(fetchPort)
	var detail *C.char
	var sqlrc C.int
	st := C.murmur_driver_files_open((*C.murmur_driver_t)(drv), &cfg, &detail, &sqlrc)
	msg := ""
	if detail != nil {
		msg = C.GoString(detail)
		C.free(unsafe.Pointer(detail))
	}
	if st != C.MURMUR_FILES_OK {
		if msg == "" {
			return fmt.Errorf("files stage: status=%d sqlrc=%d", int(st), int(sqlrc))
		}
		return fmt.Errorf("files stage: status=%d sqlrc=%d: %s", int(st), int(sqlrc), msg)
	}
	return nil
}

// Handle returns the staged store handle (nil unless staged).
func Handle(drv unsafe.Pointer) unsafe.Pointer {
	return unsafe.Pointer(C.murmur_driver_files((*C.murmur_driver_t)(drv)))
}

func callErr(op string, st C.murmur_files_status_t, detail *C.char, sqlrc C.int) error {
	msg := ""
	if detail != nil {
		msg = C.GoString(detail)
		C.free(unsafe.Pointer(detail))
	}
	if st == C.MURMUR_FILES_OK {
		return nil
	}
	if msg == "" {
		return fmt.Errorf("%s: status=%d sqlrc=%d", op, int(st), int(sqlrc))
	}
	return fmt.Errorf("%s: status=%d sqlrc=%d: %s", op, int(st), int(sqlrc), msg)
}

// UploadOne stores one object.
func UploadOne(store unsafe.Pointer, name string, data []byte) error {
	cname := C.CString(name)
	defer C.free(unsafe.Pointer(cname))
	var up *C.murmur_file_upload_t
	var detail *C.char
	var sqlrc C.int
	o := (*C.murmur_files_t)(store)
	if st := C.murmur_files_begin_upload(o, cname, &up, &detail, &sqlrc); st != C.MURMUR_FILES_OK {
		return callErr("begin upload "+name, st, detail, sqlrc)
	}
	if len(data) > 0 {
		if st := C.murmur_files_upload_append(up, (*C.uint8_t)(unsafe.Pointer(&data[0])), C.size_t(len(data)), &detail); st != C.MURMUR_FILES_OK {
			C.murmur_files_upload_abort(up)
			return callErr("append upload "+name, st, detail, 0)
		}
	}
	var meta C.murmur_files_meta_t
	if st := C.murmur_files_finish_upload(o, up, &meta, &detail, &sqlrc); st != C.MURMUR_FILES_OK {
		return callErr("finish upload "+name, st, detail, sqlrc)
	}
	C.murmur_files_meta_free(&meta)
	return nil
}

// Download fetches one object's full plaintext.
func Download(store unsafe.Pointer, name string) ([]byte, error) {
	cname := C.CString(name)
	defer C.free(unsafe.Pointer(cname))
	var d *C.murmur_file_download_t
	var detail *C.char
	var sqlrc C.int
	o := (*C.murmur_files_t)(store)
	if st := C.murmur_files_download(o, cname, &d, &detail, &sqlrc); st != C.MURMUR_FILES_OK {
		return nil, callErr("download "+name, st, detail, sqlrc)
	}
	defer C.murmur_files_download_close(d)
	var out []byte
	for {
		var start C.uint64_t
		var buf [1 << 20]byte
		var n C.size_t
		var done C.int
		st := C.murmur_files_download_next(d, C.size_t(len(buf)), &start,
			(*C.uint8_t)(unsafe.Pointer(&buf[0])), &n, &done, &detail)
		if st != C.MURMUR_FILES_OK {
			return nil, callErr("download next "+name, st, detail, 0)
		}
		out = append(out, buf[:int(n)]...)
		if done != 0 {
			break
		}
	}
	return out, nil
}

// Available reports whether the object is fetchable locally.
func Available(store unsafe.Pointer, name string) (bool, error) {
	cname := C.CString(name)
	defer C.free(unsafe.Pointer(cname))
	var avail C.int
	var detail *C.char
	var sqlrc C.int
	st := C.murmur_files_available((*C.murmur_files_t)(store), cname, &avail, &detail, &sqlrc)
	if err := callErr("available "+name, st, detail, sqlrc); err != nil {
		return false, err
	}
	return avail != 0, nil
}

// Meta is one file's decoded metadata.
type Meta struct {
	Name       string
	Digest     [32]byte
	Bytes      uint64
	Generation uint64
	Millis     uint64
	Deleted    bool
}

// Metadata reads one file's metadata.
func Metadata(store unsafe.Pointer, name string) (*Meta, bool, error) {
	cname := C.CString(name)
	defer C.free(unsafe.Pointer(cname))
	var m C.murmur_files_meta_t
	var found C.int
	var detail *C.char
	var sqlrc C.int
	st := C.murmur_files_metadata((*C.murmur_files_t)(store), cname, &m, &found, &detail, &sqlrc)
	if err := callErr("metadata "+name, st, detail, sqlrc); err != nil {
		return nil, false, err
	}
	if found == 0 {
		return nil, false, nil
	}
	defer C.murmur_files_meta_free(&m)
	out := &Meta{
		Name:       C.GoString(m.name),
		Bytes:      uint64(m.bytes),
		Generation: uint64(m.generation),
		Millis:     uint64(m.millis),
		Deleted:    m.deleted != 0,
	}
	C.memcpy(unsafe.Pointer(&out.Digest[0]), unsafe.Pointer(&m.digest[0]), 32)
	return out, true, nil
}

// List returns all file metadata.
func List(store unsafe.Pointer) ([]Meta, error) {
	var ms *C.murmur_files_meta_t
	var n C.size_t
	var detail *C.char
	var sqlrc C.int
	st := C.murmur_files_list((*C.murmur_files_t)(store), &ms, &n, &detail, &sqlrc)
	if err := callErr("list", st, detail, sqlrc); err != nil {
		return nil, err
	}
	defer C.murmur_files_meta_list_free(ms, n)
	count := int(n)
	if count == 0 || ms == nil {
		return nil, nil
	}
	elems := (*[1 << 20]C.murmur_files_meta_t)(unsafe.Pointer(ms))[:count:count]
	out := make([]Meta, 0, count)
	for i := range elems {
		m := Meta{
			Name:       C.GoString(elems[i].name),
			Bytes:      uint64(elems[i].bytes),
			Generation: uint64(elems[i].generation),
			Millis:     uint64(elems[i].millis),
			Deleted:    elems[i].deleted != 0,
		}
		C.memcpy(unsafe.Pointer(&m.Digest[0]), unsafe.Pointer(&elems[i].digest[0]), 32)
		out = append(out, m)
	}
	return out, nil
}
