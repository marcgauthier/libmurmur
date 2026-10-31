// Package driver binds the native replication engine/driver
// (deps/murmur) for Go orchestration: live-cluster tests boot one
// Node per store directory and drive replication entirely in C.
package driver

/*
#cgo CFLAGS: -I../../../.. -I../../../../deps/murmur -I../../../../deps/sqlite -I../../../../deps/keyring -I../../../../deps/crsqlite/include -O2
#cgo LDFLAGS: ${SRCDIR}/../../../../libmurmur.a -lstdc++ -lpthread -ldl -lm
#include <stdlib.h>
#include "libmurmur.h"
#include "sqlite3.h"
#include "sync.h"
#include "config.h"
#include "engine.h"
#include "driver.h"
#include "open.h"
*/
import "C"

import (
	"fmt"
	"unsafe"
)

// Status mirrors murmur_sync_status_t.
type Status int

const (
	StatusOK         Status = 0
	StatusInvalid    Status = 1
	StatusProtocol   Status = 2
	StatusOverloaded Status = 3
	StatusAuth       Status = 4
	StatusSQLite     Status = 5
)

func (s Status) Error() string {
	switch s {
	case StatusOK:
		return "ok"
	case StatusInvalid:
		return "invalid"
	case StatusProtocol:
		return "protocol"
	case StatusOverloaded:
		return "overloaded"
	case StatusAuth:
		return "auth"
	case StatusSQLite:
		return "sqlite"
	}
	return fmt.Sprintf("status(%d)", int(s))
}

// Init runs process-level libmurmur init plus VFS registration.
// Call once before opening murmur stores.
func Init(cachePages int, flushMs uint) error {
	if C.murmur_init() != 0 {
		return fmt.Errorf("murmur_init failed")
	}
	if C.murmur_vfs_register(C.int(cachePages), C.uint(flushMs)) != 0 {
		return fmt.Errorf("murmur_vfs_register failed")
	}
	return nil
}

// EnsureSchema creates the murmur_* replication tables on a raw
// sqlite3 handle (from Conn.NativeDB).
func EnsureSchema(db unsafe.Pointer) error {
	var sqlrc C.int
	st := C.murmur_sync_ensure_schema((*C.sqlite3)(db), &sqlrc)
	if st != C.MURMUR_SYNC_OK {
		return fmt.Errorf("ensure schema: %s sqlrc=%d", Status(st), int(sqlrc))
	}
	return nil
}

// SetSetting writes one murmur_config setting on a raw handle.
func SetSetting(db unsafe.Pointer, name, value string) error {
	cname := C.CString(name)
	defer C.free(unsafe.Pointer(cname))
	cval := C.CString(value)
	defer C.free(unsafe.Pointer(cval))
	var sqlrc C.int
	st := C.murmur_cfg_set_setting((*C.sqlite3)(db), cname,
		(*C.uint8_t)(unsafe.Pointer(cval)), C.size_t(len(value)), &sqlrc)
	if st != C.MURMUR_SYNC_OK {
		return fmt.Errorf("set %s: %s sqlrc=%d", name, Status(st), int(sqlrc))
	}
	return nil
}

// Node is one native replication node: an engine plus a driver over
// a borrowed SQLite connection. The connection must outlive the Node.
type Node struct {
	eng unsafe.Pointer
	drv unsafe.Pointer
}

// New allocates and initializes the engine/driver pair over db.
// Settings (group_id, bind, TLS, bootstrap) must be configured
// before Start.
func New(db unsafe.Pointer) *Node {
	eng := C.malloc(C.sizeof_struct_murmur_engine)
	drv := C.malloc(C.sizeof_struct_murmur_driver)
	n := &Node{eng: eng, drv: drv}
	C.murmur_engine_init((*C.murmur_engine_t)(eng), (*C.sqlite3)(db))
	C.murmur_driver_init((*C.murmur_driver_t)(drv), (*C.murmur_engine_t)(eng))
	return n
}

func callError(op string, st C.murmur_sync_status_t, detail *C.char, sqlrc C.int) error {
	if st == C.MURMUR_SYNC_OK {
		return nil
	}
	msg := ""
	if detail != nil {
		msg = C.GoString(detail)
	}
	if msg == "" {
		return fmt.Errorf("%s: %s sqlrc=%d", op, Status(st), int(sqlrc))
	}
	return fmt.Errorf("%s: %s sqlrc=%d: %s", op, Status(st), int(sqlrc), msg)
}

// NativeDriver exposes the raw driver handle for subsystem staging.
func (n *Node) NativeDriver() unsafe.Pointer { return n.drv }

// Start brings up replication: engine, QUIC endpoint, threads.
func (n *Node) Start() error {
	var detail *C.char
	var sqlrc C.int
	st := C.murmur_driver_start((*C.murmur_driver_t)(n.drv), &detail, &sqlrc)
	defer func() {
		if detail != nil {
			C.free(unsafe.Pointer(detail))
		}
	}()
	return callError("driver start", st, detail, sqlrc)
}

// Stop stops threads, sessions, endpoint, and engine. Idempotent.
func (n *Node) Stop() error {
	var sqlrc C.int
	st := C.murmur_driver_stop((*C.murmur_driver_t)(n.drv), &sqlrc)
	if st != C.MURMUR_SYNC_OK {
		return fmt.Errorf("driver stop: %s sqlrc=%d", Status(st), int(sqlrc))
	}
	return nil
}

// Running reports whether replication is up.
func (n *Node) Running() bool {
	return C.murmur_driver_running((*C.murmur_driver_t)(n.drv)) != 0
}

// RetentionCollect runs one retention collection pass now and
// reports floor movement and tombstone deletes.
func (n *Node) RetentionCollect() (moved, pruned uint64, err error) {
	var cmoved, cpruned C.uint64_t
	var sqlrc C.int
	st := C.murmur_driver_retention_collect((*C.murmur_driver_t)(n.drv), &cmoved, &cpruned, &sqlrc)
	if st != C.MURMUR_SYNC_OK {
		return 0, 0, fmt.Errorf("retention collect: %s sqlrc=%d", Status(st), int(sqlrc))
	}
	return uint64(cmoved), uint64(cpruned), nil
}

// Close destroys the driver/engine pair and frees it. Stop first.
func (n *Node) Close() {
	if n.drv != nil {
		C.murmur_driver_destroy((*C.murmur_driver_t)(n.drv))
		C.free(n.drv)
		n.drv = nil
	}
	if n.eng != nil {
		C.murmur_engine_destroy((*C.murmur_engine_t)(n.eng))
		C.free(n.eng)
		n.eng = nil
	}
}

func ownedString(c *C.char) string {
	if c == nil {
		return ""
	}
	s := C.GoString(c)
	C.free(unsafe.Pointer(c))
	return s
}

// Status returns the engine status snapshot (JSON).
func (n *Node) Status() string {
	return ownedString(C.murmur_engine_status((*C.murmur_engine_t)(n.eng)))
}

// Health returns the engine health snapshot (JSON).
func (n *Node) Health() string {
	return ownedString(C.murmur_engine_health((*C.murmur_engine_t)(n.eng)))
}

// Progress returns the replication progress snapshot (JSON).
func (n *Node) Progress() string {
	return ownedString(C.murmur_engine_progress((*C.murmur_engine_t)(n.eng)))
}

// Peers returns the known-peer snapshot (JSON).
func (n *Node) Peers() string {
	return ownedString(C.murmur_engine_peers((*C.murmur_engine_t)(n.eng)))
}

// AddSeed adds a dial target (host:port) at runtime.
func (n *Node) AddSeed(addr string) error {
	caddr := C.CString(addr)
	defer C.free(unsafe.Pointer(caddr))
	var sqlrc C.int
	st := C.murmur_engine_add_seed((*C.murmur_engine_t)(n.eng), caddr, &sqlrc)
	if st != C.MURMUR_SYNC_OK {
		return fmt.Errorf("add seed %s: %s sqlrc=%d", addr, Status(st), int(sqlrc))
	}
	return nil
}

// Commit forces durability on the store at canon path (MURMUR FLUSH).
func Commit(canon string) error {
	c := C.CString(canon)
	defer C.free(unsafe.Pointer(c))
	if rc := C.nvCommitDb(c); rc != 0 {
		return fmt.Errorf("commit %s: rc=%d", canon, int(rc))
	}
	return nil
}
