// Package managedharness drives the owned managed C API. It uses original
// signed export/apply records and never enables the legacy unsigned driver.
package managedharness

/*
#cgo CXXFLAGS: -std=c++17 -O2
#cgo LDFLAGS: ${SRCDIR}/../../../../libmurmur.a -lstdc++ -lm -ldl -lpthread
#include <stdlib.h>
#include "native.h"
*/
import "C"

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"unsafe"
)

type Identity struct {
	Database [16]byte `json:"database"`
	Origin   [16]byte `json:"origin"`
	Site     [16]byte `json:"site"`
	Public   [32]byte `json:"public"`
}

type Value struct {
	Type    int    `json:"type"`
	Integer int64  `json:"integer"`
	Real    string `json:"real"`
	Hex     string `json:"hex"`
}

func (v Value) Text() string { bytes, _ := hex.DecodeString(v.Hex); return string(bytes) }

type Rename struct {
	Table, NewTable, Column, NewColumn string
}

type Request struct {
	ID       uint64    `json:"id"`
	Op       string    `json:"op"`
	SQL      []string  `json:"sql,omitempty"`
	Class    int       `json:"class,omitempty"`
	Table    string    `json:"table,omitempty"`
	Column   string    `json:"column,omitempty"`
	Policy   int       `json:"policy,omitempty"`
	Enabled  bool      `json:"enabled,omitempty"`
	FTS      bool      `json:"fts,omitempty"`
	Dims     int       `json:"dims,omitempty"`
	Distance int       `json:"distance,omitempty"`
	Origin   [16]byte  `json:"origin,omitempty"`
	After    uint64    `json:"after,omitempty"`
	Identity *Identity `json:"identity,omitempty"`
	Data     []byte    `json:"data,omitempty"`
	Renames  []Rename  `json:"renames,omitempty"`
	Crash    int       `json:"crash,omitempty"`
}

type ClassStats struct {
	Acquisitions, Cancels, WaitNS, ServiceNS, Waiters uint64
}

type Stats struct {
	Classes [3]ClassStats
	DebtNS  int64
	Active  bool
}

type Response struct {
	ID           uint64     `json:"id"`
	RC           int        `json:"rc"`
	Error        string     `json:"error,omitempty"`
	Rows         [][]Value  `json:"rows,omitempty"`
	Data         []byte     `json:"data,omitempty"`
	Changed      bool       `json:"changed,omitempty"`
	Identity     *Identity  `json:"identity,omitempty"`
	Stats        *Stats     `json:"stats,omitempty"`
	Capabilities int        `json:"capabilities,omitempty"`
	Resources    *Resources `json:"resources,omitempty"`
}

type Resources struct {
	Goroutines int
	FDs        int
	Heap, RSS  uint64
	StorageFDs int
	SSTFiles   int
	FDTargets  map[string]int
}

// Native permits concurrent requests: the C scheduler provides admission.
// The RW lock protects handle lifetime, not writer ordering.
type Native struct {
	mu   sync.RWMutex
	db   *C.murmur_managed_t
	path string
}

var initialize sync.Once
var initializeRC C.int

func OpenNative(path string, key [32]byte, database, node [16]byte, seed [32]byte) (*Native, error) {
	initialize.Do(func() { initializeRC = C.murmur_init() })
	if initializeRC != 0 {
		return nil, fmt.Errorf("native init rc=%d", initializeRC)
	}
	name := C.CString(path)
	defer C.free(unsafe.Pointer(name))
	out := &Native{path: path}
	if rc := C.murmur_managed_open(name, (*C.uint8_t)(unsafe.Pointer(&key[0])), &out.db); rc != 0 {
		return nil, fmt.Errorf("managed open rc=%d", rc)
	}
	if rc := C.murmur_managed_origin_configure(out.db, (*C.uint8_t)(unsafe.Pointer(&database[0])), (*C.uint8_t)(unsafe.Pointer(&node[0])), (*C.uint8_t)(unsafe.Pointer(&seed[0]))); rc != 0 {
		out.Close()
		return nil, fmt.Errorf("managed configure rc=%d", rc)
	}
	return out, nil
}

func (n *Native) Close() {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.db != nil {
		C.murmur_managed_close(n.db)
		n.db = nil
	}
}

func (n *Native) Do(request Request) Response {
	n.mu.RLock()
	defer n.mu.RUnlock()
	out := Response{ID: request.ID}
	if n.db == nil {
		out.RC, out.Error = 21, "closed native handle"
		return out
	}
	for _, sql := range request.SQL {
		if strings.IndexByte(sql, 0) >= 0 {
			out.RC, out.Error = 21, "NUL in SQL text"
			return out
		}
	}
	var result C.mh_result
	defer func() {
		if result.json != nil {
			C.free(unsafe.Pointer(result.json))
		}
	}()
	stringArg := func(value string) *C.char { return C.CString(value) }
	table, column := stringArg(request.Table), stringArg(request.Column)
	defer C.free(unsafe.Pointer(table))
	defer C.free(unsafe.Pointer(column))
	flag := func(value bool) C.int {
		if value {
			return 1
		}
		return 0
	}
	switch request.Op {
	case "exec", "query", "hold-write":
		if len(request.SQL) == 0 || len(request.SQL) > 10000 {
			out.RC = 21
			break
		}
		memory := C.calloc(C.size_t(len(request.SQL)), C.size_t(unsafe.Sizeof(uintptr(0))))
		if memory == nil {
			out.RC = 7
			break
		}
		defer C.free(memory)
		statements := unsafe.Slice((**C.char)(memory), len(request.SQL))
		for i, statement := range request.SQL {
			statements[i] = C.CString(statement)
			defer C.free(unsafe.Pointer(statements[i]))
		}
		if request.Op == "hold-write" {
			marker := C.CString(n.path + ".hold")
			defer C.free(unsafe.Pointer(marker))
			out.RC = int(C.mh_execute_hold(n.db, C.int(request.Class), (**C.char)(memory), C.size_t(len(statements)), marker, &result))
		} else {
			out.RC = int(C.mh_execute(n.db, C.int(request.Class), (**C.char)(memory), C.size_t(len(statements)), &result))
		}
	case "migrate":
		if len(request.SQL) != 1 {
			out.RC = 21
			break
		}
		sql := C.CString(request.SQL[0])
		defer C.free(unsafe.Pointer(sql))
		if len(request.Renames) == 0 {
			out.RC = int(C.mh_migrate(n.db, sql, nil, 0, C.int(request.Crash)))
			break
		}
		memory := C.calloc(C.size_t(len(request.Renames)), C.size_t(unsafe.Sizeof(C.murmur_rename_t{})))
		if memory == nil {
			out.RC = 7
			break
		}
		defer C.free(memory)
		maps := unsafe.Slice((*C.murmur_rename_t)(memory), len(request.Renames))
		for i, mapping := range request.Renames {
			maps[i].table = C.CString(mapping.Table)
			defer C.free(unsafe.Pointer(maps[i].table))
			if mapping.NewTable != "" {
				maps[i].new_table = C.CString(mapping.NewTable)
				defer C.free(unsafe.Pointer(maps[i].new_table))
			}
			if mapping.Column != "" {
				maps[i].column = C.CString(mapping.Column)
				defer C.free(unsafe.Pointer(maps[i].column))
			}
			if mapping.NewColumn != "" {
				maps[i].new_column = C.CString(mapping.NewColumn)
				defer C.free(unsafe.Pointer(maps[i].new_column))
			}
		}
		out.RC = int(C.mh_migrate(n.db, sql, (*C.murmur_rename_t)(memory), C.size_t(len(maps)), C.int(request.Crash)))
	case "policy":
		out.RC = int(C.murmur_managed_set_policy(n.db, table, column, C.murmur_merge_policy_t(request.Policy)))
	case "replication":
		out.RC = int(C.murmur_managed_set_replication(n.db, table, flag(request.Enabled)))
	case "search":
		out.RC = int(C.murmur_managed_set_search(n.db, table, column, flag(request.FTS), C.int(request.Dims), C.int(request.Distance)))
	case "refresh":
		out.RC = int(C.murmur_managed_refresh_indexes(n.db))
	case "flush":
		out.RC = int(C.murmur_managed_flush(n.db))
	case "master":
		out.RC = int(C.murmur_managed_schema_master(n.db, (*C.uint8_t)(unsafe.Pointer(&request.Origin[0]))))
	case "identity":
		var identity C.murmur_origin_identity_t
		out.RC = int(C.murmur_managed_origin_identity(n.db, &identity))
		if out.RC == 0 {
			out.Identity = &Identity{}
			copy(out.Identity.Database[:], C.GoBytes(unsafe.Pointer(&identity.database[0]), 16))
			copy(out.Identity.Origin[:], C.GoBytes(unsafe.Pointer(&identity.origin[0]), 16))
			copy(out.Identity.Site[:], C.GoBytes(unsafe.Pointer(&identity.site[0]), 16))
			copy(out.Identity.Public[:], C.GoBytes(unsafe.Pointer(&identity.public_key[0]), 32))
		}
	case "trust":
		if request.Identity == nil {
			out.RC = 21
			break
		}
		var identity C.murmur_origin_identity_t
		copy(unsafe.Slice((*byte)(unsafe.Pointer(&identity.database[0])), 16), request.Identity.Database[:])
		copy(unsafe.Slice((*byte)(unsafe.Pointer(&identity.origin[0])), 16), request.Identity.Origin[:])
		copy(unsafe.Slice((*byte)(unsafe.Pointer(&identity.site[0])), 16), request.Identity.Site[:])
		copy(unsafe.Slice((*byte)(unsafe.Pointer(&identity.public_key[0])), 32), request.Identity.Public[:])
		out.RC = int(C.murmur_managed_origin_trust(n.db, &identity, flag(request.Enabled)))
	case "export-schema", "next":
		var record C.murmur_origin_record_t
		if request.Op == "next" {
			out.RC = int(C.murmur_managed_origin_next(n.db, (*C.uint8_t)(unsafe.Pointer(&request.Origin[0])), C.uint64_t(request.After), &record))
		} else {
			out.RC = int(C.murmur_managed_schema_export(n.db, &record))
		}
		if out.RC == 0 {
			defer C.murmur_origin_record_free(&record)
			var header [200]C.uint8_t
			out.RC = int(C.murmur_origin_envelope_encode(&record.envelope, unsafe.Pointer(&header[0]), 200))
			if record.bytes > 64<<20 {
				out.RC = 18
				break
			}
			out.Data = append(C.GoBytes(unsafe.Pointer(&header[0]), 200), C.GoBytes(unsafe.Pointer(record.payload), C.int(record.bytes))...)
		}
	case "apply", "adopt":
		if len(request.Data) < 200 || len(request.Data) > (64<<20)+200 {
			out.RC = 11
			break
		}
		memory := C.CBytes(request.Data)
		defer C.free(memory)
		var changed C.int
		out.RC = int(C.mh_apply(n.db, memory, C.size_t(len(request.Data)), flag(request.Op == "adopt"), &changed))
		out.Changed = changed != 0
	case "progress", "search-status", "schema", "policies":
		which := map[string]int{"progress": 0, "search-status": 1, "schema": 2, "policies": 3}[request.Op]
		out.RC = int(C.mh_rows(n.db, C.int(which), &result))
	case "stats":
		var stats C.murmur_scheduler_stats_t
		C.murmur_managed_scheduler_stats(n.db, &stats)
		out.Stats = &Stats{DebtNS: int64(stats.debt_ns), Active: stats.active != 0}
		for i := range out.Stats.Classes {
			s := stats.classes[i]
			out.Stats.Classes[i] = ClassStats{uint64(s.acquisitions), uint64(s.cancels), uint64(s.wait_ns), uint64(s.service_ns), uint64(s.waiters)}
		}
	case "capabilities":
		out.Capabilities = int(C.mh_capabilities())
	default:
		out.RC, out.Error = 21, "unknown managed operation"
	}
	if out.RC == 0 && result.json != nil {
		if err := json.Unmarshal(C.GoBytes(unsafe.Pointer(result.json), C.int(result.bytes)), &out.Rows); err != nil {
			out.RC, out.Error = 1, err.Error()
		}
	}
	if out.RC != 0 && out.Error == "" {
		out.Error = fmt.Sprintf("managed %s rc=%d", request.Op, out.RC)
	}
	return out
}
