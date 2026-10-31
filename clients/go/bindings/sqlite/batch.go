package sqlite

/*
#include <stdlib.h>
#include "../../../../deps/sqlite/sqlite3.h"

typedef struct {
	unsigned long long v;
	int n;
	unsigned char t;
} murmur_arg;
typedef struct {
	int row;
	int rc;
} murmur_exec_out;
typedef struct {
	unsigned long long v;
	int n;
	unsigned char t;
} murmur_cell;
typedef struct {
	int n;
	int rc;
	int truncated;
} murmur_rows_out;

int murmur_step_once(sqlite3_stmt *s);
murmur_exec_out murmur_exec_batch(sqlite3_stmt *s, const murmur_arg *args, int nparams,
                                 int nrows, const char *arena);
murmur_rows_out murmur_step_rows(sqlite3_stmt *s, int skip_step, const unsigned char *types,
                                murmur_cell *cols, int ncol, char *arena, int alen,
                                int maxrows);
int murmur_fetch_i1(sqlite3_stmt *s, long long key, const unsigned char *types,
                    murmur_cell *cols, int ncol, char *arena, int alen);
int murmur_fetch_many(sqlite3_stmt *s, const long long *keys, int nkeys,
                      const unsigned char *types, murmur_cell *cols, int ncol,
                      char *arena, int alen, unsigned char *hits);
int murmur_fetch_t1(sqlite3_stmt *s, const char *key, int keylen, const unsigned char *types,
                    murmur_cell *cols, int ncol, char *arena, int alen);
*/
import "C"

import (
	"fmt"
	"math"
	"runtime"
	"strings"
	"unsafe"
)

// Fused statement calls: one cgo crossing per batch instead of one per
// bind/step/column. Pointer-free Arg/Cell structs keep the cgo
// pointer check O(1); payload bytes live in caller-owned arenas.

const murmurTruncated = -1

// ColType selects how a scan column decodes. Must match MC_* in batch.c.
type ColType byte

const (
	ColInt   ColType = 0
	ColFloat ColType = 1
	ColText  ColType = 2
	ColBlob  ColType = 3
	// ColAny dispatches on the actual storage class per value:
	// integers and floats decode to V, text/blobs copy to the
	// arena, NULL yields a null cell. T always reports the real
	// class.
	ColAny ColType = 4
)

// Cell is one decoded batch column: 16 bytes, pointer-free. V holds
// int64/float64 bits or the arena offset of a text/blob payload, N its
// length, T the storage class (TypeInteger..TypeNull). Layout must
// match C murmur_cell.
type Cell struct {
	V uint64
	N uint32
	T uint8
	_ [3]byte
}

var (
	_ [16 - unsafe.Sizeof(Cell{})]int
	_ [8 - unsafe.Offsetof(Cell{}.N)]int
	_ [12 - unsafe.Offsetof(Cell{}.T)]int
)

// Int64 returns an integer cell's value.
func (c *Cell) Int64() int64 { return int64(c.V) }

// Float returns a float cell's value.
func (c *Cell) Float() float64 { return math.Float64frombits(c.V) }

// Type returns the cell's storage class.
func (c *Cell) Type() int { return int(c.T) }

// TextView returns the TEXT payload referencing arena. Valid until the
// caller reuses the arena.
func (c *Cell) TextView(arena []byte) string {
	if c.T == TypeNull || c.N == 0 {
		return ""
	}
	return unsafe.String(&arena[c.V], c.N)
}

// Text returns a copy of the TEXT payload.
func (c *Cell) Text(arena []byte) string { return strings.Clone(c.TextView(arena)) }

// BlobLen returns the payload byte length without building a view.
func (c *Cell) BlobLen() int { return int(c.N) }

// Bytes returns the TEXT/BLOB payload as an arena slice, preserving
// empty-but-present values. Only call on text/blob cells;
// integer/float V holds value bits, not an offset.
func (c *Cell) Bytes(arena []byte) []byte {
	return arena[c.V : c.V+uint64(c.N)]
}

// ArgType selects how an Arg binds. Must match MA_* in batch.c.
type ArgType uint8

const (
	ArgInt   ArgType = 0
	ArgFloat ArgType = 1
	ArgText  ArgType = 2
	ArgBlob  ArgType = 3
	ArgNull  ArgType = 4
)

// Arg is one bound DML value: 16 bytes, pointer-free. V holds
// int64/float64 bits or the payload-arena offset of text/blob bytes, N
// the byte length, T the kind. Layout must match C murmur_arg.
type Arg struct {
	V uint64
	N uint32
	T ArgType
	_ [3]byte
}

var (
	_ [16 - unsafe.Sizeof(Arg{})]int
	_ [8 - unsafe.Offsetof(Arg{}.N)]int
	_ [12 - unsafe.Offsetof(Arg{}.T)]int
)

// IntArg binds an int64.
func IntArg(v int64) Arg { return Arg{V: uint64(v), T: ArgInt} }

// FloatArg binds a float64.
func FloatArg(v float64) Arg { return Arg{V: math.Float64bits(v), T: ArgFloat} }

// NullArg binds SQL NULL.
func NullArg() Arg { return Arg{T: ArgNull} }

// TextArg appends s to the payload arena and returns the Arg for it.
// Empty strings bind empty (never NULL); use NullArg for NULL.
func TextArg(arena []byte, s string) (Arg, []byte) {
	off := len(arena)
	arena = append(arena, s...)
	return Arg{V: uint64(off), N: uint32(len(s)), T: ArgText}, arena
}

// BlobArg appends b to the payload arena and returns the Arg for it.
func BlobArg(arena []byte, b []byte) (Arg, []byte) {
	off := len(arena)
	arena = append(arena, b...)
	return Arg{V: uint64(off), N: uint32(len(b)), T: ArgBlob}, arena
}

// StepOnce steps a DML statement and resets it in a single crossing.
func (s *Stmt) StepOnce() error {
	s.lock()
	defer s.unlock()
	lockDB()
	defer unlockDB()
	s.pending = false
	if rc := C.murmur_step_once(s.s); rc != C.SQLITE_DONE {
		return errOf(s.db, rc)
	}
	return nil
}

// ExecBatch executes nrows DML rows in a single crossing. args holds
// nrows*nparams entries row-major; text/blob bytes live in arena. On
// failure it reports the failing row index.
func (s *Stmt) ExecBatch(args []Arg, arena []byte, nparams int) error {
	s.lock()
	defer s.unlock()
	lockDB()
	defer unlockDB()
	s.pending = false
	if nparams <= 0 || len(args)%nparams != 0 || len(args) == 0 {
		return fmt.Errorf("sqlite.ExecBatch: bad sizes args=%d nparams=%d", len(args), nparams)
	}
	a := (*C.murmur_arg)(unsafe.Pointer(unsafe.SliceData(args)))
	var p *C.char
	if len(arena) > 0 {
		p = (*C.char)(unsafe.Pointer(unsafe.SliceData(arena)))
	}
	nrows := len(args) / nparams
	out := C.murmur_exec_batch(s.s, a, C.int(nparams), C.int(nrows), p)
	runtime.KeepAlive(args)
	runtime.KeepAlive(arena)
	if out.rc != C.SQLITE_DONE {
		return fmt.Errorf("sqlite.ExecBatch: row %d: %w", int(out.row), errOf(s.db, out.rc))
	}
	return nil
}

// StepRows fetches up to maxrows rows in a single crossing. types
// describes one row; cols must hold at least maxrows*len(types)
// entries. TEXT/BLOB payloads are copied into arena (caller-owned,
// reusable across calls). It returns the rows delivered and whether
// more may follow. If the next row does not fit the remaining arena it
// is left for the next call; a call may deliver 0 rows with more=true,
// in which case the arena must grow before retrying. Do not mix other
// statement calls between StepRows calls of one scan.
func (s *Stmt) StepRows(types []ColType, cols []Cell, arena []byte, maxrows int) (int, bool, error) {
	s.lock()
	defer s.unlock()
	lockDB()
	defer unlockDB()
	ncol := len(types)
	if ncol == 0 || maxrows <= 0 || len(cols) < maxrows*ncol {
		return 0, false, fmt.Errorf("sqlite.StepRows: bad sizes types=%d cols=%d maxrows=%d", ncol, len(cols), maxrows)
	}
	t := (*C.uchar)(unsafe.Pointer(unsafe.SliceData(types)))
	c := (*C.murmur_cell)(unsafe.Pointer(unsafe.SliceData(cols)))
	a := (*C.char)(unsafe.Pointer(unsafe.SliceData(arena)))
	skip := C.int(0)
	if s.pending {
		skip = 1
	}
	out := C.murmur_step_rows(s.s, skip, t, c, C.int(ncol), a, C.int(len(arena)), C.int(maxrows))
	runtime.KeepAlive(types)
	runtime.KeepAlive(cols)
	runtime.KeepAlive(arena)
	s.pending = out.truncated != 0
	switch out.rc {
	case C.SQLITE_ROW:
		return int(out.n), true, nil
	case C.SQLITE_DONE:
		return int(out.n), false, nil
	default:
		return int(out.n), true, errOf(s.db, out.rc)
	}
}

// FetchInt64 performs a one-shot int-key point lookup: reset, bind key
// to parameter 1, step, decode — in a single crossing. Payloads land
// in arena. It reports false when no row matches.
func (s *Stmt) FetchInt64(key int64, types []ColType, cells []Cell, arena []byte) (bool, error) {
	s.lock()
	defer s.unlock()
	lockDB()
	defer unlockDB()
	s.pending = false
	if len(types) != len(cells) || len(types) == 0 {
		return false, fmt.Errorf("sqlite.FetchInt64: length mismatch %d != %d", len(types), len(cells))
	}
	t := (*C.uchar)(unsafe.Pointer(unsafe.SliceData(types)))
	c := (*C.murmur_cell)(unsafe.Pointer(unsafe.SliceData(cells)))
	a := (*C.char)(unsafe.Pointer(unsafe.SliceData(arena)))
	rc := C.murmur_fetch_i1(s.s, C.longlong(key), t, c, C.int(len(types)), a, C.int(len(arena)))
	runtime.KeepAlive(types)
	runtime.KeepAlive(cells)
	runtime.KeepAlive(arena)
	switch rc {
	case C.SQLITE_ROW:
		return true, nil
	case C.SQLITE_DONE:
		return false, nil
	case murmurTruncated:
		return false, fmt.Errorf("sqlite.FetchInt64: row exceeds arena (%d bytes)", len(arena))
	default:
		return false, errOf(s.db, rc)
	}
}

// FetchManyInt64 performs len(keys) one-shot int-key point lookups
// in a single crossing. Cells must hold len(keys)*len(types)
// entries; hits reports per-key row found. Payloads share arena,
// whose offsets accumulate across keys.
func (s *Stmt) FetchManyInt64(keys []int64, types []ColType, cells []Cell, arena []byte, hits []bool) error {
	s.lock()
	defer s.unlock()
	lockDB()
	defer unlockDB()
	s.pending = false
	if len(keys) == 0 || len(types) == 0 || len(cells) < len(keys)*len(types) || len(hits) < len(keys) {
		return fmt.Errorf("sqlite.FetchManyInt64: bad sizes keys=%d types=%d cells=%d hits=%d",
			len(keys), len(types), len(cells), len(hits))
	}
	k := (*C.longlong)(unsafe.Pointer(unsafe.SliceData(keys)))
	t := (*C.uchar)(unsafe.Pointer(unsafe.SliceData(types)))
	c := (*C.murmur_cell)(unsafe.Pointer(unsafe.SliceData(cells)))
	a := (*C.char)(unsafe.Pointer(unsafe.SliceData(arena)))
	h := (*C.uchar)(unsafe.Pointer(unsafe.SliceData(hits)))
	rc := C.murmur_fetch_many(s.s, k, C.int(len(keys)), t, c, C.int(len(types)), a, C.int(len(arena)), h)
	runtime.KeepAlive(keys)
	runtime.KeepAlive(types)
	runtime.KeepAlive(cells)
	runtime.KeepAlive(arena)
	runtime.KeepAlive(hits)
	switch rc {
	case C.SQLITE_OK:
		return nil
	case murmurTruncated:
		return fmt.Errorf("sqlite.FetchManyInt64: keys exceed arena (%d bytes)", len(arena))
	default:
		return errOf(s.db, rc)
	}
}

// FetchText performs a one-shot text-key point lookup in a single
// crossing with zero Go allocations. It reports false when no row
// matches.
func (s *Stmt) FetchText(key string, types []ColType, cells []Cell, arena []byte) (bool, error) {
	s.lock()
	defer s.unlock()
	lockDB()
	defer unlockDB()
	s.pending = false
	if len(types) != len(cells) || len(types) == 0 {
		return false, fmt.Errorf("sqlite.FetchText: length mismatch %d != %d", len(types), len(cells))
	}
	t := (*C.uchar)(unsafe.Pointer(unsafe.SliceData(types)))
	c := (*C.murmur_cell)(unsafe.Pointer(unsafe.SliceData(cells)))
	a := (*C.char)(unsafe.Pointer(unsafe.SliceData(arena)))
	var k *C.char
	if len(key) > 0 {
		k = (*C.char)(unsafe.Pointer(unsafe.StringData(key)))
	}
	rc := C.murmur_fetch_t1(s.s, k, C.int(len(key)), t, c, C.int(len(types)), a, C.int(len(arena)))
	runtime.KeepAlive(types)
	runtime.KeepAlive(cells)
	runtime.KeepAlive(arena)
	runtime.KeepAlive(key)
	switch rc {
	case C.SQLITE_ROW:
		return true, nil
	case C.SQLITE_DONE:
		return false, nil
	case murmurTruncated:
		return false, fmt.Errorf("sqlite.FetchText: row exceeds arena (%d bytes)", len(arena))
	default:
		return false, errOf(s.db, rc)
	}
}
