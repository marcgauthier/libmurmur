// Package sqlite is a minimal cgo binding over the vendored SQLite
// amalgamation in deps/sqlite. Only the standard library is used
// besides the vendored public-domain C sources, so no system SQLite is
// required.
//
// A Conn is bound to the goroutine that uses it and is not safe for
// concurrent use; serialize access with a mutex or open one Conn per
// worker. Statements belong to their Conn: finalize every Stmt before
// closing the Conn.
package sqlite

/*
#cgo CFLAGS: -DSQLITE_ENABLE_FTS5 -DSQLITE_THREADSAFE=1 -DSQLITE_ENABLE_PREUPDATE_HOOK=1 -O2
#cgo CXXFLAGS: -std=c++17 -DSQLITE_ENABLE_FTS5 -DSQLITE_THREADSAFE=1 -DSQLITE_ENABLE_PREUPDATE_HOOK=1 -O2
#cgo LDFLAGS: ${SRCDIR}/../../../../libmurmur.a -lm -lstdc++
#include <stdlib.h>
#include <string.h>
#include "../../../../deps/sqlite/sqlite3.h"

void murmur_db_writer_lock(void);
void murmur_db_writer_unlock(void);
static const char *goMainFilename(sqlite3 *db) { return sqlite3_db_filename(db, "main"); }

static sqlite3_destructor_type goTransient(void) { return SQLITE_TRANSIENT; }
*/
import "C"

import (
	"fmt"
	"runtime"
	"time"
	"unsafe"
)

// Open flags, mirroring SQLITE_OPEN_*.
const (
	OpenReadOnly  = 0x00000001
	OpenReadWrite = 0x00000002
	OpenCreate    = 0x00000004
	OpenMemory    = 0x00000080
	OpenURI       = 0x00000040
	OpenFullMutex = 0x00010000
)

// Column types, mirroring SQLITE_*.
const (
	TypeInteger = 1
	TypeFloat   = 2
	TypeText    = 3
	TypeBlob    = 4
	TypeNull    = 5
)

// Error reports a SQLite failure with its primary and extended codes.
type Error struct {
	Code    int
	ExtCode int
	Msg     string
}

func (e *Error) Error() string {
	if e.Msg == "" {
		return fmt.Sprintf("sqlite: code=%d ext=%d", e.Code, e.ExtCode)
	}
	return fmt.Sprintf("sqlite: code=%d ext=%d: %s", e.Code, e.ExtCode, e.Msg)
}

func errOf(db *C.sqlite3, rc C.int) error {
	return &Error{
		Code:    int(rc),
		ExtCode: int(C.sqlite3_extended_errcode(db)),
		Msg:     C.GoString(C.sqlite3_errmsg(db)),
	}
}

// LockWriter serializes the caller against native engine write
// transactions on handles shared with engine workers. The pthread
// guard is thread-scoped, so the goroutine stays pinned for the
// hold; pairing UnlockWriter via defer is mandatory. Nesting is
// safe (pinning nests and the C mutex is recursive).
func LockWriter() {
	runtime.LockOSThread()
	C.murmur_db_writer_lock()
}

// UnlockWriter releases a hold acquired by LockWriter.
func UnlockWriter() {
	C.murmur_db_writer_unlock()
	runtime.UnlockOSThread()
}

func lockDB() { LockWriter() }

func unlockDB() { UnlockWriter() }

// Conn is an open SQLite database connection.
type Conn struct {
	db *C.sqlite3
	// crsqlite reports whether CrsqliteInit ran on this handle; Close
	// finalizes the extension first on such connections.
	crsqlite bool
}

// Open opens the database at path with the given Open* flags.
func Open(path string, flags int) (*Conn, error) {
	cpath := C.CString(path)
	defer C.free(unsafe.Pointer(cpath))
	var db *C.sqlite3
	rc := C.sqlite3_open_v2(cpath, &db, C.int(flags), nil)
	if rc != C.SQLITE_OK {
		msg := ""
		if db != nil {
			msg = C.GoString(C.sqlite3_errmsg(db))
			C.sqlite3_close(db)
		}
		return nil, &Error{Code: int(rc), Msg: msg}
	}
	return &Conn{db: db}, nil
}

// OpenVFS opens the database at path with the given Open* flags
// through the named VFS (e.g. "sqlite-murmur" for murmur stores).
func OpenVFS(path string, flags int, vfs string) (*Conn, error) {
	cpath := C.CString(path)
	defer C.free(unsafe.Pointer(cpath))
	cvfs := C.CString(vfs)
	defer C.free(unsafe.Pointer(cvfs))
	var db *C.sqlite3
	rc := C.sqlite3_open_v2(cpath, &db, C.int(flags), cvfs)
	if rc != C.SQLITE_OK {
		msg := ""
		if db != nil {
			msg = C.GoString(C.sqlite3_errmsg(db))
			C.sqlite3_close(db)
		}
		return nil, &Error{Code: int(rc), Msg: msg}
	}
	return &Conn{db: db}, nil
}

// NativeDB exposes the raw sqlite3 handle for native subsystems
// (replication engine/driver) that borrow the connection.
func (c *Conn) NativeDB() unsafe.Pointer {
	return unsafe.Pointer(c.db)
}

// Close closes the connection. All statements must be finalized first.
func (c *Conn) Close() error {
	if c.db == nil {
		return nil
	}
	// cr-sqlite tears down per-connection state (after application
	// statements are finalized, before close); a finalize failure
	// still closes the handle.
	var ferr error
	if c.crsqlite {
		ferr = c.Exec("SELECT crsql_finalize()")
	}
	if rc := C.sqlite3_close(c.db); rc != C.SQLITE_OK {
		return errOf(c.db, rc)
	}
	if ferr != nil {
		return ferr
	}
	c.db = nil
	return nil
}

// Exec runs one or more statements that return no rows.
func (c *Conn) Exec(sql string) error {
	lockDB()
	defer unlockDB()
	csql := C.CString(sql)
	defer C.free(unsafe.Pointer(csql))
	var errmsg *C.char
	rc := C.sqlite3_exec(c.db, csql, nil, nil, &errmsg)
	if errmsg != nil {
		defer C.sqlite3_free(unsafe.Pointer(errmsg))
	}
	if rc != C.SQLITE_OK {
		return &Error{
			Code: int(rc),
			Msg:  C.GoString(errmsg),
		}
	}
	return nil
}

// Changes reports the number of rows modified by the last statement.
func (c *Conn) Changes() int64 {
	return int64(C.sqlite3_changes(c.db))
}

// Autocommit reports whether the connection is in autocommit mode
// (no open transaction). Peer and wait controls require it.
func (c *Conn) Autocommit() bool {
	return C.sqlite3_get_autocommit(c.db) != 0
}

// MainFilename returns SQLite's resolved main-database path, or an empty string
// for an in-memory database. The caller must reserve the connection.
func (c *Conn) MainFilename() string {
	return C.GoString(C.goMainFilename(c.db))
}

// LastInsertRowID reports the rowid of the last successful insert.
func (c *Conn) LastInsertRowID() int64 {
	return int64(C.sqlite3_last_insert_rowid(c.db))
}

// Stmt is a prepared statement. It is not safe for concurrent use.
type Stmt struct {
	db      *C.sqlite3
	s       *C.sqlite3_stmt
	mu      chan struct{} // serializes use; cap 1, prefilled
	pending bool          // StepRows left a stepped-but-undelivered row current
}

// Prepare compiles sql into a statement.
func (c *Conn) Prepare(sql string) (*Stmt, error) {
	csql := C.CString(sql)
	defer C.free(unsafe.Pointer(csql))
	var s *C.sqlite3_stmt
	if rc := C.sqlite3_prepare_v2(c.db, csql, -1, &s, nil); rc != C.SQLITE_OK {
		return nil, errOf(c.db, rc)
	}
	mu := make(chan struct{}, 1)
	mu <- struct{}{}
	return &Stmt{db: c.db, s: s, mu: mu}, nil
}

// PrepareTail compiles the first statement of sql and returns the
// uncompiled remainder, so callers can run multi-statement scripts
// statement by statement. A nil Stmt means the head held no statement
// (blank text, bare semicolons, or comments); keep calling while the
// remainder is non-blank.
func (c *Conn) PrepareTail(sql string) (*Stmt, string, error) {
	csql := C.CString(sql)
	defer C.free(unsafe.Pointer(csql))
	var s *C.sqlite3_stmt
	var tail *C.char
	if rc := C.sqlite3_prepare_v2(c.db, csql, -1, &s, &tail); rc != C.SQLITE_OK {
		return nil, "", errOf(c.db, rc)
	}
	var rest string
	if tail != nil {
		rest = C.GoString(tail)
	}
	if s == nil {
		return nil, rest, nil
	}
	mu := make(chan struct{}, 1)
	mu <- struct{}{}
	return &Stmt{db: c.db, s: s, mu: mu}, rest, nil
}

func (s *Stmt) lock() {
	<-s.mu
}

func (s *Stmt) unlock() {
	s.mu <- struct{}{}
}

// Close finalizes the statement.
func (s *Stmt) Close() error {
	s.lock()
	defer s.unlock()
	if s.s == nil {
		return nil
	}
	rc := C.sqlite3_finalize(s.s)
	s.s = nil
	if rc != C.SQLITE_OK {
		return errOf(s.db, rc)
	}
	return nil
}

// Reset returns the statement to its initial state with bindings kept.
func (s *Stmt) Reset() error {
	s.lock()
	defer s.unlock()
	s.pending = false
	if rc := C.sqlite3_reset(s.s); rc != C.SQLITE_OK {
		return errOf(s.db, rc)
	}
	return nil
}

// Step advances to the next row. It reports done=true when the statement
// has finished; call Column* only when done=false and err=nil.
func (s *Stmt) Step() (done bool, err error) {
	s.lock()
	defer s.unlock()
	lockDB()
	defer unlockDB()
	if s.pending {
		return false, fmt.Errorf("sqlite.Step: unconsumed StepRows row current; call StepRows")
	}
	switch rc := C.sqlite3_step(s.s); rc {
	case C.SQLITE_ROW:
		return false, nil
	case C.SQLITE_DONE:
		return true, nil
	default:
		return false, errOf(s.db, rc)
	}
}

// ColumnCount reports the number of result columns.
func (s *Stmt) ColumnCount() int {
	s.lock()
	defer s.unlock()
	return int(C.sqlite3_column_count(s.s))
}

// ColumnName reports the name of result column i.
func (s *Stmt) ColumnName(i int) string {
	s.lock()
	defer s.unlock()
	p := C.sqlite3_column_name(s.s, C.int(i))
	if p == nil {
		return ""
	}
	return C.GoString(p)
}

// ColumnType reports the storage type of column i in the current row.
func (s *Stmt) ColumnType(i int) int {
	s.lock()
	defer s.unlock()
	return int(C.sqlite3_column_type(s.s, C.int(i)))
}

// ColumnInt64 reads column i as an integer.
func (s *Stmt) ColumnInt64(i int) int64 {
	s.lock()
	defer s.unlock()
	return int64(C.sqlite3_column_int64(s.s, C.int(i)))
}

// ColumnFloat reads column i as a float.
func (s *Stmt) ColumnFloat(i int) float64 {
	s.lock()
	defer s.unlock()
	return float64(C.sqlite3_column_double(s.s, C.int(i)))
}

// ColumnText reads column i as text. The bytes are copied.
func (s *Stmt) ColumnText(i int) string {
	s.lock()
	defer s.unlock()
	n := C.sqlite3_column_bytes(s.s, C.int(i))
	p := C.sqlite3_column_text(s.s, C.int(i))
	if p == nil {
		return ""
	}
	return C.GoStringN((*C.char)(unsafe.Pointer(p)), n)
}

// ColumnBlob reads column i as a blob. The bytes are copied. NULL
// reads back nil; an empty blob reads back non-nil. (A zero-length
// blob and NULL both present a nil pointer, so the type decides.)
func (s *Stmt) ColumnBlob(i int) []byte {
	s.lock()
	defer s.unlock()
	if C.sqlite3_column_type(s.s, C.int(i)) == C.SQLITE_NULL {
		return nil
	}
	n := C.sqlite3_column_bytes(s.s, C.int(i))
	if n == 0 {
		return []byte{}
	}
	p := C.sqlite3_column_blob(s.s, C.int(i))
	return C.GoBytes(p, n)
}

func (s *Stmt) bindErr(rc C.int) error {
	if rc != C.SQLITE_OK {
		return &Error{Code: int(rc)}
	}
	return nil
}

// BindInt64 binds parameter i (1-based) to an integer.
func (s *Stmt) BindInt64(i int, v int64) error {
	s.lock()
	defer s.unlock()
	return s.bindErr(C.sqlite3_bind_int64(s.s, C.int(i), C.sqlite3_int64(v)))
}

// BindFloat binds parameter i (1-based) to a float.
func (s *Stmt) BindFloat(i int, v float64) error {
	s.lock()
	defer s.unlock()
	return s.bindErr(C.sqlite3_bind_double(s.s, C.int(i), C.double(v)))
}

// BindText binds parameter i (1-based) to text. SQLite copies the value.
// emptyByte backs empty text binds: a NULL pointer would bind NULL.
var emptyByte byte

// BindText binds parameter i (1-based) to text. Go string memory is
// passed directly and copied by SQLite (TRANSIENT): no CString
// malloc, zero Go allocations. Empty binds empty, never NULL.
func (s *Stmt) BindText(i int, v string) error {
	s.lock()
	defer s.unlock()
	p := (*C.char)(unsafe.Pointer(&emptyByte))
	if len(v) > 0 {
		p = (*C.char)(unsafe.Pointer(unsafe.StringData(v)))
	}
	rc := C.sqlite3_bind_text(s.s, C.int(i), p, C.int(len(v)), C.goTransient())
	runtime.KeepAlive(v)
	return s.bindErr(rc)
}

// BindBlob binds parameter i (1-based) to a blob. SQLite copies the value.
func (s *Stmt) BindBlob(i int, v []byte) error {
	s.lock()
	defer s.unlock()
	if len(v) == 0 {
		return s.bindErr(C.sqlite3_bind_blob(s.s, C.int(i), nil, 0, C.goTransient()))
	}
	rc := C.sqlite3_bind_blob(s.s, C.int(i), unsafe.Pointer(&v[0]), C.int(len(v)), C.goTransient())
	runtime.KeepAlive(v)
	return s.bindErr(rc)
}

// BindNull binds parameter i (1-based) to NULL.
func (s *Stmt) BindNull(i int) error {
	s.lock()
	defer s.unlock()
	return s.bindErr(C.sqlite3_bind_null(s.s, C.int(i)))
}

// BindZeroBlob binds parameter i (1-based) to a zero-filled blob of
// n bytes. n == 0 binds an empty (non-NULL) blob.
func (s *Stmt) BindZeroBlob(i, n int) error {
	s.lock()
	defer s.unlock()
	return s.bindErr(C.sqlite3_bind_zeroblob(s.s, C.int(i), C.int(n)))
}

// Bind binds args to parameters 1..N. Conversions mirror the
// reference client: nil is NULL, bools and all int/uint widths are
// integers, floats are reals, strings are text, and []byte is a
// blob (nil binds NULL, empty binds an empty blob). time.Time
// binds UTC RFC3339Nano text. Anything else is an error.
func (s *Stmt) Bind(args ...any) error {
	for n, a := range args {
		if err := s.bindOne(n+1, a); err != nil {
			return err
		}
	}
	return nil
}

func (s *Stmt) bindOne(i int, a any) error {
	switch v := a.(type) {
	case nil:
		return s.BindNull(i)
	case bool:
		if v {
			return s.BindInt64(i, 1)
		}
		return s.BindInt64(i, 0)
	case int:
		return s.BindInt64(i, int64(v))
	case int8:
		return s.BindInt64(i, int64(v))
	case int16:
		return s.BindInt64(i, int64(v))
	case int32:
		return s.BindInt64(i, int64(v))
	case int64:
		return s.BindInt64(i, v)
	case uint:
		return s.BindInt64(i, int64(v))
	case uint8:
		return s.BindInt64(i, int64(v))
	case uint16:
		return s.BindInt64(i, int64(v))
	case uint32:
		return s.BindInt64(i, int64(v))
	case uint64:
		return s.BindInt64(i, int64(v))
	case float32:
		return s.BindFloat(i, float64(v))
	case float64:
		return s.BindFloat(i, v)
	case string:
		return s.BindText(i, v)
	case []byte:
		if v == nil {
			return s.BindNull(i)
		}
		if len(v) == 0 {
			return s.BindZeroBlob(i, 0)
		}
		return s.BindBlob(i, v)
	case time.Time:
		return s.BindText(i, v.UTC().Format(time.RFC3339Nano))
	default:
		return fmt.Errorf("sqlite: cannot bind %T", a)
	}
}

// MemoryUsed reports cache, prepared-statement and schema allocations owned
// by this connection, using SQLite's native per-connection accounting.
func (c *Conn) MemoryUsed() (int64, error) {
	var total int64
	for _, op := range []C.int{C.SQLITE_DBSTATUS_CACHE_USED, C.SQLITE_DBSTATUS_SCHEMA_USED, C.SQLITE_DBSTATUS_STMT_USED} {
		var current, high C.int
		if rc := C.sqlite3_db_status(c.db, op, &current, &high, 0); rc != C.SQLITE_OK {
			return 0, errOf(c.db, rc)
		}
		total += int64(current)
	}
	return total, nil
}
