package sqlite

/*
#cgo CFLAGS: -DSQLITE_ENABLE_FTS5 -DSQLITE_THREADSAFE=1 -DSQLITE_ENABLE_PREUPDATE_HOOK=1 -O2
#cgo CXXFLAGS: -std=c++17 -DSQLITE_ENABLE_FTS5 -DSQLITE_THREADSAFE=1 -DSQLITE_ENABLE_PREUPDATE_HOOK=1 -O2
#cgo LDFLAGS: ${SRCDIR}/../../../../libmurmur.a -lm -lstdc++
#include <stdlib.h>
#include <string.h>
#include "../../../../deps/sqlite/sqlite3.h"

extern void goScalarFunc(sqlite3_context *ctx, int argc, sqlite3_value **argv);
extern int goAuthorizer(void *app, int action, char *p1, char *p2,
  char *db, char *src);

static int goCreateFunction(sqlite3 *db, const char *name, int nargs, int flags,
    sqlite3_int64 id) {
  return sqlite3_create_function_v2(db, name, nargs, SQLITE_UTF8, (void*)id,
      goScalarFunc, 0, 0, 0);
}

static int goSetAuthorizer(sqlite3 *db, sqlite3_int64 id) {
  return sqlite3_set_authorizer(db,
      (int (*)(void*,int,const char*,const char*,const char*,const char*))goAuthorizer,
      (void*)id);
}

static sqlite3_destructor_type goTransient(void) { return SQLITE_TRANSIENT; }

static const unsigned char *goValueText(sqlite3_value *v) {
  return sqlite3_value_text(v);
}
*/
import "C"

import (
	"fmt"
	"sync"
	"unsafe"
)

// Authorizer actions mirror SQLITE_* authorizer codes.
const (
	AuthSelect = 21
	AuthInsert = 18
	AuthUpdate = 23
	AuthDelete = 9
)

// Authorizer decisions.
const (
	AuthOK     = 0
	AuthDeny   = 1
	AuthIgnore = 2
)

// Value is one scalar-function argument.
type Value struct{ v *C.sqlite3_value }

// Type reports the storage type (TypeInteger/TypeFloat/TypeText/TypeBlob/TypeNull).
func (a Value) Type() int { return int(C.sqlite3_value_type(a.v)) }

// Int64 reads the argument as an integer with SQLite conversions.
func (a Value) Int64() int64 { return int64(C.sqlite3_value_int64(a.v)) }

// Float reads the argument as a float with SQLite conversions.
func (a Value) Float() float64 { return float64(C.sqlite3_value_double(a.v)) }

// Text reads the argument as text. The bytes are copied.
func (a Value) Text() string {
	n := C.sqlite3_value_bytes(a.v)
	p := C.goValueText(a.v)
	if p == nil {
		return ""
	}
	return C.GoStringN((*C.char)(unsafe.Pointer(p)), n)
}

// Blob reads the argument as a blob. The bytes are copied.
func (a Value) Blob() []byte {
	n := C.sqlite3_value_bytes(a.v)
	p := C.sqlite3_value_blob(a.v)
	if p == nil || n == 0 {
		return nil
	}
	return C.GoBytes(p, n)
}

// Context receives a scalar-function result.
type Context struct{ c *C.sqlite3_context }

// ResultInt64 sets an integer result.
func (x *Context) ResultInt64(v int64) { C.sqlite3_result_int64(x.c, C.sqlite3_int64(v)) }

// ResultText sets a text result. SQLite copies the value.
func (x *Context) ResultText(v string) {
	cs := C.CString(v)
	defer C.free(unsafe.Pointer(cs))
	C.sqlite3_result_text(x.c, cs, -1, C.goTransient())
}

// ResultError sets an error result, failing the statement.
func (x *Context) ResultError(err error) {
	cs := C.CString(err.Error())
	defer C.free(unsafe.Pointer(cs))
	C.sqlite3_result_error(x.c, cs, -1)
}

// ResultErrorCode sets an error result with an extended result code,
// failing the statement. Mirrors rusqlite's SqliteFailure path: the
// message plus the code reach the caller.
func (x *Context) ResultErrorCode(code int, err error) {
	cs := C.CString(err.Error())
	defer C.free(unsafe.Pointer(cs))
	C.sqlite3_result_error(x.c, cs, -1)
	C.sqlite3_result_error_code(x.c, C.int(code))
}

// ScalarFunc implements a SQL scalar function.
type ScalarFunc func(ctx *Context, args []Value)

var funcMu sync.Mutex
var funcNext int64
var funcReg = map[int64]ScalarFunc{}

//export goScalarFunc
func goScalarFunc(c *C.sqlite3_context, argc C.int, argv **C.sqlite3_value) {
	id := int64(uintptr(C.sqlite3_user_data(c)))
	funcMu.Lock()
	fn := funcReg[id]
	funcMu.Unlock()
	if fn == nil {
		C.sqlite3_result_error(c, C.CString("no such function"), -1)
		return
	}
	var args []Value
	if argc > 0 {
		vals := (*[1 << 30]*C.sqlite3_value)(unsafe.Pointer(argv))[:argc:argc]
		for _, v := range vals {
			args = append(args, Value{v: v})
		}
	}
	fn(&Context{c: c}, args)
}

// CreateFunction registers a scalar SQL function. nargs is the fixed arity
// (-1 for variadic). deterministic promises same-input-same-output for the
// query planner. The function lives until the connection closes.
func (c *Conn) CreateFunction(name string, nargs int, deterministic bool, fn ScalarFunc) error {
	funcMu.Lock()
	funcNext++
	id := funcNext
	funcReg[id] = fn
	funcMu.Unlock()
	cname := C.CString(name)
	defer C.free(unsafe.Pointer(cname))
	flags := 0
	if deterministic {
		flags = 0x000000800 // SQLITE_DETERMINISTIC
	}
	if rc := C.goCreateFunction(c.db, cname, C.int(nargs), C.int(flags), C.sqlite3_int64(id)); rc != C.SQLITE_OK {
		funcMu.Lock()
		delete(funcReg, id)
		funcMu.Unlock()
		return errOf(c.db, rc)
	}
	return nil
}

// AuthorizerFunc vets SQL operations. Returning AuthDeny aborts the
// statement; AuthIgnore skips the operation where the action allows it.
type AuthorizerFunc func(action int, p1, p2, db, src string) int

var authMu sync.Mutex
var authNext int64
var authReg = map[int64]AuthorizerFunc{}

//export goAuthorizer
func goAuthorizer(app unsafe.Pointer, action C.int, p1, p2, db, src *C.char) C.int {
	id := int64(uintptr(app))
	authMu.Lock()
	fn := authReg[id]
	authMu.Unlock()
	if fn == nil {
		return C.SQLITE_OK
	}
	return C.int(fn(int(action), C.GoString(p1), C.GoString(p2), C.GoString(db), C.GoString(src)))
}

// SetAuthorizer installs the connection authorizer, replacing any prior one.
func (c *Conn) SetAuthorizer(fn AuthorizerFunc) error {
	authMu.Lock()
	authNext++
	id := authNext
	authReg[id] = fn
	authMu.Unlock()
	if rc := C.goSetAuthorizer(c.db, C.sqlite3_int64(id)); rc != C.SQLITE_OK {
		authMu.Lock()
		delete(authReg, id)
		authMu.Unlock()
		return errOf(c.db, rc)
	}
	return nil
}

// BackupTo copies srcName of src into dstName of c using the online backup
// API. Names are database names ("main"), not file paths.
func (c *Conn) BackupTo(src *Conn, srcName, dstName string) error {
	csrc := C.CString(srcName)
	defer C.free(unsafe.Pointer(csrc))
	cdst := C.CString(dstName)
	defer C.free(unsafe.Pointer(cdst))
	b := C.sqlite3_backup_init(c.db, cdst, src.db, csrc)
	if b == nil {
		return errOf(c.db, C.sqlite3_errcode(c.db))
	}
	defer C.sqlite3_backup_finish(b)
	for {
		switch rc := C.sqlite3_backup_step(b, 100); rc {
		case C.SQLITE_DONE:
			return nil
		case C.SQLITE_OK, C.SQLITE_BUSY, C.SQLITE_LOCKED:
		default:
			return fmt.Errorf("sqlite: backup step: code=%d", int(rc))
		}
	}
}
