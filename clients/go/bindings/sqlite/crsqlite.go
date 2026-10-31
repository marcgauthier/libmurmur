package sqlite

/*
#cgo CFLAGS: -I${SRCDIR}/../../../../deps/sqlite
#cgo LDFLAGS: ${SRCDIR}/../../../../libmurmur.a -ldl
#include <stdlib.h>
#include "../../../../deps/crsqlite/include/sqlite_murmur_crsqlite.h"
*/
import "C"

import (
	"unsafe"
)

// CrsqliteInit initializes the vendored cr-sqlite extension (Rust core)
// on c. Idempotent per connection. After this, CRR tables are enabled
// with SELECT crsql_as_crr('main','table'), the local site reads via
// SELECT crsql_site_id(), versions via SELECT crsql_db_version(), and
// remote batches merge via SELECT crsql_ingest_blob(?). Close runs
// SELECT crsql_finalize() automatically on initialized connections.
// First init on a database writes the crsql_* metadata tables (later
// inits are read-only no-ops), so run it after the cold store PRAGMAs
// and never on a fresh read-only handle.
func CrsqliteInit(c *Conn) error {
	if c.crsqlite {
		return nil
	}
	var errMsg *C.char
	rc := C.sqlite3_crsqlite_init(c.db, &errMsg, nil)
	if errMsg != nil {
		defer C.sqlite3_free(unsafe.Pointer(errMsg))
	}
	if rc != C.SQLITE_OK {
		msg := ""
		if errMsg != nil {
			msg = C.GoString(errMsg)
		}
		return &Error{Code: int(rc), Msg: msg}
	}
	c.crsqlite = true
	return nil
}
