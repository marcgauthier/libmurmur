package sqlite

/*
#include <stdint.h>
#include "../../../../deps/sqlite/sqlite3.h"
#include "../../../../libmurmur.h"
*/
import "C"

import "unsafe"

// SetKey provisions the 32-byte master key on the connection's main
// database through the public murmur_db_key API: the ordinary-client
// path, with no SQL involved. It reports the SQLite primary result
// code (0 on success; 11 when the key does not unlock a sealed
// store; 21 for a second, different key).
func (c *Conn) SetKey(key [32]byte) int {
	if c == nil || c.db == nil {
		return int(C.SQLITE_MISUSE)
	}
	return int(C.murmur_db_key(c.db, (*C.uint8_t)(unsafe.Pointer(&key[0]))))
}
