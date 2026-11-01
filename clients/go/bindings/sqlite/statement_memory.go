package sqlite

/*
#include "../../../../deps/sqlite/sqlite3.h"
*/
import "C"

// MemoryUsed reports SQLite's current heap accounting for this statement.
// Like other Stmt methods, it must not race connection closure.
func (s *Stmt) MemoryUsed() int {
	s.lock()
	defer s.unlock()
	if s.s == nil {
		return 0
	}
	return int(C.sqlite3_stmt_status(s.s, C.SQLITE_STMTSTATUS_MEMUSED, 0))
}

// ClearBindings releases bound values without recompiling the statement.
// Reset deliberately keeps bindings; pooled statements should clear them
// separately before retaining an idle statement.
func (s *Stmt) ClearBindings() error {
	s.lock()
	defer s.unlock()
	if s.s == nil {
		return &Error{Code: int(C.SQLITE_MISUSE), Msg: "closed statement"}
	}
	if rc := C.sqlite3_clear_bindings(s.s); rc != C.SQLITE_OK {
		return errOf(s.db, rc)
	}
	return nil
}
