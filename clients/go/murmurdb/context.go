package murmurdb

/*
#cgo CFLAGS: -I${SRCDIR}/../../../deps/sqlite
#include <stdlib.h>
#include <stdatomic.h>
#include "sqlite3.h"

typedef struct { atomic_int canceled; } murmur_context;
static murmur_context *murmur_context_new(void) {
    murmur_context *p = malloc(sizeof(*p));
    if (p) atomic_init(&p->canceled, 0);
    return p;
}
static void murmur_context_cancel(murmur_context *p) {
    atomic_store_explicit(&p->canceled, 1, memory_order_relaxed);
}
static int murmur_context_poll(void *p) {
    return atomic_load_explicit(&((murmur_context *)p)->canceled, memory_order_relaxed);
}
static void murmur_context_install(sqlite3 *db, murmur_context *p) {
    sqlite3_progress_handler(db, 1000, murmur_context_poll, p);
}
static void murmur_context_remove(sqlite3 *db) {
    sqlite3_progress_handler(db, 0, NULL, NULL);
}
*/
import "C"

import (
	"context"
	"database/sql/driver"
	"errors"
	"unsafe"

	"github.com/marcgauthier/libmurmur/clients/go/bindings/sqlite"
)

// Install the statement-local cancellation handler only while native writer
// admission excludes replication SQL on this same handle.
func (c *conn) withSQLContext(ctx context.Context, fn func() error) error {
	if c.work == nil {
		return c.withContext(ctx, fn)
	}
	sqlite.LockWriter()
	defer sqlite.UnlockWriter()
	return c.withContext(ctx, fn)
}

// withContext runs while c.mu owns the connection. The progress handler
// reads a C atomic rather than calling Go from SQLite. Joining cancellation
// before freeing the flag prevents a late callback affecting another query.
func (c *conn) withContext(ctx context.Context, fn func() error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if ctx.Done() == nil {
		return fn()
	}
	flag := C.murmur_context_new()
	if flag == nil {
		return errors.New("murmurdb: allocating cancellation state")
	}
	db := (*C.sqlite3)(c.raw.NativeDB())
	C.murmur_context_install(db, flag)
	finished := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		C.murmur_context_cancel(flag)
		close(finished)
	})
	defer func() {
		if !stop() {
			<-finished
		}
		C.murmur_context_remove(db)
		C.free(unsafe.Pointer(flag))
	}()
	err := fn()
	if err != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}

var _ driver.StmtExecContext = (*stmt)(nil)
var _ driver.StmtQueryContext = (*stmt)(nil)

func (s *stmt) ExecContext(ctx context.Context, args []driver.NamedValue) (driver.Result, error) {
	return s.c.execArgs(ctx, s.query, args)
}

func (s *stmt) QueryContext(ctx context.Context, args []driver.NamedValue) (driver.Rows, error) {
	return s.c.QueryContext(ctx, s.query, args)
}
