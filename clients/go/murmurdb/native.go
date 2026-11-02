package murmurdb

import (
	"context"
	"database/sql"
	"errors"

	"github.com/marcgauthier/libmurmur/clients/go/bindings/bridge"
	"github.com/marcgauthier/libmurmur/clients/go/bindings/sqlite"
)

// WithConnection borrows the driver's native connection with SQL admission for
// a synchronous operation. The callback must not retain the connection or call
// back into db: the pool's single connection is reserved until it returns.
// Native resources created by the callback must be released before db closes.
// Use WithNativeControl for worker lifecycle and file I/O operations that
// acquire their own native SQL admission; joining a worker under this function's
// writer guard could otherwise deadlock that worker.
func WithConnection(ctx context.Context, db *sql.DB, fn func(*sqlite.Conn) error) error {
	return withNative(ctx, db, fn, true)
}

// WithNativeControl reserves the SQL connection without holding writer
// admission or installing a SQL progress handler. It is intended for native
// worker start/stop and native operations that manage their own SQL admission.
// The callback must serialize any raw SQL it executes itself.
func WithNativeControl(ctx context.Context, db *sql.DB, fn func(*sqlite.Conn) error) error {
	return withNative(ctx, db, fn, false)
}

func withNative(ctx context.Context, db *sql.DB, fn func(*sqlite.Conn) error, sqlAdmission bool) error {
	if db == nil || fn == nil {
		return errors.New("murmurdb: database and callback are required")
	}
	c, err := db.Conn(ctx)
	if err != nil {
		return err
	}
	defer c.Close()
	return c.Raw(func(raw any) error {
		native, ok := raw.(*conn)
		if !ok {
			return errors.New("murmurdb: incompatible SQL driver")
		}
		native.mu.Lock()
		defer native.mu.Unlock()
		if err := native.checkOpen(); err != nil {
			return err
		}
		defer func() {
			_ = native.runNative(func() error { native.capture = bridge.Attached(native.raw); return nil })
			native.startWorker()
		}()
		err := native.runNative(func() error {
			var err error
			if sqlAdmission {
				err = func() error {
					sqlite.LockWriter()
					defer sqlite.UnlockWriter()
					return native.withContext(ctx, func() error { return fn(native.raw) })
				}()
			} else if err = ctx.Err(); err == nil {
				err = fn(native.raw)
			}
			return err
		})
		return err
	})
}
