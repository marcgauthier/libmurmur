package murmurdb

import (
	"database/sql/driver"
	"runtime"

	"github.com/marcgauthier/libmurmur/clients/go/bindings/bridge"
	drv "github.com/marcgauthier/libmurmur/clients/go/bindings/driver"
	"github.com/marcgauthier/libmurmur/clients/go/bindings/sqlite"
)

type nativeReply struct {
	err      error
	panicked bool
	value    any
}
type nativeCall struct {
	fn   func() error
	done chan nativeReply
}

// A native-resource connection owns one OS thread. SQLite's recursive native
// writer mutex can therefore remain held across separate database/sql Tx calls,
// even when those calls arrive on different Go goroutines.
func (c *conn) startWorker() {
	if c.work != nil {
		return
	}
	c.work = make(chan nativeCall)
	c.workerDone = make(chan struct{})
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		defer close(c.workerDone)
		for call := range c.work {
			func() {
				var reply nativeReply
				completed := false
				defer func() {
					if !completed {
						reply.panicked = true
						reply.value = recover()
					}
					call.done <- reply
				}()
				reply.err = call.fn()
				completed = true
			}()
		}
	}()
}

// runNative and startWorker require c.mu. Unconfigured connections keep the
// direct execution path, including their existing streaming-query behavior.
func (c *conn) runNative(fn func() error) error {
	if c.work == nil {
		return fn()
	}
	call := nativeCall{fn: fn, done: make(chan nativeReply, 1)}
	select {
	case c.work <- call:
	case <-c.workerDone:
		return driver.ErrBadConn
	}
	reply := <-call.done
	if reply.panicked {
		panic(reply.value)
	}
	return reply.err
}

func (c *conn) beginTransaction() error {
	if c.inTx {
		return driver.ErrBadConn
	}
	if c.work != nil {
		sqlite.LockWriter()
		c.txGuard = true
	}
	c.txCapture = c.capture
	var err error
	if c.txCapture {
		err = bridge.BeginTransaction(c.raw)
	} else {
		err = c.raw.Exec("BEGIN")
	}
	if err != nil {
		if c.txGuard {
			c.txGuard = false
			sqlite.UnlockWriter()
		}
		c.txCapture = false
		return err
	}
	c.inTx = true
	return nil
}

func (c *conn) endTransaction(rollback bool) error {
	if !c.inTx {
		return driver.ErrBadConn
	}
	defer func() {
		c.inTx = false
		c.txCapture = false
		if c.txGuard {
			c.txGuard = false
			sqlite.UnlockWriter()
		}
	}()
	if c.txCapture {
		if rollback {
			return bridge.RollbackTransaction(c.raw)
		}
		return bridge.CommitTransaction(c.raw)
	}
	if rollback {
		return c.raw.Exec("ROLLBACK")
	}
	err := c.raw.Exec("COMMIT")
	if err != nil {
		_ = c.raw.Exec("ROLLBACK")
	}
	if err == nil && c.work != nil {
		if path := c.raw.MainFilename(); path != "" {
			err = drv.Commit(path)
		}
	}
	return err
}
