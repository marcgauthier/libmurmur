// Package murmurdb is a database/sql driver over libmurmur stores.
//
// It opens an encrypted Murmur store through the registered VFS and
// exposes ordinary Exec/Query/Prepare/Transaction calls:
//
//	db, err := murmurdb.Open("/var/lib/app/store?key=<64 hex>")
//	if err != nil { ... }
//	defer db.Close()
//	var name string
//	err = db.QueryRow("SELECT name FROM users WHERE id = ?", 1).Scan(&name)
//
// The driver also registers itself under the name "murmur" for
// sql.Open, but prefer Open: it validates the DSN eagerly and pins
// MaxOpenConns(1), which Murmur stores require (a store is
// single-handle; a second open fails on the storage lock).
//
// DSN form: [file:]path[?key=..&mode=..&cache_pages=..&flush_ms=..&crsqlite=..]
//
//	key         64 lowercase hex digits of the 32-byte master key.
//	            Absent leaves the store keyless.
//	mode        ro, rw, or rwc (default rwc: read-write, create).
//	cache_pages VFS page cache; first open wins process-wide.
//	flush_ms    VFS flush interval; first open wins process-wide.
//	crsqlite    on (default) or off: initialize cr-sqlite CRR support.
//
// Only positional (?) arguments are accepted. Values bind like the
// reference client (nil NULL, bools and ints integer, floats real,
// strings text, []byte blob); time.Time binds UTC RFC3339Nano text.
//
// Single-handle caveat: each driver connection opens the store, so
// interleaved use across connections (rows open on one query while
// starting another outside a transaction) fails on the storage
// lock. Finish or close rows before the next top-level query, or
// interleave inside one transaction, which pins a connection.
package murmurdb

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	drv "github.com/marcgauthier/libmurmur/clients/go/bindings/driver"
	"github.com/marcgauthier/libmurmur/clients/go/bindings/sqlite"
)

// DriverName is the database/sql registration name.
const DriverName = "murmur"

// vfsName is the Murmur storage VFS registered by driver.Init.
const vfsName = "sqlite-murmur"

// ErrWrongKey reports a key that does not unlock a sealed store.
var ErrWrongKey = errors.New("murmurdb: wrong key")

func init() { sql.Register(DriverName, murmurDriver{}) }

// options is a parsed DSN.
type options struct {
	path     string
	key      [32]byte
	hasKey   bool
	flags    int
	cache    int
	flushMs  uint
	crsqlite bool
}

func parseDSN(dsn string) (options, error) {
	var o options
	o.crsqlite = true
	rest := dsn
	if i := strings.IndexByte(rest, '?'); i >= 0 {
		rest, dsn = rest[:i], rest[i+1:]
	} else {
		dsn = ""
	}
	rest = strings.TrimPrefix(rest, "file:")
	if rest == "" {
		return o, errors.New("murmurdb: empty path")
	}
	o.path = rest
	q, err := url.ParseQuery(dsn)
	if err != nil {
		return o, fmt.Errorf("murmurdb: bad options: %w", err)
	}
	if ks := q.Get("key"); ks != "" {
		raw, err := hex.DecodeString(ks)
		if err != nil || len(raw) != 32 {
			return o, errors.New("murmurdb: key must be 64 hex digits")
		}
		copy(o.key[:], raw)
		o.hasKey = true
	}
	switch m := q.Get("mode"); m {
	case "", "rwc":
		o.flags = sqlite.OpenReadWrite | sqlite.OpenCreate
	case "rw":
		o.flags = sqlite.OpenReadWrite
	case "ro":
		o.flags = sqlite.OpenReadOnly
	default:
		return o, fmt.Errorf("murmurdb: bad mode %q", m)
	}
	if s := q.Get("cache_pages"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n < 0 {
			return o, fmt.Errorf("murmurdb: bad cache_pages %q", s)
		}
		o.cache = n
	}
	if s := q.Get("flush_ms"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n < 0 {
			return o, fmt.Errorf("murmurdb: bad flush_ms %q", s)
		}
		o.flushMs = uint(n)
	}
	switch s := q.Get("crsqlite"); s {
	case "", "on":
	case "off":
		o.crsqlite = false
	default:
		return o, fmt.Errorf("murmurdb: bad crsqlite %q", s)
	}
	return o, nil
}

// initOnce owns process init; first DSN's cache/flush values win.
var initOnce sync.Once
var initErr error

func ensureInit(cache int, flushMs uint) error {
	initOnce.Do(func() { initErr = drv.Init(cache, flushMs) })
	return initErr
}

// Open validates dsn and returns a *sql.DB over the store. The DSN
// is parsed eagerly; the store itself opens lazily on first use.
func Open(dsn string) (*sql.DB, error) {
	o, err := parseDSN(dsn)
	if err != nil {
		return nil, err
	}
	db := sql.OpenDB(connector{opts: o})
	// Murmur stores are single-handle: one open per path per
	// process. Pin the pool so database/sql never opens a second.
	db.SetMaxOpenConns(1)
	return db, nil
}

type murmurDriver struct{}

func (murmurDriver) Open(dsn string) (driver.Conn, error) {
	o, err := parseDSN(dsn)
	if err != nil {
		return nil, err
	}
	return connector{opts: o}.connect()
}

type connector struct{ opts options }

func (c connector) Connect(context.Context) (driver.Conn, error) { return c.connect() }
func (c connector) Driver() driver.Driver                        { return murmurDriver{} }

func (c connector) connect() (driver.Conn, error) {
	o := c.opts
	if err := ensureInit(o.cache, o.flushMs); err != nil {
		return nil, err
	}
	raw, err := sqlite.OpenVFS(o.path, o.flags, vfsName)
	if err != nil {
		return nil, err
	}
	if o.hasKey {
		switch rc := raw.SetKey(o.key); rc {
		case 0:
		case 11: // sealed store, key does not unlock
			raw.Close()
			return nil, ErrWrongKey
		default:
			raw.Close()
			return nil, fmt.Errorf("murmurdb: set key: rc=%d", rc)
		}
	}
	if o.hasKey {
		// SetKey provisions without validating, and a wrong key
		// surfaces only on first storage I/O. Probe the schema
		// before anything else so a bad key reports ErrWrongKey
		// instead of a downstream failure.
		st, err := raw.Prepare("SELECT count(*) FROM sqlite_master")
		if err != nil {
			raw.Close()
			return nil, ErrWrongKey
		}
		_, err = st.Step()
		st.Close()
		if err != nil {
			raw.Close()
			return nil, ErrWrongKey
		}
	}
	if o.crsqlite {
		if err := sqlite.CrsqliteInit(raw); err != nil {
			raw.Close()
			return nil, err
		}
	}
	return &conn{raw: raw}, nil
}

type conn struct {
	raw    *sqlite.Conn
	closed atomic.Bool
	// mu serializes whole Exec/Query sequences: one native
	// statement runs at a time per connection.
	mu                       sync.Mutex
	work                     chan nativeCall
	workerDone               chan struct{}
	capture                  bool
	inTx, txCapture, txGuard bool
	// cache reuses prepared statements across calls (C/Rust
	// prepare once and reset). busy marks a statement checked
	// out by open rows.
	cache      map[string]*cachedStmt
	cacheBytes int
	cacheTick  uint64
}

type cachedStmt struct {
	st    *sqlite.Stmt
	busy  bool
	used  uint64
	bytes int
}

func (c *conn) checkOpen() error {
	if c.closed.Load() {
		return driver.ErrBadConn
	}
	return nil
}

func (c *conn) Close() error {
	if c.closed.Swap(true) {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	err := c.runNative(func() error {
		var err error
		if c.inTx {
			err = c.endTransaction(true)
		}
		for q, e := range c.cache {
			err = errors.Join(err, e.st.Close())
			delete(c.cache, q)
		}
		c.cacheBytes = 0
		return errors.Join(err, c.raw.Close())
	})
	if c.work != nil {
		close(c.work)
		<-c.workerDone
		c.work = nil
	}
	return err
}

func (c *conn) Ping(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := c.checkOpen(); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.checkOpen(); err != nil {
		return err
	}
	return c.runNative(func() error {
		return c.withSQLContext(ctx, func() error {
			st, err := c.raw.Prepare("SELECT 1")
			if err != nil {
				return driver.ErrBadConn
			}
			defer st.Close()
			_, err = st.Step()
			return err
		})
	})
}

// CheckNamedValue keeps positional (?) arguments only.
func (c *conn) CheckNamedValue(v *driver.NamedValue) error {
	if v.Name != "" {
		return errors.New("murmurdb: use positional arguments")
	}
	return nil
}

func (c *conn) Prepare(query string) (driver.Stmt, error) {
	if err := c.checkOpen(); err != nil {
		return nil, err
	}
	return &stmt{c: c, query: query}, nil
}

func (c *conn) Begin() (driver.Tx, error) {
	if err := c.checkOpen(); err != nil {
		return nil, err
	}
	// Locked like Exec: prepared statements are bound to this
	// connection and may run while a transaction opens or closes.
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.checkOpen(); err != nil {
		return nil, err
	}
	if err := c.runNative(func() error {
		if err := c.checkOpen(); err != nil {
			return err
		}
		return c.beginTransaction()
	}); err != nil {
		return nil, err
	}
	return &tx{c: c}, nil
}

func valuesOf(args []driver.NamedValue) []any {
	out := make([]any, len(args))
	for i, a := range args {
		out[i] = a.Value
	}
	return out
}

// prepareOne compiles a single statement, rejecting trailing SQL.
func (c *conn) prepareOne(query string) (*sqlite.Stmt, error) {
	st, tail, err := c.raw.PrepareTail(query)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(tail) != "" {
		st.Close()
		return nil, errors.New("murmurdb: one statement per query")
	}
	return st, nil
}

// checkout returns a statement for query: the cached one when idle
// (checked out busy), a fresh compile inserted into the cache on a
// miss, or a fresh compile owned by the caller when the cached one
// is busy (open rows elsewhere).
func (c *conn) checkout(query string) (st *sqlite.Stmt, cached bool, err error) {
	if e, ok := c.cache[query]; ok {
		if !e.busy {
			e.busy = true
			c.touchCached(e)
			return e.st, true, nil
		}
		st, err = c.prepareOne(query)
		if err != nil {
			return nil, false, err
		}
		return st, false, nil
	}
	st, err = c.prepareOne(query)
	if err != nil {
		return nil, false, err
	}
	if c.cache == nil {
		c.cache = make(map[string]*cachedStmt)
	}
	bytes := st.MemoryUsed() + len(query)
	if !c.cacheRoom(bytes) {
		return st, false, nil
	}
	entry := &cachedStmt{st: st, busy: true, bytes: bytes}
	c.touchCached(entry)
	c.cache[query] = entry
	c.cacheBytes += bytes
	return st, true, nil
}

// checkin returns a cached statement, resetting it for reuse. A
// statement that will not reset is dropped. Caller-owned
// statements close.
func (c *conn) checkin(query string, st *sqlite.Stmt, cached bool) {
	if !cached {
		_ = st.Close()
		return
	}
	if err := st.Reset(); err != nil {
		c.dropCached(query)
		return
	}
	if err := st.ClearBindings(); err != nil {
		c.dropCached(query)
		return
	}
	if e, ok := c.cache[query]; ok {
		e.busy = false
		c.cacheBytes -= e.bytes
		e.bytes = st.MemoryUsed() + len(query)
		c.cacheBytes += e.bytes
		c.touchCached(e)
		// Reprepare can change a statement's size after a schema change.
		// Retaining an oversized idle statement is never required.
		if c.cacheBytes > maxCachedBytes {
			c.dropCached(query)
		}
	}
}

func (c *conn) execArgs(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := c.checkOpen(); err != nil {
		return nil, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.checkOpen(); err != nil {
		return nil, err
	}
	var res driver.Result
	err := c.runNative(func() error {
		return c.withSQLContext(ctx, func() error {
			var err error
			if c.work != nil {
				res, err = c.execSerialized(ctx, query, args)
			} else {
				res, err = c.execLocked(query, args)
			}
			return err
		})
	})
	return res, err
}

// execLocked owns the connection for a complete statement/script.
func (c *conn) execLocked(query string, args []driver.NamedValue) (driver.Result, error) {
	if len(args) == 0 {
		// No parameters: run verbatim (multi-statement scripts OK).
		if err := c.raw.Exec(query); err != nil {
			return nil, err
		}
		return result{rows: c.raw.Changes(), id: c.raw.LastInsertRowID()}, nil
	}
	st, cached, err := c.checkout(query)
	if err != nil {
		return nil, err
	}
	if err := st.Bind(valuesOf(args)...); err != nil {
		c.checkin(query, st, cached)
		return nil, err
	}
	for {
		done, err := st.Step()
		if err != nil {
			c.checkin(query, st, cached)
			return nil, err
		}
		if done {
			break
		}
	}
	c.checkin(query, st, cached)
	return result{rows: c.raw.Changes(), id: c.raw.LastInsertRowID()}, nil
}

func (c *conn) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	return c.execArgs(ctx, query, args)
}

func (c *conn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := c.checkOpen(); err != nil {
		return nil, err
	}
	c.mu.Lock()
	if err := c.checkOpen(); err != nil {
		c.mu.Unlock()
		return nil, err
	}
	if c.work != nil {
		defer c.mu.Unlock()
		var out driver.Rows
		err := c.runNative(func() error {
			return c.withSQLContext(ctx, func() error {
				var err error
				out, err = c.querySerialized(ctx, query, valuesOf(args))
				return err
			})
		})
		return out, err
	}
	st, cached, err := c.checkout(query)
	if err != nil {
		c.mu.Unlock()
		return nil, err
	}
	if err := st.Bind(valuesOf(args)...); err != nil {
		c.checkin(query, st, cached)
		c.mu.Unlock()
		return nil, err
	}
	n := st.ColumnCount()
	cols := make([]string, n)
	for i := range cols {
		cols[i] = st.ColumnName(i)
	}
	r := &rows{c: c, query: query, st: st, cols: cols, cached: cached, ctx: ctx}
	c.mu.Unlock()
	return r, nil
}

type result struct {
	rows int64
	id   int64
}

func (r result) LastInsertId() (int64, error) { return r.id, nil }
func (r result) RowsAffected() (int64, error) { return r.rows, nil }

type stmt struct {
	c     *conn
	query string
}

func (s *stmt) Close() error  { return nil }
func (s *stmt) NumInput() int { return -1 }

func renumber(args []driver.Value) []driver.NamedValue {
	out := make([]driver.NamedValue, len(args))
	for i, v := range args {
		out[i] = driver.NamedValue{Ordinal: i + 1, Value: v}
	}
	return out
}

func (s *stmt) Exec(args []driver.Value) (driver.Result, error) {
	return s.c.execArgs(context.Background(), s.query, renumber(args))
}

func (s *stmt) Query(args []driver.Value) (driver.Rows, error) {
	return s.c.QueryContext(context.Background(), s.query, renumber(args))
}

// Column type codes mirror SQLITE_* storage classes.
const (
	colInteger = 1
	colFloat   = 2
	colText    = 3
	colBlob    = 4
	colNull    = 5
)

type rows struct {
	c      *conn
	query  string
	st     *sqlite.Stmt
	cols   []string
	cached bool
	closed bool
	ctx    context.Context
}

func (r *rows) Columns() []string { return r.cols }

func (r *rows) Close() error {
	r.c.mu.Lock()
	defer r.c.mu.Unlock()
	if r.closed {
		return nil
	}
	r.closed = true
	r.c.checkin(r.query, r.st, r.cached)
	return nil
}

func (r *rows) Next(dest []driver.Value) error {
	r.c.mu.Lock()
	defer r.c.mu.Unlock()
	if r.closed {
		return io.EOF
	}
	var done bool
	err := r.c.withContext(r.ctx, func() error {
		var stepErr error
		done, stepErr = r.st.Step()
		return stepErr
	})
	if err != nil {
		return err
	}
	if done {
		return io.EOF
	}
	for i := range dest {
		switch r.st.ColumnType(i) {
		case colInteger:
			dest[i] = r.st.ColumnInt64(i)
		case colFloat:
			dest[i] = r.st.ColumnFloat(i)
		case colText:
			dest[i] = r.st.ColumnText(i)
		case colBlob:
			dest[i] = r.st.ColumnBlob(i)
		default:
			dest[i] = nil
		}
	}
	return nil
}

type tx struct {
	c    *conn
	done atomic.Bool
}

func (t *tx) finish(rb bool) error {
	if t.done.Swap(true) {
		return errors.New("murmurdb: transaction finished")
	}
	t.c.mu.Lock()
	defer t.c.mu.Unlock()
	if err := t.c.checkOpen(); err != nil {
		return err
	}
	return t.c.runNative(func() error { return t.c.endTransaction(rb) })
}

func (t *tx) Commit() error   { return t.finish(false) }
func (t *tx) Rollback() error { return t.finish(true) }
