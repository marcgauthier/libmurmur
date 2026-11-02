package replication

import (
	"encoding/json"
	"io"
	"net/netip"
	"strings"
	"time"

	"github.com/marcgauthier/libmurmur/clients/go/bindings/sqlite"
	"github.com/marcgauthier/libmurmur/clients/go/pkgs/tx"
)

// waitTimeout validates a wait bound in milliseconds.
func waitTimeout(ms int64) (time.Duration, error) {
	if ms < 0 || ms > 86400000 {
		return 0, errInvalid("timeout outside 0..86400000 ms")
	}
	return time.Duration(ms) * time.Millisecond, nil
}

// persistBootstrap appends an address to the bootstrap setting.
func persistBootstrap(db *sqlite.Conn, addr string) error {
	ap, err := netip.ParseAddrPort(addr)
	if err != nil {
		return errInvalid("expected IP:port")
	}
	raw, err := Setting(db, "bootstrap")
	if err != nil {
		return err
	}
	var seeds []string
	if raw != "" {
		if err := json.Unmarshal([]byte(raw), &seeds); err != nil {
			return errInvalid("corrupt bootstrap")
		}
	}
	found := false
	for _, s := range seeds {
		if s == ap.String() {
			found = true
			break
		}
	}
	if !found {
		if len(seeds) >= maxViewMembers {
			return errOverloaded("seed capacity")
		}
		seeds = append(seeds, ap.String())
	}
	out, err := json.Marshal(seeds)
	if err != nil {
		return err
	}
	return SetSetting(db, "bootstrap", string(out))
}

// persistExcluded records an excluded node id.
func persistExcluded(db *sqlite.Conn, id NodeID) error {
	return execArgs(db, "INSERT OR IGNORE INTO murmur_excluded VALUES(?1)", id[:])
}

// isExcluded reports whether id is in the durable exclusion set.
// Query failures fail closed (reported as excluded) so a peer that
// cannot be vetted is refused.
func isExcluded(db *sqlite.Conn, id NodeID) (bool, error) {
	st, err := db.Prepare("SELECT 1 FROM murmur_excluded WHERE node=?1 LIMIT 1")
	if err != nil {
		return true, err
	}
	defer st.Close()
	if err := st.BindBlob(1, id[:]); err != nil {
		return true, err
	}
	done, err := st.Step()
	if err != nil {
		return true, err
	}
	return !done, nil
}

// loadExcluded returns every id in the durable exclusion set,
// skipping malformed rows.
func loadExcluded(db *sqlite.Conn) ([]NodeID, error) {
	st, err := db.Prepare("SELECT node FROM murmur_excluded")
	if err != nil {
		return nil, err
	}
	defer st.Close()
	var out []NodeID
	for {
		done, err := st.Step()
		if err != nil {
			return nil, err
		}
		if done {
			return out, nil
		}
		raw := st.ColumnBlob(0)
		if len(raw) != 16 {
			continue
		}
		var id NodeID
		copy(id[:], raw)
		out = append(out, id)
	}
}

// failTo records err on the engine and fails the statement with the
// projected extended code plus the message, mirroring rusqlite's
// SqliteFailure path.
func failTo(ctx *sqlite.Context, eng *Engine, err error) {
	err = eng.fail(err)
	ctx.ResultErrorCode(int(murmurCode(err)), err)
}

// RegisterSQL installs the lifecycle SQL functions on db: the
// start/stop/sync controls, the status/health/progress readers, the
// peer controls, gc, retire, snapshot_request, and the waits. Names
// match the Rust surface exactly: configuration travels over
// PRAGMA murmur_* (pending VFS bridge, no murmur_config scalar) and
// murmur_peers is a virtual table there (pending vtab support, no
// scalar here), so both stay unregistered and callers see
// no-such-function until their subsystems land.
func RegisterSQL(db *sqlite.Conn, eng *Engine) error {
	if err := EnsureSchema(db); err != nil {
		return err
	}
	funcs := []struct {
		name  string
		nargs int
		fn    sqlite.ScalarFunc
	}{
		{"murmur_start", 0, func(ctx *sqlite.Context, args []sqlite.Value) {
			if !db.Autocommit() {
				failTo(ctx, eng, errInvalid("replication controls require autocommit"))
				return
			}
			if eng.Running() {
				ctx.ResultInt64(0)
				return
			}
			if err := eng.Start(); err != nil {
				failTo(ctx, eng, err)
				return
			}
			ctx.ResultInt64(1)
		}},
		{"murmur_stop", 0, func(ctx *sqlite.Context, args []sqlite.Value) {
			if !db.Autocommit() {
				failTo(ctx, eng, errInvalid("replication controls require autocommit"))
				return
			}
			was := eng.Running()
			if was {
				_ = eng.Stop()
			}
			if was {
				ctx.ResultInt64(1)
			} else {
				ctx.ResultInt64(0)
			}
		}},
		{"murmur_status", 0, func(ctx *sqlite.Context, args []sqlite.Value) {
			ctx.ResultText(eng.Status())
		}},
		{"murmur_health", 0, func(ctx *sqlite.Context, args []sqlite.Value) {
			ctx.ResultText(eng.Health())
		}},
		{"murmur_progress", 0, func(ctx *sqlite.Context, args []sqlite.Value) {
			ctx.ResultText(eng.Progress())
		}},
		{"murmur_add_peer", 1, func(ctx *sqlite.Context, args []sqlite.Value) {
			if !db.Autocommit() {
				failTo(ctx, eng, errInvalid("peer controls require autocommit"))
				return
			}
			if err := persistBootstrap(db, args[0].Text()); err != nil {
				failTo(ctx, eng, err)
				return
			}
			if err := eng.AddSeed(args[0].Text()); err != nil {
				failTo(ctx, eng, err)
				return
			}
			ctx.ResultInt64(1)
		}},
		{"murmur_remove_peer", 1, func(ctx *sqlite.Context, args []sqlite.Value) {
			if !db.Autocommit() {
				failTo(ctx, eng, errInvalid("peer controls require autocommit"))
				return
			}
			id, err := ParseID(args[0].Text())
			if err != nil {
				failTo(ctx, eng, err)
				return
			}
			if err := persistExcluded(db, id); err != nil {
				failTo(ctx, eng, err)
				return
			}
			eng.RemoveNode(id)
			ctx.ResultInt64(1)
		}},
		{"murmur_sync", 0, func(ctx *sqlite.Context, args []sqlite.Value) {
			if !db.Autocommit() {
				failTo(ctx, eng, errInvalid("replication controls require autocommit"))
				return
			}
			if !eng.Running() {
				failTo(ctx, eng, errClosed("replication is stopped"))
				return
			}
			select {
			case eng.syncCh <- struct{}{}:
			default:
			}
			ctx.ResultInt64(1)
		}},
		{"murmur_gc", 0, func(ctx *sqlite.Context, args []sqlite.Value) {
			// On-demand retention pass; returns tombstones pruned.
			_, pruned := eng.RetentionPass()
			ctx.ResultInt64(int64(pruned))
		}},
		{"murmur_retire_peer", 1, func(ctx *sqlite.Context, args []sqlite.Value) {
			if !db.Autocommit() {
				failTo(ctx, eng, errInvalid("peer controls require autocommit"))
				return
			}
			id, err := ParseID(args[0].Text())
			if err != nil {
				failTo(ctx, eng, err)
				return
			}
			// Exclusion first (transport safety), then the retention
			// obligation ends.
			if err := persistExcluded(db, id); err != nil {
				failTo(ctx, eng, err)
				return
			}
			if eng.Running() {
				eng.mu.Lock()
				be := NewBackend(eng.db, eng.group, eng.node)
				eng.mu.Unlock()
				if err := tx.Retire(be, id); err != nil {
					failTo(ctx, eng, backendErr(err))
					return
				}
			}
			eng.RemoveNode(id)
			ctx.ResultInt64(1)
		}},
		{"murmur_snapshot_request", 1, func(ctx *sqlite.Context, args []sqlite.Value) {
			if !db.Autocommit() {
				failTo(ctx, eng, errInvalid("peer controls require autocommit"))
				return
			}
			id, err := ParseID(args[0].Text())
			if err != nil {
				failTo(ctx, eng, err)
				return
			}
			if !eng.Running() {
				failTo(ctx, eng, errClosed("replication is not running"))
				return
			}
			eng.mu.Lock()
			sess, ok := eng.conns[id]
			eng.mu.Unlock()
			if !ok || sess == nil {
				failTo(ctx, eng, errClosed("snapshot peer is not connected"))
				return
			}
			if err := eng.RequestSnapshot(id, func() (io.Writer, io.Reader, error) {
				s, err := sess.OpenStream()
				if err != nil {
					return nil, nil, err
				}
				return streamWriter(s), streamReader(s), nil
			}); err != nil {
				failTo(ctx, eng, err)
				return
			}
			ctx.ResultInt64(1)
		}},
		{"murmur_wait_applied", 3, func(ctx *sqlite.Context, args []sqlite.Value) {
			if !db.Autocommit() {
				failTo(ctx, eng, errInvalid("waits require autocommit"))
				return
			}
			origin, err := ParseID(args[0].Text())
			if err != nil {
				failTo(ctx, eng, err)
				return
			}
			if args[1].Int64() < 0 {
				failTo(ctx, eng, errInvalid("sequence must be >= 0"))
				return
			}
			timeout, err := waitTimeout(args[2].Int64())
			if err != nil {
				failTo(ctx, eng, err)
				return
			}
			if !eng.Running() {
				ctx.ResultInt64(0)
				return
			}
			eng.mu.Lock()
			be := NewBackend(eng.db, eng.group, eng.node)
			eng.mu.Unlock()
			ok, err := WaitForApplied(be, origin, uint64(args[1].Int64()), timeout)
			if err != nil {
				failTo(ctx, eng, err)
				return
			}
			if ok {
				ctx.ResultInt64(1)
			} else {
				ctx.ResultInt64(0)
			}
		}},
		{"murmur_wait_lag", 2, func(ctx *sqlite.Context, args []sqlite.Value) {
			if !db.Autocommit() {
				failTo(ctx, eng, errInvalid("waits require autocommit"))
				return
			}
			if args[0].Int64() < 0 {
				failTo(ctx, eng, errInvalid("bound must be >= 0"))
				return
			}
			timeout, err := waitTimeout(args[1].Int64())
			if err != nil {
				failTo(ctx, eng, err)
				return
			}
			if !eng.Running() {
				ctx.ResultInt64(0)
				return
			}
			eng.mu.Lock()
			be := NewBackend(eng.db, eng.group, eng.node)
			eng.mu.Unlock()
			ok, err := WaitForLag(be, uint64(args[0].Int64()), timeout)
			if err != nil {
				failTo(ctx, eng, err)
				return
			}
			if ok {
				ctx.ResultInt64(1)
			} else {
				ctx.ResultInt64(0)
			}
		}},
	}
	for _, f := range funcs {
		if err := db.CreateFunction(f.name, f.nargs, false, f.fn); err != nil {
			return err
		}
	}
	return nil
}

func quoteIdent(s string) string {
	return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
}
