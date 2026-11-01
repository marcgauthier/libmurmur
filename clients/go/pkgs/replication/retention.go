package replication

import (
	"strings"
	"time"

	"github.com/marcgauthier/libmurmur/clients/go/bindings/sqlite"
	"github.com/marcgauthier/libmurmur/clients/go/pkgs/tx"
)

// RetentionParams are the floor inputs. No time floor: without
// per-version ages a retention interval cannot honestly gate
// anything, and physical deletion is ack-bounded for the same reason.
type RetentionParams struct {
	MinimumRetained   uint64
	MaximumOfflineMs  uint64
	BootstrapNonempty bool
}

// StartupGraceMillis mirrors the archived startup grace: a young node
// with configured seeds cannot distinguish "single-node" from "seeds
// still connecting".
const StartupGraceMillis = 60000

var retentionLastKey = []byte("07/replication/retention/last")

// RetentionParamsFrom loads floor inputs from settings.
func RetentionParamsFrom(db *sqlite.Conn) (*RetentionParams, error) {
	num := func(name string) (uint64, error) {
		raw, err := Setting(db, name)
		if err != nil {
			return 0, err
		}
		v, err := atoi(raw)
		if err != nil {
			return 0, errInvalidf("invalid %s", name)
		}
		return v, nil
	}
	minKept, err := num("retention_min_kept")
	if err != nil {
		return nil, err
	}
	maxOffline, err := num("retention_max_offline_ms")
	if err != nil {
		return nil, err
	}
	bootstrap, err := Setting(db, "bootstrap")
	if err != nil {
		return nil, err
	}
	return &RetentionParams{
		MinimumRetained:   minKept,
		MaximumOfflineMs:  maxOffline,
		BootstrapNonempty: bootstrap != "[]",
	}, nil
}

// CollectFloors advances per-origin retention floors. Returns the
// number of origins whose floor moved. Floors never decrease.
func CollectFloors(backend tx.Backend, params *RetentionParams, online map[NodeID]bool, nowMillis, bootMillis uint64) (uint64, error) {
	status, err := tx.Status(backend)
	if err != nil {
		return 0, snapshotTxErr(err)
	}
	unrecorded := false
	for id := range online {
		found := false
		for _, peer := range status.Peers {
			if peer.Node == id {
				found = true
				break
			}
		}
		if !found {
			unrecorded = true
			break
		}
	}
	var young uint64
	if params.BootstrapNonempty && nowMillis-bootMillis < StartupGraceMillis && nowMillis >= bootMillis {
		young = 1
	}
	heads, err := backend.Progress()
	if err != nil {
		return 0, snapshotTxErr(err)
	}
	var moved uint64
	var records []tx.Record
	for _, head := range heads {
		var recorded *uint64
		for _, peer := range status.Peers {
			var since uint64
			if nowMillis >= peer.LastSeenMillis {
				since = nowMillis - peer.LastSeenMillis
			}
			if peer.Retired || (!online[peer.Node] && since > params.MaximumOfflineMs) {
				continue
			}
			ack := peer.Acknowledged[head.Origin]
			if recorded == nil || ack < *recorded {
				v := ack
				recorded = &v
			}
		}
		var peerFloor uint64
		switch {
		case unrecorded:
			peerFloor = 0
		case recorded != nil:
			peerFloor = *recorded
		case young == 1:
			peerFloor = 0
		default:
			peerFloor = ^uint64(0)
		}
		snapshotFloor, err := tx.PruneLimit(backend, head.Origin, nowMillis)
		if err != nil {
			return 0, snapshotTxErr(err)
		}
		tailCap := uint64(0)
		if head.Applied > params.MinimumRetained {
			tailCap = head.Applied - params.MinimumRetained
		}
		floor := peerFloor
		if snapshotFloor < floor {
			floor = snapshotFloor
		}
		if tailCap < floor {
			floor = tailCap
		}
		var prev uint64
		if raw, ok, err := backend.Get(tx.FloorKey(head.Origin)); err != nil {
			return 0, snapshotTxErr(err)
		} else if ok {
			prev, err = tx.DecodeU64(raw)
			if err != nil {
				return 0, snapshotTxErr(err)
			}
		}
		if floor > prev {
			records = append(records, tx.Put(tx.FloorKey(head.Origin), tx.EncodeU64(floor)))
			head.RetainedFrom = floor + 1
			if floor == ^uint64(0) {
				head.RetainedFrom = ^uint64(0)
			}
			head.RetainedThrough = head.Applied
			records = append(records, tx.Put(tx.RetainedKey(head.Origin), tx.EncodeProgress(head)))
			moved++
		}
	}
	if len(records) > 0 {
		if err := snapshotTxErr(backend.Commit(records)); err != nil {
			return 0, err
		}
	}
	if err := snapshotTxErr(backend.Commit([]tx.Record{tx.Put(retentionLastKey, tx.EncodeU64(nowMillis))})); err != nil {
		return 0, err
	}
	return moved, nil
}

// MyStreamFloor is the GC floor for our own stream: the minimum over
// live, non-retired peers of what they acked of it, minus the
// minimum-kept tail. Unrecorded online peers and young seeded nodes
// pin to 0; a mature node with no qualifying peers prunes through
// its own applied head.
func MyStreamFloor(backend tx.Backend, params *RetentionParams, online map[NodeID]bool, own NodeID, ownApplied, nowMillis, bootMillis uint64) (uint64, error) {
	status, err := tx.Status(backend)
	if err != nil {
		return 0, snapshotTxErr(err)
	}
	for id := range online {
		found := false
		for _, peer := range status.Peers {
			if peer.Node == id {
				found = true
				break
			}
		}
		if !found {
			return 0, nil
		}
	}
	var acked *uint64
	for _, peer := range status.Peers {
		var since uint64
		if nowMillis >= peer.LastSeenMillis {
			since = nowMillis - peer.LastSeenMillis
		}
		if peer.Retired || (!online[peer.Node] && since > params.MaximumOfflineMs) {
			continue
		}
		v := peer.Acknowledged[own]
		if acked == nil || v < *acked {
			acked = &v
		}
	}
	young := params.BootstrapNonempty && nowMillis >= bootMillis && nowMillis-bootMillis < StartupGraceMillis
	var floor uint64
	switch {
	case acked != nil:
		floor = *acked
		if ownApplied < floor {
			floor = ownApplied
		}
	case young:
		floor = 0
	default:
		floor = ownApplied
	}
	if floor < params.MinimumRetained {
		return 0, nil
	}
	return floor - params.MinimumRetained, nil
}

// RetentionPass runs one retention pass: advance floors, sweep
// snapshot hygiene, prune acked tombstones, reap abandoned staging.
// Best-effort; returns (floors moved, tombstones pruned).
func (e *Engine) RetentionPass() (uint64, uint64) {
	e.mu.Lock()
	online := make(map[NodeID]bool, len(e.conns))
	for id := range e.conns {
		online[id] = true
	}
	group, node := e.group, e.node
	boot := uint64(e.startedAt.UnixMilli())
	if e.startedAt.IsZero() {
		boot = tx.NowMillis()
	}
	e.mu.Unlock()
	params, err := RetentionParamsFrom(e.db)
	if err != nil {
		return 0, 0
	}
	backend := NewBackend(e.db, group, node)
	now := tx.NowMillis()
	floors, _ := CollectFloors(backend, params, online, now, boot)
	_ = tx.Maintain(backend, now)
	_ = tx.ReapForgottenPins(backend, now, time.Duration(params.MaximumOfflineMs)*time.Millisecond, online)
	var pruned uint64
	if raw, err := Setting(e.db, "retention_gc"); err == nil && raw == "1" {
		ownApplied := uint64(0)
		if v, err := DbVersion(e.db); err == nil && v > 0 {
			ownApplied = uint64(v)
		}
		if floor, err := MyStreamFloor(backend, params, online, node, ownApplied, now, boot); err == nil {
			pruned, _ = GCTombstones(e.db, floor)
		}
	}
	_, _ = e.GC()
	return floors, pruned
}

// GC drops expired staging rows (created + staging_timeout_ms < now)
// and reports the rows removed.
func (e *Engine) GC() (int64, error) {
	timeout, err := Setting(e.db, "staging_timeout_ms")
	if err != nil {
		return 0, err
	}
	ms, err := atoi(timeout)
	if err != nil {
		return 0, err
	}
	cutoff := time.Now().UnixMilli() - int64(ms)
	st, err := e.db.Prepare("DELETE FROM murmur_stage WHERE created < ?")
	if err != nil {
		return 0, err
	}
	defer st.Close()
	if err := st.BindInt64(1, cutoff); err != nil {
		return 0, err
	}
	done, err := st.Step()
	if err != nil || !done {
		if err == nil {
			return 0, errProtocol("gc did not complete")
		}
		return 0, err
	}
	return e.db.Changes(), nil
}

// validClockName mirrors the reference identifier filter for clock
// table discovery.
func validClockName(name string) bool {
	const suffix = "__crsql_clock"
	if len(name) <= len(suffix) || !strings.HasSuffix(name, suffix) {
		return false
	}
	return validSidePrefix(name[:len(name)-len(suffix)])
}

// validSidePrefix accepts the identifier-checked base names the
// reference interpolates into DDL.
func validSidePrefix(prefix string) bool {
	if prefix == "" {
		return false
	}
	for _, c := range prefix {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '$') {
			return false
		}
	}
	return true
}

// clockTables lists valid per-table clock tables.
func clockTables(db *sqlite.Conn) ([]string, error) {
	st, err := db.Prepare("SELECT name FROM sqlite_schema WHERE type='table' AND name LIKE '%__crsql_clock' ESCAPE '\\'")
	if err != nil {
		return nil, err
	}
	defer st.Close()
	var out []string
	for {
		done, err := st.Step()
		if err != nil {
			return nil, err
		}
		if done {
			break
		}
		if name := st.ColumnText(0); validClockName(name) {
			out = append(out, name)
		}
	}
	return out, nil
}

// sideTables lists valid cr-sqlite side tables (clock plus pk lookup
// tables for WITHOUT ROWID tables).
func sideTables(db *sqlite.Conn) ([]string, error) {
	st, err := db.Prepare("SELECT name FROM sqlite_schema WHERE type='table' AND (name LIKE '%__crsql_clock' ESCAPE '\\' OR name LIKE '%__crsql_pks' ESCAPE '\\')")
	if err != nil {
		return nil, err
	}
	defer st.Close()
	var out []string
	for {
		done, err := st.Step()
		if err != nil {
			return nil, err
		}
		if done {
			break
		}
		name := st.ColumnText(0)
		base, ok := sideBase(name)
		if !ok || !validSidePrefix(base) {
			continue
		}
		out = append(out, name)
	}
	return out, nil
}

// sideBase strips the side-table suffix, reporting whether one
// matched.
func sideBase(name string) (string, bool) {
	for _, suffix := range []string{"__crsql_clock", "__crsql_pks"} {
		if len(name) > len(suffix) && strings.HasSuffix(name, suffix) {
			return name[:len(name)-len(suffix)], true
		}
	}
	return "", false
}

// GCTombstones drops tombstone clocks at or below floor and advances
// the gc_watermark. Durability rides the caller's next barrier.
func GCTombstones(db *sqlite.Conn, floor uint64) (uint64, error) {
	clocks, err := clockTables(db)
	if err != nil {
		return 0, err
	}
	var deleted uint64
	for _, clock := range clocks {
		st, err := db.Prepare("DELETE FROM " + quoteIdent(clock) + " WHERE col_name='-1' AND db_version<=?")
		if err != nil {
			return 0, err
		}
		st.BindInt64(1, int64(floor))
		done, err := st.Step()
		st.Close()
		if err != nil || !done {
			if err == nil {
				return 0, errProtocol("gc did not complete")
			}
			return 0, err
		}
		deleted += uint64(db.Changes())
	}
	mark, err := GCWatermark(db)
	if err != nil {
		return 0, err
	}
	if floor > mark {
		mark = floor
	}
	st, err := db.Prepare("INSERT INTO murmur_config(name,value) VALUES('gc_watermark',?) ON CONFLICT(name) DO UPDATE SET value=excluded.value")
	if err != nil {
		return 0, err
	}
	defer st.Close()
	if err := st.BindText(1, itoa(mark)); err != nil {
		return 0, err
	}
	if _, err := st.Step(); err != nil {
		return 0, err
	}
	return deleted, nil
}

// GCWatermark reports the highest pruned local db_version (0 fresh).
func GCWatermark(db *sqlite.Conn) (uint64, error) {
	st, err := db.Prepare("SELECT value FROM murmur_config WHERE name='gc_watermark'")
	if err != nil {
		return 0, err
	}
	defer st.Close()
	done, err := st.Step()
	if err != nil {
		return 0, err
	}
	if done {
		return 0, nil
	}
	v, err := atoi(st.ColumnText(0))
	if err != nil {
		return 0, errInvalid("invalid gc_watermark")
	}
	return v, nil
}

// ReapOrphanClocks drops side tables whose base tables are gone,
// pinning their peak db_version into the compaction floor first so
// max-derived versions never retreat. Callers run it when the schema
// cookie moves.
func ReapOrphanClocks(db *sqlite.Conn) (uint64, error) {
	sides, err := sideTables(db)
	if err != nil {
		return 0, err
	}
	var orphans []string
	for _, side := range sides {
		base, _ := sideBase(side)
		st, err := db.Prepare("SELECT 1 FROM sqlite_schema WHERE type='table' AND name=?")
		if err != nil {
			return 0, err
		}
		st.BindText(1, base)
		done, err := st.Step()
		st.Close()
		if err != nil {
			return 0, err
		}
		if !done {
			continue
		}
		orphans = append(orphans, side)
	}
	if err := pinVersionFloor(db, orphans); err != nil {
		return 0, err
	}
	var reaped uint64
	for _, side := range orphans {
		if err := db.Exec("DROP TABLE " + quoteIdent(side)); err != nil {
			return 0, err
		}
		reaped++
	}
	return reaped, nil
}

// pinVersionFloor pins max(db_version) over about-to-drop orphan
// clocks into crsql_master.pre_compact_dbversion (monotonic: never
// retreats an existing pin). Skipped when crsql_master is absent or
// no orphan clock carries versions.
func pinVersionFloor(db *sqlite.Conn, orphans []string) error {
	st, err := db.Prepare("SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name='crsql_master')")
	if err != nil {
		return err
	}
	done, err := st.Step()
	has := !done && err == nil && st.ColumnInt64(0) != 0
	st.Close()
	if err != nil {
		return err
	}
	if !has {
		return nil
	}
	var peak *int64
	for _, side := range orphans {
		if !strings.HasSuffix(side, "__crsql_clock") {
			continue
		}
		col, err := db.Prepare("SELECT EXISTS(SELECT 1 FROM pragma_table_info(?) WHERE name='db_version')")
		if err != nil {
			return err
		}
		col.BindText(1, side)
		cdone, err := col.Step()
		ok := !cdone && err == nil && col.ColumnInt64(0) != 0
		col.Close()
		if err != nil {
			return err
		}
		if !ok {
			continue
		}
		mx, err := db.Prepare("SELECT max(db_version) FROM " + quoteIdent(side))
		if err != nil {
			return err
		}
		mdone, err := mx.Step()
		if err == nil && !mdone && mx.ColumnType(0) != sqlite.TypeNull {
			v := mx.ColumnInt64(0)
			if peak == nil || v > *peak {
				peak = &v
			}
		}
		mx.Close()
		if err != nil {
			return err
		}
	}
	if peak == nil {
		return nil
	}
	cur, err := db.Prepare("SELECT CAST(value AS INTEGER) FROM crsql_master WHERE key='pre_compact_dbversion'")
	if err != nil {
		return err
	}
	cdone, err := cur.Step()
	floor := int64(0)
	if err == nil && !cdone {
		floor = cur.ColumnInt64(0)
	}
	cur.Close()
	if err != nil {
		return err
	}
	if *peak > floor {
		return execArgs(db, "INSERT OR REPLACE INTO crsql_master(key,value) VALUES('pre_compact_dbversion',?1)", *peak)
	}
	return nil
}
