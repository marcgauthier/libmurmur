// CRR backend: the tx.Backend adapter over the CRR/SQLite store.
//
// Go port of backend.rs (CrrBackend) plus the Store kv helpers it
// uses (kv_get_many, kv_keys, kv_keys_page, kv_commit, tx_progress,
// clock_observe). Worker round trips collapse to direct calls; flush
// barriers collapse to COMMIT (SQLite commits sync through the VFS).
package replication

import (
	"bytes"

	"github.com/marcgauthier/libmurmur/clients/go/bindings/sqlite"
	"github.com/marcgauthier/libmurmur/clients/go/pkgs/tx"
)

// clockKey is the hybrid-clock kv key.
var clockKey = []byte("07/replication/clock/hlc")

// txErr maps engine errors onto tx errors.
func txErr(err error) error {
	if err == nil {
		return nil
	}
	if e, ok := err.(*Error); ok {
		switch e.Kind {
		case "Invalid":
			return &tx.Error{Kind: "Invalid", Msg: e.Msg}
		case "Protocol":
			return &tx.Error{Kind: "Protocol", Msg: e.Msg}
		case "Auth":
			return &tx.Error{Kind: "Auth", Msg: e.Msg}
		case "Unavailable":
			return &tx.Error{Kind: "Unavailable", Msg: e.Msg}
		case "Overloaded", "Limit", "Busy":
			return &tx.Error{Kind: "Overloaded", Msg: e.Msg}
		case "Closed":
			return &tx.Error{Kind: "Unavailable", Msg: e.Msg}
		default:
			return &tx.Error{Kind: "Protocol", Msg: e.Msg}
		}
	}
	if _, ok := err.(*sqlite.Error); ok {
		return &tx.Error{Kind: "Storage", Msg: err.Error()}
	}
	return &tx.Error{Kind: "Storage", Msg: err.Error()}
}

// CrrBackend adapts the CRR store to tx.Backend. online=false serves
// kv/progress/clock reads while snapshots report unavailable.
type CrrBackend struct {
	db     *sqlite.Conn
	group  NodeID
	node   NodeID
	online bool
}

// NewBackend builds an online backend.
func NewBackend(db *sqlite.Conn, group, node NodeID) *CrrBackend {
	return &CrrBackend{db: db, group: group, node: node, online: true}
}

// NewOfflineBackend builds a backend over stored identities while
// replication is stopped.
func NewOfflineBackend(db *sqlite.Conn, group, node NodeID) *CrrBackend {
	return &CrrBackend{db: db, group: group, node: node, online: false}
}

// CancelPending interrupts pending waits; commits never abort.
func (b *CrrBackend) CancelPending() {}

// Identity returns (database, node).
func (b *CrrBackend) Identity() (tx.NodeID, tx.NodeID) { return b.group, b.node }

// Get reads one kv value.
func (b *CrrBackend) Get(key []byte) ([]byte, bool, error) {
	v, ok, err := kvGet(b.db, key)
	if err != nil {
		return nil, false, txErr(err)
	}
	return v, ok, nil
}

// GetMany reads keys in one round trip, preserving order.
func (b *CrrBackend) GetMany(keys [][]byte) ([][]byte, []bool, error) {
	vals, err := kvGetMany(b.db, keys)
	if err != nil {
		return nil, nil, txErr(err)
	}
	present := make([]bool, len(vals))
	for i, v := range vals {
		present[i] = v != nil
	}
	return vals, present, nil
}

// GetManyBounded reads an ordered prefix within a byte budget.
// Missing values consume no bytes; one oversized first value is
// allowed for progress.
func (b *CrrBackend) GetManyBounded(keys [][]byte, maxBytes int) ([][]byte, []bool, error) {
	all, present, err := b.GetMany(keys)
	if err != nil {
		return nil, nil, err
	}
	var vals [][]byte
	var flags []bool
	used := 0
	for i, v := range all {
		size := len(v)
		if len(vals) > 0 && used+size > maxBytes {
			break
		}
		used += size
		vals = append(vals, v)
		flags = append(flags, present[i])
		if used >= maxBytes {
			break
		}
	}
	return vals, flags, nil
}

// Keys scans one prefix in key order.
func (b *CrrBackend) Keys(prefix []byte) ([][]byte, error) {
	keys, err := kvKeys(b.db, prefix)
	if err != nil {
		return nil, txErr(err)
	}
	return keys, nil
}

// KeysPage scans one prefix after an exclusive cursor.
func (b *CrrBackend) KeysPage(prefix, after []byte, limit int) ([][]byte, error) {
	keys, err := kvKeysPage(b.db, prefix, after, limit)
	if err != nil {
		return nil, txErr(err)
	}
	return keys, nil
}

// Progress collects per-origin heads plus the live local db version
// (local commits never pass through Commit, so the stored head alone
// would lag and read-your-write waits would stall).
func (b *CrrBackend) Progress() ([]tx.Progress, error) {
	heads, err := txProgress(b.db)
	if err != nil {
		return nil, txErr(err)
	}
	if live, err := DbVersion(b.db); err == nil && live > 0 {
		found := false
		for i := range heads {
			if heads[i].Origin == b.node {
				if uint64(live) > heads[i].Applied {
					heads[i].Applied = uint64(live)
				}
				if uint64(live) > heads[i].Observed {
					heads[i].Observed = uint64(live)
				}
				found = true
				break
			}
		}
		if !found {
			heads = append(heads, tx.Progress{Origin: b.node, Applied: uint64(live), Observed: uint64(live)})
		}
	}
	return heads, nil
}

// Commit applies puts/deletes durably.
func (b *CrrBackend) Commit(records []tx.Record) error {
	return txErr(kvCommit(b.db, records))
}

// ImportBridge is a WP-B stub (high/low ownership import).
func (b *CrrBackend) ImportBridge(_ tx.BridgeHeader, _ []byte) (bool, error) {
	return false, nil
}

// ReleaseOwnership is a WP-B stub (high/low ownership release).
func (b *CrrBackend) ReleaseOwnership(_ string, _ []byte, _ *string) (bool, error) {
	return false, nil
}

// Publish commits control records durably.
func (b *CrrBackend) Publish(records []tx.Record) error {
	return txErr(kvCommit(b.db, records))
}

// Snapshot captures the full CRSB export plus schema digest.
func (b *CrrBackend) Snapshot() ([]byte, error) {
	if !b.online {
		return nil, &tx.Error{Kind: "Unavailable", Msg: "replication is stopped"}
	}
	snap, err := b.exportFull()
	if err != nil {
		return nil, txErr(err)
	}
	return snap, nil
}

// SnapshotWithProgress captures the export and heads together.
func (b *CrrBackend) SnapshotWithProgress() ([]byte, []tx.Progress, error) {
	if !b.online {
		return nil, nil, &tx.Error{Kind: "Unavailable", Msg: "replication is stopped"}
	}
	snap, err := b.exportFull()
	if err != nil {
		return nil, nil, txErr(err)
	}
	heads, err := txProgress(b.db)
	if err != nil {
		return nil, nil, txErr(err)
	}
	return snap, heads, nil
}

// RetentionCheckpoint is the persistence barrier; the CRR store is
// always a coherent image at commit boundaries.
func (b *CrrBackend) RetentionCheckpoint() error { return nil }

// PruneHistory is a WP-A stub (clock/tombstone GC).
func (b *CrrBackend) PruneHistory(_ NodeID, _ uint64) (uint64, error) {
	return 0, nil
}

// ReclaimRetention is a light pass until retention GC wires through.
func (b *CrrBackend) ReclaimRetention() error { return nil }

// Schema returns the canonical replicated-subset bytes.
func (b *CrrBackend) Schema() ([]byte, error) {
	raw, err := SchemaBytes(b.db)
	if err != nil {
		return nil, txErr(err)
	}
	return raw, nil
}

// Apply ingests CRSB payloads and lands control records in one
// immediate transaction. Duplicate batches are idempotent; durable
// apply always reports true.
func (b *CrrBackend) Apply(payloads [][]byte, records []tx.Record) (bool, error) {
	if err := b.db.Exec("BEGIN IMMEDIATE"); err != nil {
		return false, txErr(err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = b.db.Exec("ROLLBACK")
		}
	}()
	for _, p := range payloads {
		if err := IngestBlob(b.db, p); err != nil {
			return false, txErr(err)
		}
	}
	if err := kvApply(b.db, records); err != nil {
		return false, txErr(err)
	}
	if err := b.db.Exec("COMMIT"); err != nil {
		return false, txErr(err)
	}
	committed = true
	return true, nil
}

// Observe max-merges an authenticated hybrid clock.
func (b *CrrBackend) Observe(millis uint64, logical uint32) error {
	_, _, err := clockObserve(b.db, millis, logical)
	return txErr(err)
}

// AcceptSchema re-decides inside one call: local DDL may have raced
// the check. Additive applies; anything else declines (the caller
// only records the manifest on true).
func (b *CrrBackend) AcceptSchema(schema []byte) (bool, error) {
	params, err := SchemaParamsFrom(b.db)
	if err != nil {
		return false, txErr(err)
	}
	if !params.AcceptRemoteSchema {
		return false, nil
	}
	local, err := ManifestSchemaBytes(b.db)
	if err != nil {
		return false, txErr(err)
	}
	diff, err := SchemaDiff(local, schema)
	if err != nil {
		return false, txErr(err)
	}
	if !diff.Additive {
		return false, nil
	}
	if err := ApplySchemaAdditive(b.db, &diff.Delta); err != nil {
		return false, txErr(err)
	}
	return true, nil
}

// CreateSnapshot is unsupported (durable snapshots build via the
// replication snapshot path, not the archived constructor).
func (b *CrrBackend) CreateSnapshot(_ NodeID) (tx.Manifest, error) {
	return tx.Manifest{}, &tx.Error{Kind: "Unavailable", Msg: "durable snapshots unsupported by backend"}
}

// AcknowledgeSnapshot is unsupported (see CreateSnapshot).
func (b *CrrBackend) AcknowledgeSnapshot(_, _ NodeID, _ [32]byte) error {
	return &tx.Error{Kind: "Unavailable", Msg: "durable snapshots unsupported by backend"}
}

// exportFull exports every CRR change from version 0 as bounded CRSB
// segments plus the schema digest.
func (b *CrrBackend) exportFull() ([]byte, error) {
	p, err := loadServeParams(b.db)
	if err != nil {
		return nil, err
	}
	schema, err := Schema(b.db)
	if err != nil {
		return nil, err
	}
	var segments [][]byte
	total := 0
	cursor := Cursor{}
	for {
		batch, err := Export(b.db, cursor, p.batchBytes, p.maxBatchBytes)
		if err != nil {
			return nil, err
		}
		total += len(batch.Blob)
		if total > p.stagingBytes {
			return nil, errOverloaded("snapshot exceeds staging budget")
		}
		segments = append(segments, batch.Blob)
		if batch.Next.Through == nil && batch.Next.After == nil {
			return EncodeCrrSnapshot(CrrSnapshot{Schema: schema, Version: batch.Next.From, Segments: segments}), nil
		}
		if len(segments) > 1<<20 {
			return nil, errOverloaded("snapshot exceeds segment budget")
		}
		cursor = batch.Next
	}
}

// CrrSnapshot is the logical-state image: schema digest, source db
// version, and one CRSB segment per export batch.
type CrrSnapshot struct {
	Schema   [32]byte
	Version  int64
	Segments [][]byte
}

// EncodeCrrSnapshot serializes the image (postcard layout).
func EncodeCrrSnapshot(s CrrSnapshot) []byte {
	out := append([]byte(nil), s.Schema[:]...)
	out = appendVarint(out, zigEncode(s.Version))
	out = appendVarint(out, uint64(len(s.Segments)))
	for _, seg := range s.Segments {
		out = appendBytes(out, seg)
	}
	return out
}

// DecodeCrrSnapshot parses the image.
func DecodeCrrSnapshot(b []byte) (CrrSnapshot, error) {
	var s CrrSnapshot
	raw, rest, err := readFixed(b, 32)
	if err != nil {
		return s, err
	}
	copy(s.Schema[:], raw)
	var v uint64
	if v, rest, err = readVarint(rest); err != nil {
		return s, err
	}
	s.Version = zigDecode(v)
	var n uint64
	if n, rest, err = readVarint(rest); err != nil {
		return s, err
	}
	if n > 1<<20 {
		return s, errProtocol("snapshot segments too many")
	}
	s.Segments = make([][]byte, 0, n)
	for i := uint64(0); i < n; i++ {
		var seg []byte
		if seg, rest, err = readBytes(rest); err != nil {
			return s, err
		}
		s.Segments = append(s.Segments, append([]byte(nil), seg...))
	}
	if len(rest) != 0 {
		return s, errProtocol("trailing snapshot bytes")
	}
	return s, nil
}

// kvGetMany reads keys with one reused statement, preserving order.
func kvGetMany(db *sqlite.Conn, keys [][]byte) ([][]byte, error) {
	st, err := db.Prepare("SELECT value FROM murmur_kv WHERE key=?1")
	if err != nil {
		return nil, err
	}
	defer st.Close()
	out := make([][]byte, 0, len(keys))
	for _, k := range keys {
		if err := st.BindBlob(1, k); err != nil {
			return nil, err
		}
		done, err := st.Step()
		if err != nil {
			return nil, err
		}
		if done {
			out = append(out, nil)
		} else {
			out = append(out, append([]byte(nil), st.ColumnBlob(0)...))
		}
		if err := st.Reset(); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// prefixEnd is the exclusive BLOB range end for a prefix scan:
// increment the last non-0xff byte and truncate. nil (all-0xff
// prefix) means unbounded.
func prefixEnd(prefix []byte) []byte {
	end := append([]byte(nil), prefix...)
	for len(end) > 0 && end[len(end)-1] == 0xff {
		end = end[:len(end)-1]
	}
	if len(end) == 0 {
		return nil
	}
	end[len(end)-1]++
	return end
}

// kvKeys scans one prefix in key order.
func kvKeys(db *sqlite.Conn, prefix []byte) ([][]byte, error) {
	end := prefixEnd(prefix)
	var query string
	var args []any
	if end == nil {
		query = "SELECT key FROM murmur_kv WHERE key>=?1 ORDER BY key"
		args = []any{prefix}
	} else {
		query = "SELECT key FROM murmur_kv WHERE key>=?1 AND key<?2 ORDER BY key"
		args = []any{prefix, end}
	}
	st, err := db.Prepare(query)
	if err != nil {
		return nil, err
	}
	defer st.Close()
	for i, a := range args {
		if err := bindAny(st, i+1, a); err != nil {
			return nil, err
		}
	}
	var out [][]byte
	for {
		done, err := st.Step()
		if err != nil {
			return nil, err
		}
		if done {
			return out, nil
		}
		out = append(out, append([]byte(nil), st.ColumnBlob(0)...))
	}
}

// kvKeysPage scans one prefix after an exclusive cursor.
func kvKeysPage(db *sqlite.Conn, prefix, after []byte, limit int) ([][]byte, error) {
	end := prefixEnd(prefix)
	var query string
	var args []any
	switch {
	case end != nil && after != nil:
		query = "SELECT key FROM murmur_kv WHERE key>=?1 AND key<?2 AND key>?3 ORDER BY key LIMIT ?4"
		args = []any{prefix, end, after, int64(limit)}
	case end != nil:
		query = "SELECT key FROM murmur_kv WHERE key>=?1 AND key<?2 ORDER BY key LIMIT ?3"
		args = []any{prefix, end, int64(limit)}
	case after != nil:
		query = "SELECT key FROM murmur_kv WHERE key>=?1 AND key>?2 ORDER BY key LIMIT ?3"
		args = []any{prefix, after, int64(limit)}
	default:
		query = "SELECT key FROM murmur_kv WHERE key>=?1 ORDER BY key LIMIT ?2"
		args = []any{prefix, int64(limit)}
	}
	st, err := db.Prepare(query)
	if err != nil {
		return nil, err
	}
	defer st.Close()
	for i, a := range args {
		if err := bindAny(st, i+1, a); err != nil {
			return nil, err
		}
	}
	var out [][]byte
	for {
		done, err := st.Step()
		if err != nil {
			return nil, err
		}
		if done {
			return out, nil
		}
		out = append(out, append([]byte(nil), st.ColumnBlob(0)...))
	}
}

// kvCommit applies puts/deletes in one transaction.
func kvCommit(db *sqlite.Conn, records []tx.Record) error {
	if err := db.Exec("BEGIN"); err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			_ = db.Exec("ROLLBACK")
		}
	}()
	if err := kvApply(db, records); err != nil {
		return err
	}
	if err := db.Exec("COMMIT"); err != nil {
		return err
	}
	committed = true
	return nil
}

// kvApply puts/deletes inside the caller's transaction.
func kvApply(db *sqlite.Conn, records []tx.Record) error {
	put, err := db.Prepare("INSERT INTO murmur_kv(key,value) VALUES(?1,?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value")
	if err != nil {
		return err
	}
	defer put.Close()
	del, err := db.Prepare("DELETE FROM murmur_kv WHERE key=?1")
	if err != nil {
		return err
	}
	defer del.Close()
	for _, r := range records {
		if r.IsDelete() {
			if err := del.BindBlob(1, r.Key); err != nil {
				return err
			}
			if _, err := del.Step(); err != nil {
				return err
			}
			if err := del.Reset(); err != nil {
				return err
			}
			continue
		}
		if err := put.BindBlob(1, r.Key); err != nil {
			return err
		}
		if err := put.BindBlob(2, r.Value); err != nil {
			return err
		}
		if _, err := put.Step(); err != nil {
			return err
		}
		if err := put.Reset(); err != nil {
			return err
		}
	}
	return nil
}

// clockObserve max-merges a hybrid clock; returns the stored clock.
func clockObserve(db *sqlite.Conn, millis uint64, logical uint32) (uint64, uint32, error) {
	raw, ok, err := kvGet(db, clockKey)
	if err != nil {
		return 0, 0, err
	}
	var clock uint64
	var clockLogical uint32
	if ok {
		v, rest, err := readVarint(raw)
		if err != nil {
			return 0, 0, err
		}
		l, rest, err := readVarint(rest)
		if err != nil || len(rest) != 0 {
			if err == nil {
				err = errProtocol("trailing clock bytes")
			}
			return 0, 0, err
		}
		clock, clockLogical = v, uint32(l)
	}
	if millis > clock || (millis == clock && logical > clockLogical) {
		clock, clockLogical = millis, logical
	}
	out := appendVarint(nil, clock)
	out = appendVarint(out, uint64(clockLogical))
	if err := kvPut(db, clockKey, out); err != nil {
		return 0, 0, err
	}
	return clock, clockLogical, nil
}

// txProgress collects durable per-origin progress in one round trip.
func txProgress(db *sqlite.Conn) ([]tx.Progress, error) {
	origins := map[NodeID]*tx.Progress{}
	get := func(origin NodeID) *tx.Progress {
		p, ok := origins[origin]
		if !ok {
			p = &tx.Progress{Origin: origin}
			origins[origin] = p
		}
		return p
	}
	retained, err := kvKeys(db, []byte("07/replication/retained/"))
	if err != nil {
		return nil, err
	}
	for _, k := range retained {
		raw, ok, err := kvGet(db, k)
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}
		p, err := tx.DecodeProgress(raw)
		if err != nil {
			return nil, err
		}
		cp := p
		origins[p.Origin] = &cp
	}
	applied, err := kvKeys(db, []byte("07/replication/applied/"))
	if err != nil {
		return nil, err
	}
	for _, k := range applied {
		raw, ok, err := kvGet(db, k)
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}
		origin, err := originSuffix(k)
		if err != nil {
			return nil, err
		}
		v, err := DecodeU64(raw)
		if err != nil {
			return nil, err
		}
		get(origin).Applied = v
	}
	observed, err := kvKeys(db, []byte("07/replication/observed/"))
	if err != nil {
		return nil, err
	}
	for _, k := range observed {
		raw, ok, err := kvGet(db, k)
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}
		origin, err := originSuffix(k)
		if err != nil {
			return nil, err
		}
		v, err := DecodeU64(raw)
		if err != nil {
			return nil, err
		}
		get(origin).Observed = v
	}
	out := make([]tx.Progress, 0, len(origins))
	for _, p := range origins {
		if p.Applied > p.Observed {
			p.Observed = p.Applied
		}
		out = append(out, *p)
	}
	return out, nil
}

// originSuffix parses the trailing identity of a head key.
func originSuffix(k []byte) (NodeID, error) {
	i := bytes.LastIndexByte(k, '/')
	if i < 0 {
		return NodeID{}, errProtocol("progress key")
	}
	id, err := ParseID(string(k[i+1:]))
	if err != nil {
		return NodeID{}, errProtocol("progress key")
	}
	return id, nil
}
