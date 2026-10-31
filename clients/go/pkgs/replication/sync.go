// Sync plane: export / stage / apply / progress / schema.
//
// Go port of the Storage sync methods in murmur-replication
// (crates/murmur-replication/src/storage.rs). SQL text, cursor rules,
// budget accounting, error kinds, and wire bytes match the Rust
// implementation. Export reads the crsql_changes vtab and Apply
// ingests through crsql_ingest_blob, exactly like the reference;
// only the policy recompute is skipped (the Go mesh has no policy
// subsystem yet).
//
// Durability: Apply commits; the COMMIT barrier plus the caller's
// engine Flush provide what Rust's flush() does after storage calls.
package replication

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"strings"
	"unicode/utf8"

	"github.com/marcgauthier/sqlite-murmur-go/clients/go/bindings/sqlite"
)

// BatchExport is the result of Export: resume cursor plus CRSB blob.
type BatchExport struct {
	Next Cursor
	Blob []byte
}

// emptyCRSBLen is the byte length of EncodeCells(nil): magic + version
// + zero count. The pull flow recognises it as an empty batch.
const emptyCRSBLen = 12

// maxCellsPerBatch caps rows per export batch.
const maxCellsPerBatch = 1024

// execArgs runs a single statement with bound parameters.
func execArgs(db *sqlite.Conn, sql string, args ...any) error {
	st, err := db.Prepare(sql)
	if err != nil {
		return err
	}
	defer st.Close()
	for i, arg := range args {
		if err := bindAny(st, i+1, arg); err != nil {
			return err
		}
	}
	if _, err := st.Step(); err != nil {
		return err
	}
	return nil
}

func bindAny(st *sqlite.Stmt, n int, arg any) error {
	switch v := arg.(type) {
	case int:
		return st.BindInt64(n, int64(v))
	case int64:
		return st.BindInt64(n, v)
	case uint32:
		return st.BindInt64(n, int64(v))
	case uint64:
		if v > uint64(math_MaxInt64) {
			return errInvalid("uint64 out of range")
		}
		return st.BindInt64(n, int64(v))
	case string:
		return st.BindText(n, v)
	case []byte:
		return st.BindBlob(n, v)
	case NodeID:
		return st.BindBlob(n, v[:])
	case nil:
		return st.BindNull(n)
	default:
		return errInvalidf("unsupported bind type %T", arg)
	}
}

const math_MaxInt64 = int64(^uint64(0) >> 1)

// NodeIDFromBytes converts a 16-byte slice to a NodeID.
func NodeIDFromBytes(b []byte) (NodeID, error) {
	if len(b) != 16 {
		return NodeID{}, errInvalid("node id must be 16 bytes")
	}
	var id NodeID
	copy(id[:], b)
	return id, nil
}

// compareKey orders (version, seq, table, pk, cid) tuples.
func compareKey(a, b *Key) int {
	if a.Version != b.Version {
		if a.Version < b.Version {
			return -1
		}
		return 1
	}
	if a.Seq != b.Seq {
		if a.Seq < b.Seq {
			return -1
		}
		return 1
	}
	if a.Table != b.Table {
		if a.Table < b.Table {
			return -1
		}
		return 1
	}
	if c := bytes.Compare(a.PK, b.PK); c != 0 {
		return c
	}
	if a.CID != b.CID {
		if a.CID < b.CID {
			return -1
		}
		return 1
	}
	return 0
}

func keysEqual(a, b *Key) bool {
	if a == nil || b == nil {
		return a == b
	}
	return compareKey(a, b) == 0
}

// cursorsEqual compares stream positions field by field.
func cursorsEqual(a, b Cursor) bool {
	if a.From != b.From {
		return false
	}
	if (a.Through == nil) != (b.Through == nil) {
		return false
	}
	if a.Through != nil && *a.Through != *b.Through {
		return false
	}
	return keysEqual(a.After, b.After)
}

// scanKeyBytes reads a batched CRR key cell (table, pk, cid): text
// or blob. The bytes view the scan arena and are only valid for the
// current row; copy anything retained.
func scanKeyBytes(c *sqlite.Cell, arena []byte) ([]byte, error) {
	switch c.Type() {
	case sqlite.TypeText, sqlite.TypeBlob:
		return c.Bytes(arena), nil
	default:
		return nil, errProtocol("CRR key storage class")
	}
}

// scanCellValue converts a batched crsql_changes val cell to a
// CellVal. Text/blob values view the arena and must encode before
// the next scan call.
func scanCellValue(c *sqlite.Cell, arena []byte) (CellVal, error) {
	switch c.Type() {
	case sqlite.TypeNull:
		return NullVal(), nil
	case sqlite.TypeInteger:
		return IntVal(c.Int64()), nil
	case sqlite.TypeFloat:
		return RealVal(c.Float()), nil
	case sqlite.TypeText:
		return TextVal(c.Bytes(arena)), nil
	case sqlite.TypeBlob:
		return BlobVal(c.Bytes(arena)), nil
	default:
		return CellVal{}, errProtocol("CRR value storage class")
	}
}

// cellValue converts a crsql_changes val column to a CellVal.
func cellValue(st *sqlite.Stmt, col int) (CellVal, error) {
	switch st.ColumnType(col) {
	case sqlite.TypeNull:
		return NullVal(), nil
	case sqlite.TypeInteger:
		return IntVal(st.ColumnInt64(col)), nil
	case sqlite.TypeFloat:
		return RealVal(st.ColumnFloat(col)), nil
	case sqlite.TypeText:
		return TextVal([]byte(st.ColumnText(col))), nil
	case sqlite.TypeBlob:
		return BlobVal(append([]byte(nil), st.ColumnBlob(col)...)), nil
	default:
		return CellVal{}, errProtocol("CRR value storage class")
	}
}

// Export reads clock rows after cursor (up to batchBytes estimated,
// maxBatchBytes encoded, 1024 cells) and packs them into a CRSB blob
// with a resume cursor. Tables mapped to false in the stored
// table_replication map are skipped before any budget accounting.
func Export(db *sqlite.Conn, cursor Cursor, batchBytes, maxBatchBytes int) (BatchExport, error) {
	if batchBytes < 0 || maxBatchBytes < 0 {
		return BatchExport{}, errInvalid("negative batch budget")
	}
	through := cursor.Through
	throughVal := int64(0)
	hasThrough := through != nil
	if hasThrough {
		throughVal = *through
	}
	afterBad := cursor.After != nil &&
		(cursor.After.Version <= cursor.From ||
			!hasThrough || cursor.After.Version > throughVal)
	if cursor.From < 0 || (hasThrough && throughVal < cursor.From) || afterBad {
		return BatchExport{}, errProtocol("invalid export cursor")
	}
	if err := db.Exec("BEGIN"); err != nil {
		return BatchExport{}, err
	}
	committed := false
	defer func() {
		if !committed {
			_ = db.Exec("ROLLBACK")
		}
	}()
	current, err := DbVersion(db)
	if err != nil {
		return BatchExport{}, err
	}
	resolved := current
	if hasThrough {
		resolved = throughVal
	}
	if resolved > current || cursor.From > current {
		return BatchExport{}, errProtocol("source version regressed")
	}
	flags, err := ReplicationFlags(db)
	if err != nil {
		return BatchExport{}, err
	}
	filtering := false
	for _, v := range flags {
		if !v {
			filtering = true
			break
		}
	}
	st, err := db.Prepare(`SELECT "table",pk,cid,val,col_version,db_version,site_id,cl,seq FROM crsql_changes WHERE db_version>?1 AND db_version<=?2 AND (?3 IS NULL OR (db_version,seq,"table",pk,cid)>(?3,?4,?5,?6,?7)) ORDER BY db_version,seq,"table",pk,cid`)
	if err != nil {
		return BatchExport{}, err
	}
	defer st.Close()
	var afterArgs []any
	if cursor.After == nil {
		afterArgs = []any{cursor.From, resolved, nil, nil, nil, nil, nil}
	} else {
		afterArgs = []any{cursor.From, resolved, cursor.After.Version, cursor.After.Seq, cursor.After.Table, cursor.After.PK, cursor.After.CID}
	}
	for i, arg := range afterArgs {
		if err := bindAny(st, i+1, arg); err != nil {
			return BatchExport{}, err
		}
	}
	blob := []byte{'C', 'R', 'S', 'B', 1, 0, 0, 0, 0, 0, 0, 0}
	var count uint32
	var last *Key
	done := true
	// One crossing per 256 clock rows instead of ~30 per row. Cells
	// reference the arena; only the resume key's PK outlives the
	// row (copied below) — everything else encodes immediately.
	scanTypes := []sqlite.ColType{
		sqlite.ColBlob, sqlite.ColBlob, sqlite.ColBlob,
		sqlite.ColAny,
		sqlite.ColInt, sqlite.ColInt,
		sqlite.ColBlob,
		sqlite.ColInt, sqlite.ColInt,
	}
	const scanBatch = 256
	scanCells := make([]sqlite.Cell, scanBatch*9)
	scanArena := make([]byte, 1<<20)
	stopped := false
	for !stopped {
		n, more, err := st.StepRows(scanTypes, scanCells, scanArena, scanBatch)
		if err != nil {
			return BatchExport{}, err
		}
		for r := 0; r < n; r++ {
			row := scanCells[r*9 : (r+1)*9]
			tableRaw, err := scanKeyBytes(&row[0], scanArena)
			if err != nil {
				return BatchExport{}, err
			}
			pkView, err := scanKeyBytes(&row[1], scanArena)
			if err != nil {
				return BatchExport{}, err
			}
			cidRaw, err := scanKeyBytes(&row[2], scanArena)
			if err != nil {
				return BatchExport{}, err
			}
			if !utf8.Valid(tableRaw) || !utf8.Valid(cidRaw) {
				return BatchExport{}, errProtocol("CRR key not utf8")
			}
			key := Key{
				Version: row[5].Int64(),
				Seq:     row[8].Int64(),
				Table:   string(tableRaw),
				PK:      pkView,
				CID:     string(cidRaw),
			}
			if cursor.After != nil && compareKey(&key, cursor.After) <= 0 {
				continue
			}
			if filtering {
				if enabled, ok := flags[strings.ToLower(key.Table)]; ok && !enabled {
					continue
				}
			}
			// Estimate without copying the value: text/blob
			// length, 8 bytes per scalar, plus per-row
			// overhead. Identical to the per-column loop it
			// replaces.
			rowBytes := 64
			for i := 0; i < 9; i++ {
				switch row[i].Type() {
				case sqlite.TypeText, sqlite.TypeBlob:
					rowBytes += row[i].BlobLen()
				default:
					rowBytes += 8
				}
			}
			if rowBytes > maxBatchBytes-emptyCRSBLen {
				return BatchExport{}, errOverloaded("cell exceeds max batch")
			}
			if count > 0 && len(blob)+rowBytes > batchBytes {
				done = false
				stopped = true
				break
			}
			val, err := scanCellValue(&row[3], scanArena)
			if err != nil {
				return BatchExport{}, err
			}
			if row[6].Type() != sqlite.TypeBlob {
				return BatchExport{}, errProtocol("site not blob")
			}
			cell := Cell{
				Table:      key.Table,
				PK:         key.PK,
				CID:        key.CID,
				Val:        val,
				ColVersion: row[4].Int64(),
				DBVersion:  row[5].Int64(),
				SiteID:     row[6].Bytes(scanArena),
				CL:         row[7].Int64(),
				Seq:        row[8].Int64(),
			}
			fields := EncodeCell(nil, cell)
			if len(blob)+len(fields) > maxBatchBytes {
				return BatchExport{}, errOverloaded("batch exceeds max")
			}
			blob = append(blob, fields...)
			count++
			cp := key
			// The scan PK views the reusable arena: copy the one
			// key that outlives the row (the resume cursor).
			cp.PK = append([]byte(nil), key.PK...)
			last = &cp
			if count >= maxCellsPerBatch {
				done = false
				stopped = true
				break
			}
		}
		if !more {
			break
		}
		if n == 0 {
			// A row exceeds the arena: grow and retry the
			// same row (StepRows left it current).
			scanArena = append(scanArena, make([]byte, len(scanArena))...)
		}
	}
	st.Close()
	blob[8] = byte(count)
	blob[9] = byte(count >> 8)
	blob[10] = byte(count >> 16)
	blob[11] = byte(count >> 24)
	if err := db.Exec("COMMIT"); err != nil {
		return BatchExport{}, err
	}
	committed = true
	var next Cursor
	if done {
		next = Cursor{From: resolved}
	} else {
		t := resolved
		next = Cursor{From: cursor.From, Through: &t, After: last}
	}
	return BatchExport{Next: next, Blob: blob}, nil
}

// Apply reassembles the staged chunks for node, verifies length and
// digest, drops locally opted-out tables, ingests the cells, and
// advances the stored cursor plus the applied/observed heads. The
// stored progress must still equal previous (no concurrent transfer).
// Ingest and bookkeeping commit atomically.
func Apply(db *sqlite.Conn, node, site NodeID, previous, next Cursor, length uint64, digest [32]byte) error {
	storedSite, stored, err := Progress(db, node)
	if err != nil {
		return err
	}
	if storedSite == nil || *storedSite != site || !cursorsEqual(stored, previous) {
		return errProtocol("receive progress changed during transfer")
	}
	st, err := db.Prepare("SELECT idx,data FROM murmur_stage WHERE node=?1 ORDER BY idx")
	if err != nil {
		return err
	}
	defer st.Close()
	if err := st.BindBlob(1, node[:]); err != nil {
		return err
	}
	var blob []byte
	var index uint64
	for {
		stepDone, err := st.Step()
		if err != nil {
			return err
		}
		if stepDone {
			break
		}
		idx := st.ColumnInt64(0)
		if idx < 0 || uint64(idx) != index {
			return errProtocol("missing chunk")
		}
		data := st.ColumnBlob(1)
		if uint64(len(blob)+len(data)) > length {
			return errProtocol("excess payload")
		}
		blob = append(blob, data...)
		index++
	}
	st.Close()
	if uint64(len(blob)) != length || sha256.Sum256(blob) != digest {
		return errProtocol("batch digest or length")
	}
	flags, err := ReplicationFlags(db)
	if err != nil {
		return err
	}
	ingest := blob
	skipIngest := false
	filtering := false
	for _, v := range flags {
		if !v {
			filtering = true
			break
		}
	}
	if filtering {
		cells, err := DecodeCells(blob)
		if err != nil {
			return err
		}
		kept := cells[:0]
		for _, c := range cells {
			if enabled, ok := flags[strings.ToLower(c.Table)]; ok && !enabled {
				continue
			}
			kept = append(kept, c)
		}
		if len(kept) == 0 {
			skipIngest = true
		} else {
			ingest = EncodeCells(kept)
		}
	}
	if err := db.Exec("BEGIN IMMEDIATE"); err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			_ = db.Exec("ROLLBACK")
		}
	}()
	if !skipIngest {
		if err := IngestBlob(db, ingest); err != nil {
			return err
		}
	}
	// Policy carriers just ingested would be reduced and projected
	// here; the Go mesh has no policy subsystem yet.
	if err := execArgs(db, "UPDATE murmur_progress SET cursor=?1 WHERE node=?2", EncodeCursor(next), node[:]); err != nil {
		return err
	}
	if err := execArgs(db, "DELETE FROM murmur_stage WHERE node=?1", node[:]); err != nil {
		return err
	}
	// Heads are sender stream positions: applied is the contiguous
	// version, observed is the sender's latest (through when the
	// batch is partial).
	applied := uint64(0)
	if next.From > 0 {
		applied = uint64(next.From)
	}
	observed := next.From
	if next.Through != nil && *next.Through > observed {
		observed = *next.Through
	}
	observedHead := uint64(0)
	if observed > 0 {
		observedHead = uint64(observed)
	}
	if err := kvPut(db, ProgressKey(node), EncodeU64(applied)); err != nil {
		return err
	}
	if err := kvPut(db, ObservedKey(node), EncodeU64(observedHead)); err != nil {
		return err
	}
	if err := db.Exec("COMMIT"); err != nil {
		return err
	}
	committed = true
	return nil
}

// StageBegin clears staged chunks for a peer plus expired rows.
func StageBegin(db *sqlite.Conn, node NodeID, stagingTimeoutMs int64) error {
	return execArgs(db, "DELETE FROM murmur_stage WHERE node=?1 OR created < unixepoch()*1000-?2", node[:], stagingTimeoutMs)
}

// Stage appends one chunk for a peer, enforcing the staging budget
// over all staged bytes.
func Stage(db *sqlite.Conn, node NodeID, idx uint32, data []byte, budget int) error {
	st, err := db.Prepare("SELECT coalesce(sum(length(data)),0) FROM murmur_stage")
	if err != nil {
		return err
	}
	defer st.Close()
	stepDone, err := st.Step()
	if err != nil {
		return err
	}
	var total int64
	if !stepDone {
		total = st.ColumnInt64(0)
	}
	st.Close()
	if total+int64(len(data)) > int64(budget) {
		return errOverloaded("staging budget exceeded")
	}
	return execArgs(db, "INSERT INTO murmur_stage VALUES(?1,?2,?3,unixepoch()*1000)", node[:], idx, data)
}

// Progress loads the stored (site, cursor) for an origin. A missing
// row yields a nil site and the default cursor.
func Progress(db *sqlite.Conn, node NodeID) (*NodeID, Cursor, error) {
	st, err := db.Prepare("SELECT site,cursor FROM murmur_progress WHERE node=?1")
	if err != nil {
		return nil, Cursor{}, err
	}
	defer st.Close()
	if err := st.BindBlob(1, node[:]); err != nil {
		return nil, Cursor{}, err
	}
	stepDone, err := st.Step()
	if err != nil {
		return nil, Cursor{}, err
	}
	if stepDone {
		return nil, Cursor{}, nil
	}
	siteRaw := append([]byte(nil), st.ColumnBlob(0)...)
	raw := append([]byte(nil), st.ColumnBlob(1)...)
	st.Close()
	if len(siteRaw) != 16 {
		return nil, Cursor{}, errProtocol("stored site")
	}
	var site NodeID
	copy(site[:], siteRaw)
	cursor, err := DecodeCursor(raw)
	if err != nil {
		return nil, Cursor{}, err
	}
	return &site, cursor, nil
}

// Reset restores the default cursor for an origin with a new site.
func Reset(db *sqlite.Conn, node, site NodeID) error {
	return execArgs(db, "INSERT INTO murmur_progress(node,site,cursor) VALUES(?1,?2,?3) ON CONFLICT(node) DO UPDATE SET site=excluded.site,cursor=excluded.cursor,sent=NULL", node[:], site[:], EncodeCursor(Cursor{}))
}

// ReplicationFlags parses the table_replication JSON map
// (lower-cased table name to enabled flag). Absent or empty means
// all tables replicate.
func ReplicationFlags(db *sqlite.Conn) (map[string]bool, error) {
	raw, err := Setting(db, "table_replication")
	if err != nil {
		return nil, err
	}
	if raw == "" {
		raw = "{}"
	}
	var parsed map[string]bool
	if err := json.Unmarshal([]byte(raw), &parsed); err != nil {
		return nil, errInvalid("bad table_replication")
	}
	flags := make(map[string]bool, len(parsed))
	for k, v := range parsed {
		flags[strings.ToLower(k)] = v
	}
	return flags, nil
}

// kvGet reads one murmur_kv value.
func kvGet(db *sqlite.Conn, key []byte) ([]byte, bool, error) {
	st, err := db.Prepare("SELECT value FROM murmur_kv WHERE key=?1")
	if err != nil {
		return nil, false, err
	}
	defer st.Close()
	if err := st.BindBlob(1, key); err != nil {
		return nil, false, err
	}
	stepDone, err := st.Step()
	if err != nil {
		return nil, false, err
	}
	if stepDone {
		return nil, false, nil
	}
	return append([]byte(nil), st.ColumnBlob(0)...), true, nil
}

// kvPut writes one murmur_kv value.
func kvPut(db *sqlite.Conn, key, value []byte) error {
	return execArgs(db, "INSERT INTO murmur_kv(key,value) VALUES(?1,?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value", key, value)
}

// ObservedMax max-merges an observed version for an origin (e.g.
// what a puller acked of our data). The hint becomes durable at the
// next barrier; retention re-flushes before pruning decisions.
func ObservedMax(db *sqlite.Conn, origin NodeID, seq uint64) error {
	raw, ok, err := kvGet(db, ObservedKey(origin))
	if err != nil {
		return err
	}
	var current uint64
	if ok {
		current, err = DecodeU64(raw)
		if err != nil {
			return err
		}
	}
	if seq > current {
		return kvPut(db, ObservedKey(origin), EncodeU64(seq))
	}
	return nil
}

// SchemaPair is one replicated (table, DDL) pair.
type SchemaPair struct {
	Table string
	DDL   string
}

// postcardUvarint appends a postcard-style unsigned LEB128 varint.
func postcardUvarint(out []byte, v uint64) []byte {
	for {
		b := byte(v & 0x7f)
		v >>= 7
		if v == 0 {
			return append(out, b)
		}
		out = append(out, b|0x80)
	}
}

// postcardUvarintDecode reads one unsigned LEB128 varint.
func postcardUvarintDecode(b []byte) (uint64, int, error) {
	var v uint64
	var shift uint
	for i, c := range b {
		if i >= 10 {
			return 0, 0, errInvalid("varint overflow")
		}
		v |= uint64(c&0x7f) << shift
		if c&0x80 == 0 {
			return v, i + 1, nil
		}
		shift += 7
	}
	return 0, 0, errInvalid("truncated varint")
}

// EncodeSchemaPairs encodes ordered pairs the way postcard encodes
// Vec<(String, String)>: varint length, then per pair varint-prefixed
// table and DDL bytes.
func EncodeSchemaPairs(pairs []SchemaPair) []byte {
	out := postcardUvarint(nil, uint64(len(pairs)))
	for _, p := range pairs {
		out = postcardUvarint(out, uint64(len(p.Table)))
		out = append(out, p.Table...)
		out = postcardUvarint(out, uint64(len(p.DDL)))
		out = append(out, p.DDL...)
	}
	return out
}

// DecodeSchemaPairs parses EncodeSchemaPairs output.
func DecodeSchemaPairs(b []byte) ([]SchemaPair, error) {
	n, off, err := postcardUvarintDecode(b)
	if err != nil {
		return nil, err
	}
	b = b[off:]
	pairs := make([]SchemaPair, 0, n)
	for i := uint64(0); i < n; i++ {
		ln, off, err := postcardUvarintDecode(b)
		if err != nil {
			return nil, err
		}
		b = b[off:]
		if uint64(len(b)) < ln {
			return nil, errInvalid("truncated schema pair")
		}
		table := string(b[:ln])
		b = b[ln:]
		ln, off, err = postcardUvarintDecode(b)
		if err != nil {
			return nil, err
		}
		b = b[off:]
		if uint64(len(b)) < ln {
			return nil, errInvalid("truncated schema pair")
		}
		ddl := string(b[:ln])
		b = b[ln:]
		pairs = append(pairs, SchemaPair{Table: table, DDL: ddl})
	}
	if len(b) != 0 {
		return nil, errInvalid("trailing schema bytes")
	}
	return pairs, nil
}

// SchemaPairs lists the replicated subset: ordered (table, DDL) pairs
// for every CRR application table, discovered through the
// __crsql_clock tables. murmur_ tables must not be CRRs.
//
// Note: the Rust side additionally tolerates the policy carrier and
// ownership event tables (exact DDL match, excluded from the digest).
// The Go mesh has no policy subsystem, so those tables cannot exist
// here and the generic murmur_ guard covers their names.
func SchemaPairs(db *sqlite.Conn) ([]SchemaPair, error) {
	st, err := db.Prepare("SELECT name,sql FROM sqlite_schema WHERE type='table' AND name IN (SELECT substr(name,1,length(name)-13) FROM sqlite_schema WHERE type='table' AND substr(name,-13)='__crsql_clock') ORDER BY name")
	if err != nil {
		return nil, err
	}
	defer st.Close()
	var pairs []SchemaPair
	for {
		stepDone, err := st.Step()
		if err != nil {
			return nil, err
		}
		if stepDone {
			break
		}
		name := st.ColumnText(0)
		ddl := st.ColumnText(1)
		if strings.HasPrefix(name, "murmur_") {
			return nil, errInvalid("murmur tables must not be CRRs")
		}
		pairs = append(pairs, SchemaPair{Table: name, DDL: ddl})
	}
	if len(pairs) == 0 {
		return nil, errInvalid("no CRR tables configured")
	}
	return pairs, nil
}

// SchemaBytes returns the canonical replicated-subset bytes.
func SchemaBytes(db *sqlite.Conn) ([]byte, error) {
	pairs, err := SchemaPairs(db)
	if err != nil {
		return nil, err
	}
	return EncodeSchemaPairs(pairs), nil
}

// ManifestSchemaBytes returns the canonical pairs minus local-only
// (opted-out) tables. An all-opted-out node signs an empty set.
func ManifestSchemaBytes(db *sqlite.Conn) ([]byte, error) {
	pairs, err := SchemaPairs(db)
	if err != nil {
		return nil, err
	}
	flags, err := ReplicationFlags(db)
	if err != nil {
		return nil, err
	}
	var kept []SchemaPair
	for _, p := range pairs {
		if enabled, ok := flags[strings.ToLower(p.Table)]; ok && !enabled {
			continue
		}
		kept = append(kept, p)
	}
	return EncodeSchemaPairs(kept), nil
}

// Schema returns the SHA-256 digest of the canonical schema bytes.
func Schema(db *sqlite.Conn) ([32]byte, error) {
	raw, err := SchemaBytes(db)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(raw), nil
}

// SiteID returns the local 16-byte cr-sqlite site id.
func SiteID(db *sqlite.Conn) (NodeID, error) {
	var id NodeID
	st, err := db.Prepare("SELECT crsql_site_id()")
	if err != nil {
		return id, err
	}
	defer st.Close()
	done, err := st.Step()
	if err != nil {
		return id, err
	}
	if done {
		return id, errInvalid("crr site not claimed")
	}
	raw := st.ColumnBlob(0)
	if len(raw) != 16 {
		return id, errInvalid("crr site not claimed")
	}
	copy(id[:], raw)
	return id, nil
}

// DbVersion returns the current local db version.
func DbVersion(db *sqlite.Conn) (int64, error) {
	st, err := db.Prepare("SELECT crsql_db_version()")
	if err != nil {
		return 0, err
	}
	defer st.Close()
	done, err := st.Step()
	if err != nil {
		return 0, err
	}
	if done {
		return 0, errInvalid("crr version missing")
	}
	return st.ColumnInt64(0), nil
}

// IngestCells merges cells with cr-sqlite's own merge (per-cell
// last-writer-wins), the same entry point sync Apply uses for blobs.
func IngestCells(db *sqlite.Conn, cells []Cell) error {
	return IngestBlob(db, EncodeCells(cells))
}

// IngestBlob merges one CRSB batch through cr-sqlite. Malformed
// input fails the batch; the caller owns the transaction. Cells
// carry cl opaquely (stored, echoed, never compared).
func IngestBlob(db *sqlite.Conn, blob []byte) error {
	st, err := db.Prepare("SELECT crsql_ingest_blob(?)")
	if err != nil {
		return err
	}
	defer st.Close()
	if err := st.BindBlob(1, blob); err != nil {
		return err
	}
	// Like the reference query_row: the function returns one row.
	done, err := st.Step()
	if err != nil {
		return err
	}
	if done {
		return errProtocol("crsql_ingest_blob returned no row")
	}
	return nil
}
