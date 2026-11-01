package replication

import (
	"testing"

	"github.com/marcgauthier/libmurmur/clients/go/bindings/sqlite"
)

func openCRR(t *testing.T) *sqlite.Conn {
	t.Helper()
	db, err := sqlite.Open(":memory:", sqlite.OpenReadWrite|sqlite.OpenCreate)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if err := EnsureSchema(db); err != nil {
		t.Fatalf("schema: %v", err)
	}
	if err := sqlite.CrsqliteInit(db); err != nil {
		t.Fatalf("crr: %v", err)
	}
	return db
}

func countChanges(t *testing.T, db *sqlite.Conn) int {
	t.Helper()
	st, err := db.Prepare("SELECT COUNT(*) FROM crsql_changes")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if done, err := st.Step(); err != nil || done {
		t.Fatalf("count: %v %v", done, err)
	}
	return int(st.ColumnInt64(0))
}

// clockRow reads one (key, col) clock entry: col_version, db_version.
func clockRow(t *testing.T, db *sqlite.Conn, table string, key int64, col string) (int64, int64, bool) {
	t.Helper()
	st, err := db.Prepare("SELECT col_version,db_version FROM " + quoteIdent(table+"__crsql_clock") + " WHERE key=? AND col_name=?")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	st.BindInt64(1, key)
	st.BindText(2, col)
	done, err := st.Step()
	if err != nil {
		t.Fatal(err)
	}
	if done {
		return 0, 0, false
	}
	return st.ColumnInt64(0), st.ColumnInt64(1), true
}

// exportCells reads live cells through the same vtab query sync
// Export uses, returning them as wire Cells.
func exportCells(t *testing.T, db *sqlite.Conn) []Cell {
	t.Helper()
	st, err := db.Prepare(`SELECT "table",pk,cid,val,col_version,db_version,site_id,cl,seq FROM crsql_changes ORDER BY db_version,seq`)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	var out []Cell
	for {
		done, err := st.Step()
		if err != nil {
			t.Fatal(err)
		}
		if done {
			break
		}
		val, err := cellValue(st, 3)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, Cell{
			Table:      st.ColumnText(0),
			PK:         append([]byte(nil), st.ColumnBlob(1)...),
			CID:        st.ColumnText(2),
			Val:        val,
			ColVersion: st.ColumnInt64(4),
			DBVersion:  st.ColumnInt64(5),
			SiteID:     append([]byte(nil), st.ColumnBlob(6)...),
			CL:         st.ColumnInt64(7),
			Seq:        st.ColumnInt64(8),
		})
	}
	return out
}

func cellText(t *testing.T, db *sqlite.Conn, sql string) string {
	t.Helper()
	st, err := db.Prepare(sql)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if done, err := st.Step(); err != nil || done {
		t.Fatalf("query %q: %v %v", sql, done, err)
	}
	return st.ColumnText(0)
}

func TestCRRCapture(t *testing.T) {
	db := openCRR(t)
	if err := db.Exec("CREATE TABLE t(a INTEGER PRIMARY KEY NOT NULL, b TEXT, c REAL); INSERT INTO t VALUES(1,'x',1.5);"); err != nil {
		t.Fatal(err)
	}
	if err := MakeCRR(db, "t"); err != nil {
		t.Fatalf("make: %v", err)
	}
	// Backfill captured the existing row (2 data cols).
	if n := countChanges(t, db); n != 2 {
		t.Fatalf("backfill changes = %d, want 2", n)
	}
	// Insert captures new cells.
	if err := db.Exec("INSERT INTO t VALUES(2,'y',2.5);"); err != nil {
		t.Fatal(err)
	}
	if n := countChanges(t, db); n != 4 {
		t.Fatalf("after insert = %d, want 4", n)
	}
	// No-op update captures nothing.
	if err := db.Exec("UPDATE t SET b='y' WHERE a=2;"); err != nil {
		t.Fatal(err)
	}
	if n := countChanges(t, db); n != 4 {
		t.Fatalf("after noop update = %d, want 4", n)
	}
	// Real update bumps the changed column's clock in place (the
	// vtab shows live state, not an event log).
	if err := db.Exec("UPDATE t SET b='z',c=2.5 WHERE a=2;"); err != nil {
		t.Fatal(err)
	}
	if n := countChanges(t, db); n != 4 {
		t.Fatalf("after update = %d, want 4", n)
	}
	vb, _, ok := clockRow(t, db, "t", 2, "b")
	if !ok || vb != 2 {
		t.Fatalf("b clock version = %d,%v, want 2", vb, ok)
	}
	vc, _, ok := clockRow(t, db, "t", 2, "c")
	if !ok || vc != 1 {
		t.Fatalf("c clock version = %d,%v, want 1", vc, ok)
	}
	// Delete replaces the row's clocks with one tombstone.
	if err := db.Exec("DELETE FROM t WHERE a=1;"); err != nil {
		t.Fatal(err)
	}
	if n := countChanges(t, db); n != 3 {
		t.Fatalf("after delete = %d, want 3", n)
	}
	v, _, ok := clockRow(t, db, "t", 1, "-1")
	if !ok || v == 0 {
		t.Fatalf("tombstone clock missing: %d %v", v, ok)
	}
	// Re-running MakeCRR is a no-op.
	if err := MakeCRR(db, "t"); err != nil {
		t.Fatalf("re-make: %v", err)
	}
	if n := countChanges(t, db); n != 3 {
		t.Fatalf("after re-make = %d, want 3", n)
	}
	yes, err := IsCRR(db, "t")
	if err != nil || !yes {
		t.Fatalf("IsCRR = %v,%v", yes, err)
	}
}

func TestCRRRejects(t *testing.T) {
	db := openCRR(t)
	if err := MakeCRR(db, "missing"); err == nil {
		t.Fatal("missing table accepted")
	}
	// Rowid tables need the fork's explicit NOT NULL marker on the
	// pk (pragma reports plain INTEGER PRIMARY KEY as nullable).
	if err := db.Exec("CREATE TABLE r(a INTEGER PRIMARY KEY, b TEXT);"); err != nil {
		t.Fatal(err)
	}
	if err := MakeCRR(db, "r"); err == nil {
		t.Fatal("implicit-null pk accepted")
	}
	// WITHOUT ROWID tables replicate (nullable pk included: the
	// fork accepts and captures them).
	if err := db.Exec("CREATE TABLE w(a TEXT, b TEXT, PRIMARY KEY(a)) WITHOUT ROWID;"); err != nil {
		t.Fatal(err)
	}
	if err := MakeCRR(db, "w"); err != nil {
		t.Fatalf("wr table rejected: %v", err)
	}
	// WITHOUT ROWID with a non-null pk replicates through pks side
	// tables.
	if err := db.Exec("CREATE TABLE k(a TEXT NOT NULL, b TEXT, PRIMARY KEY(a)) WITHOUT ROWID;"); err != nil {
		t.Fatal(err)
	}
	if err := MakeCRR(db, "k"); err != nil {
		t.Fatalf("pks table rejected: %v", err)
	}
	yes, err := IsCRR(db, "k")
	if err != nil || !yes {
		t.Fatalf("IsCRR = %v,%v", yes, err)
	}
}

func TestCRRSiteVersion(t *testing.T) {
	db := openCRR(t)
	s1, err := SiteID(db)
	if err != nil {
		t.Fatal(err)
	}
	if s1.Zero() {
		t.Fatal("zero site")
	}
	s2, err := SiteID(db)
	if err != nil || s1 != s2 {
		t.Fatal("site not stable")
	}
	v0, err := DbVersion(db)
	if err != nil || v0 != 0 {
		t.Fatalf("version = %d,%v", v0, err)
	}
	if err := db.Exec("CREATE TABLE t(a INTEGER PRIMARY KEY NOT NULL, b TEXT);"); err != nil {
		t.Fatal(err)
	}
	if err := MakeCRR(db, "t"); err != nil {
		t.Fatal(err)
	}
	if err := db.Exec("INSERT INTO t VALUES(1,'x');"); err != nil {
		t.Fatal(err)
	}
	v1, err := DbVersion(db)
	if err != nil || v1 <= v0 {
		t.Fatalf("version did not advance: %d", v1)
	}
}

// mergePair builds two CRR databases with the same table but distinct
// site ids (separate connections mint distinct ids).
func mergePair(t *testing.T) (a, b *sqlite.Conn) {
	t.Helper()
	a, b = openCRR(t), openCRR(t)
	for _, db := range []*sqlite.Conn{a, b} {
		if err := db.Exec("CREATE TABLE t(a INTEGER PRIMARY KEY NOT NULL, b TEXT);"); err != nil {
			t.Fatal(err)
		}
		if err := MakeCRR(db, "t"); err != nil {
			t.Fatal(err)
		}
	}
	return a, b
}

func TestIngestMerge(t *testing.T) {
	a, b := mergePair(t)
	if err := a.Exec("INSERT INTO t VALUES(1,'local');"); err != nil {
		t.Fatal(err)
	}
	if err := b.Exec("INSERT INTO t VALUES(1,'remote');"); err != nil {
		t.Fatal(err)
	}
	// A concurrent remote cell merges; both sides wrote version 1,
	// so the site-id tiebreak picks one winner deterministically.
	cells := exportCells(t, b)
	if len(cells) != 1 || cells[0].CID != "b" {
		t.Fatalf("exported = %+v", cells)
	}
	if err := IngestCells(a, cells); err != nil {
		t.Fatalf("ingest: %v", err)
	}
	got := cellText(t, a, "SELECT b FROM t WHERE a=1")
	if got != "local" && got != "remote" {
		t.Fatalf("merged = %q", got)
	}
	// Merging is convergent: B absorbs A's state and both agree.
	back := exportCells(t, a)
	if err := IngestCells(b, back); err != nil {
		t.Fatalf("ingest back: %v", err)
	}
	if gotB := cellText(t, b, "SELECT b FROM t WHERE a=1"); gotB != got {
		t.Fatalf("diverged: a=%q b=%q", got, gotB)
	}
	// Ingest does not re-capture: the vtab still shows one live cell.
	if n := countChanges(t, a); n != 1 {
		t.Fatalf("changes after ingest = %d, want 1", n)
	}
	// An older remote write loses to newer local state.
	if err := a.Exec("UPDATE t SET b='evolved' WHERE a=1;"); err != nil {
		t.Fatal(err)
	}
	stale := back[0]
	stale.Val = TextVal([]byte("stale"))
	if err := IngestCells(a, []Cell{stale}); err != nil {
		t.Fatalf("ingest stale: %v", err)
	}
	if now := cellText(t, a, "SELECT b FROM t WHERE a=1"); now != "evolved" {
		t.Fatalf("after stale = %q, want evolved", now)
	}
	// A newer remote write wins.
	nv, _, _ := clockRow(t, a, "t", 1, "b")
	win := back[0]
	win.ColVersion = nv + 1
	win.DBVersion += 100
	win.Val = TextVal([]byte("newer"))
	if err := IngestCells(a, []Cell{win}); err != nil {
		t.Fatalf("ingest newer: %v", err)
	}
	if now := cellText(t, a, "SELECT b FROM t WHERE a=1"); now != "newer" {
		t.Fatalf("after newer = %q, want newer", now)
	}
}

func TestIngestTombstones(t *testing.T) {
	a, b := mergePair(t)
	if err := a.Exec("INSERT INTO t VALUES(1,'x');"); err != nil {
		t.Fatal(err)
	}
	if err := b.Exec("INSERT INTO t VALUES(1,'x');"); err != nil {
		t.Fatal(err)
	}
	if err := b.Exec("DELETE FROM t WHERE a=1;"); err != nil {
		t.Fatal(err)
	}
	cells := exportCells(t, b)
	if len(cells) != 1 || cells[0].CID != "-1" {
		t.Fatalf("exported = %+v", cells)
	}
	// The tombstone's version (2: backfill... no, insert+delete)
	// beats A's live version 1: the row drops.
	if err := IngestCells(a, cells); err != nil {
		t.Fatal(err)
	}
	st, _ := a.Prepare("SELECT COUNT(*) FROM t")
	st.Step()
	if n := st.ColumnInt64(0); n != 0 {
		t.Fatalf("rows after tombstone = %d", n)
	}
	st.Close()
	// An older live write stays buried.
	old := cells[0]
	old.CID = "b"
	old.Val = TextVal([]byte("old"))
	old.ColVersion = 1
	if err := IngestCells(a, []Cell{old}); err != nil {
		t.Fatal(err)
	}
	st, _ = a.Prepare("SELECT COUNT(*) FROM t")
	st.Step()
	if n := st.ColumnInt64(0); n != 0 {
		t.Fatalf("resurrected by older write")
	}
	st.Close()
	// A newer live write resurrects (a genuinely newer write
	// carries a newer db_version/clock, not just a newer
	// col_version).
	nw := old
	nw.ColVersion = 3
	nw.DBVersion = cells[0].DBVersion + 1
	nw.CL = cells[0].CL + 1
	nw.Val = TextVal([]byte("new"))
	if err := IngestCells(a, []Cell{nw}); err != nil {
		t.Fatal(err)
	}
	if got := cellText(t, a, "SELECT b FROM t WHERE a=1"); got != "new" {
		t.Fatalf("resurrect = %q", got)
	}
	// Unknown table/column fail the ingest.
	bad := nw
	bad.Table = "nope"
	if err := IngestCells(a, []Cell{bad}); err == nil {
		t.Fatal("unknown table accepted")
	}
	bad = nw
	bad.CID = "nope"
	if err := IngestCells(a, []Cell{bad}); err == nil {
		t.Fatal("unknown column accepted")
	}
}

func TestGCTombstones(t *testing.T) {
	db := openCRR(t)
	if err := db.Exec("CREATE TABLE t(a INTEGER PRIMARY KEY NOT NULL, b TEXT);"); err != nil {
		t.Fatal(err)
	}
	if err := MakeCRR(db, "t"); err != nil {
		t.Fatal(err)
	}
	if err := db.Exec("INSERT INTO t VALUES(1,'x'); DELETE FROM t;"); err != nil {
		t.Fatal(err)
	}
	_, dv, ok := clockRow(t, db, "t", 1, "-1")
	if !ok {
		t.Fatal("no tombstone clock")
	}
	v := uint64(dv)
	if n, err := GCTombstones(db, v-1); err != nil || n != 0 {
		t.Fatalf("gc below floor = %d,%v", n, err)
	}
	if n, err := GCTombstones(db, v); err != nil || n != 1 {
		t.Fatalf("gc at floor = %d,%v", n, err)
	}
	if _, _, ok := clockRow(t, db, "t", 1, "-1"); ok {
		t.Fatal("tombstone survived gc")
	}
	mark, err := GCWatermark(db)
	if err != nil || mark != v {
		t.Fatalf("watermark = %d,%v", mark, err)
	}
}

func TestReapOrphans(t *testing.T) {
	db := openCRR(t)
	if err := db.Exec("CREATE TABLE t(a INTEGER PRIMARY KEY NOT NULL, b TEXT);"); err != nil {
		t.Fatal(err)
	}
	if err := MakeCRR(db, "t"); err != nil {
		t.Fatal(err)
	}
	if n, err := ReapOrphanClocks(db); err != nil || n != 0 {
		t.Fatalf("reap live = %d,%v", n, err)
	}
	if err := db.Exec("DROP TABLE t;"); err != nil {
		t.Fatal(err)
	}
	// Clock plus pks side tables drop together.
	if n, err := ReapOrphanClocks(db); err != nil || n != 2 {
		t.Fatalf("reap orphan = %d,%v", n, err)
	}
	if yes, _ := IsCRR(db, "t"); yes {
		t.Fatal("clock survived")
	}
}
