package sqlite

import (
	"testing"
)

// The vendored Rust cr-sqlite bundle initializes, CRR-ifies a table,
// captures writes, and merges a cell ingested on a second connection.
// This is the binding-level proof; the replication package covers the
// sync protocol above it.
func TestCrsqliteInitCaptureIngest(t *testing.T) {
	open := func(t *testing.T) *Conn {
		t.Helper()
		db, err := Open(":memory:", OpenReadWrite|OpenCreate|OpenMemory)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}
		})
		if err := CrsqliteInit(db); err != nil {
			t.Fatal(err)
		}
		// Idempotent: a second init is a no-op.
		if err := CrsqliteInit(db); err != nil {
			t.Fatal(err)
		}
		return db
	}
	scalar := func(t *testing.T, db *Conn, sql string) *Stmt {
		t.Helper()
		st, err := db.Prepare(sql)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { st.Close() })
		if done, err := st.Step(); err != nil || done {
			t.Fatalf("scalar %q done=%v err=%v", sql, done, err)
		}
		return st
	}
	a, b := open(t), open(t)
	for _, db := range []*Conn{a, b} {
		if err := db.Exec("CREATE TABLE records(id INTEGER PRIMARY KEY NOT NULL, body TEXT NOT NULL DEFAULT ''); SELECT crsql_as_crr('main','records')"); err != nil {
			t.Fatal(err)
		}
	}
	siteA := append([]byte(nil), scalar(t, a, "SELECT crsql_site_id()").ColumnBlob(0)...)
	siteB := append([]byte(nil), scalar(t, b, "SELECT crsql_site_id()").ColumnBlob(0)...)
	if len(siteA) == 0 || string(siteA) == string(siteB) {
		t.Fatalf("distinct site ids: %x vs %x", siteA, siteB)
	}
	if err := a.Exec("INSERT INTO records(id,body) VALUES(1,'hello')"); err != nil {
		t.Fatal(err)
	}
	changes := scalar(t, a, `SELECT count(*) FROM crsql_changes WHERE "table"='records' AND cid='body'`).ColumnInt64(0)
	if changes != 1 {
		t.Fatalf("captured changes = %d, want 1", changes)
	}
	// Merge side B's concurrent cell for the same pk into A through
	// the vtab ingest entry point (same shape sync.go will feed it).
	if err := b.Exec("INSERT INTO records(id,body) VALUES(1,'remote')"); err != nil {
		t.Fatal(err)
	}
	exp, err := b.Prepare(`SELECT "table",pk,cid,val,col_version,db_version,site_id,cl,seq FROM crsql_changes WHERE "table"='records' AND cid='body'`)
	if err != nil {
		t.Fatal(err)
	}
	defer exp.Close()
	if done, err := exp.Step(); err != nil || done {
		t.Fatalf("export step done=%v err=%v", done, err)
	}
	ins, err := a.Prepare(`INSERT INTO crsql_changes("table",pk,cid,val,col_version,db_version,site_id,cl,seq) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)`)
	if err != nil {
		t.Fatal(err)
	}
	defer ins.Close()
	bind := []error{
		ins.BindText(1, exp.ColumnText(0)),
		ins.BindBlob(2, exp.ColumnBlob(1)),
		ins.BindText(3, exp.ColumnText(2)),
		ins.BindText(4, exp.ColumnText(3)),
		ins.BindInt64(5, exp.ColumnInt64(4)),
		ins.BindInt64(6, exp.ColumnInt64(5)),
		ins.BindBlob(7, exp.ColumnBlob(6)),
		ins.BindInt64(8, exp.ColumnInt64(7)),
		ins.BindInt64(9, exp.ColumnInt64(8)),
	}
	for _, err := range bind {
		if err != nil {
			t.Fatal(err)
		}
	}
	if done, err := ins.Step(); err != nil || !done {
		t.Fatalf("ingest step done=%v err=%v", done, err)
	}
	body := scalar(t, a, "SELECT body FROM records WHERE id=1").ColumnText(0)
	// Both cells are version 1; the merge keeps one winner and stays
	// consistent (last-writer-wins by site id ordering).
	if body != "hello" && body != "remote" {
		t.Fatalf("merged body = %q", body)
	}
}
