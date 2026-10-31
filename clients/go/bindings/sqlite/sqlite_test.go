package sqlite

import (
	"errors"
	"path/filepath"
	"testing"
)

func TestMemoryRoundTrip(t *testing.T) {
	db, err := Open(":memory:", OpenReadWrite|OpenCreate)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()
	if err := db.Exec(`CREATE TABLE kv(k TEXT PRIMARY KEY, v BLOB);
		INSERT INTO kv(k,v) VALUES('a', x'0102'), ('b', NULL);`); err != nil {
		t.Fatalf("exec: %v", err)
	}
	if got := db.Changes(); got != 2 {
		t.Fatalf("changes=%d, want 2", got)
	}
	stmt, err := db.Prepare(`SELECT k, v, typeof(v) FROM kv ORDER BY k`)
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	defer stmt.Close()
	if got := stmt.ColumnCount(); got != 3 {
		t.Fatalf("columns=%d, want 3", got)
	}
	var rows [][2]string
	for {
		done, err := stmt.Step()
		if err != nil {
			t.Fatalf("step: %v", err)
		}
		if done {
			break
		}
		rows = append(rows, [2]string{stmt.ColumnText(0), stmt.ColumnText(2)})
	}
	if len(rows) != 2 || rows[0][0] != "a" || rows[0][1] != "blob" || rows[1][1] != "null" {
		t.Fatalf("rows=%v", rows)
	}
}

func TestBindAndFileBacked(t *testing.T) {
	path := filepath.Join(t.TempDir(), "smoke.db")
	db, err := Open(path, OpenReadWrite|OpenCreate)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := db.Exec(`CREATE TABLE t(id INTEGER PRIMARY KEY, name TEXT, score REAL, data BLOB)`); err != nil {
		t.Fatalf("exec: %v", err)
	}
	ins, err := db.Prepare(`INSERT INTO t(name, score, data) VALUES(?, ?, ?)`)
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if err := ins.BindText(1, "seven"); err != nil {
		t.Fatalf("bind text: %v", err)
	}
	if err := ins.BindFloat(2, 7.5); err != nil {
		t.Fatalf("bind float: %v", err)
	}
	if err := ins.BindBlob(3, []byte{0xde, 0xad}); err != nil {
		t.Fatalf("bind blob: %v", err)
	}
	if done, err := ins.Step(); err != nil || !done {
		t.Fatalf("insert step: done=%v err=%v", done, err)
	}
	ins.Close()
	q, err := db.Prepare(`SELECT name, score, data FROM t`)
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if done, err := q.Step(); err != nil || done {
		t.Fatalf("select step: done=%v err=%v", done, err)
	}
	if q.ColumnText(0) != "seven" || q.ColumnFloat(1) != 7.5 {
		t.Fatalf("bad row: %q %v", q.ColumnText(0), q.ColumnFloat(1))
	}
	if got := q.ColumnBlob(2); len(got) != 2 || got[0] != 0xde || got[1] != 0xad {
		t.Fatalf("bad blob: %x", got)
	}
	if q.ColumnType(2) != TypeBlob || q.ColumnType(0) != TypeText {
		t.Fatalf("bad types")
	}
	if err := q.Close(); err != nil {
		t.Fatalf("stmt close: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	// Reopen: file-backed data survives.
	db2, err := Open(path, OpenReadWrite)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer db2.Close()
	chk, err := db2.Prepare(`SELECT COUNT(*) FROM t`)
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	defer chk.Close()
	if done, err := chk.Step(); err != nil || done {
		t.Fatalf("count step: done=%v err=%v", done, err)
	}
	if got := chk.ColumnInt64(0); got != 1 {
		t.Fatalf("count=%d, want 1", got)
	}
}

func TestBadSQLErrors(t *testing.T) {
	db, err := Open(":memory:", OpenReadWrite|OpenCreate)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()
	if err := db.Exec(`CREATE TABLE`); err == nil {
		t.Fatal("expected syntax error")
	} else {
		var serr *Error
		if !errors.As(err, &serr) || serr.Code == 0 {
			t.Fatalf("expected *Error with code, got %#v", err)
		}
	}
	if _, err := db.Prepare(`SELECT * FROM missing`); err == nil {
		t.Fatal("expected prepare error")
	}
}
