package sqlite

import (
	"errors"
	"path/filepath"
	"testing"
)

func TestScalarFunction(t *testing.T) {
	db, err := Open(":memory:", OpenReadWrite|OpenCreate)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()
	if err := db.Exec(`CREATE TABLE t(a INTEGER, b TEXT)`); err != nil {
		t.Fatalf("exec: %v", err)
	}
	err = db.CreateFunction("murmur_add42", 1, true, func(x *Context, args []Value) {
		if len(args) != 1 || args[0].Type() != TypeInteger {
			x.ResultError(errors.New("want 1 integer"))
			return
		}
		x.ResultInt64(args[0].Int64() + 42)
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	err = db.CreateFunction("murmur_greet", 1, false, func(x *Context, args []Value) {
		x.ResultText("hello " + args[0].Text())
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	stmt, err := db.Prepare(`SELECT murmur_add42(8), murmur_greet('bob')`)
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	defer stmt.Close()
	if done, err := stmt.Step(); err != nil || done {
		t.Fatalf("step: done=%v err=%v", done, err)
	}
	if stmt.ColumnInt64(0) != 50 || stmt.ColumnText(1) != "hello bob" {
		t.Fatalf("bad row: %d %q", stmt.ColumnInt64(0), stmt.ColumnText(1))
	}
	stmt2, err := db.Prepare(`SELECT murmur_add42('x')`)
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	defer stmt2.Close()
	if _, err := stmt2.Step(); err == nil {
		t.Fatal("function error must fail the statement")
	}
}

func TestAuthorizer(t *testing.T) {
	db, err := Open(":memory:", OpenReadWrite|OpenCreate)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()
	if err := db.Exec(`CREATE TABLE t(a)`); err != nil {
		t.Fatalf("exec: %v", err)
	}
	if err := db.SetAuthorizer(func(action int, p1, p2, db, src string) int {
		if action == AuthInsert {
			return AuthDeny
		}
		return AuthOK
	}); err != nil {
		t.Fatalf("authorizer: %v", err)
	}
	if err := db.Exec(`INSERT INTO t(a) VALUES(1)`); err == nil {
		t.Fatal("denied insert must fail")
	}
	if err := db.Exec(`SELECT * FROM t`); err != nil {
		t.Fatalf("allowed select: %v", err)
	}
}

func TestBackupRoundTrip(t *testing.T) {
	dir := t.TempDir()
	src, err := Open(":memory:", OpenReadWrite|OpenCreate)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer src.Close()
	if err := src.Exec(`CREATE TABLE t(a PRIMARY KEY, b TEXT);
		INSERT INTO t(a,b) VALUES(1,'one'),(2,'two');`); err != nil {
		t.Fatalf("exec: %v", err)
	}
	dstPath := filepath.Join(dir, "copy.db")
	dst, err := Open(dstPath, OpenReadWrite|OpenCreate)
	if err != nil {
		t.Fatalf("open dst: %v", err)
	}
	if err := dst.BackupTo(src, "main", "main"); err != nil {
		t.Fatalf("backup: %v", err)
	}
	dst.Close()
	chk, err := Open(dstPath, OpenReadOnly)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer chk.Close()
	stmt, err := chk.Prepare(`SELECT COUNT(*), SUM(a) FROM t`)
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	defer stmt.Close()
	if done, err := stmt.Step(); err != nil || done {
		t.Fatalf("step: done=%v err=%v", done, err)
	}
	if stmt.ColumnInt64(0) != 2 || stmt.ColumnInt64(1) != 3 {
		t.Fatalf("bad copy: %d %d", stmt.ColumnInt64(0), stmt.ColumnInt64(1))
	}
}
