package murmurdb

import (
	"database/sql"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

// Test-only key, never a real secret.
const testKeyHex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func openTest(t *testing.T, query string) *sql.DB {
	t.Helper()
	dsn := t.TempDir() + "/store" + query
	db, err := Open(dsn)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if err := db.Ping(); err != nil {
		t.Fatalf("Ping: %v", err)
	}
	return db
}

func TestRoundtripTypes(t *testing.T) {
	db := openTest(t, "?key="+testKeyHex)
	if _, err := db.Exec(`CREATE TABLE t(
		id INTEGER PRIMARY KEY, b INTEGER, f REAL, s TEXT, bl BLOB, n TEXT, ts TEXT)`); err != nil {
		t.Fatalf("create: %v", err)
	}
	when := time.Date(2026, 10, 31, 12, 34, 56, 123456789, time.UTC)
	res, err := db.Exec(`INSERT INTO t(id,b,f,s,bl,n,ts) VALUES(?,?,?,?,?,?,?)`,
		1, true, 1.5, "hi", []byte{0xde, 0xad}, nil, when)
	if err != nil {
		t.Fatalf("insert: %v", err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		t.Fatalf("rows affected = %d, want 1", n)
	}
	if id, _ := res.LastInsertId(); id != 1 {
		t.Fatalf("last insert id = %d, want 1", id)
	}
	rows, err := db.Query(`SELECT id,b,f,s,bl,n,ts FROM t`)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	defer rows.Close()
	cols, err := rows.Columns()
	if err != nil {
		t.Fatalf("columns: %v", err)
	}
	want := []string{"id", "b", "f", "s", "bl", "n", "ts"}
	if strings.Join(cols, ",") != strings.Join(want, ",") {
		t.Fatalf("columns = %v, want %v", cols, want)
	}
	if !rows.Next() {
		t.Fatal("no rows")
	}
	var id int64
	var b bool
	var f float64
	var s string
	var bl []byte
	var n *string
	var ts string
	if err := rows.Scan(&id, &b, &f, &s, &bl, &n, &ts); err != nil {
		t.Fatalf("scan: %v", err)
	}
	if id != 1 || !b || f != 1.5 || s != "hi" || string(bl) != "\xde\xad" {
		t.Fatalf("row mismatch: %d %v %v %q %x", id, b, f, s, bl)
	}
	if n != nil {
		t.Fatalf("NULL scanned as %q", *n)
	}
	if ts != when.Format(time.RFC3339Nano) {
		t.Fatalf("time = %q", ts)
	}
	if rows.Next() {
		t.Fatal("extra row")
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows err: %v", err)
	}
}

func TestNullVsEmpty(t *testing.T) {
	db := openTest(t, "?key="+testKeyHex)
	if _, err := db.Exec(`CREATE TABLE t(s TEXT, b BLOB)`); err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO t(s,b) VALUES(?,?)`, "", []byte{}); err != nil {
		t.Fatalf("insert empty: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO t(s,b) VALUES(?,?)`, nil, nil); err != nil {
		t.Fatalf("insert null: %v", err)
	}
	var emptyText, nullText sql.NullString
	var emptyBlob, nullBlob []byte
	row := db.QueryRow(`SELECT s, b FROM t WHERE s IS NOT NULL ORDER BY rowid LIMIT 1`)
	if err := row.Scan(&emptyText, &emptyBlob); err != nil {
		t.Fatalf("scan empty: %v", err)
	}
	if !emptyText.Valid || emptyText.String != "" {
		t.Fatalf("empty text = %+v", emptyText)
	}
	if emptyBlob == nil {
		t.Fatal("empty blob read back NULL")
	}
	row = db.QueryRow(`SELECT s, b FROM t WHERE s IS NULL`)
	if err := row.Scan(&nullText, &nullBlob); err != nil {
		t.Fatalf("scan null: %v", err)
	}
	if nullText.Valid || nullBlob != nil {
		t.Fatalf("nulls = %+v %x", nullText, nullBlob)
	}
}

func TestTxCommitRollback(t *testing.T) {
	db := openTest(t, "?key="+testKeyHex)
	if _, err := db.Exec(`CREATE TABLE t(id INTEGER PRIMARY KEY)`); err != nil {
		t.Fatalf("create: %v", err)
	}
	tx, err := db.Begin()
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if _, err := tx.Exec(`INSERT INTO t(id) VALUES(1)`); err != nil {
		t.Fatalf("tx insert: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}
	tx, err = db.Begin()
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if _, err := tx.Exec(`INSERT INTO t(id) VALUES(2)`); err != nil {
		t.Fatalf("tx insert: %v", err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM t`).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 1 {
		t.Fatalf("count = %d, want 1", n)
	}
}

func TestPrepareReuse(t *testing.T) {
	db := openTest(t, "?key="+testKeyHex)
	if _, err := db.Exec(`CREATE TABLE t(id INTEGER PRIMARY KEY, s TEXT)`); err != nil {
		t.Fatalf("create: %v", err)
	}
	ins, err := db.Prepare(`INSERT INTO t(id,s) VALUES(?,?)`)
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	defer ins.Close()
	for i := 1; i <= 5; i++ {
		if _, err := ins.Exec(i, "x"); err != nil {
			t.Fatalf("exec %d: %v", i, err)
		}
	}
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM t`).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 5 {
		t.Fatalf("count = %d, want 5", n)
	}
}

func TestMultiStatement(t *testing.T) {
	db := openTest(t, "?key="+testKeyHex)
	_, err := db.Exec(`CREATE TABLE a(id INTEGER); CREATE TABLE b(id INTEGER); INSERT INTO a(id) VALUES(7)`)
	if err != nil {
		t.Fatalf("script exec: %v", err)
	}
	var n int
	if err := db.QueryRow(`SELECT id FROM a`).Scan(&n); err != nil || n != 7 {
		t.Fatalf("a = %d, err %v", n, err)
	}
	if _, err := db.Exec(`INSERT INTO a(id) VALUES(?); INSERT INTO b(id) VALUES(?)`, 1, 2); err == nil {
		t.Fatal("parameterized multi-statement exec succeeded, want error")
	}
}

func TestBadDSN(t *testing.T) {
	for _, dsn := range []string{
		"",
		"?key=zz",
		"/tmp/x?key=abcd",
		"/tmp/x?mode=bogus",
		"/tmp/x?crsqlite=bogus",
		"/tmp/x?cache_pages=-1",
	} {
		if _, err := Open(dsn); err == nil {
			t.Fatalf("Open(%q) succeeded, want error", dsn)
		}
	}
}

func TestWrongKey(t *testing.T) {
	dir := t.TempDir() + "/store"
	db, err := Open(dir + "?key=" + testKeyHex)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if _, err := db.Exec(`CREATE TABLE t(id INTEGER)`); err != nil {
		t.Fatalf("create: %v", err)
	}
	db.Close()
	other := "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	db2, err := Open(dir + "?key=" + other)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer db2.Close()
	if err := db2.Ping(); !errors.Is(err, ErrWrongKey) {
		t.Fatalf("Ping with wrong key = %v, want ErrWrongKey", err)
	}
}

func TestSQLRegisterName(t *testing.T) {
	db, err := sql.Open(DriverName, t.TempDir()+"/store?key="+testKeyHex)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	if err := db.Ping(); err != nil {
		t.Fatalf("Ping: %v", err)
	}
}

func TestInterleavedRowsExec(t *testing.T) {
	db := openTest(t, "?key="+testKeyHex)
	if _, err := db.Exec(`CREATE TABLE t(id INTEGER PRIMARY KEY, s TEXT)`); err != nil {
		t.Fatalf("create: %v", err)
	}
	for i := 0; i < 10; i++ {
		if _, err := db.Exec(`INSERT INTO t(id,s) VALUES(?,?)`, i, "v"); err != nil {
			t.Fatalf("insert: %v", err)
		}
	}
	// Hold rows open on the cached select while running the same
	// query again inside one transaction (one driver connection):
	// the second checkout must not steal the live statement.
	tx, err := db.Begin()
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback()
	rows1, err := tx.Query(`SELECT id FROM t ORDER BY id`)
	if err != nil {
		t.Fatalf("query1: %v", err)
	}
	defer rows1.Close()
	if !rows1.Next() {
		t.Fatal("rows1 empty")
	}
	var first int
	if err := rows1.Scan(&first); err != nil || first != 0 {
		t.Fatalf("rows1 first = %d, %v", first, err)
	}
	rows2, err := tx.Query(`SELECT id FROM t ORDER BY id`)
	if err != nil {
		t.Fatalf("query2: %v", err)
	}
	defer rows2.Close()
	n := 0
	for rows2.Next() {
		n++
	}
	if n != 10 {
		t.Fatalf("rows2 count = %d, want 10", n)
	}
	// rows1 must still stream the remainder undisturbed.
	rest := 0
	for rows1.Next() {
		rest++
	}
	if rest != 9 {
		t.Fatalf("rows1 rest = %d, want 9", rest)
	}
}

func TestPartialRowsClose(t *testing.T) {
	db := openTest(t, "?key="+testKeyHex)
	if _, err := db.Exec(`CREATE TABLE t(id INTEGER PRIMARY KEY)`); err != nil {
		t.Fatalf("create: %v", err)
	}
	for i := 0; i < 5; i++ {
		if _, err := db.Exec(`INSERT INTO t(id) VALUES(?)`, i); err != nil {
			t.Fatalf("insert: %v", err)
		}
	}
	// Partially consume, then abandon: the cached statement must
	// reset cleanly for the next identical query.
	for round := 0; round < 3; round++ {
		rows, err := db.Query(`SELECT id FROM t ORDER BY id`)
		if err != nil {
			t.Fatalf("query: %v", err)
		}
		if !rows.Next() {
			t.Fatal("empty")
		}
		rows.Close()
	}
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM t`).Scan(&n); err != nil || n != 5 {
		t.Fatalf("count = %d, %v", n, err)
	}
}

func TestTxWithReads(t *testing.T) {
	db := openTest(t, "?key="+testKeyHex)
	if _, err := db.Exec(`CREATE TABLE t(id INTEGER PRIMARY KEY, s TEXT)`); err != nil {
		t.Fatalf("create: %v", err)
	}
	tx, err := db.Begin()
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if _, err := tx.Exec(`INSERT INTO t(id,s) VALUES(1,'a')`); err != nil {
		t.Fatalf("insert: %v", err)
	}
	var s string
	if err := tx.QueryRow(`SELECT s FROM t WHERE id=1`).Scan(&s); err != nil || s != "a" {
		t.Fatalf("tx read = %q, %v", s, err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM t`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("count = %d, %v", n, err)
	}
}

func TestWideValues(t *testing.T) {
	db := openTest(t, "?key="+testKeyHex)
	if _, err := db.Exec(`CREATE TABLE t(id INTEGER PRIMARY KEY, s TEXT, b BLOB)`); err != nil {
		t.Fatalf("create: %v", err)
	}
	big := make([]byte, 1<<20)
	for i := range big {
		big[i] = byte(i)
	}
	uni := "héllo wörld "
	if _, err := db.Exec(`INSERT INTO t(id,s,b) VALUES(?,?,?)`, 1, uni, big); err != nil {
		t.Fatalf("insert: %v", err)
	}
	var s string
	var b []byte
	if err := db.QueryRow(`SELECT s,b FROM t WHERE id=1`).Scan(&s, &b); err != nil {
		t.Fatalf("scan: %v", err)
	}
	if s != uni || len(b) != len(big) || b[1000] != big[1000] {
		t.Fatal("wide value mismatch")
	}
}

func TestConcurrentUse(t *testing.T) {
	db := openTest(t, "?key="+testKeyHex)
	if _, err := db.Exec(`CREATE TABLE t(id INTEGER PRIMARY KEY)`); err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO t(id) VALUES(1)`); err != nil {
		t.Fatalf("insert: %v", err)
	}
	var wg sync.WaitGroup
	errs := make(chan error, 16)
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var n int
			if err := db.QueryRow(`SELECT COUNT(*) FROM t`).Scan(&n); err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent query: %v", err)
	}
}
