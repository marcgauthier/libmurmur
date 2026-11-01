package murmurdb

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"runtime"
	"strings"
	"testing"
	"time"
)

const longQuery = `WITH RECURSIVE r(n) AS (VALUES(1) UNION ALL SELECT n+1 FROM r WHERE n<20000000) SELECT sum(n) FROM r`

func assertUsable(t *testing.T, db *sql.DB) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	var value int
	if err := db.QueryRowContext(ctx, "SELECT 42").Scan(&value); err != nil || value != 42 {
		t.Fatalf("connection unusable after cancellation/error: value=%d err=%v", value, err)
	}
}

func TestCanceledContextsDoNotWrite(t *testing.T) {
	db := openTest(t, "?key="+testKeyHex)
	if _, err := db.Exec("CREATE TABLE t(id INTEGER PRIMARY KEY)"); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := db.ExecContext(ctx, "INSERT INTO t VALUES(1)"); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled Exec: %v", err)
	}
	if _, err := db.QueryContext(ctx, "SELECT 1"); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled Query: %v", err)
	}
	if _, err := db.BeginTx(ctx, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled BeginTx: %v", err)
	}
	var count int
	if err := db.QueryRow("SELECT count(*) FROM t").Scan(&count); err != nil || count != 0 {
		t.Fatalf("canceled statement wrote: count=%d err=%v", count, err)
	}
	assertUsable(t, db)
}

func TestRunningStatementsHonorContext(t *testing.T) {
	for _, mode := range []string{"query", "prepared-query", "exec", "prepared-exec"} {
		t.Run(mode, func(t *testing.T) {
			db := openTest(t, "?key="+testKeyHex)
			if _, err := db.Exec("CREATE TABLE results(n INTEGER)"); err != nil {
				t.Fatal(err)
			}
			query := longQuery
			if strings.Contains(mode, "exec") {
				query = "INSERT INTO results " + longQuery
			}
			var statement *sql.Stmt
			if strings.HasPrefix(mode, "prepared") {
				var err error
				statement, err = db.Prepare(query)
				if err != nil {
					t.Fatal(err)
				}
				defer statement.Close()
			}
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
			defer cancel()
			started := time.Now()
			var err error
			switch mode {
			case "query":
				var value int64
				err = db.QueryRowContext(ctx, query).Scan(&value)
			case "prepared-query":
				var value int64
				err = statement.QueryRowContext(ctx).Scan(&value)
			case "exec":
				_, err = db.ExecContext(ctx, query)
			case "prepared-exec":
				_, err = statement.ExecContext(ctx)
			}
			elapsed := time.Since(started)
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Errorf("running statement ignored cancellation: %v", err)
			}
			if elapsed > time.Second {
				t.Errorf("cancellation took %s; want <1s for a 20ms deadline", elapsed)
			}
			var count int
			if err := db.QueryRow("SELECT count(*) FROM results").Scan(&count); err != nil || count != 0 {
				t.Fatalf("interrupted DML partially committed: count=%d err=%v", count, err)
			}
			assertUsable(t, db)
		})
	}
}

func TestEarlyRowsCloseScanFailureAndReuse(t *testing.T) {
	db := openTest(t, "?key="+testKeyHex)
	if _, err := db.Exec("CREATE TABLE t(id INTEGER PRIMARY KEY,s TEXT); INSERT INTO t VALUES(1,'bad-number'),(2,'second')"); err != nil {
		t.Fatal(err)
	}
	statement, err := db.Prepare("SELECT s FROM t WHERE id>=? ORDER BY id")
	if err != nil {
		t.Fatal(err)
	}
	defer statement.Close()
	for i := 0; i < 30; i++ {
		rows, err := statement.Query(1)
		if err != nil || !rows.Next() {
			t.Fatalf("query: %v", err)
		}
		var invalid int
		if err := rows.Scan(&invalid); err == nil {
			t.Fatal("expected conversion error")
		}
		if err := rows.Close(); err != nil {
			t.Fatal(err)
		}
		if err := rows.Close(); err != nil {
			t.Fatalf("second close: %v", err)
		}
		var value string
		if err := statement.QueryRow(2).Scan(&value); err != nil || value != "second" {
			t.Fatalf("statement not reusable after early close: value=%q err=%v", value, err)
		}
	}
	assertUsable(t, db)
}

func TestLateCancellationDoesNotInterruptNextStatement(t *testing.T) {
	db := openTest(t, "?key="+testKeyHex)
	for i := 0; i < 100; i++ {
		ctx, cancel := context.WithCancel(context.Background())
		var value int
		if err := db.QueryRowContext(ctx, "SELECT 1").Scan(&value); err != nil || value != 1 {
			cancel()
			t.Fatalf("completed query: value=%d err=%v", value, err)
		}
		cancel()
		assertUsable(t, db)
		ctx, cancel = context.WithCancel(context.Background())
		rows, err := db.QueryContext(ctx, "SELECT 1 UNION ALL SELECT 2")
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		if !rows.Next() {
			cancel()
			t.Fatal("missing stream row")
		}
		if err := rows.Close(); err != nil {
			cancel()
			t.Fatal(err)
		}
		cancel()
		assertUsable(t, db)
	}
}

func TestBoundAndReturnedBytesHaveOwnedLifetimes(t *testing.T) {
	db := openTest(t, "?key="+testKeyHex)
	if _, err := db.Exec("CREATE TABLE t(id INTEGER PRIMARY KEY,s TEXT,b BLOB)"); err != nil {
		t.Fatal(err)
	}
	wantText := strings.Repeat("text\x00", 1000)
	wantBlob := bytes.Repeat([]byte{0, 255, 1, 128}, 2048)
	input := bytes.Clone(wantBlob)
	if _, err := db.Exec("INSERT INTO t VALUES(?,?,?)", 1, wantText, input); err != nil {
		t.Fatal(err)
	}
	clear(input)
	var savedText string
	var savedBlob []byte
	if err := db.QueryRow("SELECT s,b FROM t WHERE id=?", 1).Scan(&savedText, &savedBlob); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 40; i++ {
		if _, err := db.Exec("INSERT OR REPLACE INTO t VALUES(?,?,?)", 2, strings.Repeat("x", 12000), bytes.Repeat([]byte{byte(i)}, 12000)); err != nil {
			t.Fatal(err)
		}
		var scratchText string
		var scratchBlob []byte
		if err := db.QueryRow("SELECT s,b FROM t WHERE id=?", 2).Scan(&scratchText, &scratchBlob); err != nil {
			t.Fatal(err)
		}
		runtime.GC()
	}
	if savedText != wantText || !bytes.Equal(savedBlob, wantBlob) {
		t.Fatal("returned bytes/text changed after statement reuse or garbage collection")
	}
	clear(savedBlob)
	var stored []byte
	if err := db.QueryRow("SELECT b FROM t WHERE id=?", 1).Scan(&stored); err != nil || !bytes.Equal(stored, wantBlob) {
		t.Fatalf("mutating returned bytes changed stored data: %v", err)
	}
}

func TestStatementReuseAfterConstraintAndTransactionRollback(t *testing.T) {
	db := openTest(t, "?key="+testKeyHex)
	if _, err := db.Exec("CREATE TABLE t(id INTEGER PRIMARY KEY,s TEXT UNIQUE)"); err != nil {
		t.Fatal(err)
	}
	statement, err := db.Prepare("INSERT INTO t VALUES(?,?)")
	if err != nil {
		t.Fatal(err)
	}
	defer statement.Close()
	if _, err := statement.Exec(1, "first"); err != nil {
		t.Fatal(err)
	}
	if _, err := statement.Exec(2, "first"); err == nil {
		t.Fatal("expected unique constraint")
	}
	if _, err := statement.Exec(2, "second"); err != nil {
		t.Fatalf("statement reuse after constraint: %v", err)
	}
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec("INSERT INTO t VALUES(3,'third')"); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec("INSERT INTO t VALUES(4,'first')"); err == nil {
		t.Fatal("expected transaction statement constraint")
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := db.QueryRow("SELECT count(*) FROM t").Scan(&count); err != nil || count != 2 {
		t.Fatalf("rollback did not undo earlier transaction statement: count=%d err=%v", count, err)
	}
	assertUsable(t, db)
}
