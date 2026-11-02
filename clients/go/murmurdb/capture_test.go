package murmurdb

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/marcgauthier/libmurmur/clients/go/bindings/bridge"
	"github.com/marcgauthier/libmurmur/clients/go/bindings/sqlite"
)

func capturedDB(t *testing.T) *sql.DB {
	t.Helper()
	db := openTest(t, "?key="+testKeyHex)
	if _, err := db.Exec("CREATE TABLE docs(id TEXT PRIMARY KEY NOT NULL,label TEXT)"); err != nil {
		t.Fatal(err)
	}
	var secret [32]byte
	secret[16] = 2
	recipient, err := bridge.RecipientPublic(secret)
	if err != nil {
		t.Fatal(err)
	}
	err = WithConnection(context.Background(), db, func(c *sqlite.Conn) error {
		if _, err := bridge.RegisterTable(c, "docs"); err != nil {
			return err
		}
		return bridge.AttachCapture(c, bridge.CaptureConfig{Role: bridge.Low, Database: [16]byte{1}, Node: [16]byte{2}, Signer: [32]byte{1}, Recipient: recipient, Stream: "test"})
	})
	if err != nil {
		t.Fatal(err)
	}
	return db
}

func countRows(t *testing.T, db *sql.DB, table string) int {
	t.Helper()
	var n int
	if err := db.QueryRow("SELECT count(*) FROM " + table).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestSQLCaptureExecPreparedAndReturning(t *testing.T) {
	db := capturedDB(t)
	if _, err := db.Exec("INSERT INTO docs VALUES(?,?)", "one", "first"); err != nil {
		t.Fatal(err)
	}
	stmt, err := db.Prepare("UPDATE docs SET label=? WHERE id=?")
	if err != nil {
		t.Fatal(err)
	}
	defer stmt.Close()
	if _, err := stmt.Exec("updated", "one"); err != nil {
		t.Fatal(err)
	}
	rows, err := db.Query("INSERT INTO docs VALUES('two','second'),('three','third') RETURNING id")
	if err != nil {
		t.Fatal(err)
	}
	// Closing RETURNING early must retain one complete captured transaction.
	if err := rows.Close(); err != nil {
		t.Fatal(err)
	}
	if n := countRows(t, db, "docs"); n != 3 {
		t.Fatalf("docs=%d", n)
	}
	if n := countRows(t, db, "murmur_bridge_artifact"); n != 3 {
		t.Fatalf("captured transactions=%d", n)
	}
	var secret, seed, pub [32]byte
	secret[16] = 2
	seed[0] = 1
	copy(pub[:], ed25519.NewKeyFromSeed(seed[:])[32:])
	err = WithConnection(context.Background(), db, func(c *sqlite.Conn) error {
		seq, b, err := bridge.Next(c, [16]byte{1}, "test")
		if err != nil {
			return err
		}
		h, payload, err := bridge.Unseal(b, [16]byte{1}, "test", pub, secret)
		if err != nil {
			return err
		}
		if seq != 1 || h.Sequence != 1 || !strings.HasPrefix(string(payload), "MBT1") {
			return fmt.Errorf("invalid first captured bundle")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestSQLCaptureTransactionCrossGoroutineAndRollback(t *testing.T) {
	db := capturedDB(t)
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	done := make(chan error, 1)
	go func() { _, err := tx.Exec("INSERT INTO docs VALUES('one','first')"); done <- err }()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec("INSERT INTO docs VALUES('two','second')"); err != nil {
		t.Fatal(err)
	}
	var pending int
	if err := tx.QueryRow("SELECT count(*) FROM murmur_bridge_artifact").Scan(&pending); err != nil || pending != 0 {
		t.Fatalf("premature capture=%d err=%v", pending, err)
	}
	attempting, acquired := make(chan struct{}), make(chan struct{})
	go func() { close(attempting); sqlite.LockWriter(); sqlite.UnlockWriter(); close(acquired) }()
	<-attempting
	select {
	case <-acquired:
		t.Fatal("native writer entered an open SQL transaction")
	case <-time.After(15 * time.Millisecond):
	}
	go func() { done <- tx.Commit() }()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	select {
	case <-acquired:
	case <-time.After(time.Second):
		t.Fatal("native writer guard leaked after commit")
	}
	if n := countRows(t, db, "murmur_bridge_artifact"); n != 1 {
		t.Fatalf("expected one atomic bundle, got %d", n)
	}
	tx, err = db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec("INSERT INTO docs VALUES('rollback','rollback')"); err != nil {
		t.Fatal(err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if n := countRows(t, db, "docs"); n != 2 {
		t.Fatalf("rollback retained data: %d", n)
	}
	if n := countRows(t, db, "murmur_bridge_artifact"); n != 1 {
		t.Fatalf("rollback retained capture: %d", n)
	}
}

func TestSQLCaptureRejectsTransactionControlWithoutPartialScript(t *testing.T) {
	db := capturedDB(t)
	for _, control := range []string{"COMMIT", "END", "ROLLBACK", "SAVEPOINT hidden", "RELEASE hidden", "\ufeff /* prefix */ BEGIN"} {
		_, err := db.Exec("INSERT INTO docs VALUES('unsafe','unsafe'); " + control)
		if !errors.Is(err, errSQLTransactionControl) {
			t.Fatalf("%q: %v", control, err)
		}
		if n := countRows(t, db, "docs"); n != 0 {
			t.Fatalf("%q committed %d rows", control, n)
		}
	}
	if _, err := db.Exec("CREATE TABLE audit(value TEXT); CREATE TRIGGER audit_doc AFTER INSERT ON docs BEGIN INSERT INTO audit VALUES(NEW.id); END; INSERT INTO docs VALUES('safe','safe')"); err != nil {
		t.Fatal(err)
	}
	if n := countRows(t, db, "audit"); n != 1 {
		t.Fatalf("trigger body was not executed: %d", n)
	}
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec("INSERT INTO docs VALUES('kept','kept')"); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec("INSERT INTO docs VALUES('partial','partial'); INSERT INTO docs VALUES('kept','duplicate')"); err == nil {
		t.Fatal("duplicate accepted")
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if n := countRows(t, db, "docs"); n != 2 {
		t.Fatalf("failed script retained partial work: %d", n)
	}
}

func TestSQLCaptureCancellationLeavesConnectionUsable(t *testing.T) {
	db := capturedDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
	defer cancel()
	_, err := db.ExecContext(ctx, "WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<100000000) INSERT INTO docs SELECT 'c'||x,'c'||x FROM n")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("cancellation: %v", err)
	}
	if n := countRows(t, db, "docs"); n != 0 {
		t.Fatalf("canceled write retained rows: %d", n)
	}
	if n := countRows(t, db, "murmur_bridge_artifact"); n != 0 {
		t.Fatalf("canceled write retained capture: %d", n)
	}
	if _, err := db.Exec("INSERT INTO docs VALUES('after','usable')"); err != nil {
		t.Fatal(err)
	}
}

func TestNativeControlCanJoinWriterAndCallbackPanicRecovers(t *testing.T) {
	db := capturedDB(t)
	err := WithNativeControl(context.Background(), db, func(*sqlite.Conn) error {
		done := make(chan struct{})
		go func() { sqlite.LockWriter(); sqlite.UnlockWriter(); close(done) }()
		select {
		case <-done:
			return nil
		case <-time.After(time.Second):
			return errors.New("control operation held writer admission")
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	func() {
		defer func() {
			if recover() == nil {
				t.Error("missing callback panic")
			}
		}()
		_ = WithConnection(context.Background(), db, func(*sqlite.Conn) error { panic("callback") })
	}()
	if _, err := db.Exec("INSERT INTO docs VALUES('after','panic')"); err != nil {
		t.Fatal(err)
	}
}
