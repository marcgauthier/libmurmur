package overwatch

import (
	"context"
	"database/sql"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Write scopes commit all statements together or roll them all back
// (OVERWATCH WriteOperation). Concurrent CRUD and session lifecycles
// stress the shared *sql.DB handle.

// writeOperation runs fn inside one transaction, committing on nil
// and rolling back otherwise.
func writeOperation(t *testing.T, db *sql.DB, fn func(tx *sql.Tx) error) error {
	t.Helper()
	tx, err := db.Begin()
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if err := fn(tx); err != nil {
		if rb := tx.Rollback(); rb != nil {
			t.Fatalf("rollback: %v", rb)
		}
		return err
	}
	return tx.Commit()
}

func TestWriteOperationCommitsAll(t *testing.T) {
	db, _ := openStore(t, testKey(t))
	setupSchema(t, db)
	now := time.Now().UTC().Unix()
	err := writeOperation(t, db, func(tx *sql.Tx) error {
		if _, err := tx.Exec(
			"INSERT INTO tasks(id,title,created_time) VALUES('t-9','Ship',$1)", now); err != nil {
			return err
		}
		if _, err := tx.Exec(
			"INSERT INTO sites(id,name,smc_id) VALUES('s-9','Depot','smc-z')"); err != nil {
			return err
		}
		_, err := tx.Exec("INSERT INTO task_site(task_id,site_id) VALUES('t-9','s-9')")
		return err
	})
	if err != nil {
		t.Fatalf("write operation: %v", err)
	}
	for _, q := range []string{
		"SELECT COUNT(*) FROM tasks WHERE id='t-9'",
		"SELECT COUNT(*) FROM sites WHERE id='s-9'",
		"SELECT COUNT(*) FROM task_site WHERE task_id='t-9'",
	} {
		var n int
		if err := db.QueryRow(q).Scan(&n); err != nil || n != 1 {
			t.Fatalf("%s = %d,%v", q, n, err)
		}
	}
}

func TestWriteOperationRollsBackAll(t *testing.T) {
	db, _ := openStore(t, testKey(t))
	setupSchema(t, db)
	if _, err := db.Exec("INSERT INTO tasks(id,title) VALUES('t-dup','First')"); err != nil {
		t.Fatalf("seed: %v", err)
	}
	err := writeOperation(t, db, func(tx *sql.Tx) error {
		if _, err := tx.Exec("INSERT INTO sites(id,name) VALUES('s-temp','Temp')"); err != nil {
			return err
		}
		// Duplicate key fails the operation; the site above must
		// roll back with it.
		_, err := tx.Exec("INSERT INTO tasks(id,title) VALUES('t-dup','Second')")
		return err
	})
	if err == nil {
		t.Fatal("operation with duplicate key succeeded")
	}
	var n int
	if err := db.QueryRow("SELECT COUNT(*) FROM sites WHERE id='s-temp'").Scan(&n); err != nil || n != 0 {
		t.Fatalf("rolled-back site persisted: %d,%v", n, err)
	}
	var title string
	if err := db.QueryRow("SELECT title FROM tasks WHERE id='t-dup'").Scan(&title); err != nil || title != "First" {
		t.Fatalf("task = %q,%v", title, err)
	}
	// A later statement failing against a missing table rolls the
	// earlier write back too; nothing is retained.
	err = writeOperation(t, db, func(tx *sql.Tx) error {
		if _, err := tx.Exec("INSERT INTO sites(id,name) VALUES('s-gone','Gone')"); err != nil {
			return err
		}
		_, err := tx.Exec("INSERT INTO missing_table(id) VALUES('x')")
		return err
	})
	if err == nil {
		t.Fatal("operation against missing table succeeded")
	}
	if err := db.QueryRow("SELECT COUNT(*) FROM sites WHERE id='s-gone'").Scan(&n); err != nil || n != 0 {
		t.Fatalf("rolled-back site persisted: %d,%v", n, err)
	}
}

func TestCancelledContextFailsFast(t *testing.T) {
	db, _ := openStore(t, testKey(t))
	setupSchema(t, db)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := db.ExecContext(ctx, "INSERT INTO contacts(id) VALUES('x')"); err == nil {
		t.Fatal("exec with canceled context succeeded")
	}
	if _, err := db.QueryContext(ctx, "SELECT 1"); err == nil {
		t.Fatal("query with canceled context succeeded")
	}
}

func TestConcurrentTypedRecordCRUDStress(t *testing.T) {
	db, _ := openStore(t, testKey(t))
	setupSchema(t, db)
	const workers, iterations = 12, 20
	var wg sync.WaitGroup
	var failures atomic.Int64
	for worker := 0; worker < workers; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				name := fmt.Sprintf("worker-%d-record-%d", worker, i)
				id := fmt.Sprintf("w%d-%d", worker, i)
				if _, err := db.Exec("INSERT INTO contacts(id,name) VALUES(?,?)", id, name); err != nil {
					failures.Add(1)
					continue
				}
				if _, err := db.Exec("UPDATE contacts SET name=? WHERE id=?", name+"-updated", id); err != nil {
					failures.Add(1)
					continue
				}
				var got string
				if err := db.QueryRow("SELECT name FROM contacts WHERE id=?", id).Scan(&got); err != nil || got != name+"-updated" {
					failures.Add(1)
				}
			}
		}(worker)
	}
	wg.Wait()
	if failures.Load() != 0 {
		t.Fatalf("typed record CRUD failed %d times", failures.Load())
	}
	var total int
	if err := db.QueryRow("SELECT COUNT(*) FROM contacts").Scan(&total); err != nil || total != workers*iterations {
		t.Fatalf("total = %d,%v", total, err)
	}
}

func TestConcurrentSessionLifecycleStress(t *testing.T) {
	db, _ := openStore(t, testKey(t))
	setupSchema(t, db)
	const workers, iterations = 12, 12
	var wg sync.WaitGroup
	var failures atomic.Int64
	for worker := 0; worker < workers; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				id := fmt.Sprintf("sess-%d-%d", worker, i)
				if _, err := db.Exec("INSERT INTO sessions(id,user_id,expires) VALUES(?,?,?)",
					id, fmt.Sprintf("user-%d", worker), time.Now().Unix()+3600); err != nil {
					failures.Add(1)
					continue
				}
				var user string
				if err := db.QueryRow("SELECT user_id FROM sessions WHERE id=?", id).Scan(&user); err != nil {
					failures.Add(1)
					continue
				}
				if _, err := db.Exec("DELETE FROM sessions WHERE id=?", id); err != nil {
					failures.Add(1)
				}
			}
		}(worker)
	}
	wg.Wait()
	if failures.Load() != 0 {
		t.Fatalf("session lifecycle failed %d times", failures.Load())
	}
	var total int
	if err := db.QueryRow("SELECT COUNT(*) FROM sessions").Scan(&total); err != nil || total != 0 {
		t.Fatalf("sessions left = %d,%v", total, err)
	}
}

func TestReadersDuringWrites(t *testing.T) {
	db, _ := openStore(t, testKey(t))
	setupSchema(t, db)
	const writers = 2
	const perWriter = 50
	const readers = 4
	var wg sync.WaitGroup
	var readFailures atomic.Int64
	stop := make(chan struct{})
	for r := 0; r < readers; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				var n int
				if err := db.QueryRow("SELECT COUNT(*) FROM contacts").Scan(&n); err != nil {
					readFailures.Add(1)
					return
				}
			}
		}()
	}
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < perWriter; i++ {
				if _, err := db.Exec("INSERT INTO contacts(id,name) VALUES(?,?)",
					fmt.Sprintf("rw-%d-%d", w, i), "x"); err != nil {
					readFailures.Add(1)
					return
				}
			}
		}(w)
	}
	// Wait for writers via a done channel pattern: poll count.
	deadline := time.Now().Add(60 * time.Second)
	for {
		var n int
		if err := db.QueryRow("SELECT COUNT(*) FROM contacts").Scan(&n); err != nil {
			t.Fatalf("count: %v", err)
		}
		if n == writers*perWriter {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("writes stalled at %d", n)
		}
		time.Sleep(10 * time.Millisecond)
	}
	close(stop)
	wg.Wait()
	if readFailures.Load() != 0 {
		t.Fatalf("reader/writer failures: %d", readFailures.Load())
	}
}
