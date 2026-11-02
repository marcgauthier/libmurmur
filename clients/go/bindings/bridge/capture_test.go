package bridge_test

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"

	"github.com/marcgauthier/libmurmur/clients/go/bindings/bridge"
	"github.com/marcgauthier/libmurmur/clients/go/bindings/sqlite"
	"github.com/marcgauthier/libmurmur/clients/go/murmurdb"
)

func TestAutomaticCaptureAndBaselineOverEncryptedStores(t *testing.T) {
	ctx := context.Background()
	seed, secret, pub, recipient := credentials()
	lowPath, highPath := filepath.Join(t.TempDir(), "low"), filepath.Join(t.TempDir(), "high")
	open := func(path string) *sql.DB {
		db, err := murmurdb.Open(path + "?key=0101010101010101010101010101010101010101010101010101010101010101")
		if err != nil {
			t.Fatal(err)
		}
		return db
	}
	low, high := open(lowPath), open(highPath)
	defer func() { low.Close(); high.Close() }()
	with := func(db *sql.DB, fn func(*sqlite.Conn) error) {
		t.Helper()
		if err := murmurdb.WithConnection(ctx, db, fn); err != nil {
			t.Fatal(err)
		}
	}
	lcfg := bridge.CaptureConfig{Role: bridge.Low, Database: [16]byte{1}, Node: [16]byte{2}, Signer: seed, Recipient: recipient, Stream: "overwatch"}
	hcfg := bridge.CaptureConfig{Role: bridge.High, Database: [16]byte{9}, Node: [16]byte{3}, Stream: "overwatch"}
	attach := func(db *sql.DB, cfg bridge.CaptureConfig) {
		t.Helper()
		with(db, func(c *sqlite.Conn) error { return bridge.AttachCapture(c, cfg) })
	}
	for _, db := range []*sql.DB{low, high} {
		if _, err := db.Exec("CREATE TABLE notes(id TEXT PRIMARY KEY NOT NULL,name TEXT,email TEXT)"); err != nil {
			t.Fatal(err)
		}
		with(db, func(c *sqlite.Conn) error { _, err := bridge.RegisterTable(c, "notes"); return err })
	}
	if _, err := low.Exec("INSERT INTO notes VALUES('one','existing','first'),('two','existing two','second')"); err != nil {
		t.Fatal(err)
	}
	attach(low, lcfg)
	attach(high, hcfg)
	for i := 0; i < 3; i++ {
		with(low, func(c *sqlite.Conn) error {
			count, complete, err := bridge.Prepare(c, 1)
			if err != nil {
				return err
			}
			if i < 2 && (count != 1 || complete) {
				t.Fatalf("baseline batch %d: %d %v", i, count, complete)
			}
			if i == 2 && (!complete || count != 0) {
				t.Fatalf("baseline completion: %d %v", count, complete)
			}
			return nil
		})
	}
	drain := func() {
		t.Helper()
		for {
			var seq uint64
			var bundle []byte
			var empty bool
			with(low, func(c *sqlite.Conn) error {
				var err error
				seq, bundle, err = bridge.Next(c, lcfg.Database, lcfg.Stream)
				var native *bridge.Error
				if errors.As(err, &native) && native.Code == 12 {
					empty = true
					return nil
				}
				return err
			})
			if empty {
				return
			}
			with(high, func(c *sqlite.Conn) error {
				if err := bridge.Stage(c, bundle, lcfg.Database, lcfg.Stream, pub, secret, bridge.DefaultStaging); err != nil {
					return err
				}
				return bridge.ApplyRows(c, lcfg.Database, lcfg.Stream, pub, secret)
			})
			with(low, func(c *sqlite.Conn) error { return bridge.Ack(c, lcfg.Database, lcfg.Stream, seq) })
		}
	}
	drain()
	if err := low.Close(); err != nil {
		t.Fatal(err)
	}
	low = open(lowPath)
	attach(low, lcfg)
	with(low, func(c *sqlite.Conn) error {
		n, done, err := bridge.Prepare(c, 1)
		if err != nil {
			return err
		}
		if n != 0 || !done {
			t.Fatalf("repeated baseline after reopen: %d %v", n, done)
		}
		return nil
	})
	write := func(db *sql.DB, sql string) {
		t.Helper()
		with(db, func(c *sqlite.Conn) error { return bridge.Write(c, func(c *sqlite.Conn) error { return c.Exec(sql) }) })
	}
	check := func(want string) {
		t.Helper()
		var value string
		if err := high.QueryRow("SELECT name||':'||email FROM notes WHERE id='one'").Scan(&value); err != nil || value != want {
			t.Fatalf("row=%q want=%q: %v", value, want, err)
		}
	}
	check("existing:first")
	write(high, "UPDATE notes SET name='High' WHERE id='one'")
	if err := high.Close(); err != nil {
		t.Fatal(err)
	}
	high = open(highPath)
	attach(high, hcfg)
	write(low, "UPDATE notes SET name='Low update',email='Low email' WHERE id='one'")
	drain()
	check("High:Low email")
	abort := errors.New("abort source write")
	with(low, func(c *sqlite.Conn) error {
		err := bridge.Write(c, func(c *sqlite.Conn) error {
			if err := c.Exec("UPDATE notes SET email='rolled back' WHERE id='one'"); err != nil {
				return err
			}
			return abort
		})
		if !errors.Is(err, abort) {
			t.Fatalf("rollback error: %v", err)
		}
		err = bridge.Write(c, func(c *sqlite.Conn) error {
			if err := c.Exec("UPDATE notes SET email='panic rollback' WHERE id='one'"); err != nil {
				return err
			}
			panic("callback")
		})
		if err == nil {
			t.Fatal("callback panic accepted")
		}
		return nil
	})
	drain()
	check("High:Low email")
	var email string
	if err := low.QueryRow("SELECT email FROM notes WHERE id='one'").Scan(&email); err != nil || email != "Low email" {
		t.Fatalf("source rollback: %q %v", email, err)
	}
}
