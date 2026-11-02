package bridge_test

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/marcgauthier/libmurmur/clients/go/bindings/bridge"
	"github.com/marcgauthier/libmurmur/clients/go/bindings/driver"
	"github.com/marcgauthier/libmurmur/clients/go/bindings/sqlite"
	"github.com/marcgauthier/libmurmur/clients/go/murmurdb"
)

func TestTypedRowsOwnershipPersistsAcrossEncryptedRestart(t *testing.T) {
	ctx := context.Background()
	seed, secret, pub, recipient := credentials()
	lowPath, highPath := filepath.Join(t.TempDir(), "low"), filepath.Join(t.TempDir(), "high")
	dsn := func(path string) string {
		return path + "?key=0101010101010101010101010101010101010101010101010101010101010101"
	}
	open := func(path string) *sql.DB {
		db, err := murmurdb.Open(dsn(path))
		if err != nil {
			t.Fatal(err)
		}
		return db
	}
	low, high := open(lowPath), open(highPath)
	defer low.Close()
	defer func() { high.Close() }()
	var table bridge.TableID
	for _, db := range []*sql.DB{low, high} {
		if _, err := db.Exec("CREATE TABLE contacts(id TEXT PRIMARY KEY NOT NULL,name TEXT NOT NULL DEFAULT '',number INTEGER,data BLOB)"); err != nil {
			t.Fatal(err)
		}
		err := murmurdb.WithConnection(ctx, db, func(c *sqlite.Conn) error {
			if err := bridge.Init(c); err != nil {
				return err
			}
			var err error
			table, err = bridge.RegisterTable(c, "contacts")
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	tx := func(db *sql.DB, path string, fn func(*sqlite.Conn) error) {
		t.Helper()
		err := murmurdb.WithConnection(ctx, db, func(c *sqlite.Conn) error {
			sqlite.LockWriter()
			defer sqlite.UnlockWriter()
			if err := c.Exec("BEGIN IMMEDIATE"); err != nil {
				return err
			}
			defer c.Exec("ROLLBACK")
			if err := fn(c); err != nil {
				return err
			}
			if err := c.Exec("COMMIT"); err != nil {
				return err
			}
			return driver.Commit(path)
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	h := bridge.Header{Stream: "overwatch", Database: [16]byte{1}, Node: [16]byte{2}}
	var clock uint64
	send := func(changes string, deleted bool) {
		t.Helper()
		clock++
		tx(low, lowPath, func(c *sqlite.Conn) error {
			if err := c.Exec(changes); err != nil {
				return err
			}
			record, err := bridge.CaptureRow(c, table, []any{"one"}, deleted, bridge.Version{Millis: clock, Origin: [16]byte{2}})
			if err != nil {
				return err
			}
			payload, err := bridge.PackRows(record)
			if err != nil {
				return err
			}
			h.Schema, err = bridge.Schema(c)
			if err != nil {
				return err
			}
			h.Transaction[0] = byte(clock)
			_, err = bridge.Queue(c, h, seed, recipient, payload, bridge.DefaultStaging)
			return err
		})
		var seq uint64
		var bundle []byte
		if err := murmurdb.WithConnection(ctx, low, func(c *sqlite.Conn) error {
			var err error
			seq, bundle, err = bridge.Next(c, h.Database, h.Stream)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		if err := murmurdb.WithConnection(ctx, high, func(c *sqlite.Conn) error {
			if err := bridge.Stage(c, bundle, h.Database, h.Stream, pub, secret, bridge.DefaultStaging); err != nil {
				return err
			}
			return bridge.ApplyRows(c, h.Database, h.Stream, pub, secret)
		}); err != nil {
			t.Fatal(err)
		}
		if err := murmurdb.WithConnection(ctx, low, func(c *sqlite.Conn) error { return bridge.Ack(c, h.Database, h.Stream, seq) }); err != nil {
			t.Fatal(err)
		}
	}
	check := func(want string) {
		t.Helper()
		var name string
		if err := high.QueryRow("SELECT name FROM contacts WHERE id='one'").Scan(&name); err != nil || name != want {
			t.Fatalf("name=%q, want %q: %v", name, want, err)
		}
	}
	send("INSERT INTO contacts VALUES('one','Low',9223372036854775807,x'00FF')", false)
	check("Low")
	column := "name"
	tx(high, highPath, func(c *sqlite.Conn) error {
		if err := c.Exec("UPDATE contacts SET name='High'"); err != nil {
			return err
		}
		return bridge.Claim(c, table, []any{"one"}, &column, bridge.Version{Millis: 100, Origin: [16]byte{3}})
	})
	if err := high.Close(); err != nil {
		t.Fatal(err)
	}
	high = open(highPath)
	send("UPDATE contacts SET name='new Low',number=NULL", false)
	check("High")
	var kind string
	if err := high.QueryRow("SELECT typeof(number)||':'||hex(data) FROM contacts").Scan(&kind); err != nil || kind != "null:00FF" {
		t.Fatalf("typed data=%q: %v", kind, err)
	}
	tx(high, highPath, func(c *sqlite.Conn) error {
		return bridge.Release(c, table, []any{"one"}, &column, bridge.Version{Millis: 101, Origin: [16]byte{3}})
	})
	check("new Low")
	tx(high, highPath, func(c *sqlite.Conn) error {
		if err := c.Exec("DELETE FROM contacts"); err != nil {
			return err
		}
		return bridge.Claim(c, table, []any{"one"}, nil, bridge.Version{Millis: 200, Origin: [16]byte{3}})
	})
	send("UPDATE contacts SET name='latest Low'", false)
	var count int
	if err := high.QueryRow("SELECT count(*) FROM contacts").Scan(&count); err != nil || count != 0 {
		t.Fatalf("row delete not protected: %d %v", count, err)
	}
	tx(high, highPath, func(c *sqlite.Conn) error {
		return bridge.Release(c, table, []any{"one"}, nil, bridge.Version{Millis: 201, Origin: [16]byte{3}})
	})
	check("latest Low")
}

func FuzzPackRows(f *testing.F) {
	db, err := murmurdb.Open(filepath.Join(f.TempDir(), "seed") + "?key=0101010101010101010101010101010101010101010101010101010101010101")
	if err != nil {
		f.Fatal(err)
	}
	var record []byte
	err = murmurdb.WithConnection(context.Background(), db, func(c *sqlite.Conn) error {
		sqlite.LockWriter()
		defer sqlite.UnlockWriter()
		if err := c.Exec("CREATE TABLE seed(id TEXT PRIMARY KEY NOT NULL,value BLOB)"); err != nil {
			return err
		}
		table, err := bridge.RegisterTable(c, "seed")
		if err != nil {
			return err
		}
		if err := c.Exec("BEGIN"); err != nil {
			return err
		}
		defer c.Exec("ROLLBACK")
		if err := c.Exec("INSERT INTO seed VALUES('one',x'00FF')"); err != nil {
			return err
		}
		record, err = bridge.CaptureRow(c, table, []any{"one"}, false, bridge.Version{Millis: 1, Origin: [16]byte{2}})
		if err != nil {
			return err
		}
		return c.Exec("COMMIT")
	})
	closeErr := db.Close()
	if err != nil {
		f.Fatal(err)
	}
	if closeErr != nil {
		f.Fatal(closeErr)
	}
	f.Add(record)
	f.Add([]byte("MMR2"))
	f.Fuzz(func(t *testing.T, input []byte) {
		payload, err := bridge.PackRows(input)
		if err != nil {
			if payload != nil {
				t.Fatal("failed pack returned output")
			}
			return
		}
		if len(payload) == 0 {
			t.Fatal("valid pack returned empty output")
		}
		if _, err := bridge.PackRows(input, input); err == nil {
			t.Fatal("duplicate row accepted")
		}
	})
}
