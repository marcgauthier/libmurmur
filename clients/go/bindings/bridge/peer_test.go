package bridge_test

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/marcgauthier/libmurmur/clients/go/bindings/bridge"
	"github.com/marcgauthier/libmurmur/clients/go/bindings/sqlite"
	"github.com/marcgauthier/libmurmur/clients/go/murmurdb"
)

func TestHighPeerOwnershipJournalAndRelease(t *testing.T) {
	f := newFerryFixture(t)
	other, err := murmurdb.Open(filepath.Join(t.TempDir(), "peer") + "?key=0101010101010101010101010101010101010101010101010101010101010101")
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	f.exec(other, "CREATE TABLE notes(id TEXT PRIMARY KEY NOT NULL,name TEXT,email TEXT)")
	f.with(other, func(c *sqlite.Conn) error {
		if _, err := bridge.RegisterTable(c, "notes"); err != nil {
			return err
		}
		return bridge.AttachCapture(c, bridge.CaptureConfig{Role: bridge.High, Database: [16]byte{9}, Node: [16]byte{4}, Stream: "test"})
	})
	var seeds [2][32]byte
	seeds[0][0] = 11
	seeds[1][0] = 12
	var keys [2][32]byte
	for i := range seeds {
		copy(keys[i][:], ed25519.NewKeyFromSeed(seeds[i][:])[32:])
	}
	nodes := [][16]byte{{3}, {4}}
	dbs := []*sql.DB{f.high, other}
	for i, db := range dbs {
		f.with(db, func(c *sqlite.Conn) error {
			if err := bridge.ConfigurePeer(c, [16]byte{9}, nodes[i], seeds[i]); err != nil {
				return err
			}
			if err := bridge.TrustPeer(c, nodes[1-i], keys[1-i], true); err != nil {
				return err
			}
			return bridge.ConfigurePeerSource(c, bridge.ReceiverConfig{Source: f.lcfg.Database, Exporter: f.lcfg.Node, Secret: f.secret, Signers: [][32]byte{f.pub}, Stream: "test"})
		})
	}
	f.exec(f.low, "INSERT INTO notes VALUES('one','Low','email')")
	var bundle []byte
	f.with(f.low, func(c *sqlite.Conn) error {
		var err error
		_, bundle, err = bridge.Next(c, f.lcfg.Database, "test")
		return err
	})
	for _, db := range dbs {
		f.with(db, func(c *sqlite.Conn) error {
			if err := bridge.Stage(c, bundle, f.lcfg.Database, "test", f.pub, f.secret, bridge.DefaultStaging); err != nil {
				return err
			}
			return bridge.ApplyRows(c, f.lcfg.Database, "test", f.pub, f.secret)
		})
	}
	type record struct{ id, body []byte }
	logs := func(db *sql.DB) []record {
		t.Helper()
		rows, err := db.Query("SELECT id,body FROM murmur_bridge_peer_log ORDER BY rowid")
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		var out []record
		for rows.Next() {
			var r record
			if err := rows.Scan(&r.id, &r.body); err != nil {
				t.Fatal(err)
			}
			out = append(out, r)
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		return out
	}
	apply := func(db *sql.DB, records []record) {
		t.Helper()
		f.with(db, func(c *sqlite.Conn) error {
			return bridge.Write(c, func(c *sqlite.Conn) error {
				for _, r := range records {
					st, err := c.Prepare("INSERT INTO murmur_bridge_peer_log VALUES(?,?) ON CONFLICT(id) DO NOTHING")
					if err != nil {
						return err
					}
					err = st.Bind(r.id, r.body)
					if err == nil {
						_, err = st.Step()
					}
					st.Close()
					if err != nil {
						return err
					}
				}
				return bridge.ApplyPeer(c)
			})
		})
	}
	check := func(db *sql.DB, want string) {
		t.Helper()
		var got string
		if err := db.QueryRow("SELECT name||':'||email FROM notes WHERE id='one'").Scan(&got); err != nil || got != want {
			t.Fatalf("got %q want %q: %v", got, want, err)
		}
	}
	f.exec(f.high, "UPDATE notes SET name='High' WHERE id='one'")
	first := logs(f.high)
	if len(first) != 2 {
		t.Fatalf("journal=%d", len(first))
	}
	first = first[1:]
	f.exec(f.high, "UPDATE notes SET name='High second' WHERE id='one'")
	source := logs(f.high)
	apply(other, []record{source[0], source[2], source[1]})
	check(other, "High:email")
	apply(other, nil)
	check(other, "High second:email")
	f.exec(other, "UPDATE notes SET name='High peer' WHERE id='one'")
	apply(f.high, logs(other))
	check(f.high, "High peer:email")
	col := "name"
	f.with(f.high, func(c *sqlite.Conn) error {
		ok, err := bridge.ReleaseOwnership(c, "notes", []any{"one"}, &col)
		if err == nil && !ok {
			t.Fatal("release missing")
		}
		return err
	})
	apply(other, logs(f.high))
	check(other, "Low:email")
	apply(other, first)
	check(other, "Low:email")
	// Pinned keys and database identities cannot be changed on reconfigure.
	f.with(other, func(c *sqlite.Conn) error {
		wrong := keys[0]
		wrong[0] ^= 1
		if err := bridge.TrustPeer(c, nodes[0], wrong, true); err == nil {
			t.Fatal("peer key rebound")
		}
		if err := bridge.ConfigurePeer(c, [16]byte{8}, nodes[1], seeds[1]); err == nil {
			t.Fatal("peer database rebound")
		}
		return nil
	})
	// Forged journal bytes cannot commit their raw CRR-like insert or a claim.
	forged := append([]byte(nil), first[0].body...)
	forged[140] ^= 1
	digest := sha256.Sum256(forged)
	beforeForgery := len(logs(other))
	err = murmurdb.WithConnection(context.Background(), other, func(c *sqlite.Conn) error {
		return bridge.Write(c, func(c *sqlite.Conn) error {
			st, err := c.Prepare("INSERT INTO murmur_bridge_peer_log VALUES(?,?)")
			if err != nil {
				return err
			}
			defer st.Close()
			if err = st.Bind(digest[:], forged); err != nil {
				return err
			}
			if _, err = st.Step(); err != nil {
				return err
			}
			return bridge.ApplyPeer(c)
		})
	})
	if err == nil {
		t.Fatal("forged ownership record accepted")
	}
	if got := len(logs(other)); got != beforeForgery {
		t.Fatalf("forged journal insert committed: %d want %d", got, beforeForgery)
	}
	check(other, "Low:email")

	// Failed local user writes leave neither a claim nor a signed journal entry.
	before := len(logs(other))
	tx, err := other.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec("UPDATE notes SET name='rollback' WHERE id='one'"); err != nil {
		t.Fatal(err)
	}
	if err = tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if got := len(logs(other)); got != before {
		t.Fatalf("rollback journal=%d want %d", got, before)
	}
	check(other, "Low:email")
}

func TestHighPeerReopenRequiresPinnedSigningKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "peer")
	open := func() *sql.DB {
		db, err := murmurdb.Open(path + "?key=0101010101010101010101010101010101010101010101010101010101010101")
		if err != nil {
			t.Fatal(err)
		}
		return db
	}
	db := open()
	defer func() { db.Close() }()
	if _, err := db.Exec("CREATE TABLE notes(id TEXT PRIMARY KEY NOT NULL,name TEXT)"); err != nil {
		t.Fatal(err)
	}
	cfg := bridge.CaptureConfig{Role: bridge.High, Database: [16]byte{9}, Node: [16]byte{3}, Stream: "test"}
	var seed [32]byte
	seed[0] = 17
	attach := func() {
		t.Helper()
		if err := murmurdb.WithConnection(context.Background(), db, func(c *sqlite.Conn) error {
			if _, err := bridge.RegisterTable(c, "notes"); err != nil {
				return err
			}
			return bridge.AttachCapture(c, cfg)
		}); err != nil {
			t.Fatal(err)
		}
	}
	attach()
	if err := murmurdb.WithConnection(context.Background(), db, func(c *sqlite.Conn) error { return bridge.ConfigurePeer(c, cfg.Database, cfg.Node, seed) }); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("INSERT INTO notes VALUES('one','High')"); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db = open()
	attach()
	if _, err := db.Exec("UPDATE notes SET name='unsigned' WHERE id='one'"); err == nil {
		t.Fatal("High edit admitted without reopening signed peer identity")
	}
	if err := murmurdb.WithConnection(context.Background(), db, func(c *sqlite.Conn) error {
		wrong := seed
		wrong[0] ^= 1
		if err := bridge.ConfigurePeer(c, cfg.Database, cfg.Node, wrong); err == nil {
			t.Fatal("reopen signing key rebound")
		}
		return bridge.ConfigurePeer(c, cfg.Database, cfg.Node, seed)
	}); err != nil {
		t.Fatal(err)
	}
	var name string
	if err := db.QueryRow("SELECT name FROM notes WHERE id='one'").Scan(&name); err != nil || name != "High" {
		t.Fatalf("unsigned write changed row: %q %v", name, err)
	}
	if _, err := db.Exec("UPDATE notes SET name='signed' WHERE id='one'"); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := db.QueryRow("SELECT count(*) FROM murmur_bridge_peer_log").Scan(&count); err != nil || count != 2 {
		t.Fatalf("journal did not resume: %d %v", count, err)
	}
}

func TestHighPeerRequiresRawTableTransportDisabled(t *testing.T) {
	for _, disabled := range []bool{false, true} {
		t.Run(fmt.Sprint(disabled), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "raw-peer")
			db, err := murmurdb.Open(path + "?key=0101010101010101010101010101010101010101010101010101010101010101")
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			_, err = db.Exec("CREATE TABLE notes(id TEXT PRIMARY KEY NOT NULL,name TEXT); SELECT crsql_as_crr('main','notes'); CREATE TABLE murmur_config(name TEXT PRIMARY KEY,value TEXT NOT NULL)")
			if err != nil {
				t.Fatal(err)
			}
			flag := `{"notes":true}`
			if disabled {
				flag = `{"notes":false}`
			}
			if _, err := db.Exec("INSERT INTO murmur_config VALUES('table_replication',?)", flag); err != nil {
				t.Fatal(err)
			}
			err = murmurdb.WithConnection(context.Background(), db, func(c *sqlite.Conn) error {
				if _, err := bridge.RegisterTable(c, "notes"); err != nil {
					return err
				}
				if err := bridge.AttachCapture(c, bridge.CaptureConfig{Role: bridge.High, Database: [16]byte{9}, Node: [16]byte{3}, Stream: "test"}); err != nil {
					return err
				}
				return bridge.ConfigurePeer(c, [16]byte{9}, [16]byte{3}, [32]byte{17})
			})
			if disabled && err != nil {
				t.Fatalf("disabled existing CRR rejected: %v", err)
			}
			if !disabled && err == nil {
				t.Fatal("raw row transport admitted alongside semantic ownership")
			}
		})
	}
}
