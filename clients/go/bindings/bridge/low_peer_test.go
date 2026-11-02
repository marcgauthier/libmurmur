package bridge_test

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/binary"
	"errors"
	"path/filepath"
	"testing"

	"github.com/marcgauthier/libmurmur/clients/go/bindings/bridge"
	"github.com/marcgauthier/libmurmur/clients/go/bindings/sqlite"
	"github.com/marcgauthier/libmurmur/clients/go/murmurdb"
)

func TestOriginalLowPeerWritesReachExporterAndHigh(t *testing.T) {
	f := newFerryFixture(t)
	other, err := murmurdb.Open(filepath.Join(t.TempDir(), "low-peer") + "?key=0101010101010101010101010101010101010101010101010101010101010101")
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	f.exec(other, "CREATE TABLE notes(id TEXT PRIMARY KEY NOT NULL,name TEXT,email TEXT)")
	cfg := f.lcfg
	cfg.Node = [16]byte{4}
	f.with(other, func(c *sqlite.Conn) error {
		if _, err := bridge.RegisterTable(c, "notes"); err != nil {
			return err
		}
		return bridge.AttachCapture(c, cfg)
	})
	nodes := [][16]byte{f.lcfg.Node, cfg.Node}
	dbs := []*sql.DB{f.low, other}
	var seeds, keys [2][32]byte
	for i := range seeds {
		seeds[i][0] = byte(21 + i)
		copy(keys[i][:], ed25519.NewKeyFromSeed(seeds[i][:])[32:])
	}
	for i, db := range dbs {
		f.with(db, func(c *sqlite.Conn) error {
			if err := bridge.ConfigureLowPeer(c, f.lcfg.Database, nodes[i], seeds[i], f.lcfg.Node); err != nil {
				return err
			}
			return bridge.TrustPeer(c, nodes[1-i], keys[1-i], true)
		})
	}
	f.with(f.high, func(c *sqlite.Conn) error {
		for i, node := range nodes {
			if err := bridge.TrustSourceOrigin(c, f.lcfg.Database, node, keys[i], true); err != nil {
				return err
			}
		}
		return nil
	})
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
	copyRecords := func(from, to *sql.DB) {
		t.Helper()
		records := logs(from)
		f.with(to, func(c *sqlite.Conn) error {
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
	drain := func() {
		t.Helper()
		for {
			var seq uint64
			var bundle []byte
			err := murmurdb.WithConnection(context.Background(), f.low, func(c *sqlite.Conn) error {
				var err error
				seq, bundle, err = bridge.Next(c, f.lcfg.Database, "test")
				return err
			})
			var native *bridge.Error
			if errors.As(err, &native) && native.Code == 12 {
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			f.with(f.high, func(c *sqlite.Conn) error {
				if err := bridge.Stage(c, bundle, f.lcfg.Database, "test", f.pub, f.secret, bridge.DefaultStaging); err != nil {
					return err
				}
				return bridge.ApplyRows(c, f.lcfg.Database, "test", f.pub, f.secret)
			})
			f.with(f.low, func(c *sqlite.Conn) error { return bridge.Ack(c, f.lcfg.Database, "test", seq) })
		}
	}
	f.exec(other, "INSERT INTO notes VALUES('one','peer insert','first')")
	var queued int
	if err := other.QueryRow("SELECT count(*) FROM murmur_bridge_artifact WHERE kind='out'").Scan(&queued); err != nil || queued != 0 {
		t.Fatalf("non-exporter queued ferry bytes: %d %v", queued, err)
	}
	f.with(other, func(c *sqlite.Conn) error {
		if sender, err := bridge.NewSender(c, f.lcfg.Database, "test", f.dir, true); err == nil {
			sender.Close()
			t.Fatal("non-exporter started sender")
		}
		return nil
	})
	copyRecords(other, f.low)
	// A valid exporter seal cannot conceal a forged original Low signature.
	var original []byte
	f.with(f.low, func(c *sqlite.Conn) error {
		var err error
		_, original, err = bridge.Next(c, f.lcfg.Database, "test")
		return err
	})
	h, payload, err := bridge.Unseal(original, f.lcfg.Database, "test", f.pub, f.secret)
	if err != nil {
		t.Fatal(err)
	}
	if string(payload[:4]) != "MHP1" {
		t.Fatal("original Low proof missing")
	}
	_, prefix := binary.Uvarint(payload[4:])
	if prefix <= 0 {
		t.Fatal("invalid proof length")
	}
	forged := append([]byte(nil), payload...)
	forged[4+prefix+4+136] ^= 1
	sealed, err := bridge.Seal(h, f.seed, f.recipient, forged)
	if err != nil {
		t.Fatal(err)
	}
	f.with(f.high, func(high *sqlite.Conn) error {
		if err := bridge.Stage(high, sealed, f.lcfg.Database, "test", f.pub, f.secret, bridge.DefaultStaging); err != nil {
			return err
		}
		if err := bridge.ApplyRows(high, f.lcfg.Database, "test", f.pub, f.secret); err == nil {
			t.Fatal("forged original writer signature accepted")
		}
		return high.Exec("DELETE FROM murmur_bridge_artifact WHERE kind='in'")
	})
	// Dropping the original proof is also rejected once origin keys are pinned.
	proofRecord := payload[4+prefix:]
	_, recordPrefix := binary.Uvarint(proofRecord[204:])
	if recordPrefix <= 0 {
		t.Fatal("invalid journal payload")
	}
	lowPacket := proofRecord[204+recordPrefix:]
	if string(lowPacket[:4]) != "MBL1" {
		t.Fatal("invalid Low record")
	}
	_, rowPrefix := binary.Uvarint(lowPacket[4:])
	if rowPrefix <= 0 {
		t.Fatal("invalid row packet")
	}
	rawRows := lowPacket[4+rowPrefix:]
	downgraded, err := bridge.Seal(h, f.seed, f.recipient, rawRows)
	if err != nil {
		t.Fatal(err)
	}
	f.with(f.high, func(high *sqlite.Conn) error {
		if err := bridge.Stage(high, downgraded, f.lcfg.Database, "test", f.pub, f.secret, bridge.DefaultStaging); err != nil {
			return err
		}
		if err := bridge.ApplyRows(high, f.lcfg.Database, "test", f.pub, f.secret); err == nil {
			t.Fatal("original proof downgrade accepted")
		}
		return high.Exec("DELETE FROM murmur_bridge_artifact WHERE kind='in'")
	})
	drain()
	f.check("peer insert:first")
	f.exec(f.low, "UPDATE notes SET email='exporter email' WHERE id='one'")
	copyRecords(f.low, other)
	drain()
	f.check("peer insert:exporter email")
	f.exec(other, "UPDATE notes SET name='peer update' WHERE id='one'")
	copyRecords(other, f.low)
	drain()
	f.check("peer update:exporter email")
	f.with(f.low, func(c *sqlite.Conn) error {
		n, done, err := bridge.Prepare(c, 256)
		if err == nil && (n != 0 || !done) {
			t.Fatalf("forwarded peer rows recaptured by baseline: %d %v", n, done)
		}
		return err
	})
	f.exec(other, "DELETE FROM notes WHERE id='one'")
	copyRecords(other, f.low)
	drain()
	var count int
	if err := f.high.QueryRow("SELECT count(*) FROM notes").Scan(&count); err != nil || count != 0 {
		t.Fatalf("peer delete not imported: %d %v", count, err)
	}
	f.exec(f.low, "INSERT INTO notes VALUES('one','reinsert','new')")
	copyRecords(f.low, other)
	drain()
	f.check("reinsert:new")
}
