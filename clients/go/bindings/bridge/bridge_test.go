package bridge_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/marcgauthier/libmurmur/clients/go/bindings/bridge"
	"github.com/marcgauthier/libmurmur/clients/go/bindings/sqlite"
	"github.com/marcgauthier/libmurmur/clients/go/murmurdb"
)

func credentials() (seed, secret, pub, recipient [32]byte) {
	seed[0] = 1
	secret[16] = 2
	key := ed25519.NewKeyFromSeed(seed[:])
	copy(pub[:], key[32:])
	recipient, _ = bridge.RecipientPublic(secret)
	return
}

func TestEncryptedQueueSurvivesReopenAndStages(t *testing.T) {
	seed, secret, pub, recipient := credentials()
	ctx := context.Background()
	h := bridge.Header{Stream: "overwatch", Database: [16]byte{1}, Node: [16]byte{2}, Transaction: [16]byte{3}}
	dsn := filepath.Join(t.TempDir(), "store") + "?key=0101010101010101010101010101010101010101010101010101010101010101"
	db, err := murmurdb.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	err = murmurdb.WithConnection(ctx, db, func(c *sqlite.Conn) error {
		sqlite.LockWriter()
		defer sqlite.UnlockWriter()
		if err := bridge.Init(c); err != nil {
			return err
		}
		if err := c.Exec("BEGIN"); err != nil {
			return err
		}
		defer c.Exec("ROLLBACK")
		queued, err := bridge.Queue(c, h, seed, recipient, []byte("typed payload"), bridge.DefaultStaging)
		if err != nil {
			return err
		}
		if queued.Sequence != 1 {
			t.Fatalf("sequence = %d", queued.Sequence)
		}
		return c.Exec("COMMIT")
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = murmurdb.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	err = murmurdb.WithConnection(ctx, db, func(c *sqlite.Conn) error {
		seq, bundle, err := bridge.Next(c, h.Database, h.Stream)
		if err != nil {
			return err
		}
		if seq != 1 {
			t.Fatalf("reopened sequence = %d", seq)
		}
		got, payload, err := bridge.Unseal(bundle, h.Database, h.Stream, pub, secret)
		if err != nil {
			return err
		}
		if got.Sequence != 1 || !bytes.Equal(payload, []byte("typed payload")) {
			t.Fatalf("reopened payload = %q", payload)
		}
		if err := bridge.Stage(c, bundle, h.Database, h.Stream, pub, secret, bridge.DefaultStaging); err != nil {
			return err
		}
		if err := bridge.Stage(c, bundle, h.Database, h.Stream, pub, secret, bridge.DefaultStaging); err != nil {
			return err
		}
		if err := c.Exec("CREATE TABLE imported(value TEXT)"); err != nil {
			return err
		}
		failed := errors.New("apply failed")
		err = bridge.Apply(c, h.Database, h.Stream, pub, secret, h.Schema, func(bridge.Header, []byte) error {
			if err := c.Exec("INSERT INTO imported VALUES('rolled back')"); err != nil {
				return err
			}
			return failed
		})
		if !errors.Is(err, failed) {
			t.Fatalf("callback failure = %v", err)
		}
		err = bridge.Apply(c, h.Database, h.Stream, pub, secret, h.Schema, func(bridge.Header, []byte) error {
			panic("test callback")
		})
		if err == nil {
			t.Fatal("panic escaped rollback")
		}
		if err := bridge.Apply(c, h.Database, h.Stream, pub, secret, h.Schema, func(_ bridge.Header, payload []byte) error {
			if !bytes.Equal(payload, []byte("typed payload")) {
				t.Fatalf("apply payload = %q", payload)
			}
			return c.Exec("INSERT INTO imported VALUES('committed')")
		}); err != nil {
			return err
		}
		return bridge.Ack(c, h.Database, h.Stream, seq)
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = murmurdb.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	err = murmurdb.WithConnection(ctx, db, func(c *sqlite.Conn) error {
		_, _, err := bridge.Next(c, h.Database, h.Stream)
		var native *bridge.Error
		if !errors.As(err, &native) || native.Code != 12 {
			t.Fatalf("ack not durable: %v", err)
		}
		err = bridge.Apply(c, h.Database, h.Stream, pub, secret, h.Schema, func(bridge.Header, []byte) error {
			t.Fatal("reapplied after reopen")
			return nil
		})
		if !errors.As(err, &native) || native.Code != 12 {
			t.Fatalf("receipt not durable: %v", err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	var rows int
	if err := db.QueryRow("SELECT count(*) FROM imported WHERE value='committed'").Scan(&rows); err != nil || rows != 1 {
		t.Fatalf("committed effects: %d %v", rows, err)
	}
	if err := db.QueryRow("SELECT count(*) FROM imported WHERE value='rolled back'").Scan(&rows); err != nil || rows != 0 {
		t.Fatalf("rolled back effects: %d %v", rows, err)
	}
}

func TestEnvelopeFailureDoesNotReturnPlaintext(t *testing.T) {
	seed, secret, pub, recipient := credentials()
	h := bridge.Header{Stream: "overwatch", Sequence: 1, Database: [16]byte{1}, Node: [16]byte{2}, Transaction: [16]byte{3}}
	bundle, err := bridge.Seal(h, seed, recipient, []byte{0, 255, 42})
	if err != nil {
		t.Fatal(err)
	}
	bundle[len(bundle)-1] ^= 1
	got, payload, err := bridge.Unseal(bundle, h.Database, h.Stream, pub, secret)
	if err == nil || payload != nil || got.Sequence != 0 {
		t.Fatalf("forgery result: %+v %x %v", got, payload, err)
	}
	h.Stream = "overwatch\x00other"
	if _, err := bridge.Seal(h, seed, recipient, nil); err == nil {
		t.Fatal("accepted embedded NUL")
	}
}

func FuzzUnseal(f *testing.F) {
	seed, secret, pub, recipient := credentials()
	h := bridge.Header{Stream: "overwatch", Sequence: 1, Database: [16]byte{1}, Node: [16]byte{2}, Transaction: [16]byte{3}}
	bundle, err := bridge.Seal(h, seed, recipient, []byte("payload"))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(bundle)
	f.Add([]byte("MHB1"))
	f.Fuzz(func(t *testing.T, b []byte) {
		got, payload, err := bridge.Unseal(b, h.Database, h.Stream, pub, secret)
		if err != nil && (got.Sequence != 0 || payload != nil) {
			t.Fatal("failure leaked output")
		}
	})
}

func TestPublishRetriesWithoutLosingQueuedArtifact(t *testing.T) {
	ctx := context.Background()
	seed, _, _, recipient := credentials()
	h := bridge.Header{Stream: "overwatch", Database: [16]byte{1}, Node: [16]byte{2}, Transaction: [16]byte{3}}
	db, err := murmurdb.Open(filepath.Join(t.TempDir(), "store") + "?key=0101010101010101010101010101010101010101010101010101010101010101")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	dir := t.TempDir()
	err = murmurdb.WithConnection(ctx, db, func(c *sqlite.Conn) error {
		sqlite.LockWriter()
		defer sqlite.UnlockWriter()
		if err := bridge.Init(c); err != nil {
			return err
		}
		if err := c.Exec("BEGIN"); err != nil {
			return err
		}
		if _, err := bridge.Queue(c, h, seed, recipient, []byte("publication"), bridge.DefaultStaging); err != nil {
			c.Exec("ROLLBACK")
			return err
		}
		if err := c.Exec("COMMIT"); err != nil {
			return err
		}
		_, bundle, err := bridge.Next(c, h.Database, h.Stream)
		if err != nil {
			return err
		}
		if err := bridge.Publish(c, h.Database, h.Stream, filepath.Join(dir, "missing")); err == nil {
			t.Fatal("published to missing directory")
		}
		digest := sha256.Sum256(bundle)
		path := filepath.Join(dir, hex.EncodeToString(digest[:])+".bundle")
		if err := os.WriteFile(path, []byte("conflict"), 0600); err != nil {
			return err
		}
		if err := bridge.Publish(c, h.Database, h.Stream, dir); err == nil {
			t.Fatal("overwrote conflicting artifact")
		}
		_, retry, err := bridge.Next(c, h.Database, h.Stream)
		if err != nil || !bytes.Equal(retry, bundle) {
			t.Fatalf("queue changed on failed publication: %v", err)
		}
		// Simulate publication completed before a crash prevented acknowledgment.
		if err := os.WriteFile(path, bundle, 0600); err != nil {
			return err
		}
		if err := bridge.Publish(c, h.Database, h.Stream, dir); err != nil {
			return err
		}
		_, _, err = bridge.Next(c, h.Database, h.Stream)
		var native *bridge.Error
		if !errors.As(err, &native) || native.Code != 12 {
			t.Fatalf("publication not acknowledged: %v", err)
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			return err
		}
		if len(entries) != 1 || entries[0].Name() != filepath.Base(path) {
			t.Fatalf("publication cleanup: %v", entries)
		}
		h.Transaction[0] = 4
		if err := c.Exec("BEGIN"); err != nil {
			return err
		}
		if _, err := bridge.Queue(c, h, seed, recipient, []byte("second publication"), bridge.DefaultStaging); err != nil {
			c.Exec("ROLLBACK")
			return err
		}
		if err := c.Exec("COMMIT"); err != nil {
			return err
		}
		if err := bridge.Publish(c, h.Database, h.Stream, dir); err != nil {
			return err
		}
		entries, err = os.ReadDir(dir)
		if err != nil {
			return err
		}
		if len(entries) != 2 {
			t.Fatalf("new artifact not published: %v", entries)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
