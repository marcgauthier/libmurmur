package bridge_test

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/marcgauthier/libmurmur/clients/go/bindings/bridge"
	"github.com/marcgauthier/libmurmur/clients/go/bindings/sqlite"
	"github.com/marcgauthier/libmurmur/clients/go/murmurdb"
)

type ferryFixture struct {
	t                            *testing.T
	low, high                    *sql.DB
	dir                          string
	seed, secret, pub, recipient [32]byte
	lcfg                         bridge.CaptureConfig
	receiver                     *bridge.Receiver
}

func newFerryFixture(t *testing.T) *ferryFixture {
	t.Helper()
	f := &ferryFixture{t: t, dir: t.TempDir()}
	f.seed, f.secret, f.pub, f.recipient = credentials()
	open := func(name string) *sql.DB {
		db, err := murmurdb.Open(filepath.Join(t.TempDir(), name) + "?key=0101010101010101010101010101010101010101010101010101010101010101")
		if err != nil {
			t.Fatal(err)
		}
		if _, err = db.Exec("CREATE TABLE notes(id TEXT PRIMARY KEY NOT NULL,name TEXT,email TEXT)"); err != nil {
			t.Fatal(err)
		}
		f.with(db, func(c *sqlite.Conn) error { _, err := bridge.RegisterTable(c, "notes"); return err })
		return db
	}
	f.low = open("low")
	f.high = open("high")
	f.lcfg = bridge.CaptureConfig{Role: bridge.Low, Database: [16]byte{1}, Node: [16]byte{2}, Signer: f.seed, Recipient: f.recipient, Stream: "test"}
	f.with(f.low, func(c *sqlite.Conn) error { return bridge.AttachCapture(c, f.lcfg) })
	f.with(f.high, func(c *sqlite.Conn) error {
		return bridge.AttachCapture(c, bridge.CaptureConfig{Role: bridge.High, Database: [16]byte{9}, Node: [16]byte{3}, Stream: "test"})
	})
	t.Cleanup(func() {
		if f.receiver != nil {
			f.receiver.Close()
		}
		f.low.Close()
		f.high.Close()
	})
	return f
}
func (f *ferryFixture) with(db *sql.DB, fn func(*sqlite.Conn) error) {
	f.t.Helper()
	if err := murmurdb.WithConnection(context.Background(), db, fn); err != nil {
		f.t.Fatal(err)
	}
}
func (f *ferryFixture) exec(db *sql.DB, query string) {
	f.t.Helper()
	if _, err := db.Exec(query); err != nil {
		f.t.Fatal(err)
	}
}
func (f *ferryFixture) newReceiver(keys ...[32]byte) {
	f.t.Helper()
	if f.receiver != nil {
		f.receiver.Close()
	}
	err := murmurdb.WithNativeControl(context.Background(), f.high, func(c *sqlite.Conn) error {
		var err error
		f.receiver, err = bridge.NewReceiver(c, bridge.ReceiverConfig{Source: f.lcfg.Database, Exporter: f.lcfg.Node, Secret: f.secret, Signers: keys, Stream: "test", Directory: f.dir})
		return err
	})
	if err != nil {
		f.t.Fatal(err)
	}
}
func (f *ferryFixture) publish() string {
	f.t.Helper()
	var bundle []byte
	f.with(f.low, func(c *sqlite.Conn) error {
		var err error
		_, bundle, err = bridge.Next(c, f.lcfg.Database, "test")
		if err != nil {
			return err
		}
		return bridge.Publish(c, f.lcfg.Database, "test", f.dir)
	})
	sum := sha256.Sum256(bundle)
	return filepath.Join(f.dir, hex.EncodeToString(sum[:])+".bundle")
}
func (f *ferryFixture) poll() {
	f.t.Helper()
	if err := f.receiver.Poll(256); err != nil {
		f.t.Fatal(err)
	}
}
func (f *ferryFixture) check(want string) {
	f.t.Helper()
	var got string
	if err := f.high.QueryRow("SELECT name||':'||email FROM notes WHERE id='one'").Scan(&got); err != nil || got != want {
		f.t.Fatalf("got %q want %q: %v", got, want, err)
	}
}
func (f *ferryFixture) artifact(b []byte) {
	f.t.Helper()
	sum := sha256.Sum256(b)
	if err := os.WriteFile(filepath.Join(f.dir, hex.EncodeToString(sum[:])+".bundle"), b, 0600); err != nil {
		f.t.Fatal(err)
	}
}

func TestFerryGapsHighSQLClaimsRotationAndReplay(t *testing.T) {
	f := newFerryFixture(t)
	f.newReceiver(f.pub)
	f.exec(f.low, "INSERT INTO notes VALUES('one','first','email')")
	first := f.publish()
	held := filepath.Join(t.TempDir(), "held")
	if err := os.Rename(first, held); err != nil {
		t.Fatal(err)
	}
	f.exec(f.low, "UPDATE notes SET name='second' WHERE id='one'")
	f.publish()
	f.poll()
	if s := f.receiver.Status(); s.Applied != 0 || s.Deferred != 1 {
		t.Fatalf("gap: %+v", s)
	}
	var inbox int
	if err := f.high.QueryRow("SELECT count(*) FROM murmur_bridge_artifact WHERE kind='in'").Scan(&inbox); err != nil || inbox != 0 {
		t.Fatalf("gap filled inbox: %d %v", inbox, err)
	}
	if err := os.Rename(held, first); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		f.poll()
	}
	f.check("second:email")
	f.exec(f.high, "UPDATE notes SET name='High' WHERE id='one'")
	f.exec(f.low, "UPDATE notes SET name='third',email='new email' WHERE id='one'")
	f.publish()
	f.poll()
	f.check("High:new email")
	var nextSeed, nextPub [32]byte
	nextSeed[0] = 9
	copy(nextPub[:], ed25519.NewKeyFromSeed(nextSeed[:])[32:])
	f.with(f.low, func(c *sqlite.Conn) error {
		if err := bridge.DetachCapture(c); err != nil {
			return err
		}
		f.lcfg.Signer = nextSeed
		return bridge.AttachCapture(c, f.lcfg)
	})
	f.newReceiver(f.pub, nextPub)
	f.exec(f.low, "UPDATE notes SET email='rotated' WHERE id='one'")
	f.publish()
	f.poll()
	f.check("High:rotated")
	f.newReceiver(nextPub)
	f.poll()
	if s := f.receiver.Status(); s.Duplicate != 4 || s.Applied != 0 || s.Rejected != 0 {
		t.Fatalf("replay after rotation: %+v", s)
	}
	var schema [32]byte
	f.with(f.low, func(c *sqlite.Conn) error { var err error; schema, err = bridge.Schema(c); return err })
	bad, err := bridge.Seal(bridge.Header{Database: f.lcfg.Database, Node: f.lcfg.Node, Transaction: [16]byte{7}, Sequence: 1, Stream: "test", Schema: schema}, nextSeed, f.recipient, []byte("different"))
	if err != nil {
		t.Fatal(err)
	}
	f.artifact(bad)
	f.poll()
	if s := f.receiver.Status(); s.Rejected != 1 {
		t.Fatalf("equivocation: %+v", s)
	}
}
func TestFerryRejectsArtifactsAndPinsExporter(t *testing.T) {
	f := newFerryFixture(t)
	f.newReceiver(f.pub)
	f.exec(f.low, "INSERT INTO notes VALUES('one','first','email')")
	path := f.publish()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	h, payload, err := bridge.Unseal(data, f.lcfg.Database, "test", f.pub, f.secret)
	if err != nil {
		t.Fatal(err)
	}
	h.Node = [16]byte{44}
	other, err := bridge.Seal(h, f.seed, f.recipient, payload)
	if err != nil {
		t.Fatal(err)
	}
	f.artifact(other)
	forged := append([]byte(nil), data...)
	forged[len(forged)-1] ^= 1
	f.artifact(forged)
	if err := os.WriteFile(path, []byte("truncated"), 0600); err != nil {
		t.Fatal(err)
	}
	want := uint64(3)
	if runtime.GOOS != "windows" {
		want++
		if err := os.Symlink(path, filepath.Join(f.dir, hex.EncodeToString(make([]byte, 32))+".bundle")); err != nil {
			t.Fatal(err)
		}
	}
	f.poll()
	if s := f.receiver.Status(); s.Rejected != want || s.Applied != 0 {
		t.Fatalf("invalid artifacts: %+v", s)
	}
	entries, err := os.ReadDir(f.dir)
	if err != nil || uint64(len(entries)) != want {
		t.Fatalf("artifacts removed: %d %v", len(entries), err)
	}
}
func TestFerryNativeWorkerLifecycleAndConcurrentSQL(t *testing.T) {
	f := newFerryFixture(t)
	f.newReceiver(f.pub)
	if err := f.receiver.Start(10 * time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if err := f.receiver.Poll(1); err == nil {
		t.Fatal("manual poll admitted while running")
	}
	f.exec(f.low, "INSERT INTO notes VALUES('one','first','email')")
	f.publish()
	wait := func(n uint64) {
		t.Helper()
		deadline := time.Now().Add(3 * time.Second)
		for f.receiver.Status().Applied < n {
			if time.Now().After(deadline) {
				t.Fatalf("worker stalled: %+v", f.receiver.Status())
			}
			var count int
			if err := f.high.QueryRow("SELECT count(*) FROM notes").Scan(&count); err != nil {
				t.Fatal(err)
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
	wait(1)
	f.check("first:email")
	f.receiver.Stop()
	f.receiver.Stop()
	if err := f.receiver.Start(10 * time.Millisecond); err != nil {
		t.Fatal(err)
	}
	f.exec(f.high, "UPDATE notes SET name='High' WHERE id='one'")
	f.exec(f.low, "UPDATE notes SET name='Low',email='later' WHERE id='one'")
	f.publish()
	wait(2)
	f.receiver.Stop()
	f.check("High:later")
}

func TestFerrySchemaHoldResumesAndScanIsBounded(t *testing.T) {
	f := newFerryFixture(t)
	f.newReceiver(f.pub)
	f.exec(f.low, "ALTER TABLE notes ADD COLUMN extra TEXT")
	f.with(f.low, func(c *sqlite.Conn) error { _, err := bridge.RegisterTable(c, "notes"); return err })
	f.exec(f.low, "INSERT INTO notes VALUES('one','first','email','additional')")
	f.publish()
	f.poll()
	if s := f.receiver.Status(); s.Deferred != 1 || s.Applied != 0 {
		t.Fatalf("schema hold: %+v", s)
	}
	var held int
	if err := f.high.QueryRow("SELECT count(*) FROM murmur_bridge_artifact WHERE kind='in'").Scan(&held); err != nil || held != 1 {
		t.Fatalf("missing durable held bundle: %d %v", held, err)
	}
	f.receiver.Close()
	f.exec(f.high, "ALTER TABLE notes ADD COLUMN extra TEXT")
	f.with(f.high, func(c *sqlite.Conn) error { _, err := bridge.RegisterTable(c, "notes"); return err })
	f.newReceiver(f.pub)
	f.poll()
	f.check("first:email")
	var extra string
	if err := f.high.QueryRow("SELECT extra FROM notes WHERE id='one'").Scan(&extra); err != nil || extra != "additional" {
		t.Fatalf("schema resume: %q %v", extra, err)
	}
	// Names that are not artifact names still consume the bounded scan budget.
	for i := 0; i < 300; i++ {
		if err := os.WriteFile(filepath.Join(f.dir, hex.EncodeToString([]byte{byte(i >> 8), byte(i)})+".ignored"), nil, 0600); err != nil {
			t.Fatal(err)
		}
	}
	f.newReceiver(f.pub)
	for i := 0; i < 3; i++ {
		if err := f.receiver.Poll(1); err != nil {
			t.Fatal(err)
		}
	}
	if s := f.receiver.Status(); s.Scanned != 3 {
		t.Fatalf("scan exceeded budget: %+v", s)
	}
	if err := f.receiver.Poll(257); err == nil {
		t.Fatal("unbounded scan admitted")
	}
}

func TestFerrySenderResumesBaselineAndLiveSQL(t *testing.T) {
	f := newFerryFixture(t)
	// Preexisting rows precede automatic capture, simulating a converted store.
	f.with(f.low, func(c *sqlite.Conn) error { return bridge.DetachCapture(c) })
	f.exec(f.low, "INSERT INTO notes VALUES('one','baseline','email')")
	f.with(f.low, func(c *sqlite.Conn) error { return bridge.AttachCapture(c, f.lcfg) })
	var sender *bridge.Sender
	create := func() {
		t.Helper()
		if err := murmurdb.WithNativeControl(context.Background(), f.low, func(c *sqlite.Conn) error {
			var err error
			sender, err = bridge.NewSender(c, f.lcfg.Database, "test", f.dir, true)
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	create()
	defer func() { sender.Close() }()
	// First poll prepares a batch, but leaves publication for the next poll.
	if err := sender.Poll(1); err != nil {
		t.Fatal(err)
	}
	if s := sender.Status(); s.BaselineRows != 1 || s.Published != 0 {
		t.Fatalf("prepare: %+v", s)
	}
	sender.Close()
	create()
	f.newReceiver(f.pub)
	if err := sender.Poll(1); err != nil {
		t.Fatal(err)
	}
	f.poll()
	f.check("baseline:email")
	if err := sender.Poll(1); err != nil {
		t.Fatal(err)
	}
	if s := sender.Status(); !s.BaselineComplete || s.BaselineRows != 0 || s.Published != 1 {
		t.Fatalf("resume: %+v", s)
	}
	sender.Close()
	create()
	if err := sender.Poll(1); err != nil {
		t.Fatal(err)
	}
	if s := sender.Status(); !s.BaselineComplete || s.BaselineRows != 0 || s.Published != 0 {
		t.Fatalf("baseline repeated: %+v", s)
	}
	if err := sender.Start(10 * time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if err := f.receiver.Start(10 * time.Millisecond); err != nil {
		t.Fatal(err)
	}
	f.exec(f.low, "UPDATE notes SET name='live' WHERE id='one'")
	deadline := time.Now().Add(3 * time.Second)
	for f.receiver.Status().Applied < 2 {
		if time.Now().After(deadline) {
			t.Fatalf("live ferry stalled: sender=%+v receiver=%+v", sender.Status(), f.receiver.Status())
		}
		time.Sleep(5 * time.Millisecond)
	}
	sender.Stop()
	f.receiver.Stop()
	f.check("live:email")
}

func TestFerryQuarantinePreservesSharedArtifactsAndHasQuota(t *testing.T) {
	f := newFerryFixture(t)
	quarantine := t.TempDir()
	create := func() {
		t.Helper()
		if f.receiver != nil {
			f.receiver.Close()
		}
		err := murmurdb.WithNativeControl(context.Background(), f.high, func(c *sqlite.Conn) error {
			var err error
			f.receiver, err = bridge.NewReceiver(c, bridge.ReceiverConfig{Source: f.lcfg.Database, Exporter: f.lcfg.Node, Secret: f.secret, Signers: [][32]byte{f.pub}, Stream: "test", Directory: f.dir, QuarantineDirectory: quarantine})
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	f.exec(f.low, "INSERT INTO notes VALUES('one','first','email')")
	path := f.publish()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	data[len(data)-1] ^= 1
	f.artifact(data)
	create()
	f.poll()
	f.poll()
	entries, err := os.ReadDir(quarantine)
	if err != nil || len(entries) != 1 {
		t.Fatalf("quarantine duplicates: %v %v", entries, err)
	}
	preserved, err := os.ReadFile(filepath.Join(quarantine, entries[0].Name()))
	if err != nil || string(preserved) != string(data) {
		t.Fatalf("quarantine content: %v", err)
	}
	if entries, err := os.ReadDir(f.dir); err != nil || len(entries) != 1 {
		t.Fatalf("shared artifact removed: %v %v", entries, err)
	}
	// Exhausting private quarantine returns backpressure without losing shared
	// artifacts or importing the rejected bundle. Bounded count avoids full scans.
	for i := 0; i < 1023; i++ {
		if err := os.WriteFile(filepath.Join(quarantine, hex.EncodeToString([]byte{byte(i >> 8), byte(i)})+".occupied"), nil, 0600); err != nil {
			t.Fatal(err)
		}
	}
	data[len(data)-2] ^= 1
	f.artifact(data)
	err = f.receiver.Poll(256)
	var native *bridge.Error
	if !errors.As(err, &native) || native.Code != 13 {
		t.Fatalf("quarantine quota: %v", err)
	}
	if s := f.receiver.Status(); s.Applied != 0 {
		t.Fatalf("rejected bundle imported: %+v", s)
	}
}

func TestFerryNativeClockReleaseAndRowDeletion(t *testing.T) {
	f := newFerryFixture(t)
	f.newReceiver(f.pub)
	f.exec(f.low, "INSERT INTO notes VALUES('one','Low','email')")
	f.publish()
	f.poll()
	f.exec(f.high, "UPDATE notes SET name='High' WHERE id='one'")
	f.exec(f.low, "UPDATE notes SET name='new Low' WHERE id='one'")
	f.publish()
	f.poll()
	f.check("High:email")
	release := func(column *string, want bool) {
		t.Helper()
		f.with(f.high, func(c *sqlite.Conn) error {
			got, err := bridge.ReleaseOwnership(c, "notes", []any{"one"}, column)
			if err == nil && got != want {
				t.Fatalf("release=%v want %v", got, want)
			}
			return err
		})
	}
	col := "name"
	release(&col, true)
	f.check("new Low:email")
	release(&col, false)
	f.exec(f.high, "DELETE FROM notes WHERE id='one'")
	f.exec(f.low, "UPDATE notes SET name='after deletion' WHERE id='one'")
	f.publish()
	f.poll()
	var n int
	if err := f.high.QueryRow("SELECT count(*) FROM notes").Scan(&n); err != nil || n != 0 {
		t.Fatalf("row delete claim lost: %d %v", n, err)
	}
	release(nil, true)
	f.check("after deletion:email")
	release(nil, false)
	// A release projection never becomes a new High edit or claims Low fields.
	var owned int
	if err := f.high.QueryRow("SELECT count(*) FROM murmur_bridge_owners").Scan(&owned); err != nil || owned != 2 {
		t.Fatalf("projection created extra owners: %d %v", owned, err)
	}
	f.exec(f.low, "UPDATE notes SET name='latest',email='latest email' WHERE id='one'")
	f.publish()
	f.poll()
	f.check("latest:latest email")
	f.with(f.low, func(c *sqlite.Conn) error {
		if _, err := bridge.ReleaseOwnership(c, "notes", []any{"one"}, &col); err == nil {
			t.Fatal("Low released High ownership")
		}
		return nil
	})
}

func TestFerryWorkerWaitsForCanceledSQLTransaction(t *testing.T) {
	f := newFerryFixture(t)
	f.newReceiver(f.pub)
	f.exec(f.low, "INSERT INTO notes VALUES('one','after cancellation','email')")
	f.publish()
	tx, err := f.high.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if err := f.receiver.Start(10 * time.Millisecond); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
	defer cancel()
	var sum int64
	err = tx.QueryRowContext(ctx, "WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<100000000) SELECT sum(x) FROM n").Scan(&sum)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("query cancellation: %v", err)
	}
	if s := f.receiver.Status(); s.Applied != 0 {
		t.Fatalf("worker entered open SQL transaction: %+v", s)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for f.receiver.Status().Applied < 1 {
		if time.Now().After(deadline) {
			t.Fatalf("native worker inherited cancellation or writer lock: %+v", f.receiver.Status())
		}
		time.Sleep(5 * time.Millisecond)
	}
	f.receiver.Stop()
	f.check("after cancellation:email")
	if s := f.receiver.Status(); s.LastResult != 0 {
		t.Fatalf("native worker interrupted: %+v", s)
	}
}
