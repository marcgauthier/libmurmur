package replication

import (
	"crypto/ed25519"
	"testing"

	"github.com/marcgauthier/libmurmur/clients/go/bindings/bridge"
	"github.com/marcgauthier/libmurmur/clients/go/bindings/sqlite"
	"github.com/marcgauthier/libmurmur/clients/go/pkgs/tx"
)

func TestBackendNativeBridgeImportAndOwnershipRelease(t *testing.T) {
	open := func() *sqlite.Conn {
		db, err := sqlite.Open(":memory:", sqlite.OpenReadWrite|sqlite.OpenCreate)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { db.Close() })
		if err := db.Exec("CREATE TABLE notes(id TEXT PRIMARY KEY NOT NULL,title TEXT)"); err != nil {
			t.Fatal(err)
		}
		if _, err := bridge.RegisterTable(db, "notes"); err != nil {
			t.Fatal(err)
		}
		return db
	}
	low, high := open(), open()
	var seed, secret, pub [32]byte
	seed[0] = 3
	secret[0] = 7
	copy(pub[:], ed25519.NewKeyFromSeed(seed[:])[32:])
	recipient, err := bridge.RecipientPublic(secret)
	if err != nil {
		t.Fatal(err)
	}
	if err := bridge.AttachCapture(low, bridge.CaptureConfig{Role: bridge.Low, Database: [16]byte{1}, Node: [16]byte{2}, Signer: seed, Recipient: recipient, Stream: "backend"}); err != nil {
		t.Fatal(err)
	}
	if err := bridge.AttachCapture(high, bridge.CaptureConfig{Role: bridge.High, Database: [16]byte{9}, Node: [16]byte{3}, Stream: "backend"}); err != nil {
		t.Fatal(err)
	}
	backend := NewOfflineBackend(high, NodeID{9}, NodeID{3})
	policy := tx.BridgeHeader{Database: tx.NodeID{1}, Stream: "backend", Signer: pub, Receiver: secret}
	write := func(db *sqlite.Conn, sql string) {
		t.Helper()
		if err := bridge.Write(db, func(c *sqlite.Conn) error { return c.Exec(sql) }); err != nil {
			t.Fatal(err)
		}
	}
	importNext := func() []byte {
		t.Helper()
		seq, bundle, err := bridge.Next(low, [16]byte{1}, "backend")
		if err != nil {
			t.Fatal(err)
		}
		ok, err := backend.ImportBridge(policy, bundle)
		if err != nil || !ok {
			t.Fatalf("import=%v %v", ok, err)
		}
		if err := bridge.Ack(low, [16]byte{1}, "backend", seq); err != nil {
			t.Fatal(err)
		}
		return bundle
	}
	title := func() string {
		t.Helper()
		st, err := high.Prepare("SELECT title FROM notes WHERE id='one'")
		if err != nil {
			t.Fatal(err)
		}
		defer st.Close()
		done, err := st.Step()
		if err != nil || done {
			t.Fatalf("read imported row: done=%v err=%v", done, err)
		}
		return st.ColumnText(0)
	}
	write(low, "INSERT INTO notes VALUES('one','Low')")
	bundle := importNext()
	if got := title(); got != "Low" {
		t.Fatal(got)
	}
	if ok, err := backend.ImportBridge(policy, bundle); err != nil || ok {
		t.Fatalf("duplicate import=%v %v", ok, err)
	}
	write(high, "UPDATE notes SET title='High' WHERE id='one'")
	write(low, "UPDATE notes SET title='new Low' WHERE id='one'")
	importNext()
	if got := title(); got != "High" {
		t.Fatalf("High claim lost: %q", got)
	}
	st, err := high.Prepare("SELECT murmur_bridge_values('one')")
	if err != nil {
		t.Fatal(err)
	}
	done, err := st.Step()
	if err != nil || done {
		t.Fatalf("encode key: %v %v", done, err)
	}
	key := st.ColumnBlob(0)
	st.Close()
	column := "title"
	if released, err := backend.ReleaseOwnership("notes", key, &column); err != nil || !released {
		t.Fatalf("release=%v %v", released, err)
	}
	if got := title(); got != "new Low" {
		t.Fatalf("release projection=%q", got)
	}
	if released, err := backend.ReleaseOwnership("notes", key, &column); err != nil || released {
		t.Fatalf("duplicate release=%v %v", released, err)
	}
	if ok, err := backend.ImportBridge(policy, []byte("forged")); err == nil || ok {
		t.Fatalf("forged import=%v %v", ok, err)
	}
	if got := title(); got != "new Low" {
		t.Fatalf("forged import changed data: %q", got)
	}
}
