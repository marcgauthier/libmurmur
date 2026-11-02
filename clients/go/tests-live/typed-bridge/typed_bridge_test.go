// Live native Low and High domains exchange typed rows through the directory
// ferry. High claims, release and durable restart use the same C APIs exposed
// by the SQL-driver integration.
package typedbridge

import (
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/marcgauthier/libmurmur/clients/go/bindings/bridge"
	goharness "github.com/marcgauthier/libmurmur/clients/go/tests-live/goharness"
)

func TestTypedBridgeImportsIntoNativeRime(t *testing.T) {
	goharness.SkipUnlessLive(t)
	low, err := goharness.NewCluster(goharness.ClusterOptions{Name: "typed-bridge-low", NumNodes: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { low.Finish(t.Failed()) }()
	high, err := goharness.NewCluster(goharness.ClusterOptions{Name: "typed-bridge-high", NumNodes: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { high.Finish(t.Failed()) }()
	directory, quarantine := t.TempDir(), t.TempDir()
	for _, cluster := range []*goharness.Cluster{low, high} {
		if err := cluster.Node(0).ExecBatch("CREATE TABLE notes(id TEXT PRIMARY KEY NOT NULL,name TEXT,email TEXT)"); err != nil {
			t.Fatal(err)
		}
	}
	var seed, secret, signer [32]byte
	seed[0] = 7
	secret[0] = 9
	copy(signer[:], ed25519.NewKeyFromSeed(seed[:])[32:])
	recipient, err := bridge.RecipientPublic(secret)
	if err != nil {
		t.Fatal(err)
	}
	if err := low.Node(0).ConfigureBridgeCapture(bridge.CaptureConfig{Role: bridge.Low, Database: low.Group, Node: low.Node(0).ID, Signer: seed, Recipient: recipient, Stream: "typed-stream"}, "notes"); err != nil {
		t.Fatal(err)
	}
	if err := low.Node(0).StartBridgeSender(low.Group, "typed-stream", directory, true); err != nil {
		t.Fatal(err)
	}
	configureHigh := func() {
		t.Helper()
		if err := high.Node(0).ConfigureBridgeCapture(bridge.CaptureConfig{Role: bridge.High, Database: high.Group, Node: high.Node(0).ID, Stream: "typed-stream"}, "notes"); err != nil {
			t.Fatal(err)
		}
		if err := high.Node(0).StartBridgeReceiver(bridge.ReceiverConfig{Source: low.Group, Exporter: low.Node(0).ID, Secret: secret, Signers: [][32]byte{signer}, Stream: "typed-stream", Directory: directory, QuarantineDirectory: quarantine}); err != nil {
			t.Fatal(err)
		}
	}
	configureHigh()
	exec := func(node *goharness.Node, query string) {
		t.Helper()
		if _, err := node.Execute(query); err != nil {
			t.Fatal(err)
		}
	}
	wait := func(want string) {
		t.Helper()
		if !goharness.WaitUntil(5*time.Second, 10*time.Millisecond, func() bool {
			rows, err := high.Node(0).Simple("SELECT name||':'||email FROM notes WHERE id='one'")
			return err == nil && len(rows) == 1 && rows[0][0] == want
		}) {
			t.Fatalf("row did not become %q: sender=%+v receiver=%+v", want, low.Node(0).BridgeSenderStatus(), high.Node(0).BridgeReceiverStatus())
		}
	}
	exec(low.Node(0), "INSERT INTO notes VALUES('one','Low','first')")
	wait("Low:first")
	exec(high.Node(0), "UPDATE notes SET name='High' WHERE id='one'")
	exec(low.Node(0), "UPDATE notes SET name='new Low',email='second' WHERE id='one'")
	wait("High:second")
	if err := high.ReopenNode(0); err != nil {
		t.Fatal(err)
	}
	configureHigh()
	wait("High:second")
	column := "name"
	if released, err := high.Node(0).ReleaseBridgeOwnership("notes", []any{"one"}, &column); err != nil || !released {
		t.Fatalf("release=%v %v", released, err)
	}
	wait("new Low:second")
	exec(low.Node(0), "UPDATE notes SET name='latest',email='third' WHERE id='one'")
	wait("latest:third")
	if err := high.ReopenNode(0); err != nil {
		t.Fatal(err)
	}
	configureHigh()
	wait("latest:third")
	if !goharness.WaitUntil(time.Second, 10*time.Millisecond, func() bool { return high.Node(0).BridgeReceiverStatus().Duplicate >= 3 }) {
		t.Fatalf("replay receipts lost: %+v", high.Node(0).BridgeReceiverStatus())
	}
	if s := high.Node(0).BridgeReceiverStatus(); s.Applied != 0 || s.Rejected != 0 {
		t.Fatalf("restart reapplied or rejected committed bundles: %+v", s)
	}
}
