// Two native Low domains share one directory and import through independent
// source/stream lanes on a single High node.
package bridgetwostreams

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/marcgauthier/libmurmur/clients/go/bindings/bridge"
	goharness "github.com/marcgauthier/libmurmur/clients/go/tests-live/goharness"
)

func TestTwoLowDomainsIntoOneHigh(t *testing.T) {
	goharness.SkipUnlessLive(t)
	clusters := make([]*goharness.Cluster, 0, 3)
	defer func() {
		for _, c := range clusters {
			c.Finish(t.Failed())
		}
	}()
	for _, name := range []string{"bridge-first-low", "bridge-second-low", "bridge-two-high"} {
		c, err := goharness.NewCluster(goharness.ClusterOptions{Name: name, NumNodes: 1})
		if err != nil {
			t.Fatal(err)
		}
		clusters = append(clusters, c)
		if err := c.Node(0).ExecBatch("CREATE TABLE notes(id TEXT PRIMARY KEY NOT NULL,name TEXT,email TEXT)"); err != nil {
			t.Fatal(err)
		}
	}
	first, second, high := clusters[0], clusters[1], clusters[2]
	directory := t.TempDir()
	quarantine := []string{t.TempDir(), t.TempDir()}
	if err := high.Node(0).ConfigureBridgeCapture(bridge.CaptureConfig{Role: bridge.High, Database: high.Group, Node: high.Node(0).ID, Stream: "high"}, "notes"); err != nil {
		t.Fatal(err)
	}
	streams := []string{"first", "second"}
	for i, low := range []*goharness.Cluster{first, second} {
		var seed, secret, pub [32]byte
		seed[0] = byte(i + 1)
		secret[0] = byte(i + 11)
		copy(pub[:], ed25519.NewKeyFromSeed(seed[:])[32:])
		recipient, err := bridge.RecipientPublic(secret)
		if err != nil {
			t.Fatal(err)
		}
		cfg := bridge.CaptureConfig{Role: bridge.Low, Database: low.Group, Node: low.Node(0).ID, Signer: seed, Recipient: recipient, Stream: streams[i], StagingBytes: 16 << 20}
		if err := low.Node(0).ConfigureBridgeCapture(cfg, "notes"); err != nil {
			t.Fatal(err)
		}
		if err := low.Node(0).StartBridgeSender(low.Group, streams[i], directory, true); err != nil {
			t.Fatal(err)
		}
		if err := high.Node(0).StartBridgeReceiver(bridge.ReceiverConfig{Source: low.Group, Exporter: low.Node(0).ID, Secret: secret, Signers: [][32]byte{pub}, Stream: streams[i], Directory: directory, QuarantineDirectory: quarantine[i], StagingBytes: 16 << 20}); err != nil {
			t.Fatal(err)
		}
	}
	exec := func(node *goharness.Node, sql string, args ...any) {
		t.Helper()
		if _, err := node.Execute(sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(first.Node(0), "INSERT INTO notes VALUES(?,?,?)", "first", "First", "a")
	exec(second.Node(0), "INSERT INTO notes VALUES(?,?,?)", "second", "Second", "b")
	wait := func(want string) {
		t.Helper()
		if !goharness.WaitUntil(5*time.Second, 10*time.Millisecond, func() bool {
			rows, err := high.Node(0).Simple("SELECT group_concat(name||':'||email,'|') FROM (SELECT * FROM notes ORDER BY id)")
			return err == nil && len(rows) == 1 && rows[0][0] == want
		}) {
			t.Fatalf("streams did not converge to %q: %+v", want, high.Node(0).BridgeReceiverStatus())
		}
	}
	wait("First:a|Second:b")
	exec(high.Node(0), "UPDATE notes SET name='High' WHERE id='first'")
	exec(first.Node(0), "UPDATE notes SET name='First updated',email='a2' WHERE id='first'")
	exec(second.Node(0), "UPDATE notes SET name='Second updated',email='b2' WHERE id='second'")
	wait("High:a2|Second updated:b2")
	for i, low := range []*goharness.Cluster{first, second} {
		s := high.Node(0).BridgeReceiverStatusFor(low.Group, streams[i])
		if s.Applied != 2 || s.Rejected != 0 || s.LastResult != 0 {
			t.Fatalf("lane %s: %+v", streams[i], s)
		}
		rows, err := low.Node(0).Simple("SELECT count(*) FROM murmur_bridge_artifact WHERE kind='out'")
		if err != nil || len(rows) != 1 || rows[0][0] != "0" {
			t.Fatalf("outbox %s not drained: %v %v", streams[i], rows, err)
		}
	}
	// Corrupt only the second stream. Its receiver quarantines the ciphertext;
	// the first stream continues to import and retains an empty quarantine.
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	var forged []byte
	for _, entry := range entries {
		b, err := os.ReadFile(filepath.Join(directory, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if len(b) > 345 && string(b[4:20]) == string(second.Group[:]) {
			forged = b
			break
		}
	}
	if forged == nil {
		t.Fatal("second-stream artifact not published")
	}
	forged[len(forged)-1] ^= 1
	sum := sha256.Sum256(forged)
	if err := os.WriteFile(filepath.Join(directory, hex.EncodeToString(sum[:])+".bundle"), forged, 0600); err != nil {
		t.Fatal(err)
	}
	exec(first.Node(0), "UPDATE notes SET email='a3' WHERE id='first'")
	wait("High:a3|Second updated:b2")
	if !goharness.WaitUntil(time.Second, 10*time.Millisecond, func() bool { return high.Node(0).BridgeReceiverStatusFor(second.Group, "second").Rejected > 0 }) {
		t.Fatal("second stream did not reject forgery")
	}
	for i, want := range []int{0, 1} {
		entries, err := os.ReadDir(quarantine[i])
		if err != nil || len(entries) != want {
			t.Fatalf("quarantine %d: %d %v", i, len(entries), err)
		}
	}
	rows, err := high.Node(0).Simple("SELECT count(*) FROM murmur_bridge_artifact WHERE kind='in'")
	if err != nil || len(rows) != 1 || rows[0][0] != "0" {
		t.Fatalf("inbox did not burn down: %v %v", rows, err)
	}
}
