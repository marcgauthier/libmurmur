package filesbridge

import (
	"bytes"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/marcgauthier/libmurmur/clients/go/bindings/bridge"
	goharness "github.com/marcgauthier/libmurmur/clients/go/tests-live/goharness"
)

func TestTwoLowTwoHighFileBridgeLive(t *testing.T) {
	goharness.SkipUnlessLive(t)
	low, err := goharness.NewCluster(goharness.ClusterOptions{Name: "files-bridge-low", NumNodes: 2, Files: true, FileFetchInterval: 100 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { low.Finish(t.Failed()) }()
	high, err := goharness.NewCluster(goharness.ClusterOptions{Name: "files-bridge-high", NumNodes: 2, Files: true, FileFetchInterval: 100 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { high.Finish(t.Failed()) }()
	directory := t.TempDir()
	var seed, secret, signer [32]byte
	seed[0] = 7
	secret[0] = 9
	copy(signer[:], ed25519.NewKeyFromSeed(seed[:])[32:])
	recipient, err := bridge.RecipientPublic(secret)
	if err != nil {
		t.Fatal(err)
	}
	// The exporter reads peer-fetched objects. The High importer publishes native
	// metadata and objects, which the other High peer fetches under its own key.
	for _, c := range []*goharness.Cluster{low, high} {
		for i := 0; i < 2; i++ {
			if err := c.Node(i).ExecBatch("CREATE TABLE notes(id TEXT PRIMARY KEY NOT NULL,name TEXT)"); err != nil {
				t.Fatal(err)
			}
		}
	}
	configureLow := func() {
		t.Helper()
		if err := low.Node(0).ConfigureBridgeCapture(bridge.CaptureConfig{Role: bridge.Low, Database: low.Group, Node: low.Node(0).ID, Signer: seed, Recipient: recipient, Stream: "files"}, "notes"); err != nil {
			t.Fatal(err)
		}
		if err := low.Node(0).StartBridgeSender(low.Group, "files", directory, true); err != nil {
			t.Fatal(err)
		}
	}
	var highSeeds, highKeys [2][32]byte
	for i := range highSeeds {
		highSeeds[i][0] = byte(20 + i)
		copy(highKeys[i][:], ed25519.NewKeyFromSeed(highSeeds[i][:])[32:])
	}
	configureHigh := func(i int) {
		t.Helper()
		node := high.Node(i)
		if err := node.ConfigureBridgeCapture(bridge.CaptureConfig{Role: bridge.High, Database: high.Group, Node: node.ID, Stream: "files"}, "notes"); err != nil {
			t.Fatal(err)
		}
		if err := node.ConfigureBridgePeer(high.Group, highSeeds[i], map[[16]byte][32]byte{high.Node(1 - i).ID: highKeys[1-i]}); err != nil {
			t.Fatal(err)
		}
		cfg := bridge.ReceiverConfig{Source: low.Group, Exporter: low.Node(0).ID, Secret: secret, Signers: [][32]byte{signer}, Stream: "files", Directory: directory}
		if i == 0 {
			if err := node.StartBridgeReceiver(cfg); err != nil {
				t.Fatal(err)
			}
		} else {
			if err := node.ConfigureBridgeReceiverSource(cfg); err != nil {
				t.Fatal(err)
			}
		}
	}

	for _, c := range []*goharness.Cluster{low, high} {
		for i := 0; i < 2; i++ {
			if err := c.Node(i).ExecBatch("CREATE TABLE meshgate(id INTEGER PRIMARY KEY NOT NULL)"); err != nil {
				t.Fatal(err)
			}
			if err := c.Node(i).SetTableReplicated("meshgate", true); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := c.Node(0).Execute("INSERT INTO meshgate VALUES(1)"); err != nil {
			t.Fatal(err)
		}
		if err := c.Node(0).Flush(); err != nil {
			t.Fatal(err)
		}
		if err := goharness.AssertRows(c, []int{0, 1}, "SELECT id FROM meshgate", [][]string{{"1"}}); err != nil {
			t.Fatal(err)
		}
		if err := goharness.PeerCounts(c, []int{0, 1}, []int{1, 1}, 10*time.Second); err != nil {
			t.Fatal(err)
		}
	}
	configureLow()
	configureHigh(0)
	configureHigh(1)
	content := make([]byte, 384<<10)
	for i := range content {
		content[i] = byte((i*37 + i/251) % 256)
	}
	name := "bridge/proof.bin"
	if err := low.Node(1).FileUpload(name, content); err != nil {
		t.Fatal(err)
	}
	if err := low.Node(1).Flush(); err != nil {
		t.Fatal(err)
	}
	wait := func(node *goharness.Node, want []byte) {
		t.Helper()
		if !goharness.WaitUntil(20*time.Second, 20*time.Millisecond, func() bool {
			got, err := node.FileDownload(name)
			return err == nil && bytes.Equal(got, want)
		}) {
			got, downloadErr := node.FileDownload(name)
			listed, listErr := node.FileList()
			status, _ := node.Simple("SELECT name,value FROM murmur_config WHERE name LIKE '%fetch%'")
			progress, _ := node.Simple("SELECT count(*) FROM murmur_file_meta")
			t.Fatalf("file did not arrive at %s: download bytes=%d err=%v list=%+v err=%v cfg=%v meta=%v sender=%+v receiver=%+v", node.Dir, len(got), downloadErr, listed, listErr, status, progress, low.Node(0).BridgeSenderStatus(), high.Node(0).BridgeReceiverStatus())
		}
	}
	wait(low.Node(0), content)
	wait(high.Node(0), content)
	wait(high.Node(1), content)
	if s := high.Node(0).BridgeReceiverStatus(); s.FilesCompleted != 1 || s.Rejected != 0 {
		t.Fatalf("file completion: %+v", s)
	}
	// The second High node never scans the ferry. It verifies the forwarded
	// source parts and drains its encrypted chunk staging through native sync.
	if !goharness.WaitUntil(10*time.Second, 10*time.Millisecond, func() bool {
		rows, err := high.Node(1).Simple("SELECT (SELECT count(*) FROM murmur_bridge_file_transfer WHERE done=1),(SELECT count(*) FROM murmur_bridge_file_chunk),(SELECT count(*) FROM murmur_bridge_receipt)")
		return err == nil && len(rows) == 1 && rows[0][0] == "1" && rows[0][1] == "0" && rows[0][2] == "7"
	}) {
		t.Fatal("High peer did not finish and receipt forwarded file parts")
	}
	if status := high.Node(1).BridgeReceiverStatus(); status.Scanned != 0 || status.Applied != 0 {
		t.Fatalf("High file peer scanned ferry: %+v", status)
	}
	// The object bytes differ because High encrypts under a separate object key.
	objectBytes := func(dir string) [][]byte {
		var out [][]byte
		filepath.WalkDir(dir, func(path string, entry os.DirEntry, err error) error {
			if err == nil && !entry.IsDir() {
				b, e := os.ReadFile(path)
				if e == nil && bytes.HasPrefix(b, []byte("SPFO0001")) {
					out = append(out, b)
				}
			}
			return nil
		})
		return out
	}
	lowObjects := objectBytes(filepath.Join(low.Node(0).Dir, "files"))
	highObjects := objectBytes(filepath.Join(high.Node(0).Dir, "files"))
	if len(lowObjects) == 0 || len(highObjects) == 0 {
		t.Fatal("encrypted object containers missing")
	}
	for _, a := range lowObjects {
		for _, b := range highObjects {
			if bytes.Equal(a, b) {
				t.Fatal("Low ciphertext copied without High re-encryption")
			}
		}
	}
	if err := high.ReopenNode(0); err != nil {
		t.Fatal(err)
	}
	configureHigh(0)
	wait(high.Node(0), content)
	if err := low.ReopenNode(0); err != nil {
		t.Fatal(err)
	}
	configureLow()
	if !goharness.WaitUntil(2*time.Second, 10*time.Millisecond, func() bool { return high.Node(0).BridgeReceiverStatus().Duplicate >= 7 }) {
		t.Fatalf("file receipts lost: %+v", high.Node(0).BridgeReceiverStatus())
	}
	if s := low.Node(0).BridgeSenderStatus(); s.FileParts != 0 {
		t.Fatalf("completed file recaptured: %+v", s)
	}
	if s := high.Node(0).BridgeReceiverStatus(); s.FilesCompleted != 0 || s.Applied != 0 {
		t.Fatalf("completed file reapplied: %+v", s)
	}
}
