package highlowpeer

import (
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/marcgauthier/libmurmur/clients/go/bindings/bridge"
	goharness "github.com/marcgauthier/libmurmur/clients/go/tests-live/goharness"
)

// Only the first High node scans the ferry. The other receives signed source
// proofs, shadows, ownership and release through native peer replication.
func RunSignedHighLowCluster(t *testing.T, prefix string) {
	goharness.SkipUnlessLive(t)
	low, err := goharness.NewCluster(goharness.ClusterOptions{Name: prefix + "-low", NumNodes: 2})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { low.Finish(t.Failed()) }()
	high, err := goharness.NewCluster(goharness.ClusterOptions{Name: prefix + "-high", NumNodes: 2})
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
	var peerSeeds, peerKeys [2][32]byte
	for i := range peerSeeds {
		peerSeeds[i][0] = byte(20 + i)
		copy(peerKeys[i][:], ed25519.NewKeyFromSeed(peerSeeds[i][:])[32:])
	}
	for _, cluster := range []*goharness.Cluster{low, high} {
		for i := 0; i < cluster.Len(); i++ {
			if err := cluster.Node(i).ExecBatch("CREATE TABLE notes(id TEXT PRIMARY KEY NOT NULL,name TEXT,email TEXT)"); err != nil {
				t.Fatal(err)
			}
		}
	}
	var lowSeeds, lowKeys [2][32]byte
	for i := range lowSeeds {
		lowSeeds[i][0] = byte(30 + i)
		copy(lowKeys[i][:], ed25519.NewKeyFromSeed(lowSeeds[i][:])[32:])
	}
	configureLow := func(i int) {
		t.Helper()
		node := low.Node(i)
		if err := node.ConfigureBridgeCapture(bridge.CaptureConfig{Role: bridge.Low, Database: low.Group, Node: node.ID, Signer: seed, Recipient: recipient, Stream: "peer"}, "notes"); err != nil {
			t.Fatal(err)
		}
		if err := node.ConfigureLowBridgePeer(low.Group, lowSeeds[i], low.Node(0).ID, map[[16]byte][32]byte{low.Node(1 - i).ID: lowKeys[1-i]}); err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			if err := node.StartBridgeSender(low.Group, "peer", directory, true); err != nil {
				t.Fatal(err)
			}
		}
	}
	configureHigh := func(i int) {
		t.Helper()
		node := high.Node(i)
		if err := node.ConfigureBridgeCapture(bridge.CaptureConfig{Role: bridge.High, Database: high.Group, Node: node.ID, Stream: "peer"}, "notes"); err != nil {
			t.Fatal(err)
		}
		if err := node.ConfigureBridgePeer(high.Group, peerSeeds[i], map[[16]byte][32]byte{high.Node(1 - i).ID: peerKeys[1-i]}); err != nil {
			t.Fatal(err)
		}
		for j := 0; j < 2; j++ {
			if err := node.TrustBridgeSourceOrigin(low.Group, low.Node(j).ID, lowKeys[j]); err != nil {
				t.Fatal(err)
			}
		}
		cfg := bridge.ReceiverConfig{Source: low.Group, Exporter: low.Node(0).ID, Secret: secret, Signers: [][32]byte{signer}, Stream: "peer", Directory: directory}
		if i == 0 {
			if err := node.StartBridgeReceiver(cfg); err != nil {
				t.Fatal(err)
			}
		} else {
			cfg.Directory = t.TempDir()
			if err := node.ConfigureBridgeReceiverSource(cfg); err != nil {
				t.Fatal(err)
			}
		}

	}
	for _, cluster := range []*goharness.Cluster{low, high} {
		for i := 0; i < 2; i++ {
			if err := cluster.Node(i).ExecBatch("CREATE TABLE meshgate(id INTEGER PRIMARY KEY NOT NULL)"); err != nil {
				t.Fatal(err)
			}
			if err := cluster.Node(i).SetTableReplicated("meshgate", true); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := cluster.Node(0).Execute("INSERT INTO meshgate VALUES(1)"); err != nil {
			t.Fatal(err)
		}
		if err := cluster.Node(0).Flush(); err != nil {
			t.Fatal(err)
		}
		if err := goharness.AssertRows(cluster, []int{0, 1}, "SELECT id FROM meshgate", [][]string{{"1"}}); err != nil {
			t.Fatal(err)
		}
	}
	configureLow(0)
	configureLow(1)
	configureHigh(0)
	configureHigh(1)
	if err := high.PeerMesh(); err != nil {
		t.Fatal(err)
	}
	exec := func(node *goharness.Node, query string) {
		t.Helper()
		if _, err := node.Execute(query); err != nil {
			t.Fatal(err)
		}
	}
	wait := func(want string) {
		t.Helper()
		if !goharness.WaitUntil(15*time.Second, 10*time.Millisecond, func() bool {
			for i := 0; i < 2; i++ {
				rows, err := high.Node(i).Simple("SELECT name||':'||email FROM notes WHERE id='one'")
				if err != nil || len(rows) != 1 || rows[0][0] != want {
					return false
				}
			}
			return true
		}) {
			for i := 0; i < 2; i++ {
				rows, _ := high.Node(i).Simple("SELECT name||':'||email FROM notes WHERE id='one'")
				heads, _ := high.Node(i).Simple("SELECT hex(origin),sequence FROM murmur_bridge_peer_heads")
				peers, _ := high.Node(i).ShowPeers()
				status, _ := high.Node(i).ShowStatus()
				replication, _ := high.Node(i).ShowReplication()
				journal, _ := high.Node(i).Simple("SELECT count(*) FROM murmur_bridge_peer_log")
				changes, _ := high.Node(i).Simple("SELECT [table],count(*) FROM crsql_changes GROUP BY [table]")
				t.Logf("native changes=%v", changes)
				t.Logf("node %d rows=%v heads=%v journal=%v peers=%+v status=%+v replication=%+v", i, rows, heads, journal, peers, status, replication)
			}
			t.Fatalf("High peers did not converge to %q", want)
		}
	}
	exec(low.Node(1), "INSERT INTO notes VALUES('one','Low','email')")
	wait("Low:email")
	exec(low.Node(0), "UPDATE notes SET email='exporter email' WHERE id='one'")
	wait("Low:exporter email")
	exec(high.Node(0), "UPDATE notes SET name='High zero' WHERE id='one'")
	wait("High zero:exporter email")
	exec(high.Node(1), "UPDATE notes SET name='High one' WHERE id='one'")
	wait("High one:exporter email")
	exec(low.Node(1), "UPDATE notes SET name='latest Low',email='new email' WHERE id='one'")
	wait("High one:new email")
	column := "name"
	if ok, err := high.Node(0).ReleaseBridgeOwnership("notes", []any{"one"}, &column); err != nil || !ok {
		t.Fatalf("release=%v %v", ok, err)
	}
	wait("latest Low:new email")
	if err := high.ReopenNode(1); err != nil {
		t.Fatal(err)
	}
	configureHigh(1)
	wait("latest Low:new email")
	exec(high.Node(0), "DELETE FROM notes WHERE id='one'")
	if !goharness.WaitUntil(15*time.Second, 10*time.Millisecond, func() bool {
		for i := 0; i < 2; i++ {
			rows, err := high.Node(i).Simple("SELECT count(*) FROM notes")
			if err != nil || len(rows) != 1 || rows[0][0] != "0" {
				return false
			}
		}
		return true
	}) {
		t.Fatal("row-delete claim did not replicate")
	}
	if ok, err := high.Node(1).ReleaseBridgeOwnership("notes", []any{"one"}, nil); err != nil || !ok {
		t.Fatalf("row release=%v %v", ok, err)
	}
	wait("latest Low:new email")
	if err := low.ReopenNode(0); err != nil {
		t.Fatal(err)
	}
	configureLow(0)
	exec(low.Node(1), "UPDATE notes SET email='after exporter reopen' WHERE id='one'")
	wait("latest Low:after exporter reopen")
	for i := 0; i < 2; i++ {
		rows, err := high.Node(i).Simple("SELECT count(DISTINCT origin) FROM murmur_bridge_source_receipts")
		if err != nil || len(rows) != 1 || rows[0][0] != "2" {
			t.Fatalf("original Low writer receipts missing on High %d: %v %v", i, rows, err)
		}
	}
	if status := high.Node(1).BridgeReceiverStatus(); status.Scanned != 0 || status.Applied != 0 {
		t.Fatalf("High peer bypassed native replication by scanning ferry: %+v", status)
	}
}
