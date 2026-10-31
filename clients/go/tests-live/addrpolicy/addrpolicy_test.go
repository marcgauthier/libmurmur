// Live scenario: replication address policy (allowed_networks CIDR)
// enforcement across processes.
//
// Port of MURMUR-SQL addrpolicy: node 0 admits loopback peers
// (127.0.0.0/8), node 1's TEST-NET policy (198.51.100.0/24) excludes
// all actual loopback socket addresses, node 2 is unrestricted; the
// admitted pair replicates while the denied node keeps its write
// local. The reference SetConfig section writes become murmur_config
// allowed_networks updates plus replication restart (QUIC settings
// reload on every Start), following the allow-nodes port.
package addrpolicy

import (
	"os"
	"testing"
	"time"

	goharness "github.com/marcgauthier/sqlite-murmur-go/clients/go/tests-live/goharness"
)

func TestAddressPolicyAcrossProcesses(t *testing.T) {
	goharness.SkipUnlessLive(t)
	cluster, err := goharness.NewCluster(goharness.ClusterOptions{
		Name:     "addrpolicy",
		NumNodes: 3,
	})
	if err != nil {
		t.Fatalf("cluster setup: %v", err)
	}
	failed := true
	defer func() { cluster.Finish(failed) }()

	// Stop all nodes to configure address policies cleanly without stale
	// QUIC sessions.
	for _, i := range []int{0, 1, 2} {
		if err := cluster.StopNode(i); err != nil {
			t.Fatalf("stop node %d: %v", i, err)
		}
	}

	// Node 0 admits loopback peers.
	if err := setAllowedNetworks(cluster, 0, `["127.0.0.0/8"]`); err != nil {
		t.Fatalf("node 0 allow loopback: %v", err)
	}
	// Node 1 admits only TEST-NET peers (denies all loopback addresses).
	if err := setAllowedNetworks(cluster, 1, `["198.51.100.0/24"]`); err != nil {
		t.Fatalf("node 1 allow TEST-NET: %v", err)
	}
	// Node 2 has unrestricted allowed_networks (default empty allows all).

	for _, i := range []int{0, 1, 2} {
		if err := cluster.StartNode(i); err != nil {
			t.Fatalf("restart node %d: %v", i, err)
		}
	}

	for i := 0; i < cluster.Len(); i++ {
		if _, err := cluster.Node(i).Simple(
			"CREATE TABLE IF NOT EXISTS records(id INTEGER PRIMARY KEY NOT NULL, name TEXT NOT NULL DEFAULT '')"); err != nil {
			t.Fatalf("node %d create records: %v", i, err)
		}
		if err := cluster.Node(i).SetTableReplicated("records", true); err != nil {
			t.Fatalf("node %d replicate records: %v", i, err)
		}
		if err := cluster.Node(i).Flush(); err != nil {
			t.Fatalf("node %d flush schema: %v", i, err)
		}
	}

	if _, err := cluster.Node(0).Execute(
		"INSERT INTO records(id, name) VALUES($1, $2)", int64(1), "allowed-loopback"); err != nil {
		t.Fatalf("node 0 insert: %v", err)
	}
	if err := cluster.Node(0).Flush(); err != nil {
		t.Fatalf("node 0 flush: %v", err)
	}
	if _, err := cluster.Node(1).Execute(
		"INSERT INTO records(id, name) VALUES($1, $2)", int64(2), "denied-testnet"); err != nil {
		t.Fatalf("node 1 insert: %v", err)
	}
	if err := cluster.Node(1).Flush(); err != nil {
		t.Fatalf("node 1 flush: %v", err)
	}
	if _, err := cluster.Node(2).Execute(
		"INSERT INTO records(id, name) VALUES($1, $2)", int64(3), "unrestricted-loopback"); err != nil {
		t.Fatalf("node 2 insert: %v", err)
	}
	if err := cluster.Node(2).Flush(); err != nil {
		t.Fatalf("node 2 flush: %v", err)
	}

	// Admitted pair (Node 0 and Node 2) must converge on both rows.
	expectedAdmitted := [][]string{{"allowed-loopback"}, {"unrestricted-loopback"}}
	if err := goharness.AssertRows(cluster, []int{0, 2},
		"SELECT name FROM records ORDER BY name", expectedAdmitted); err != nil {
		t.Fatalf("converge admitted pair: %v", err)
	}

	// Settle window: several dial/accept retries must not move the denied
	// node's state.
	time.Sleep(1000 * time.Millisecond)

	// Node 1 must retain ONLY its local write.
	n1Rows, err := cluster.Node(1).Simple("SELECT name FROM records ORDER BY name")
	if err != nil {
		t.Fatalf("node 1 read names: %v", err)
	}
	if !equalRows(n1Rows, [][]string{{"denied-testnet"}}) {
		t.Fatalf("denied node state changed across network: want only its local row, got %v", n1Rows)
	}

	// Node 0 must retain exactly the 2 admitted rows.
	n0Rows, err := cluster.Node(0).Simple("SELECT name FROM records ORDER BY name")
	if err != nil {
		t.Fatalf("node 0 read names: %v", err)
	}
	if !equalRows(n0Rows, expectedAdmitted) {
		t.Fatalf("admitted node received unexpected extra rows: got %v", n0Rows)
	}

	// Verify peer topology via MURMUR SHOW PEERS.
	n1Peers, err := cluster.Node(1).ShowPeers()
	if err != nil {
		t.Fatalf("node 1 show peers: %v", err)
	}
	for _, p := range n1Peers {
		if p.Connected {
			t.Fatalf("denied Node 1 unexpectedly formed a connected session with %s", p.NodeID)
		}
	}

	for i := 0; i < cluster.Len(); i++ {
		if _, err := os.Stat(cluster.Node(i).Dir); err != nil {
			t.Fatalf("node %d directory does not exist", i)
		}
	}
	failed = false
}

// setAllowedNetworks writes the replication.allowed_networks CIDR list
// (JSON array) to node i's murmur_config; it takes effect on restart.
func setAllowedNetworks(cluster *goharness.Cluster, i int, cidrs string) error {
	_, err := cluster.Node(i).Simple(
		"INSERT INTO murmur_config(name,value) VALUES('allowed_networks','" + cidrs +
			"') ON CONFLICT(name) DO UPDATE SET value=excluded.value")
	return err
}

func equalRows(a, b [][]string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if len(a[i]) != len(b[i]) {
			return false
		}
		for j := range a[i] {
			if a[i][j] != b[i][j] {
				return false
			}
		}
	}
	return true
}
