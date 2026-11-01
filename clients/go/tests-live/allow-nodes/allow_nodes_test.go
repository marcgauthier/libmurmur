// Live scenario: node identity allow-list enforcement.
//
// Port of MURMUR-SQL allow-nodes: node 1's allow-list permits only
// node 0 while the other nodes accept any valid identity; node 2
// communicates with node 1 strictly indirectly through node 0, yet all
// writes converge completely. The reference SetConfig section write
// becomes a murmur_config allowed_peers update plus replication restart
// (QUIC settings reload on every Start), and the reference tokio::join!
// over the three writers becomes a sync.WaitGroup over three goroutines.
package allownodes

import (
	"fmt"
	"sort"
	"sync"
	"testing"
	"time"

	goharness "github.com/marcgauthier/libmurmur/clients/go/tests-live/goharness"
)

func TestAllowedNodeIDsAcrossProcesses(t *testing.T) {
	goharness.SkipUnlessLive(t)
	cluster, err := goharness.NewCluster(goharness.ClusterOptions{
		Name:     "allow-nodes",
		NumNodes: 3,
	})
	if err != nil {
		t.Fatalf("cluster setup: %v", err)
	}
	failed := true
	defer func() { cluster.Finish(failed) }()

	// Configure node 1 to allow only node 0.
	node0ID := cluster.NodeID(0)
	if err := cluster.StopNode(1); err != nil {
		t.Fatalf("stop node 1: %v", err)
	}
	allow := fmt.Sprintf(`["%s"]`, node0ID)
	if _, err := cluster.Node(1).Simple(
		"INSERT INTO murmur_config(name,value) VALUES('allowed_peers','" + allow +
			"') ON CONFLICT(name) DO UPDATE SET value=excluded.value"); err != nil {
		t.Fatalf("node 1 allow node 0: %v", err)
	}
	if err := cluster.StartNode(1); err != nil {
		t.Fatalf("restart node 1: %v", err)
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

	// Concurrent writers on all three nodes.
	const numWrites = 15
	var wg sync.WaitGroup
	writerErrs := make([]error, cluster.Len())
	for node := 0; node < cluster.Len(); node++ {
		wg.Add(1)
		go func(node int) {
			defer wg.Done()
			for seq := 0; seq < numWrites; seq++ {
				id := int64(node+1)*10_000 + int64(seq)
				name := fmt.Sprintf("node%d-write-%02d", node, seq)
				if _, err := cluster.Node(node).Execute(
					"INSERT INTO records(id, name) VALUES($1, $2)", id, name); err != nil {
					writerErrs[node] = err
					return
				}
			}
			if err := cluster.Node(node).Flush(); err != nil {
				writerErrs[node] = err
			}
		}(node)
	}
	wg.Wait()
	for node, err := range writerErrs {
		if err != nil {
			t.Fatalf("node %d writer: %v", node, err)
		}
	}

	// Construct expected rows (15 per node = 45 total).
	var expected [][]string
	for node := 0; node < 3; node++ {
		for seq := 0; seq < numWrites; seq++ {
			expected = append(expected, []string{fmt.Sprintf("node%d-write-%02d", node, seq)})
		}
	}
	sort.Slice(expected, func(a, b int) bool { return expected[a][0] < expected[b][0] })

	if err := goharness.AssertRows(cluster, []int{0, 1, 2},
		"SELECT name FROM records ORDER BY name", expected); err != nil {
		t.Fatalf("converge all rows: %v", err)
	}

	// Allowed topology [2, 1, 1]: node 1 sees only node 0, node 2 sees
	// only node 0, node 0 sees both.
	if err := goharness.PeerCounts(cluster, []int{0, 1, 2}, []int{2, 1, 1}, 60*time.Second); err != nil {
		t.Fatalf("peer counts: %v", err)
	}

	// Verify peer topology via SHOW PEERS:
	// Node 1 must have only node 0, NEVER node 2.
	node2ID := cluster.NodeID(2)
	n1Peers, err := cluster.Node(1).ShowPeers()
	if err != nil {
		t.Fatalf("node 1 show peers: %v", err)
	}
	for _, p := range n1Peers {
		if p.NodeID == node2ID && p.Connected {
			t.Fatal("Node 1 directly connected to unauthorized Node 2!")
		}
	}

	// Node 2 must have only node 0, NEVER node 1.
	node1ID := cluster.NodeID(1)
	n2Peers, err := cluster.Node(2).ShowPeers()
	if err != nil {
		t.Fatalf("node 2 show peers: %v", err)
	}
	for _, p := range n2Peers {
		if p.NodeID == node1ID && p.Connected {
			t.Fatal("Node 2 directly connected to unauthorized Node 1!")
		}
	}
	failed = false
}
