// Live scenario: contended same-key writes across nodes must resolve
// deterministically to identical LWW winners on every node.
//
// Port of MURMUR-SQL clock-skew: concurrent same-key writes on
// nodes 0-1 converge to identical winners on all 3 nodes, then node 2's
// later updates win everywhere. The reference tokio::join! over the two
// writers becomes a sync.WaitGroup over two goroutines.
package clockskew

import (
	"fmt"
	"sync"
	"testing"
	"time"

	goharness "github.com/marcgauthier/libmurmur/clients/go/tests-live/goharness"
)

// rows is the contended key count (reference: ROWS = 20).
const rows = 20

func TestSkewedClocksResolveIdenticalWinners(t *testing.T) {
	goharness.SkipUnlessLive(t)
	cluster, err := goharness.NewCluster(goharness.ClusterOptions{
		Name:     "clock-skew",
		NumNodes: 3,
	})
	if err != nil {
		t.Fatalf("cluster setup: %v", err)
	}
	failed := true
	defer func() { cluster.Finish(failed) }()

	for i := 0; i < cluster.Len(); i++ {
		if _, err := cluster.Node(i).Simple(
			"CREATE TABLE IF NOT EXISTS skew(id TEXT PRIMARY KEY NOT NULL DEFAULT '', val TEXT NOT NULL DEFAULT '')"); err != nil {
			t.Fatalf("node %d create skew: %v", i, err)
		}
		if err := cluster.Node(i).SetTableReplicated("skew", true); err != nil {
			t.Fatalf("node %d replicate skew: %v", i, err)
		}
		if err := cluster.Node(i).Flush(); err != nil {
			t.Fatalf("node %d flush schema: %v", i, err)
		}
	}

	// Phase 1: Concurrent same-key writes on node 0 and node 1.
	var wg sync.WaitGroup
	writerErrs := make([]error, 2)
	for node := 0; node < 2; node++ {
		wg.Add(1)
		go func(node int) {
			defer wg.Done()
			for i := 0; i < rows; i++ {
				id := fmt.Sprintf("skew-%02d", i)
				val := fmt.Sprintf("val-node%d-%02d", node, i)
				if _, err := cluster.Node(node).Execute(
					"INSERT OR REPLACE INTO skew(id, val) VALUES($1, $2)", id, val); err != nil {
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

	// Wait for all nodes in the cluster to converge to identical state.
	deadline := time.Now().Add(30 * time.Second)
	for {
		r0, err := cluster.Node(0).Simple("SELECT id, val FROM skew ORDER BY id")
		if err != nil {
			t.Fatalf("node 0 read skew: %v", err)
		}
		r1, err := cluster.Node(1).Simple("SELECT id, val FROM skew ORDER BY id")
		if err != nil {
			t.Fatalf("node 1 read skew: %v", err)
		}
		r2, err := cluster.Node(2).Simple("SELECT id, val FROM skew ORDER BY id")
		if err != nil {
			t.Fatalf("node 2 read skew: %v", err)
		}
		if len(r0) == rows && equalRows(r0, r1) && equalRows(r1, r2) {
			break
		}
		if !time.Now().Before(deadline) {
			t.Fatal("Cluster failed to converge to identical winners on 20 rows")
		}
		time.Sleep(50 * time.Millisecond)
	}

	// Phase 2: Sequential updates simulating higher HLC clock (fast clock
	// wins). Node 2 updates all 20 rows.
	var expectedUpdated [][]string
	for i := 0; i < rows; i++ {
		id := fmt.Sprintf("skew-%02d", i)
		val := fmt.Sprintf("val-node2-winner-%02d", i)
		if _, err := cluster.Node(2).Execute(
			"UPDATE skew SET val = $1 WHERE id = $2", val, id); err != nil {
			t.Fatalf("node 2 update %s: %v", id, err)
		}
		expectedUpdated = append(expectedUpdated, []string{id, val})
	}
	if err := cluster.Node(2).Flush(); err != nil {
		t.Fatalf("node 2 flush updates: %v", err)
	}

	// Verify all 3 nodes converge to node 2's later writes.
	if err := goharness.AssertRows(cluster, []int{0, 1, 2},
		"SELECT id, val FROM skew ORDER BY id", expectedUpdated); err != nil {
		t.Fatalf("converge node 2 winners: %v", err)
	}
	failed = false
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
