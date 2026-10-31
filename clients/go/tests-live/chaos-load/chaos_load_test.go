// Live scenario: continuous writes across a partition and healing.
//
// Port of MURMUR-SQL chaos-load: node 2 is partitioned from nodes 0-1,
// three concurrent writers insert 80 rows each, the test waits for
// divergent acknowledged state, heals the mesh, and converges on all 240
// rows plus a post-heal write. The reference starts meshed with
// membership disabled and removes peers; this stack has no peer removal,
// so the cluster boots unmeshed and only nodes 0-1 are peered, which
// isolates node 2 identically (nobody learns its address). The reference
// spawned writer tasks become a sync.WaitGroup over three goroutines.
package chaosload

import (
	"fmt"
	"sort"
	"sync"
	"testing"
	"time"

	goharness "github.com/marcgauthier/sqlite-murmur-go/clients/go/tests-live/goharness"
)

// wait is the convergence deadline (reference: WAIT = 120 s).
const wait = 120 * time.Second

func TestContinuousWritesAcrossPartitionAndHealing(t *testing.T) {
	goharness.SkipUnlessLive(t)
	cluster, err := goharness.NewCluster(goharness.ClusterOptions{
		Name:     "chaos-load",
		NumNodes: 3,
		NoMesh:   true,
	})
	if err != nil {
		t.Fatalf("start cluster: %v", err)
	}
	failed := true
	defer func() { cluster.Finish(failed) }()

	if err := goharness.Fixture(cluster); err != nil {
		t.Fatalf("fixture: %v", err)
	}
	// Peer only nodes 0-1; node 2 stays isolated (no seeds, no dials).
	if err := cluster.Node(0).PeerAdd(cluster.Node(1).Addr); err != nil {
		t.Fatalf("peer 0->1: %v", err)
	}
	if err := cluster.Node(1).PeerAdd(cluster.Node(0).Addr); err != nil {
		t.Fatalf("peer 1->0: %v", err)
	}
	if err := goharness.PeerCounts(cluster, []int{0, 1, 2}, []int{1, 1, 0}, wait); err != nil {
		t.Fatalf("peer counts: %v", err)
	}
	var wg sync.WaitGroup
	acked := make([][][]string, 3)
	writerErrs := make([]error, 3)
	for node := 0; node < 3; node++ {
		wg.Add(1)
		go func(node int) {
			defer wg.Done()
			client := cluster.Node(node)
			var got [][]string
			for n := 0; n < 80; n++ {
				id := fmt.Sprintf("n%d-%04d", node, n)
				name := fmt.Sprintf("continuous-%s", id)
				if _, err := client.Execute(
					"INSERT INTO records(id,name) VALUES($1,$2)", id, name); err != nil {
					writerErrs[node] = err
					return
				}
				if n%10 == 0 {
					if err := client.Flush(); err != nil {
						writerErrs[node] = err
						return
					}
				}
				got = append(got, []string{id, name})
				time.Sleep(25 * time.Millisecond)
			}
			if err := client.Flush(); err != nil {
				writerErrs[node] = err
				return
			}
			acked[node] = got
		}(node)
	}
	// Wait for divergent acknowledged state before healing, while
	// writers run.
	diverged := goharness.WaitUntil(wait, 25*time.Millisecond, func() bool {
		a, err := goharness.Rows(cluster.Node(0))
		if err != nil {
			return false
		}
		b, err := goharness.Rows(cluster.Node(2))
		if err != nil {
			return false
		}
		return len(a) >= 10 && len(b) >= 5 && !equalRows(a, b)
	})
	if !diverged {
		t.Fatal("partition failed to diverge acknowledged state")
	}
	if err := cluster.PeerMesh(); err != nil {
		t.Fatalf("remesh: %v", err)
	}
	var expected [][]string
	wg.Wait()
	for node, err := range writerErrs {
		if err != nil {
			t.Fatalf("node %d writer: %v", node, err)
		}
		expected = append(expected, acked[node]...)
	}
	sortRows(expected)
	if err := goharness.Converge(cluster, []int{0, 1, 2}, expected, wait); err != nil {
		t.Fatalf("converge: %v", err)
	}
	if _, err := cluster.Node(0).Execute(
		"INSERT INTO records(id,name) VALUES('post-heal','still-writable')"); err != nil {
		t.Fatalf("insert post-heal: %v", err)
	}
	if err := cluster.Node(0).Flush(); err != nil {
		t.Fatalf("flush post-heal: %v", err)
	}
	expected = append(expected, []string{"post-heal", "still-writable"})
	sortRows(expected)
	if err := goharness.Converge(cluster, []int{0, 1, 2}, expected, wait); err != nil {
		t.Fatalf("converge post-heal: %v", err)
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

// sortRows sorts row sets lexicographically (reference: Vec<Vec<String>> sort).
func sortRows(rows [][]string) {
	sort.Slice(rows, func(a, b int) bool {
		for i := 0; i < len(rows[a]) && i < len(rows[b]); i++ {
			if rows[a][i] != rows[b][i] {
				return rows[a][i] < rows[b][i]
			}
		}
		return len(rows[a]) < len(rows[b])
	})
}
