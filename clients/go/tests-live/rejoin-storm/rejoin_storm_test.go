// Live scenario: two nodes killed simultaneously must rejoin at once and
// catch up without errors.
//
// Port of MURMUR-SQL rejoin-storm: a 3-node cluster converges on 10
// base rows, nodes 1-2 are killed, node 0 acknowledges 30 more rows
// while they are down, both nodes restart in parallel and remesh, and
// all three nodes converge on all 40 rows with full peer counts,
// received replication traffic, and no replication errors. Kill/restart
// legs run as child processes (MURMUR_NODE_BIN); the flat native status
// snapshot maps received_transactions to applied_batches and the
// replication last_error check to the last_error_kind/code fail channel.
package rejoinstorm

import (
	"fmt"
	"sort"
	"sync"
	"testing"
	"time"

	goharness "github.com/marcgauthier/sqlite-murmur-go/clients/go/tests-live/goharness"
)

// wait is the convergence/peer-count deadline (reference: WAIT = 120 s).
const wait = 120 * time.Second

func TestDualKillSimultaneousRejoin(t *testing.T) {
	goharness.SkipUnlessLive(t)
	cluster, err := goharness.NewCluster(goharness.ClusterOptions{
		Name:       "rejoin-storm",
		NumNodes:   3,
		ChildNodes: true,
	})
	if err != nil {
		t.Fatalf("start cluster: %v", err)
	}
	failed := true
	defer func() { cluster.Finish(failed) }()

	if err := goharness.Fixture(cluster); err != nil {
		t.Fatalf("fixture: %v", err)
	}
	var expected [][]string
	for n := 0; n < 10; n++ {
		id := fmt.Sprintf("base-%03d", n)
		name := fmt.Sprintf("base-%d", n)
		if _, err := cluster.Node(0).Execute(
			"INSERT INTO records(id,name) VALUES($1,$2)", id, name); err != nil {
			t.Fatalf("insert %s: %v", id, err)
		}
		expected = append(expected, []string{id, name})
	}
	if err := cluster.Node(0).Flush(); err != nil {
		t.Fatalf("flush base rows: %v", err)
	}
	if err := goharness.Converge(cluster, []int{0, 1, 2}, expected, wait); err != nil {
		t.Fatalf("converge base rows: %v", err)
	}
	for _, node := range []int{1, 2} {
		if err := cluster.Node(node).Flush(); err != nil {
			t.Fatalf("node %d pre-kill flush: %v", node, err)
		}
		if err := cluster.KillNode(node); err != nil {
			t.Fatalf("kill node %d: %v", node, err)
		}
	}
	for n := 0; n < 30; n++ {
		id := fmt.Sprintf("offline-%03d", n)
		name := fmt.Sprintf("acknowledged-%d", n)
		if _, err := cluster.Node(0).Execute(
			"INSERT INTO records(id,name) VALUES($1,$2)", id, name); err != nil {
			t.Fatalf("insert %s: %v", id, err)
		}
		expected = append(expected, []string{id, name})
	}
	if err := cluster.Node(0).Flush(); err != nil {
		t.Fatalf("flush offline rows: %v", err)
	}
	if err := restartNodesParallel(cluster, []int{1, 2}); err != nil {
		t.Fatalf("restart nodes 1-2: %v", err)
	}
	if err := cluster.PeerMesh(); err != nil {
		t.Fatalf("remesh: %v", err)
	}
	sort.Slice(expected, func(a, b int) bool {
		if expected[a][0] != expected[b][0] {
			return expected[a][0] < expected[b][0]
		}
		return expected[a][1] < expected[b][1]
	})
	if err := goharness.Converge(cluster, []int{0, 1, 2}, expected, wait); err != nil {
		t.Fatalf("converge after rejoin: %v", err)
	}
	if err := goharness.PeerCounts(cluster, []int{0, 1, 2}, []int{2, 2, 2}, wait); err != nil {
		t.Fatalf("peer counts: %v", err)
	}
	for i := 1; i < 3; i++ {
		s, err := goharness.Status(cluster.Node(i))
		if err != nil {
			t.Fatalf("node %d status: %v", i, err)
		}
		applied, ok := statusNumber(s, "applied_batches")
		if !ok || applied <= 0 {
			t.Fatalf("node %d applied_batches = %v, want > 0", i, applied)
		}
		// No replication-layer errors: the fail channel
		// (last_error_kind/code) records ingest/apply failures, while
		// the sticky last_error text also keeps expected transport
		// noise from the killed peers' severed streams.
		if kind := statusValue(s, "last_error_kind"); kind != nil {
			t.Fatalf("node %d last_error_kind = %v, want absent", i, kind)
		}
		if code := statusValue(s, "last_error_code"); code != nil {
			t.Fatalf("node %d last_error_code = %v, want absent", i, code)
		}
	}
	failed = false
}

// restartNodesParallel reboots every listed node concurrently so every
// node rejoins from the same backlog.
func restartNodesParallel(cluster *goharness.Cluster, idxs []int) error {
	errs := make([]error, len(idxs))
	var wg sync.WaitGroup
	for k, idx := range idxs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs[k] = cluster.RestartNode(idx)
		}()
	}
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}

// statusValue walks a SHOW STATUS JSON snapshot along path, reporting
// nil for a missing key or an explicit JSON null.
func statusValue(s any, path ...string) any {
	cur := s
	for _, p := range path {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur, ok = m[p]
		if !ok {
			return nil
		}
	}
	return cur
}

// statusNumber walks a status snapshot and returns the value as a float64.
func statusNumber(s any, path ...string) (float64, bool) {
	v := statusValue(s, path...)
	f, ok := v.(float64)
	return f, ok
}
