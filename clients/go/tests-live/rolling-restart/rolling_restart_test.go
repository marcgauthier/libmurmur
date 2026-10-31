// Live scenario: rolling process restarts lose no writes.
//
// Port of MURMUR-SQL rolling-restart: a 3-node cluster converges on 5
// base rows, then each round restarts one node (round-robin) while the
// two live peers each acknowledge 25 rows concurrently with 25 ms
// pacing, the restarted node rejoins mid-write, and all three nodes
// converge on every acknowledged row. Restarts are real child-process
// kills plus reboots on the same dir (MURMUR_NODE_BIN); writers capture
// their node handles before the restart. The reference tokio tasks
// become goroutines over a sync.WaitGroup.
package rollingrestart

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

func TestRollingRestartLosesNoWrites(t *testing.T) {
	goharness.SkipUnlessLive(t)
	roll(t, 3)
}

func TestRollingRestartChurn(t *testing.T) {
	goharness.SkipUnlessLive(t)
	roll(t, 6)
}

func roll(t *testing.T, rounds int) {
	t.Helper()
	cluster, err := goharness.NewCluster(goharness.ClusterOptions{
		Name:       fmt.Sprintf("rolling-restart-%d", rounds),
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
	for n := 0; n < 5; n++ {
		id := fmt.Sprintf("base-%d", n)
		name := fmt.Sprintf("baseline-%d", n)
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
	for round := 0; round < rounds; round++ {
		restarting := round % 3
		// Persist acknowledged state, then write concurrently on both
		// live peers throughout this real process restart. Every
		// successful write is checked.
		for i := 0; i < 3; i++ {
			if err := cluster.Node(i).Flush(); err != nil {
				t.Fatalf("round %d node %d pre-restart flush: %v", round, i, err)
			}
		}
		if err := cluster.KillNode(restarting); err != nil {
			t.Fatalf("round %d kill node %d: %v", round, restarting, err)
		}
		var wg sync.WaitGroup
		type writerOut struct {
			acked [][]string
			err   error
		}
		outs := make([]writerOut, 3)
		for node := 0; node < 3; node++ {
			if node == restarting {
				continue
			}
			wg.Add(1)
			go func(node int) {
				defer wg.Done()
				client := cluster.Node(node)
				var acked [][]string
				for n := 0; n < 25; n++ {
					id := fmt.Sprintf("r%d-n%d-%03d", round, node, n)
					name := fmt.Sprintf("live-%s", id)
					if _, err := client.Execute(
						"INSERT INTO records(id,name) VALUES($1,$2)", id, name); err != nil {
						outs[node].err = err
						return
					}
					acked = append(acked, []string{id, name})
					time.Sleep(25 * time.Millisecond)
				}
				if err := client.Flush(); err != nil {
					outs[node].err = err
					return
				}
				outs[node].acked = acked
			}(node)
		}
		time.Sleep(100 * time.Millisecond)
		if err := cluster.RestartNode(restarting); err != nil {
			t.Fatalf("round %d restart node %d: %v", round, restarting, err)
		}
		if err := cluster.PeerMesh(); err != nil {
			t.Fatalf("round %d remesh: %v", round, err)
		}
		wg.Wait()
		for node := 0; node < 3; node++ {
			if node == restarting {
				continue
			}
			if outs[node].err != nil {
				t.Fatalf("round %d node %d writer: %v", round, node, outs[node].err)
			}
			expected = append(expected, outs[node].acked...)
		}
		sortRows(expected)
		if err := goharness.Converge(cluster, []int{0, 1, 2}, expected, wait); err != nil {
			t.Fatalf("round %d converge: %v", round, err)
		}
	}
	failed = false
}

// sortRows sorts rows lexicographically by (id, name), matching the
// reference Vec<Vec<String>> sort.
func sortRows(rows [][]string) {
	sort.Slice(rows, func(a, b int) bool {
		if rows[a][0] != rows[b][0] {
			return rows[a][0] < rows[b][0]
		}
		return rows[a][1] < rows[b][1]
	})
}
