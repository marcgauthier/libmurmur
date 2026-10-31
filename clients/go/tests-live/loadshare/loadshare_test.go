// Live scenario: local writers keep their share of scheduler
// acquisitions while a remote node replicates under load.
//
// Port of MURMUR-SQL loadshare: four writers on node 0 insert 60 rows
// each concurrently while node 1 inserts 20 rows with 25 ms pacing;
// both nodes converge on all 260 rows and the slowest local write
// stays within 10 s. The reference per-worker SQL connections become
// goroutines over the shared node handle (the harness serializes
// statements). The scheduler-acquisitions/debt snapshot leg is
// skipped: the native status snapshot exposes no scheduler acquisition
// counters or debt gauge.
package loadshare

import (
	"fmt"
	"sort"
	"sync"
	"testing"
	"time"

	goharness "github.com/marcgauthier/sqlite-murmur-go/clients/go/tests-live/goharness"
)

// wait is the convergence deadline (Rust: WAIT = 120 s).
const wait = 120 * time.Second

func TestWriterSharesUnderLoad(t *testing.T) {
	goharness.SkipUnlessLive(t)
	cluster, err := goharness.NewCluster(goharness.ClusterOptions{
		Name:     "loadshare",
		NumNodes: 2,
	})
	if err != nil {
		t.Fatalf("start cluster: %v", err)
	}
	failed := true
	defer func() { cluster.Finish(failed) }()

	if err := goharness.Fixture(cluster); err != nil {
		t.Fatalf("fixture: %v", err)
	}
	type workerOut struct {
		acked   [][]string
		latency []time.Duration
		err     error
	}
	outs := make([]workerOut, 4)
	var wg sync.WaitGroup
	for worker := 0; worker < 4; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			var acked [][]string
			var latency []time.Duration
			for n := 0; n < 60; n++ {
				id := fmt.Sprintf("local-%d-%04d", worker, n)
				name := fmt.Sprintf("value-%s", id)
				start := time.Now()
				if _, err := cluster.Node(0).Execute(
					"INSERT INTO records(id,name) VALUES($1,$2)", id, name); err != nil {
					outs[worker].err = err
					return
				}
				latency = append(latency, time.Since(start))
				acked = append(acked, []string{id, name})
			}
			if err := cluster.Node(0).Flush(); err != nil {
				outs[worker].err = err
				return
			}
			outs[worker].acked = acked
			outs[worker].latency = latency
		}(worker)
	}
	var expected [][]string
	for n := 0; n < 20; n++ {
		id := fmt.Sprintf("remote-%04d", n)
		name := fmt.Sprintf("value-%s", id)
		if _, err := cluster.Node(1).Execute(
			"INSERT INTO records(id,name) VALUES($1,$2)", id, name); err != nil {
			t.Fatalf("insert %s: %v", id, err)
		}
		if err := cluster.Node(1).Flush(); err != nil {
			t.Fatalf("flush %s: %v", id, err)
		}
		expected = append(expected, []string{id, name})
		time.Sleep(25 * time.Millisecond)
	}
	var latencies []time.Duration
	wg.Wait()
	for worker, out := range outs {
		if out.err != nil {
			t.Fatalf("worker %d: %v", worker, out.err)
		}
		expected = append(expected, out.acked...)
		latencies = append(latencies, out.latency...)
	}
	sort.Slice(expected, func(a, b int) bool {
		if expected[a][0] != expected[b][0] {
			return expected[a][0] < expected[b][0]
		}
		return expected[a][1] < expected[b][1]
	})
	if err := goharness.Converge(cluster, []int{0, 1}, expected, wait); err != nil {
		t.Fatalf("converge: %v", err)
	}
	if len(latencies) != 240 {
		t.Fatalf("latencies = %d, want 240", len(latencies))
	}
	sort.Slice(latencies, func(a, b int) bool { return latencies[a] < latencies[b] })
	if latencies[239] > 10*time.Second {
		t.Fatalf("slowest write = %v, want <= 10s", latencies[239])
	}
	failed = false
}

func TestSchedulerAcquisitionsAndDebt(t *testing.T) {
	goharness.SkipUnlessLive(t)
	// Blocked: the native status snapshot carries no
	// scheduler.local/remote acquisition counters and no debt_nanos
	// gauge (ShowHealth reports only the static scheduler share
	// config).
	t.Skip("harness: scheduler acquisition counters and debt gauge in status snapshot")
}
