// Live scenario: sustained concurrent writes hold latency SLOs and
// bounded resource gauges.
//
// Port of MURMUR-SQL soak-slo: three writers (one per node) insert
// then overwrite a rolling 1000-key window for
// MURMUR_SLO_DURATION_SECONDS (default 5 s) at 10 ms pacing, all nodes
// converge within MURMUR_SLO_SETTLE_SECONDS (default 30 s), p95 ack
// latency stays within 5 s with a 20 s max, and every node reports a
// null last_error. The staged-transactions / spool-bytes /
// pending-bytes gauge legs are skipped: the native status snapshot
// exposes none of those gauges. The Rust tokio tasks become goroutines
// over a sync.WaitGroup.
package soakslo

import (
	"fmt"
	"sort"
	"sync"
	"testing"
	"time"

	goharness "github.com/marcgauthier/libmurmur/clients/go/tests-live/goharness"
)

// wait is the peer-count deadline (Rust: WAIT = 120 s).
const wait = 120 * time.Second

func TestSoakSLO(t *testing.T) {
	goharness.SkipUnlessLive(t)
	cluster, err := goharness.NewCluster(goharness.ClusterOptions{
		Name:     "soak-slo",
		NumNodes: 3,
	})
	if err != nil {
		t.Fatalf("start cluster: %v", err)
	}
	failed := true
	defer func() { cluster.Finish(failed) }()

	// The reference harness meshes fully by default; native nodes only
	// dial their seed, so mesh explicitly.
	if err := cluster.PeerMesh(); err != nil {
		t.Fatalf("mesh: %v", err)
	}
	if err := goharness.Fixture(cluster); err != nil {
		t.Fatalf("fixture: %v", err)
	}
	if err := goharness.PeerCounts(cluster, []int{0, 1, 2}, []int{2, 2, 2}, wait); err != nil {
		t.Fatalf("peer counts: %v", err)
	}
	end := time.Now().Add(goharness.EnvSeconds("MURMUR_SLO_DURATION_SECONDS", 5))
	type workerOut struct {
		expected map[string]string
		lat      []time.Duration
		n        int
		err      error
	}
	outs := make([]workerOut, 3)
	var wg sync.WaitGroup
	for node := 0; node < 3; node++ {
		wg.Add(1)
		go func(node int) {
			defer wg.Done()
			out := &outs[node]
			out.expected = map[string]string{}
			n := 0
			for time.Now().Before(end) {
				id := fmt.Sprintf("n%d-%04d", node, n%1000)
				name := fmt.Sprintf("revision-%d", n)
				start := time.Now()
				var err error
				if n < 1000 {
					_, err = cluster.Node(node).Execute(
						"INSERT INTO records(id,name) VALUES($1,$2)", id, name)
				} else {
					_, err = cluster.Node(node).Execute(
						"UPDATE records SET name=$1 WHERE id=$2", name, id)
				}
				if err != nil {
					out.err = err
					return
				}
				out.lat = append(out.lat, time.Since(start))
				out.expected[id] = name
				n++
				time.Sleep(10 * time.Millisecond)
			}
			if err := cluster.Node(node).Flush(); err != nil {
				out.err = err
				return
			}
			out.n = n
		}(node)
	}
	wg.Wait()
	var expected [][]string
	var latency []time.Duration
	operations := 0
	for node := 0; node < 3; node++ {
		if outs[node].err != nil {
			t.Fatalf("node %d writer: %v", node, outs[node].err)
		}
		for id, name := range outs[node].expected {
			expected = append(expected, []string{id, name})
		}
		latency = append(latency, outs[node].lat...)
		operations += outs[node].n
	}
	if operations < 60 {
		t.Fatalf("operations = %d, want >= 60", operations)
	}
	sort.Slice(expected, func(a, b int) bool {
		if expected[a][0] != expected[b][0] {
			return expected[a][0] < expected[b][0]
		}
		return expected[a][1] < expected[b][1]
	})
	if err := goharness.Converge(cluster, []int{0, 1, 2}, expected,
		goharness.EnvSeconds("MURMUR_SLO_SETTLE_SECONDS", 30)); err != nil {
		t.Fatalf("converge: %v", err)
	}
	sort.Slice(latency, func(a, b int) bool { return latency[a] < latency[b] })
	if p95 := latency[len(latency)*95/100]; p95 > 5*time.Second {
		t.Fatalf("p95 latency = %v, want <= 5s", p95)
	}
	if max := latency[len(latency)-1]; max > 20*time.Second {
		t.Fatalf("max latency = %v, want <= 20s", max)
	}
	for i := 0; i < 3; i++ {
		if err := cluster.Node(i).Flush(); err != nil {
			t.Fatalf("node %d flush: %v", i, err)
		}
		s, err := goharness.Status(cluster.Node(i))
		if err != nil {
			t.Fatalf("node %d status: %v", i, err)
		}
		// The native snapshot has no storage_error key; the flat
		// last_error fail channel is the portable no-error analog.
		if lastErr := statusValue(s, "last_error"); lastErr != nil {
			t.Fatalf("node %d last_error = %v, want null", i, lastErr)
		}
	}
	failed = false
}

func TestSoakResourceGauges(t *testing.T) {
	goharness.SkipUnlessLive(t)
	// Blocked: the native status snapshot exposes no
	// staged_transactions counter, no spool disk_bytes gauge, and no
	// pending_bytes gauge.
	t.Skip("harness: staged/spool/pending resource gauges in status snapshot")
}

// statusValue walks a status snapshot along path, reporting nil for a
// missing key or an explicit JSON null.
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
