// Live scenario: a concurrent blast fully converges with bounded tail
// latency while both nodes stay ready.
//
// Port of MURMUR-SQL overload-budgets: two native nodes take a small
// baseline write, then 8 writers x 50 inserts converge with p99 under
// 10 s while both nodes stay ready. The reference's oversize-write
// rejection legs need local commit-budget enforcement, which this
// stack does not implement (budgets bind the replication export path,
// not local inserts), so they are skipped (see
// TestBudgetRejectionNamesTheBudget).
package overloadbudgets

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"sync"
	"testing"
	"time"

	goharness "github.com/marcgauthier/sqlite-murmur-go/clients/go/tests-live/goharness"
)

// Post-rejection convergence deadline (Go: 30 s).
const probeTimeout = 30 * time.Second

// Blast convergence deadline (Go: 60 s).
const blastTimeout = 60 * time.Second

// Convergence poll interval (Go: 200 ms).
const convergePoll = 200 * time.Millisecond

// Final readiness deadline per node (Go: `WaitNodeReady`).
const readyTimeout = 30 * time.Second

// Readiness poll interval.
const readyPoll = 100 * time.Millisecond

// Blast tail-latency bound (Go: p99 under 10 s).
const p99Bound = 10 * time.Second

// Blast shape (Go: 8 writers x 50 inserts).
const (
	writers   = 8
	perWriter = 50
)

// rows returns all rows on one node as text cells.
func rows(cluster *goharness.Cluster, idx int) ([][]string, error) {
	out, err := cluster.Node(idx).Simple("SELECT id, name, phone, score FROM records")
	if err != nil {
		return nil, fmt.Errorf("node%d SELECT rows: %w", idx+1, err)
	}
	return out, nil
}

func rowsLess(a, b []string) bool {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return len(a) < len(b)
}

// digest renders the canonical digest of a row set: sorted rows.
func digest(rows [][]string) string {
	sorted := append([][]string(nil), rows...)
	sort.Slice(sorted, func(a, b int) bool { return rowsLess(sorted[a], sorted[b]) })
	return fmt.Sprintf("%q", sorted)
}

// rowCount returns the row count on one node (cheap pre-check before full
// digest reads).
func rowCount(cluster *goharness.Cluster, idx int) (int, error) {
	rows, err := cluster.Node(idx).Simple("SELECT COUNT(*) FROM records")
	if err != nil {
		return 0, fmt.Errorf("node%d COUNT: %w", idx+1, err)
	}
	if len(rows) == 0 || len(rows[0]) == 0 {
		return 0, fmt.Errorf("node%d COUNT returned no rows", idx+1)
	}
	n, err := strconv.Atoi(rows[0][0])
	if err != nil {
		return 0, fmt.Errorf("node%d COUNT %q: %w", idx+1, rows[0][0], err)
	}
	return n, nil
}

// waitConverged waits until every node holds exactly `want` rows with
// equal digests.
func waitConverged(cluster *goharness.Cluster, want int, timeout time.Duration, what string) error {
	deadline := time.Now().Add(timeout)
	for {
		counts := make([]int, 0, cluster.Len())
		for i := 0; i < cluster.Len(); i++ {
			n, err := rowCount(cluster, i)
			if err != nil {
				return err
			}
			counts = append(counts, n)
		}
		all := true
		for _, n := range counts {
			if n != want {
				all = false
				break
			}
		}
		if all {
			first := ""
			equal := true
			for idx := 0; idx < cluster.Len(); idx++ {
				got, err := rows(cluster, idx)
				if err != nil {
					return err
				}
				d := digest(got)
				if idx == 0 {
					first = d
				} else if d != first {
					equal = false
					break
				}
			}
			if equal {
				return nil
			}
		}
		if !time.Now().Before(deadline) {
			return fmt.Errorf("nodes did not converge on %d rows within %v (%s)", want, timeout, what)
		}
		time.Sleep(convergePoll)
	}
}

// waitNodeReady waits until one node is responsive with its full peer set.
func waitNodeReady(cluster *goharness.Cluster, idx int, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		peers, err := cluster.Node(idx).ShowPeers()
		if err != nil {
			return fmt.Errorf("node%d SHOW PEERS: %w", idx+1, err)
		}
		n := 0
		for _, p := range peers {
			if p.Connected {
				n++
			}
		}
		// A successful read proves the writer path is responsive, not just
		// the replication endpoint.
		_, readErr := rowCount(cluster, idx)
		readable := readErr == nil
		if n == cluster.Len()-1 && readable {
			return nil
		}
		if !time.Now().Before(deadline) {
			return fmt.Errorf("node%d not ready within %v (peers=%d, readable=%v)",
				idx+1, timeout, n, readable)
		}
		time.Sleep(readyPoll)
	}
}

// insert adds one contention row on one node.
func insert(cluster *goharness.Cluster, node int, id, name string) error {
	if _, err := cluster.Node(node).Execute(
		"INSERT INTO records(id, name, phone, score) VALUES($1, $2, $3, $4)",
		id, name, "", int64(0)); err != nil {
		return fmt.Errorf("node%d insert '%s': %v", node+1, name, err)
	}
	return nil
}

// writerResult is one blast writer's outcome: per-insert latencies, a
// failed-write count, and the first error.
type writerResult struct {
	lat    []time.Duration
	failed uint64
	err    error
}

// writer runs one blast writer: `perWriter` sequential inserts, recording
// per-insert latency.
func writer(cluster *goharness.Cluster, w int) writerResult {
	var out writerResult
	out.lat = make([]time.Duration, 0, perWriter)
	for i := 0; i < perWriter; i++ {
		id := fmt.Sprintf("%032x", 10000+w*1000+i)
		name := fmt.Sprintf("w%d-%d", w, i)
		start := time.Now()
		err := insert(cluster, 0, id, name)
		out.lat = append(out.lat, time.Since(start))
		if err != nil {
			out.failed++
			out.err = err
			return out
		}
		// Bound the session capture with a durability boundary every
		// 10 inserts (reference: without it the blast would sign as
		// one capture past the replication budget).
		if (i+1)%10 == 0 {
			if err := cluster.Node(0).Flush(); err != nil {
				out.failed++
				out.err = fmt.Errorf("blast flush: %v", err)
				return out
			}
		}
	}
	return out
}

// TestBudgetRejectionNamesTheBudget is the reference's oversize-write
// leg: a single insert carrying a value past the 64 KiB commit budget
// fails naming the budget, both nodes still hold 0 rows, and a small
// post-rejection write succeeds (retrying replayable 40001 pressure).
// Blocked: this stack enforces byte budgets on the replication export
// path only — local inserts have no commit budget to trip, and there
// is no 40001 backpressure signal.
func TestBudgetRejectionNamesTheBudget(t *testing.T) {
	goharness.SkipUnlessLive(t)
	t.Skip("harness: local commit budget enforcement (oversize-insert rejection naming the budget, replayable 40001 pressure)")
}

func TestPressureBlastConvergence(t *testing.T) {
	goharness.SkipUnlessLive(t)
	cluster, err := goharness.NewCluster(goharness.ClusterOptions{
		Name:     "overload-budgets",
		NumNodes: 2,
	})
	if err != nil {
		t.Fatalf("cluster setup: %v", err)
	}
	if cluster.Len() != 2 {
		cluster.Finish(true)
		t.Fatalf("this scenario is written for 2 nodes, got %d", cluster.Len())
	}
	failed := true
	defer func() { cluster.Finish(failed) }()
	if err := runBlast(cluster); err != nil {
		fmt.Fprintf(os.Stderr, "scenario failed: %v\n", err)
		t.Fatalf("scenario failed: %v", err)
	}
	failed = false
}

func runBlast(cluster *goharness.Cluster) error {
	// Same schema on every node, flagged replicated on each node (row
	// convergence needs the per-node flag).
	for i := 0; i < cluster.Len(); i++ {
		if _, err := cluster.Node(i).Simple(
			"CREATE TABLE IF NOT EXISTS records(id TEXT PRIMARY KEY NOT NULL DEFAULT '', name TEXT NOT NULL DEFAULT '', phone TEXT NOT NULL DEFAULT '', score INTEGER NOT NULL DEFAULT 0)"); err != nil {
			return fmt.Errorf("migrate node%d: %w", i+1, err)
		}
	}
	for i := 0; i < cluster.Len(); i++ {
		if err := cluster.Node(i).SetTableReplicated("records", true); err != nil {
			return fmt.Errorf("node%d SET TABLE REPLICATED: %w", i+1, err)
		}
		if err := cluster.Node(i).Flush(); err != nil {
			return fmt.Errorf("node%d flush after SET TABLE: %w", i+1, err)
		}
	}
	if err := cluster.PeerMesh(); err != nil {
		return fmt.Errorf("mesh: %w", err)
	}

	// Baseline small write converges (reference: the post-rejection
	// probe; here it seeds the blast baseline).
	if err := insert(cluster, 0, fmt.Sprintf("%032x", 3), "ok"); err != nil {
		return err
	}
	if err := cluster.Node(0).Flush(); err != nil {
		return fmt.Errorf("flush after baseline write: %w", err)
	}
	if err := waitConverged(cluster, 1, probeTimeout, "baseline probe"); err != nil {
		return err
	}

	// Pressure blast: concurrent writers converge with bounded tail.
	results := make([]writerResult, writers)
	var wg sync.WaitGroup
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			results[w] = writer(cluster, w)
		}(w)
	}
	wg.Wait()
	var lat []time.Duration
	lat = make([]time.Duration, 0, writers*perWriter)
	var failedWrites uint64
	var firstError error
	for _, r := range results {
		lat = append(lat, r.lat...)
		failedWrites += r.failed
		if firstError == nil {
			firstError = r.err
		}
	}
	if failedWrites != 0 {
		return fmt.Errorf("%d blast writes failed: %v", failedWrites, firstError)
	}
	if len(lat) != writers*perWriter {
		return fmt.Errorf("blast recorded %d latencies, want %d", len(lat), writers*perWriter)
	}
	sort.Slice(lat, func(a, b int) bool { return lat[a] < lat[b] })
	p99 := lat[int(float64(len(lat))*0.99)]
	fmt.Fprintf(os.Stderr, "blast: %d inserts p50=%v p99=%v max=%v\n",
		len(lat), lat[len(lat)/2], p99, lat[len(lat)-1])
	if p99 > p99Bound {
		return fmt.Errorf("blast p99 %v exceeds %v bound", p99, p99Bound)
	}
	if err := waitConverged(cluster, 1+writers*perWriter, blastTimeout, "blast"); err != nil {
		return err
	}
	if err := waitNodeReady(cluster, 0, readyTimeout); err != nil {
		return err
	}
	if err := waitNodeReady(cluster, 1, readyTimeout); err != nil {
		return err
	}
	return nil
}
