// Live scenario: retention keeps running while real SQL clients sustain
// inserts and updates.
//
// Port of MURMUR-SQL maintenance-under-load: three nodes with
// minimum-retained 1 converge on the seed rows; three writers sustain
// inserts (then updates past the cap) until every node reports a
// retention pass past the baseline; writers join, all rows converge,
// and a post-maintenance write converges everywhere. Nodes are native
// replication drivers over VFS stores, in-process. The reference's
// retention_runs counter maps to the health snapshot's
// retention.last_collection_millis, which advances on every pass. The
// retention_pruned half has no native observable (the engine never
// advances collected_transactions) and is skipped (see
// TestRetentionCollectsUnderSustainedLoad).
package maintenanceunderload

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	goharness "github.com/marcgauthier/sqlite-murmur-go/clients/go/tests-live/goharness"
)

// wait is the convergence deadline (Rust: WAIT = 120 s).
const wait = 120 * time.Second

// writerPace bounds sustained-write volume: the reference writers loop
// unpaced, but native replication converges only tens of rows per
// second, so unpaced ingest leaves a backlog the 120 s convergence
// wait can never drain. Paced writers still sustain writes on all
// three nodes for the full run-to-tick window while the mesh keeps up
// and teardown stays safe.
const writerPace = 60 * time.Millisecond

// TestRetentionCollectsUnderSustainedLoad is the reference's pruning
// half: every node must report collection past the baseline while
// writes are active. Not wired: the leg needs writing against the
// health collected_transactions counter plus Node.RetentionCollect
// (there is still no cumulative pruned counter, only per-pass pruned).
func TestRetentionCollectsUnderSustainedLoad(t *testing.T) {
	goharness.SkipUnlessLive(t)
	t.Skip("harness: pruning proof not wired (no cumulative pruned counter)")
}

func TestMaintenanceUnderSustainedLoad(t *testing.T) {
	goharness.SkipUnlessLive(t)
	cluster, err := goharness.NewCluster(goharness.ClusterOptions{
		Name:     "maintenance-sql",
		NumNodes: 3,
	})
	if err != nil {
		t.Fatalf("start cluster: %v", err)
	}
	failed := true
	defer func() { cluster.Finish(failed) }()

	// Aggressive collection floor (reference: retention 10 ms,
	// interval 100 ms, minimum 1): the native pass runs on the
	// engine tick and reads its parameters from the store, so only
	// the minimum needs lowering. This suite's waits are tuned for
	// the 60 s native retention tick (see the README).
	for i := 0; i < 3; i++ {
		if _, err := cluster.Node(i).Simple(
			"INSERT INTO murmur_config(name,value) VALUES('retention_min_kept','1')" +
				" ON CONFLICT(name) DO UPDATE SET value=excluded.value"); err != nil {
			t.Fatalf("node %d set retention_min_kept: %v", i, err)
		}
	}

	for i := 0; i < 3; i++ {
		if _, err := cluster.Node(i).Simple("CREATE TABLE IF NOT EXISTS contention(id TEXT PRIMARY KEY NOT NULL DEFAULT '', name TEXT NOT NULL DEFAULT '', phone TEXT NOT NULL DEFAULT '', score INTEGER NOT NULL DEFAULT 0)"); err != nil {
			t.Fatalf("node %d create contention: %v", i, err)
		}
		if err := cluster.Node(i).SetTableReplicated("contention", true); err != nil {
			t.Fatalf("node %d replicate contention: %v", i, err)
		}
		if err := cluster.Node(i).Flush(); err != nil {
			t.Fatalf("node %d flush schema: %v", i, err)
		}
	}
	if err := cluster.PeerMesh(); err != nil {
		t.Fatalf("mesh: %v", err)
	}
	seed := 120
	if raw := os.Getenv("MURMUR_MAINT_LOAD_SEED"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil {
			t.Fatalf("MURMUR_MAINT_LOAD_SEED = %q: %v", raw, err)
		}
		seed = n
	}
	cap_ := 4000
	if raw := os.Getenv("MURMUR_MAINT_LOAD_MAX_INSERTS"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil {
			t.Fatalf("MURMUR_MAINT_LOAD_MAX_INSERTS = %q: %v", raw, err)
		}
		cap_ = n
	}
	if cap_ <= 0 {
		t.Fatalf("cap = %d, want > 0", cap_)
	}
	var expected [][]string
	for n := 0; n < seed; n++ {
		id := fmt.Sprintf("seed-%08d", n)
		if _, err := cluster.Node(0).Execute(
			"INSERT INTO contention(id,name,phone,score) VALUES($1,'seed','unchanged',0)", id); err != nil {
			t.Fatalf("insert %s: %v", id, err)
		}
		expected = append(expected, []string{id, "seed", "unchanged", "0"})
	}
	if err := cluster.Node(0).Flush(); err != nil {
		t.Fatalf("flush seed rows: %v", err)
	}
	if !goharness.WaitUntil(wait, 50*time.Millisecond, func() bool {
		return rowsMatch(t, cluster, expected)
	}) {
		t.Fatal("seed rows did not converge")
	}
	before := make([]float64, 3)
	for i := 0; i < 3; i++ {
		health, err := cluster.Node(i).ShowHealth()
		if err != nil {
			t.Fatalf("node %d health: %v", i, err)
		}
		stamp, ok := healthNumber(health, "retention", "last_collection_millis")
		if !ok {
			t.Fatalf("node %d has no retention.last_collection_millis", i)
		}
		before[i] = stamp
	}
	var stop atomic.Bool
	type finalRows struct {
		rows map[string]string
		err  error
	}
	finals := make([]finalRows, 3)
	var wg sync.WaitGroup
	for worker := 0; worker < 3; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			client := cluster.Node(worker)
			rows := map[string]string{}
			n := 0
			deadline := time.Now().Add(900 * time.Second)
			for !stop.Load() && time.Now().Before(deadline) {
				id := fmt.Sprintf("worker-%d-%08d", worker, n%cap_)
				name := fmt.Sprintf("revision-%d", n)
				var err error
				if n < cap_ {
					_, err = client.Execute("INSERT INTO contention(id,name,phone,score) VALUES($1,$2,'unchanged',0)", id, name)
				} else {
					_, err = client.Execute("UPDATE contention SET name=$1 WHERE id=$2", name, id)
				}
				if err != nil {
					finals[worker].err = err
					return
				}
				rows[id] = name
				n++
				if n%10 == 0 {
					if err := client.Flush(); err != nil {
						finals[worker].err = err
						return
					}
				}
				time.Sleep(writerPace)
			}
			if err := client.Flush(); err != nil {
				finals[worker].err = err
				return
			}
			finals[worker].rows = rows
		}(worker)
	}
	timeout := parseDurationEnv("MURMUR_MAINT_LOAD_GC_TIMEOUT", "150s", 150)
	maintStart := time.Now()
	maintained := goharness.WaitUntil(timeout, 200*time.Millisecond, func() bool {
		for i := 0; i < 3; i++ {
			h, err := cluster.Node(i).ShowHealth()
			if err != nil {
				return false
			}
			stamp, ok := healthNumber(h, "retention", "last_collection_millis")
			if !ok || stamp <= before[i] {
				return false
			}
		}
		return true
	})
	stop.Store(true)
	wg.Wait()
	for worker, f := range finals {
		if f.err != nil {
			t.Fatalf("worker %d: %v", worker, f.err)
		}
		for id, name := range f.rows {
			expected = append(expected, []string{id, name, "unchanged", "0"})
		}
	}
	if !maintained {
		t.Fatal("retention did not run under sustained SQL writes")
	}
	sortRows(expected)
	fmt.Fprintf(os.Stderr, "maintenance: runs observed after %v; converging %d rows\n",
		time.Since(maintStart).Round(time.Second), len(expected))
	// Final durability barrier on every node (flap-port SyncAll): the
	// tail of one node's stream otherwise stalls once its writer stops.
	for i := 0; i < 3; i++ {
		if err := cluster.Node(i).Flush(); err != nil {
			t.Fatalf("node %d final sync flush: %v", i, err)
		}
	}
	if !goharness.WaitUntil(wait, 100*time.Millisecond, func() bool {
		return rowsMatch(t, cluster, expected)
	}) {
		for i := 0; i < 3; i++ {
			rows, err := cluster.Node(i).Simple("SELECT id,name,phone,score FROM contention ORDER BY id")
			if err != nil {
				t.Fatalf("node %d read contention: %v", i, err)
			}
			missing, extra := 0, 0
			want := map[string]string{}
			for _, r := range expected {
				want[r[0]] = r[1]
			}
			got := map[string]string{}
			for _, r := range rows {
				got[r[0]] = r[1]
			}
			stale := 0
			for id, name := range want {
				if g, ok := got[id]; !ok {
					missing++
				} else if g != name {
					stale++
				}
			}
			for id := range got {
				if _, ok := want[id]; !ok {
					extra++
				}
			}
			missSample := []string{}
			for id := range want {
				if _, ok := got[id]; !ok {
					missSample = append(missSample, id)
					if len(missSample) >= 8 {
						break
					}
				}
			}
			fmt.Fprintf(os.Stderr, "node %d at timeout: rows=%d missing=%d stale=%d extra=%d missSample=%q\n",
				i, len(rows), missing, stale, extra, missSample)
		}
		t.Fatal("worker rows did not converge")
	}
	if _, err := cluster.Node(0).Execute(
		"INSERT INTO contention(id,name,phone,score) VALUES('post-maintenance','ready','unchanged',0)"); err != nil {
		t.Fatalf("insert post-maintenance: %v", err)
	}
	if err := cluster.Node(0).Flush(); err != nil {
		t.Fatalf("flush post-maintenance: %v", err)
	}
	expected = append(expected, []string{"post-maintenance", "ready", "unchanged", "0"})
	sortRows(expected)
	if !goharness.WaitUntil(wait, 100*time.Millisecond, func() bool {
		return rowsMatch(t, cluster, expected)
	}) {
		t.Fatal("post-maintenance row did not converge")
	}
	failed = false
}

// rowsMatch reports whether all three nodes read expected contention rows.
// A query error fails the test: unlike the polling helpers the Rust
// closure unwraps every query.
func rowsMatch(t *testing.T, cluster *goharness.Cluster, expected [][]string) bool {
	t.Helper()
	for i := 0; i < 3; i++ {
		rows, err := cluster.Node(i).Simple("SELECT id,name,phone,score FROM contention ORDER BY id")
		if err != nil {
			t.Fatalf("node %d read contention: %v", i, err)
		}
		if !equalRows(rows, expected) {
			return false
		}
	}
	return true
}

// parseDurationEnv parses the Rust timeout knob form: a trailing m/h
// multiplies minutes/hours, anything else is seconds (a trailing s is
// stripped); unparseable or non-positive values fall back.
func parseDurationEnv(name, def string, fallback uint64) time.Duration {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		raw = def
	}
	raw = strings.TrimSpace(raw)
	multiplier := uint64(1)
	number := raw
	if n, ok := strings.CutSuffix(raw, "m"); ok {
		number, multiplier = n, 60
	} else if n, ok := strings.CutSuffix(raw, "h"); ok {
		number, multiplier = n, 3600
	} else {
		number = strings.TrimRight(raw, "s")
	}
	n, err := strconv.ParseUint(number, 10, 64)
	if err != nil || n == 0 {
		n = fallback
	}
	return time.Duration(n*multiplier) * time.Second
}

func sortRows(rows [][]string) {
	sort.Slice(rows, func(a, b int) bool {
		for k := 0; k < len(rows[a]) && k < len(rows[b]); k++ {
			if rows[a][k] != rows[b][k] {
				return rows[a][k] < rows[b][k]
			}
		}
		return len(rows[a]) < len(rows[b])
	})
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

// healthValue walks a health JSON snapshot along path, reporting nil
// for a missing key or an explicit JSON null.
func healthValue(s any, path ...string) any {
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

// healthNumber walks a health snapshot and returns the value as a float64.
func healthNumber(s any, path ...string) (float64, bool) {
	v := healthValue(s, path...)
	f, ok := v.(float64)
	return f, ok
}
