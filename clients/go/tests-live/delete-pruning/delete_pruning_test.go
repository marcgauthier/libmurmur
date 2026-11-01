// Live scenario: three nodes hold the same key range; they run
// concurrent deletes, resurrections, and updates, converge after every
// phase, and then retention collection prunes the delete batches while
// a post-prune write still replicates everywhere.
//
// Port of MURMUR-SQL delete-pruning: aggressive per-test retention is
// set through murmur_config (min_kept 10, matching the reference's
// aggressive floor), and collection is observed rather than driven:
// there is no RETENTION COLLECT verb or SHOW RETENTION counter
// binding here, so the test awaits the engine's automatic retention
// pass (every 60 s) and proves collection two ways — retained_from
// floors advance past baseline (as in graceful-shutdown), and the
// replicated tombstone count drops. Table replication state persists
// in the store; the reference re-set of REPLICATED is skipped.
package deletepruning

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"testing"
	"time"

	goharness "github.com/marcgauthier/libmurmur/clients/go/tests-live/goharness"
)

// Convergence poll interval.
const poll = 100 * time.Millisecond

// envU64 is a positive-integer env knob with fallback.
func envU64(t *testing.T, name string, fallback uint64) uint64 {
	t.Helper()
	if raw := os.Getenv(name); raw != "" {
		v, err := strconv.ParseUint(raw, 10, 64)
		if err != nil || v == 0 {
			t.Fatalf("env %s must be a positive integer", name)
		}
		return v
	}
	return fallback
}

// names returns the sorted names on one node.
func names(cluster *goharness.Cluster, idx int) ([]string, error) {
	rows, err := cluster.Node(idx).Simple("SELECT name FROM rows")
	if err != nil {
		return nil, fmt.Errorf("node%d SELECT names: %w", idx+1, err)
	}
	out := make([]string, 0, len(rows))
	for _, row := range rows {
		if len(row) == 0 {
			return nil, fmt.Errorf("node%d decode name: short row", idx+1)
		}
		out = append(out, row[0])
	}
	sort.Strings(out)
	return out, nil
}

// waitConverged waits until every node holds want rows with equal sorted
// names.
func waitConverged(cluster *goharness.Cluster, want int, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		allMatch := true
		var first []string
		for i := 0; i < cluster.Len(); i++ {
			nodeNames, err := names(cluster, i)
			if err != nil {
				return err
			}
			if i == 0 {
				first = nodeNames
			}
			if len(nodeNames) != want || !equalStrings(nodeNames, first) {
				allMatch = false
				break
			}
		}
		if allMatch {
			return nil
		}
		if !time.Now().Before(deadline) {
			counts := make([]int, 0, cluster.Len())
			for i := 0; i < cluster.Len(); i++ {
				nodeNames, err := names(cluster, i)
				if err != nil {
					return err
				}
				counts = append(counts, len(nodeNames))
			}
			return fmt.Errorf("counts %v did not converge on %d within %v", counts, want, timeout)
		}
		time.Sleep(poll)
	}
}

// retainedFloors sums retained_from across all ShowReplication entries
// on all nodes. Rising sums prove the retention pass moved the floors.
func retainedFloors(cluster *goharness.Cluster) (uint64, error) {
	var sum uint64
	for i := 0; i < cluster.Len(); i++ {
		snap, err := cluster.Node(i).ShowReplication()
		if err != nil {
			return 0, fmt.Errorf("node%d SHOW REPLICATION: %w", i+1, err)
		}
		entries, ok := snap.([]any)
		if !ok {
			return 0, fmt.Errorf("node%d SHOW REPLICATION: want list, got %T", i+1, snap)
		}
		for _, e := range entries {
			m, ok := e.(map[string]any)
			if !ok {
				return 0, fmt.Errorf("node%d SHOW REPLICATION: want object, got %T", i+1, e)
			}
			floor, ok := m["retained_from"].(float64)
			if !ok {
				return 0, fmt.Errorf("node%d SHOW REPLICATION: retained_from missing: %v", i+1, e)
			}
			sum += uint64(floor)
		}
	}
	return sum, nil
}

// tombstones counts replicated delete markers (cid '-1' change rows)
// visible on one node through the public changes view.
func tombstones(cluster *goharness.Cluster, idx int) (int, error) {
	rows, err := cluster.Node(idx).Simple("SELECT COUNT(*) FROM crsql_changes WHERE cid = '-1'")
	if err != nil {
		return 0, fmt.Errorf("node%d tombstone count: %w", idx+1, err)
	}
	if len(rows) == 0 || len(rows[0]) == 0 {
		return 0, fmt.Errorf("node%d tombstone count: no rows", idx+1)
	}
	var n int
	if _, err := fmt.Sscanf(rows[0][0], "%d", &n); err != nil {
		return 0, fmt.Errorf("node%d tombstone count: %w", idx+1, err)
	}
	return n, nil
}

// waitFloorsAdvance waits until the summed floors exceed base.
func waitFloorsAdvance(cluster *goharness.Cluster, base uint64, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		sum, err := retainedFloors(cluster)
		if err != nil {
			return err
		}
		if sum > base {
			fmt.Fprintf(os.Stderr, "retained floors advanced: summed floors=%d (base=%d)\n", sum, base)
			return nil
		}
		if !time.Now().Before(deadline) {
			return fmt.Errorf("retained floors did not advance past %d within %v", base, timeout)
		}
		time.Sleep(2 * time.Second)
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestConcurrentDeletesResurrectionsAndPruning(t *testing.T) {
	goharness.SkipUnlessLive(t)
	keys := int(envU64(t, "MURMUR_PRUNE_KEYS", 300))
	timeout := goharness.EnvSeconds("MURMUR_PRUNE_TIMEOUT_S", 25)
	// Reference value is 120 s with an explicitly driven collector;
	// here collection rides the engine's automatic 60 s retention
	// pass, so 150 s covers a just-missed tick plus margin.
	collectTimeout := goharness.EnvSeconds("MURMUR_PRUNE_COLLECT_TIMEOUT_S", 150)
	third := keys / 3
	if keys < 3 || keys%3 != 0 {
		t.Fatalf("MURMUR_PRUNE_KEYS=%d must be a positive multiple of 3", keys)
	}

	cluster, err := goharness.NewCluster(goharness.ClusterOptions{
		Name:     "delete-pruning",
		NumNodes: 3,
	})
	if err != nil {
		t.Fatalf("cluster setup: %v", err)
	}
	if cluster.Len() != 3 {
		t.Fatalf("this scenario is written for 3 nodes, got %d", cluster.Len())
	}
	failed := true
	defer func() { cluster.Finish(failed) }()

	// Aggressive retention floor (min_kept 10, as in the reference)
	// so the automatic pass prunes below the workload's versions.
	// The collection cadence itself stays the engine's automatic
	// 60 s tick (no per-test interval knob exists).
	for i := 0; i < 3; i++ {
		if _, err := cluster.Node(i).Simple(
			"INSERT INTO murmur_config(name,value) VALUES('retention_min_kept','10') ON CONFLICT(name) DO UPDATE SET value=excluded.value"); err != nil {
			t.Fatalf("node%d set retention floor: %v", i+1, err)
		}
	}
	for i := 0; i < 3; i++ {
		if _, err := cluster.Node(i).Simple(
			"CREATE TABLE IF NOT EXISTS rows(id TEXT PRIMARY KEY NOT NULL DEFAULT '', name TEXT NOT NULL DEFAULT '')"); err != nil {
			t.Fatalf("migrate node%d: %v", i+1, err)
		}
	}
	for i := 0; i < 3; i++ {
		if err := cluster.Node(i).SetTableReplicated("rows", true); err != nil {
			t.Fatalf("node%d SET TABLE REPLICATED: %v", i+1, err)
		}
		if err := cluster.Node(i).Flush(); err != nil {
			t.Fatalf("node%d flush after SET TABLE: %v", i+1, err)
		}
	}
	if err := cluster.PeerMesh(); err != nil {
		t.Fatalf("initial mesh: %v", err)
	}

	for k := 0; k < keys; k++ {
		if _, err := cluster.Node(0).Execute(
			"INSERT INTO rows(id, name) VALUES($1, $2)",
			fmt.Sprintf("key-%d", k), fmt.Sprintf("name-%d", k)); err != nil {
			t.Fatalf("seed key-%d: %v", k, err)
		}
	}
	if err := cluster.Node(0).Flush(); err != nil {
		t.Fatalf("seed flush: %v", err)
	}
	if err := waitConverged(cluster, keys, timeout); err != nil {
		t.Fatalf("seed: %v", err)
	}
	base, err := retainedFloors(cluster)
	if err != nil {
		t.Fatalf("baseline floors: %v", err)
	}

	// Phase 1: concurrent deletes plus an update on disjoint thirds.
	for k := 0; k < third; k++ {
		if _, err := cluster.Node(0).Execute("DELETE FROM rows WHERE id = $1", fmt.Sprintf("key-%d", k)); err != nil {
			t.Fatalf("phase 1 node1 delete: %v", err)
		}
	}
	for k := third; k < 2*third; k++ {
		if _, err := cluster.Node(1).Execute("UPDATE rows SET name = $1 WHERE id = $2",
			fmt.Sprintf("phase1-node2-%d", k), fmt.Sprintf("key-%d", k)); err != nil {
			t.Fatalf("phase 1 node2 update: %v", err)
		}
	}
	for k := 2 * third; k < keys; k++ {
		if _, err := cluster.Node(2).Execute("DELETE FROM rows WHERE id = $1", fmt.Sprintf("key-%d", k)); err != nil {
			t.Fatalf("phase 1 node3 delete: %v", err)
		}
	}
	for i := 0; i < 3; i++ {
		if err := cluster.Node(i).Flush(); err != nil {
			t.Fatalf("phase 1 node%d flush: %v", i+1, err)
		}
	}
	if err := waitConverged(cluster, third, timeout); err != nil {
		t.Fatalf("phase 1: %v", err)
	}

	// Phase 2: resurrect the first third from a survivor with new values.
	for k := 0; k < third; k++ {
		if _, err := cluster.Node(1).Execute(
			"INSERT INTO rows(id, name) VALUES($1, $2)",
			fmt.Sprintf("key-%d", k), fmt.Sprintf("phase2-resurrected-%d", k)); err != nil {
			t.Fatalf("phase 2 resurrect: %v", err)
		}
	}
	if err := cluster.Node(1).Flush(); err != nil {
		t.Fatalf("phase 2 flush: %v", err)
	}
	if err := waitConverged(cluster, 2*third, timeout); err != nil {
		t.Fatalf("phase 2: %v", err)
	}

	// Phase 3: delete the updated middle third.
	for k := third; k < 2*third; k++ {
		if _, err := cluster.Node(0).Execute("DELETE FROM rows WHERE id = $1", fmt.Sprintf("key-%d", k)); err != nil {
			t.Fatalf("phase 3 delete: %v", err)
		}
	}
	if err := cluster.Node(0).Flush(); err != nil {
		t.Fatalf("phase 3 flush: %v", err)
	}
	if err := waitConverged(cluster, third, timeout); err != nil {
		t.Fatalf("phase 3: %v", err)
	}

	// Retention collection: the automatic pass must prune delete
	// batches and advance the retained floors. Floors are polled for
	// the wait; the tombstone count is checked once before and once
	// after (a single before/after pair, not a poll loop, to keep
	// heavy view scans off the nodes while the collector runs).
	before, err := tombstones(cluster, 0)
	if err != nil {
		t.Fatalf("pre-collection tombstones: %v", err)
	}
	if before < 100 {
		t.Fatalf("pre-collection tombstones = %d, want >= 100 (vacuous collection?)", before)
	}
	fmt.Fprintf(os.Stderr, "pre-collection tombstones on node1: %d\n", before)
	if err := waitFloorsAdvance(cluster, base, collectTimeout); err != nil {
		t.Fatalf("collection: %v", err)
	}
	after, err := tombstones(cluster, 0)
	if err != nil {
		t.Fatalf("post-collection tombstones: %v", err)
	}
	fmt.Fprintf(os.Stderr, "tombstones collected on node1: %d -> %d\n", before, after)
	if after >= before {
		t.Fatalf("tombstones did not drop: before=%d after=%d", before, after)
	}

	// Post-prune proof: a fresh write still replicates everywhere.
	if _, err := cluster.Node(1).Execute(
		"INSERT INTO rows(id, name) VALUES($1, $2)",
		fmt.Sprintf("key-%d", keys), "post-prune"); err != nil {
		t.Fatalf("post-prune insert: %v", err)
	}
	if err := cluster.Node(1).Flush(); err != nil {
		t.Fatalf("post-prune flush: %v", err)
	}
	var want []string
	for k := 0; k < third; k++ {
		want = append(want, fmt.Sprintf("phase2-resurrected-%d", k))
	}
	want = append(want, "post-prune")
	sort.Strings(want)
	deadline := time.Now().Add(timeout)
	for {
		nodeNames, err := names(cluster, 0)
		if err != nil {
			t.Fatalf("post-prune names: %v", err)
		}
		node2Names, err := names(cluster, 1)
		if err != nil {
			t.Fatalf("post-prune names: %v", err)
		}
		node3Names, err := names(cluster, 2)
		if err != nil {
			t.Fatalf("post-prune names: %v", err)
		}
		if equalStrings(nodeNames, want) && equalStrings(node2Names, want) && equalStrings(node3Names, want) {
			break
		}
		if !time.Now().Before(deadline) {
			t.Fatalf("post-prune names did not converge on %v within %v", want, timeout)
		}
		time.Sleep(poll)
	}
	fmt.Fprintf(os.Stderr, "post-prune write replicated; tombstone collection proven\n")
	failed = false
}
