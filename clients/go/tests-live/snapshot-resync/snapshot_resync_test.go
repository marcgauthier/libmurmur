// Live scenario: stale nodes rejoin via snapshot after their log
// ranges are pruned past retention.
//
// Port of MURMUR-SQL snapshot-resync. Identical behavior: three nodes
// mesh with aggressive retention; a node stops while the survivors
// write past retention and GC expiry, then restarts with the same
// durable directory and must rejoin by merging a snapshot without
// discarding its acknowledged pre-stop state. A second test restarts
// two stale nodes back-to-back so their snapshot requests overlap on
// one survivor, and a multi-source case gives the stale node three
// snapshot sources concurrently. The snapshot path is proven by flat
// log-path counters (applied-batch growth must stay within the
// retained tail and far below the gap).
//
// Adaptations: retention bounds are written to murmur_config with a
// replication restart (no ReplicationOptions on this stack); snapshot
// trust already covers every peer via the harness; pruning is proven
// by polling health retention.collected_transactions through the
// 60 s automatic collection tick (no RETENTION COLLECT verb); the
// per-victim last-seen deadline leg is folded into the prune proof
// (floors cannot advance past a pinned peer, so collected>=40 proves
// every victim aged out of offline memory); cluster ids are harness
// random (no NodeIDs option).
package snapshotresync

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	goharness "github.com/marcgauthier/libmurmur/clients/go/tests-live/goharness"
)

// Newest transactions per origin the survivors must keep (Go:
// MinRetainedBatches = 10).
const minimumRetained = uint64(10)

// Offline-peer memory in ms (Go: MaxOfflineLogRetentionMs = 20000).
const maximumOfflineMs = "20000"

// Minimum pruned transactions per survivor before the rejoin: 60
// survivor writes minus the 10 retained, with margin. Proves the stale
// node's needed ranges are genuinely unrecoverable from logs, so the
// rejoin must use the snapshot path.
const minCollected = uint64(40)

// Baseline convergence deadline (Go: 30 s; margin matches the
// corrupt-snapshot port).
const baselineTimeout = 60 * time.Second

// Survivor row-count deadline (Go: 30 s).
const rowTimeout = 30 * time.Second

// Convergence poll interval (Go: 200 ms).
const convergePoll = 200 * time.Millisecond

// GC collection-loop deadline past the expiry wait. Native collection
// runs on the automatic 60 s tick (no on-demand verb), so this must
// cover a full tick past the offline wait.
const collectTimeout = 180 * time.Second

// Single-stale rejoin convergence deadline (Go: 90 s).
const resyncTimeout = 90 * time.Second

// Dual/multi-source rejoin convergence deadline (Go: 120 s).
const resyncTimeoutLong = 120 * time.Second

// names returns the canonical ordered names on one node.
func names(cluster *goharness.Cluster, idx int) ([]string, error) {
	rows, err := cluster.Node(idx).Simple("SELECT name FROM records ORDER BY name")
	if err != nil {
		return nil, fmt.Errorf("node%d SELECT names: %w", idx+1, err)
	}
	out := make([]string, 0, len(rows))
	for _, row := range rows {
		out = append(out, row[0])
	}
	return out, nil
}

// digest is the canonical digest of a name set (sorted rows hashed;
// newline-joined names are equally strict here since every row differs
// by name).
func digest(names []string) string {
	return strings.Join(names, "\n")
}

// rowCount returns the row count on one node (cheap pre-check before
// full name reads).
func rowCount(cluster *goharness.Cluster, idx int) (int, error) {
	rows, err := cluster.Node(idx).Simple("SELECT COUNT(*) FROM records")
	if err != nil {
		return 0, fmt.Errorf("node%d SELECT count: %w", idx+1, err)
	}
	if len(rows) == 0 || len(rows[0]) == 0 {
		return 0, fmt.Errorf("node%d count returned no rows", idx+1)
	}
	var n int
	if _, err := fmt.Sscanf(rows[0][0], "%d", &n); err != nil {
		return 0, fmt.Errorf("node%d decode count: %w", idx+1, err)
	}
	return n, nil
}

// insert writes one single-row transaction. No flush: the caller batches
// (baseline) or flushes per write (survivor legs, where one replication
// log entry is minted per flush batch).
func insert(cluster *goharness.Cluster, node int, id int64, name string) error {
	if _, err := cluster.Node(node).Execute(
		"INSERT INTO records(id, name) VALUES(?, ?)", id, name); err != nil {
		return fmt.Errorf("node%d insert '%s': %w", node+1, name, err)
	}
	return nil
}

func flush(cluster *goharness.Cluster, node int, what string) error {
	if err := cluster.Node(node).Flush(); err != nil {
		return fmt.Errorf("node%d flush (%s): %w", node+1, what, err)
	}
	return nil
}

// insertMany writes one multi-row transaction of count rows (the
// multi-source leg needs snapshot volume, not round trips).
func insertMany(cluster *goharness.Cluster, node int, startID, count int64, prefix string) error {
	if _, err := cluster.Node(node).Execute("BEGIN"); err != nil {
		return fmt.Errorf("node%d batch BEGIN: %w", node+1, err)
	}
	for n := startID; n < startID+count; n++ {
		name := fmt.Sprintf("%s-%d", prefix, n)
		if _, err := cluster.Node(node).Execute("INSERT INTO records(id, name) VALUES(?, ?)", n, name); err != nil {
			return fmt.Errorf("node%d batch insert '%s': %w", node+1, name, err)
		}
	}
	if _, err := cluster.Node(node).Execute("COMMIT"); err != nil {
		return fmt.Errorf("node%d batch COMMIT: %w", node+1, err)
	}
	return nil
}

// waitRowCount waits until one node holds exactly want rows.
func waitRowCount(cluster *goharness.Cluster, idx, want int, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		n, err := rowCount(cluster, idx)
		if err != nil {
			return err
		}
		if n == want {
			return nil
		}
		if !time.Now().Before(deadline) {
			now, err := rowCount(cluster, idx)
			if err != nil {
				return err
			}
			return fmt.Errorf("node%d record count = %d, want %d within %v",
				idx+1, now, want, timeout)
		}
		time.Sleep(convergePoll)
	}
}

// waitConverged waits until every node holds exactly want rows with
// equal digests.
func waitConverged(cluster *goharness.Cluster, want int, timeout time.Duration) error {
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
			for i := 0; i < cluster.Len(); i++ {
				ns, err := names(cluster, i)
				if err != nil {
					return err
				}
				d := digest(ns)
				if i == 0 {
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
			for i := 0; i < cluster.Len(); i++ {
				ns, err := names(cluster, i)
				if err != nil {
					return err
				}
				fmt.Fprintf(os.Stderr, "node%d at timeout: count=%d digest=%.100s\n",
					i+1, len(ns), digest(ns))
			}
			return fmt.Errorf("nodes did not converge on %d rows with equal digests within %v",
				want, timeout)
		}
		time.Sleep(convergePoll)
	}
}

func statusNum(cluster *goharness.Cluster, idx int, key string) (uint64, error) {
	st, err := cluster.Node(idx).ShowStatus()
	if err != nil {
		return 0, fmt.Errorf("node%d status: %w", idx+1, err)
	}
	m, ok := st.(map[string]any)
	if !ok {
		return 0, fmt.Errorf("node%d status is not an object", idx+1)
	}
	v, ok := m[key].(float64)
	if !ok {
		return 0, fmt.Errorf("node%d status has no numeric %s", idx+1, key)
	}
	return uint64(v), nil
}

// appliedBatches returns the cumulative applied batches on one node.
// Snapshot installs bump it once, so flat growth across a resync (within
// the retained tail) proves the rows arrived via snapshot.
func appliedBatches(cluster *goharness.Cluster, idx int) (uint64, error) {
	return statusNum(cluster, idx, "applied_batches")
}

// connectedPeers returns the live replication sessions on one node.
func connectedPeers(cluster *goharness.Cluster, idx int) (int, error) {
	n, err := statusNum(cluster, idx, "connected_peers")
	if err != nil {
		return 0, err
	}
	return int(n), nil
}

// assertSnapshotPath asserts the resync used the snapshot path. The
// retained tail (minimum_retained per origin) legitimately arrives via
// logs, so the applied growth must stay within the tail and far below
// the gap; the bulk can only have arrived via snapshot, the only other
// row path.
func assertSnapshotPath(cluster *goharness.Cluster, idx int, before uint64, gap int) error {
	after, err := appliedBatches(cluster, idx)
	if err != nil {
		return err
	}
	var growth uint64
	if after > before {
		growth = after - before
	}
	if growth > 2*minimumRetained {
		return fmt.Errorf("node%d resync applied %d batches, above the retained tail (2 x %d)",
			idx+1, growth, minimumRetained)
	}
	if int(growth) >= gap {
		return fmt.Errorf("node%d resync arrived over the log path (applied growth %d, gap %d), not a snapshot (log catch-up would hide a snapshot-path regression)",
			idx+1, growth, gap)
	}
	return nil
}

// collectedTotal returns the total transactions ever pruned on one
// node (node-global trailing counter in the health snapshot).
func collectedTotal(cluster *goharness.Cluster, idx int) (uint64, error) {
	h, err := cluster.Node(idx).ShowHealth()
	if err != nil {
		return 0, fmt.Errorf("node%d health: %w", idx+1, err)
	}
	m, ok := h.(map[string]any)
	if !ok {
		return 0, fmt.Errorf("node%d health is not an object", idx+1)
	}
	r, ok := m["retention"].(map[string]any)
	if !ok {
		return 0, nil
	}
	v, ok := r["collected_transactions"].(float64)
	if !ok {
		return 0, nil
	}
	return uint64(v), nil
}

// staleRows counts acknowledged pre-stop rows surviving on one node.
func staleRows(cluster *goharness.Cluster, idx int) (int, error) {
	ns, err := names(cluster, idx)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, name := range ns {
		if strings.HasPrefix(name, "stale-") {
			n++
		}
	}
	return n, nil
}

// migrateAll lays the same schema on every node, then replicates it:
// row convergence needs the per-table flag on each node.
func migrateAll(cluster *goharness.Cluster) error {
	for i := 0; i < cluster.Len(); i++ {
		if _, err := cluster.Node(i).Simple(
			"CREATE TABLE IF NOT EXISTS records(id INTEGER PRIMARY KEY NOT NULL, name TEXT NOT NULL DEFAULT '')"); err != nil {
			return fmt.Errorf("migrate node%d: %w", i+1, err)
		}
	}
	for i := 0; i < cluster.Len(); i++ {
		if err := cluster.Node(i).SetTableReplicated("records", true); err != nil {
			return fmt.Errorf("node%d SET TABLE REPLICATED: %w", i+1, err)
		}
		if err := flush(cluster, i, "SET TABLE"); err != nil {
			return err
		}
	}
	return nil
}

// snapshotCluster builds the standard snapshot-resync cluster:
// aggressive retention plus all-node snapshot trust (the engine only
// requests snapshots from explicitly trusted sources; the harness
// already trusts every peer).
func snapshotCluster(name string, numNodes int) (*goharness.Cluster, error) {
	cluster, err := goharness.NewCluster(goharness.ClusterOptions{
		Name:     name,
		NumNodes: numNodes,
	})
	if err != nil {
		return nil, fmt.Errorf("cluster setup: %w", err)
	}
	for i := 0; i < cluster.Len(); i++ {
		if err := cluster.StopNode(i); err != nil {
			cluster.Finish(true)
			return nil, fmt.Errorf("stop node %d: %w", i, err)
		}
	}
	for i := 0; i < cluster.Len(); i++ {
		for _, kv := range [][2]string{
			{"retention_min_kept", "10"},
			{"retention_max_offline_ms", maximumOfflineMs},
		} {
			if _, err := cluster.Node(i).Simple(
				"INSERT INTO murmur_config(name,value) VALUES('" + kv[0] + "','" + kv[1] +
					"') ON CONFLICT(name) DO UPDATE SET value=excluded.value"); err != nil {
				cluster.Finish(true)
				return nil, fmt.Errorf("node %d set %s: %w", i, kv[0], err)
			}
		}
	}
	for i := 0; i < cluster.Len(); i++ {
		if err := cluster.StartNode(i); err != nil {
			cluster.Finish(true)
			return nil, fmt.Errorf("start node %d: %w", i, err)
		}
	}
	if err := cluster.PeerMesh(); err != nil {
		cluster.Finish(true)
		return nil, fmt.Errorf("remesh: %w", err)
	}
	return cluster, nil
}

// ensureSnapshotPath waits for member-deadline expiry plus automatic
// collection passes: every survivor must prune past retention and stop
// pinning every victim, proving the victims' needed ranges are
// genuinely unrecoverable from logs. Collection runs on the automatic
// 60 s tick (no on-demand verb), so this polls. The explicit
// per-victim last-seen deadline leg has no native equivalent (no
// per-peer last-seen binding); it is folded into the prune proof,
// since floors cannot advance past a pinned peer.
func ensureSnapshotPath(cluster *goharness.Cluster, survivors, victims []int) error {
	fmt.Fprintln(os.Stderr, "waiting for member-deadline expiry and collection")
	_ = victims
	time.Sleep(goharness.EnvSeconds("MURMUR_SNAPSHOT_RESYNC_GC_WAIT_SECONDS", 30))
	collectDeadline := time.Now().Add(collectTimeout)
	for {
		var totals []uint64
		for _, i := range survivors {
			n, err := collectedTotal(cluster, i)
			if err != nil {
				return err
			}
			totals = append(totals, n)
		}
		all := true
		for _, n := range totals {
			if n < minCollected {
				all = false
				break
			}
		}
		if all {
			fmt.Fprintf(os.Stderr, "survivors pruned %v transactions past retention\n", totals)
			break
		}
		if !time.Now().Before(collectDeadline) {
			return fmt.Errorf("survivors collected only %v transactions, want >= %d each (snapshot path not forced)",
				totals, minCollected)
		}
		time.Sleep(2 * time.Second)
	}
	return nil
}

func singleBody(cluster *goharness.Cluster) error {
	// Phase 1: node3 writes acknowledged rows, then all three converge.
	if err := migrateAll(cluster); err != nil {
		return err
	}
	for i := int64(0); i < 5; i++ {
		if err := insert(cluster, 2, i+1, fmt.Sprintf("stale-%d", i)); err != nil {
			return err
		}
	}
	if err := flush(cluster, 2, "baseline"); err != nil {
		return err
	}
	if err := waitConverged(cluster, 5, baselineTimeout); err != nil {
		return err
	}

	// Phase 2: node3 stops; survivors write far past retention.
	// Flush every write: the product mints one replication log entry
	// per flush batch, not per SQL transaction, so a single trailing
	// flush would leave fewer entries than `minimum_retained` and
	// nothing would ever become eligible for pruning.
	cluster.StopNode(2)
	for i := int64(0); i < 60; i++ {
		if err := insert(cluster, 0, 100+i, fmt.Sprintf("fresh-%d", i)); err != nil {
			return err
		}
		if err := flush(cluster, 0, "survivor write"); err != nil {
			return err
		}
	}
	if err := waitRowCount(cluster, 0, 65, rowTimeout); err != nil {
		return err
	}
	if err := waitRowCount(cluster, 1, 65, rowTimeout); err != nil {
		return err
	}
	if err := ensureSnapshotPath(cluster, []int{0, 1}, []int{2}); err != nil {
		return err
	}

	// Phase 3: node3 restarts with the same durable directory and rejoins.
	if err := cluster.StartNode(2); err != nil {
		return fmt.Errorf("stale node restart: %w", err)
	}
	if err := cluster.PeerMesh(); err != nil {
		return fmt.Errorf("re-mesh after restart: %w", err)
	}
	appliedBefore, err := appliedBatches(cluster, 2)
	if err != nil {
		return err
	}
	if err := waitConverged(cluster, 65, resyncTimeout); err != nil {
		return err
	}

	// The rejoin must have used the snapshot path, not log catch-up.
	if err := assertSnapshotPath(cluster, 2, appliedBefore, 65-5); err != nil {
		return err
	}

	// Node3's acknowledged pre-stop state survives the snapshot merge.
	stale, err := staleRows(cluster, 2)
	if err != nil {
		return err
	}
	if stale != 5 {
		return fmt.Errorf("node3 stale rows after resync = %d, want 5", stale)
	}
	return nil
}

func dualBody(cluster *goharness.Cluster) error {
	if err := migrateAll(cluster); err != nil {
		return err
	}
	for i := int64(0); i < 5; i++ {
		if err := insert(cluster, 2, i+1, fmt.Sprintf("stale-%d", i)); err != nil {
			return err
		}
	}
	if err := flush(cluster, 2, "baseline"); err != nil {
		return err
	}
	if err := waitConverged(cluster, 5, baselineTimeout); err != nil {
		return err
	}

	// Two nodes stop; the survivor writes far past retention (flushed
	// per write: one replication log entry is minted per flush batch).
	cluster.StopNode(1)
	cluster.StopNode(2)
	for i := int64(0); i < 60; i++ {
		if err := insert(cluster, 0, 100+i, fmt.Sprintf("fresh-%d", i)); err != nil {
			return err
		}
		if err := flush(cluster, 0, "survivor write"); err != nil {
			return err
		}
	}
	if err := waitRowCount(cluster, 0, 65, rowTimeout); err != nil {
		return err
	}
	if err := ensureSnapshotPath(cluster, []int{0}, []int{1, 2}); err != nil {
		return err
	}

	// Restart both stale nodes back-to-back so their snapshot requests
	// overlap on the survivor.
	if err := cluster.StartNode(1); err != nil {
		return fmt.Errorf("stale node2 restart: %w", err)
	}
	if err := cluster.StartNode(2); err != nil {
		return fmt.Errorf("stale node3 restart: %w", err)
	}
	if err := cluster.PeerMesh(); err != nil {
		return fmt.Errorf("re-mesh after restart: %w", err)
	}
	var appliedBefore []uint64
	for _, i := range []int{1, 2} {
		n, err := appliedBatches(cluster, i)
		if err != nil {
			return err
		}
		appliedBefore = append(appliedBefore, n)
	}
	if err := waitConverged(cluster, 65, resyncTimeoutLong); err != nil {
		return err
	}

	for k, idx := range []int{1, 2} {
		if err := assertSnapshotPath(cluster, idx, appliedBefore[k], 65-5); err != nil {
			return err
		}
		stale, err := staleRows(cluster, idx)
		if err != nil {
			return err
		}
		if stale != 5 {
			return fmt.Errorf("node%d stale rows after resync = %d, want 5", idx+1, stale)
		}
		// The resync diagnostics surface end to end: each rejoined
		// node reports live replication sessions.
		peers, err := connectedPeers(cluster, idx)
		if err != nil {
			return err
		}
		if peers < 1 {
			return fmt.Errorf("node%d reports no connected peers after resync", idx+1)
		}
	}
	return nil
}

func multisourceBody(cluster *goharness.Cluster) error {
	const victim = 3
	if err := migrateAll(cluster); err != nil {
		return err
	}
	for i := int64(0); i < 5; i++ {
		if err := insert(cluster, victim, i+1, fmt.Sprintf("stale-%d", i)); err != nil {
			return err
		}
	}
	if err := flush(cluster, victim, "baseline"); err != nil {
		return err
	}
	if err := waitConverged(cluster, 5, baselineTimeout); err != nil {
		return err
	}

	// Victim stops; survivors write thousands of rows so the resync
	// snapshot spans many chunks (a 1-2 chunk snapshot rarely
	// interleaves badly enough to expose source contention).
	cluster.StopNode(victim)
	// Batched multi-row transactions: the test needs snapshot volume
	// (many chunks), not round trips. Flush per batch: one replication
	// log entry is minted per flush batch, and retention needs dozens
	// of entries to prune past (a single trailing flush would leave
	// fewer entries than `minimum_retained`).
	const freshRows = int64(6000)
	const batch = int64(100)
	start := time.Now()
	for base := int64(0); base < freshRows; base += batch {
		if err := insertMany(cluster, 0, 100+base, batch, "fresh"); err != nil {
			return err
		}
		if err := flush(cluster, 0, "survivor batch"); err != nil {
			return err
		}
	}
	fmt.Fprintf(os.Stderr, "wrote %d survivor rows in %v\n", freshRows, time.Since(start))
	want := 5 + int(freshRows)
	for i := 0; i < 3; i++ {
		if err := waitRowCount(cluster, i, want, rowTimeout); err != nil {
			return err
		}
	}
	if err := ensureSnapshotPath(cluster, []int{0, 1, 2}, []int{victim}); err != nil {
		return err
	}

	if err := cluster.StartNode(victim); err != nil {
		return fmt.Errorf("victim restart: %w", err)
	}
	if err := cluster.PeerMesh(); err != nil {
		return fmt.Errorf("re-mesh after restart: %w", err)
	}
	appliedBefore, err := appliedBatches(cluster, victim)
	if err != nil {
		return err
	}
	if err := waitConverged(cluster, want, resyncTimeoutLong); err != nil {
		return err
	}

	// The rejoin used the snapshot path (not log catch-up) under real
	// multi-source contention: three survivors serve concurrently while
	// the transfer completes to convergence. Rival-source suppression
	// has no native counter; contention coverage is behavioral.
	if err := assertSnapshotPath(cluster, victim, appliedBefore, want-5); err != nil {
		return err
	}
	stale, err := staleRows(cluster, victim)
	if err != nil {
		return err
	}
	if stale != 5 {
		return fmt.Errorf("victim stale rows after resync = %d, want 5", stale)
	}
	return nil
}

func runScenario(t *testing.T, name string, numNodes int, body func(*goharness.Cluster) error) {
	t.Helper()
	cluster, err := snapshotCluster(name, numNodes)
	if err != nil {
		t.Fatal(err)
	}
	result := body(cluster)
	failed := result != nil
	if result != nil {
		fmt.Fprintf(os.Stderr, "scenario failed: %v\n", result)
	}
	cluster.Finish(failed)
	if failed {
		t.Fatal("scenario failed; artifacts retained under tests-live/failures/")
	}
}

func TestStaleNodeRejoinsViaSnapshot(t *testing.T) {
	goharness.SkipUnlessLive(t)
	runScenario(t, "snapshot-resync", 3, singleBody)
}

func TestDualStaleNodesRejoinViaSnapshot(t *testing.T) {
	goharness.SkipUnlessLive(t)
	runScenario(t, "snapshot-resync-dual", 3, dualBody)
}

func TestStaleNodeRejoinsViaSingleSnapshotSource(t *testing.T) {
	goharness.SkipUnlessLive(t)
	runScenario(t, "snapshot-multisource", 4, multisourceBody)
}
