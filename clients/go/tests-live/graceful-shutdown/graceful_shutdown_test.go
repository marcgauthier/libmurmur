// Live scenario: graceful shutdown mid-write under load and mid-snapshot
// during rejoin.
//
// Port of MURMUR-SQL graceful-shutdown. Phase A (running) stops node 0
// mid-write under concurrent client load, restarts it, and requires
// reconvergence with zero acknowledged writes lost. Phase B (skipped)
// restarts node 2 after retention log GC (forcing snapshot resync) and
// stops it again mid-transfer: the stale node rejoins its sessions but
// the pruned range never arrives (no snapshot delivery), so the
// reconvergence leg cannot pass on this stack.
//
// The reference delivers SIGTERM to a server child; this stack exposes
// no child PID/signal surface, so shutdown is the graceful in-process
// driver stop (StopNode) and restart is StartNode. Retention GC runs on
// the driver's automatic pass (there is no RETENTION COLLECT verb
// here), so the collection proof polls the progress snapshot until the
// survivors' retained floors advance past the stale peer.
package gracefulshutdown

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	goharness "github.com/marcgauthier/libmurmur/clients/go/tests-live/goharness"
)

const tableDDL = "CREATE TABLE IF NOT EXISTS contention(id TEXT PRIMARY KEY NOT NULL DEFAULT '', name TEXT NOT NULL DEFAULT '', phone TEXT NOT NULL DEFAULT '')"

func rowID(node int, seq uint64) string {
	return fmt.Sprintf("%08x-0000-4000-8000-%012x", node, seq)
}

// ackedSet is the concurrent acknowledged-write registry (Rust:
// Arc<tokio::sync::Mutex<HashSet<String>>>).
type ackedSet struct {
	mu sync.Mutex
	m  map[string]bool
}

func (s *ackedSet) insert(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[name] = true
}

func (s *ackedSet) snapshot() map[string]bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]bool, len(s.m))
	for k, v := range s.m {
		out[k] = v
	}
	return out
}

func waitConverged(t *testing.T, cluster *goharness.Cluster, timeout time.Duration) []string {
	t.Helper()
	deadline := time.Now().Add(timeout)
	query := "SELECT name FROM contention ORDER BY name"
	for {
		r0, e0 := cluster.Node(0).Simple(query)
		r1, e1 := cluster.Node(1).Simple(query)
		r2, e2 := cluster.Node(2).Simple(query)
		if e0 == nil && e1 == nil && e2 == nil && len(r0) > 0 && equalRows(r0, r1) && equalRows(r1, r2) {
			out := make([]string, len(r0))
			for i, row := range r0 {
				out[i] = row[0]
			}
			return out
		}
		if !time.Now().Before(deadline) {
			for i := 0; i < 3; i++ {
				r, e := cluster.Node(i).Simple(query)
				peers, pe := cluster.Node(i).ShowPeers()
				nconn := -1
				if pe == nil {
					nconn = 0
					for _, p := range peers {
						if p.Connected {
							nconn++
						}
					}
				}
				t.Logf("node %d at timeout: rows=%d err=%v peers=%d peererr=%v", i, len(r), e, nconn, pe)
			}
			t.Fatalf("cluster failed to converge within %v", timeout)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// waitPeerGone waits until none of watchers holds a connected session
// to goneID. A lingering session keeps the dead peer's unacked range
// protected past maximum_offline by design, so pruning assertions must
// await teardown, not just record staleness.
func waitPeerGone(t *testing.T, cluster *goharness.Cluster, watchers []int, goneID string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		present := false
		for _, i := range watchers {
			if peers, err := cluster.Node(i).ShowPeers(); err == nil {
				for _, p := range peers {
					if p.Connected && strings.EqualFold(p.NodeID, goneID) {
						present = true
					}
				}
			}
		}
		if !present {
			return
		}
		if !time.Now().Before(deadline) {
			t.Fatalf("peer %s session never dropped", goneID)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// retainedSum totals the retained_from floors over every origin head in
// one node's progress snapshot.
func retainedSum(cluster *goharness.Cluster, idx int) (uint64, error) {
	snap, err := cluster.Node(idx).ShowReplication()
	if err != nil {
		return 0, fmt.Errorf("node%d SHOW REPLICATION: %w", idx+1, err)
	}
	arr, ok := snap.([]any)
	if !ok {
		return 0, fmt.Errorf("node%d SHOW REPLICATION: unexpected shape %T", idx+1, snap)
	}
	var sum uint64
	for _, e := range arr {
		m, ok := e.(map[string]any)
		if !ok {
			return 0, fmt.Errorf("node%d SHOW REPLICATION: bad entry %T", idx+1, e)
		}
		v, ok := m["retained_from"].(float64)
		if !ok {
			return 0, fmt.Errorf("node%d SHOW REPLICATION: no retained_from floor", idx+1)
		}
		sum += uint64(v)
	}
	return sum, nil
}

// waitFloorsAdvance waits until the survivors' retained floors move
// past their baseline: the stale peer's unacked range must be pruned
// by retention GC before the stale node rejoins (the on-demand
// RETENTION COLLECT proof in the reference; here the driver's
// automatic pass runs every 60 s).
func waitFloorsAdvance(t *testing.T, cluster *goharness.Cluster, base0, base1 uint64, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		s0, e0 := retainedSum(cluster, 0)
		s1, e1 := retainedSum(cluster, 1)
		if e0 == nil && e1 == nil && s0 > base0 && s1 > base1 {
			t.Logf("retention pruned stale range: floors %d->%d / %d->%d", base0, s0, base1, s1)
			return
		}
		if !time.Now().Before(deadline) {
			t.Fatalf("retention floors never advanced past %d/%d (last %d/%d, errs %v/%v)",
				base0, base1, s0, s1, e0, e1)
		}
		time.Sleep(time.Second)
	}
}

func assertAcknowledgedPresent(t *testing.T, present []string, acknowledged map[string]bool) {
	t.Helper()
	set := make(map[string]bool, len(present))
	for _, p := range present {
		set[p] = true
	}
	for ack := range acknowledged {
		if !set[ack] {
			t.Fatalf("acknowledged write %q missing from converged cluster state", ack)
		}
	}
}

// setRetention writes aggressive retention bounds (minimum_retained 10,
// maximum_offline 5 s, mirroring the reference replication YAML) and
// restarts replication so the bounds take effect. Trusted snapshot
// sources need no setup: the harness already trusts every peer.
func setRetention(t *testing.T, cluster *goharness.Cluster) {
	t.Helper()
	for i := 0; i < cluster.Len(); i++ {
		if err := cluster.StopNode(i); err != nil {
			t.Fatalf("stop node %d: %v", i, err)
		}
	}
	for i := 0; i < cluster.Len(); i++ {
		for _, kv := range [][2]string{
			{"retention_min_kept", "10"},
			{"retention_max_offline_ms", "5000"},
		} {
			if _, err := cluster.Node(i).Simple(
				"INSERT INTO murmur_config(name,value) VALUES('" + kv[0] + "','" + kv[1] +
					"') ON CONFLICT(name) DO UPDATE SET value=excluded.value"); err != nil {
				t.Fatalf("node %d set %s: %v", i, kv[0], err)
			}
		}
	}
	for i := 0; i < cluster.Len(); i++ {
		if err := cluster.StartNode(i); err != nil {
			t.Fatalf("start node %d: %v", i, err)
		}
	}
	if err := cluster.PeerMesh(); err != nil {
		t.Fatalf("remesh: %v", err)
	}
}

// setupCluster boots the scenario cluster with aggressive retention
// and the replicated contention table on all 3 nodes.
func setupCluster(t *testing.T) *goharness.Cluster {
	t.Helper()
	cluster, err := goharness.NewCluster(goharness.ClusterOptions{
		Name:     "graceful-shutdown",
		NumNodes: 3,
	})
	if err != nil {
		t.Fatalf("cluster setup: %v", err)
	}
	setRetention(t, cluster)
	for i := 0; i < cluster.Len(); i++ {
		if _, err := cluster.Node(i).Simple(tableDDL); err != nil {
			cluster.Finish(true)
			t.Fatalf("node %d migrate: %v", i, err)
		}
		if err := cluster.Node(i).SetTableReplicated("contention", true); err != nil {
			cluster.Finish(true)
			t.Fatalf("node %d replicate: %v", i, err)
		}
		if err := cluster.Node(i).Flush(); err != nil {
			cluster.Finish(true)
			t.Fatalf("node %d flush schema: %v", i, err)
		}
	}
	return cluster
}

// seedBaseline writes the 5 converging baseline rows on node 0 and
// returns the acknowledged set.
func seedBaseline(t *testing.T, cluster *goharness.Cluster) map[string]bool {
	t.Helper()
	acknowledged := map[string]bool{}
	var expectedBaseline [][]string
	for i := 0; i < 5; i++ {
		id := rowID(0, uint64(i))
		name := fmt.Sprintf("base-%d", i)
		if _, err := cluster.Node(0).Execute(
			"INSERT INTO contention(id, name, phone) VALUES($1, $2, $3)", id, name, ""); err != nil {
			t.Fatalf("insert %s: %v", id, err)
		}
		acknowledged[name] = true
		expectedBaseline = append(expectedBaseline, []string{name})
	}
	if err := cluster.Node(0).Flush(); err != nil {
		t.Fatalf("flush baseline: %v", err)
	}
	sort.Slice(expectedBaseline, func(a, b int) bool { return expectedBaseline[a][0] < expectedBaseline[b][0] })
	if err := goharness.AssertRows(cluster, []int{0, 1, 2},
		"SELECT name FROM contention ORDER BY name", expectedBaseline); err != nil {
		t.Fatalf("baseline converge: %v", err)
	}
	return acknowledged
}

// runPhaseA stops node 0 mid-write under concurrent client load on all
// nodes, restarts it, and requires reconvergence with every
// acknowledged write present. It returns the acknowledged set.
func runPhaseA(t *testing.T, cluster *goharness.Cluster, acknowledged map[string]bool) map[string]bool {
	t.Helper()
	var stop atomic.Bool
	var paused [3]atomic.Bool
	acked := &ackedSet{m: map[string]bool{}}
	for k, v := range acknowledged {
		acked.m[k] = v
	}

	var wg sync.WaitGroup
	for nodeIdx := 0; nodeIdx < 3; nodeIdx++ {
		wg.Add(1)
		go func(nodeIdx int) {
			defer wg.Done()
			var seq uint64
			for !stop.Load() {
				if paused[nodeIdx].Load() {
					time.Sleep(20 * time.Millisecond)
					continue
				}
				seq++
				id := rowID(nodeIdx+1, seq)
				name := fmt.Sprintf("load-n%d-%06d", nodeIdx, seq)
				if _, resErr := cluster.Node(nodeIdx).Execute(
					"INSERT INTO contention(id, name, phone) VALUES($1, $2, $3)", id, name, ""); resErr == nil {
					acked.insert(name)
				}
				time.Sleep(15 * time.Millisecond)
			}
		}(nodeIdx)
	}

	// Let writes get in flight.
	time.Sleep(300 * time.Millisecond)

	// Pause node 0 writer and drain pending writes.
	paused[0].Store(true)
	time.Sleep(100 * time.Millisecond)
	if err := cluster.Node(0).Flush(); err != nil {
		t.Fatalf("flush node 0: %v", err)
	}

	// Graceful shutdown of node 0 (the reference SIGTERMs the server
	// child; here the graceful driver stop is the shutdown).
	if err := cluster.StopNode(0); err != nil {
		t.Fatalf("stop node 0: %v", err)
	}

	// Nodes 1 and 2 continue writing while node 0 is offline.
	time.Sleep(200 * time.Millisecond)

	// Restart node 0 cleanly.
	if err := cluster.StartNode(0); err != nil {
		t.Fatalf("restart node 0: %v", err)
	}
	if err := cluster.PeerMesh(); err != nil {
		t.Fatalf("remesh after node 0 restart: %v", err)
	}

	// Reconnect the node 0 writer (the paused original stays parked
	// until the phase ends).
	wg.Add(1)
	go func() {
		defer wg.Done()
		var seq uint64 = 500
		for !stop.Load() {
			seq++
			id := rowID(1, seq)
			name := fmt.Sprintf("load-n0-postrestart-%06d", seq)
			if _, resErr := cluster.Node(0).Execute(
				"INSERT INTO contention(id, name, phone) VALUES($1, $2, $3)", id, name, ""); resErr == nil {
				acked.insert(name)
			}
			time.Sleep(15 * time.Millisecond)
		}
	}()

	// Let concurrent writes proceed across all nodes after restart.
	time.Sleep(300 * time.Millisecond)

	// Stop all phase A writers.
	stop.Store(true)
	wg.Wait()

	// Flush all nodes.
	for i := 0; i < 3; i++ {
		if err := cluster.Node(i).Flush(); err != nil {
			t.Fatalf("flush node %d: %v", i, err)
		}
	}

	// Verify all 3 nodes converge with identical contents, and every
	// acknowledged write is present.
	ackedSnapshot := acked.snapshot()
	convergedA := waitConverged(t, cluster, 60*time.Second)
	assertAcknowledgedPresent(t, convergedA, ackedSnapshot)
	return ackedSnapshot
}

// runPhaseB takes node 2 stale under aggressive retention while the
// survivors write bulk + fat payload, prunes its range, restarts it
// mid-transfer, and requires full reconvergence plus a post-recovery
// write. Blocked: the stale node rejoins but the pruned range never
// arrives (see TestGracefulShutdownMidSnapshotDuringRejoin).
func runPhaseB(t *testing.T, cluster *goharness.Cluster, ackedSnapshot map[string]bool) {
	t.Helper()
	base0, err := retainedSum(cluster, 0)
	if err != nil {
		t.Fatalf("retained baseline node 0: %v", err)
	}
	base1, err := retainedSum(cluster, 1)
	if err != nil {
		t.Fatalf("retained baseline node 1: %v", err)
	}
	if err := cluster.StopNode(2); err != nil {
		t.Fatalf("stop node 2: %v", err)
	}
	phaseBAcked := map[string]bool{}
	for k, v := range ackedSnapshot {
		phaseBAcked[k] = v
	}
	for i := 0; i < 50; i++ {
		name := fmt.Sprintf("fresh-%03d", i)
		id := rowID(1, 5000+uint64(i))
		if _, err := cluster.Node(0).Execute(
			"INSERT INTO contention(id, name, phone) VALUES($1, $2, $3)", id, name, ""); err != nil {
			t.Fatalf("insert %s: %v", id, err)
		}
		phaseBAcked[name] = true
	}

	// 8 fat rows (~64 KB each) to widen the transfer window.
	fatChunk := strings.Repeat("FAT-FILLER-DATA-STRING-PADDING-1234567890\n", 1500)
	for i := 0; i < 8; i++ {
		name := fmt.Sprintf("fat-%02d", i)
		id := rowID(2, 6000+uint64(i))
		if _, err := cluster.Node(1).Execute(
			"INSERT INTO contention(id, name, phone) VALUES($1, $2, $3)", id, name, fatChunk); err != nil {
			t.Fatalf("insert %s: %v", id, err)
		}
		phaseBAcked[name] = true
	}

	if err := cluster.Node(0).Flush(); err != nil {
		t.Fatalf("flush node 0: %v", err)
	}
	if err := cluster.Node(1).Flush(); err != nil {
		t.Fatalf("flush node 1: %v", err)
	}

	var expectedSurvivors [][]string
	for n := range phaseBAcked {
		expectedSurvivors = append(expectedSurvivors, []string{n})
	}
	sort.Slice(expectedSurvivors, func(a, b int) bool { return expectedSurvivors[a][0] < expectedSurvivors[b][0] })
	if err := goharness.AssertRows(cluster, []int{0, 1},
		"SELECT name FROM contention ORDER BY name", expectedSurvivors); err != nil {
		t.Fatalf("survivors converge: %v", err)
	}

	// Node 2's session must drop before its unacknowledged logs unpin.
	node2ID := cluster.NodeID(2)
	waitPeerGone(t, cluster, []int{0, 1}, node2ID, 60*time.Second)

	// Retention GC must prune node 2's unacked range on the survivors
	// (the reference asserts collected batches from an on-demand
	// MURMUR RETENTION COLLECT; here the automatic pass is awaited via
	// the retained floors).
	waitFloorsAdvance(t, cluster, base0, base1, 150*time.Second)

	// Restart stale node 2: it must take the snapshot path because its log position was pruned.
	if err := cluster.StartNode(2); err != nil {
		t.Fatalf("restart stale node 2: %v", err)
	}
	if err := cluster.PeerMesh(); err != nil {
		t.Fatalf("remesh stale node 2: %v", err)
	}

	// Interrupt node 2 mid-transfer: brief delay then stop.
	time.Sleep(25 * time.Millisecond)
	if err := cluster.StopNode(2); err != nil {
		t.Fatalf("interrupt node 2: %v", err)
	}

	// Restart node 2 again after interrupt.
	if err := cluster.StartNode(2); err != nil {
		t.Fatalf("restart node 2 after interrupt: %v", err)
	}
	if err := cluster.PeerMesh(); err != nil {
		t.Fatalf("remesh node 2 after interrupt: %v", err)
	}

	// All nodes must reconverge on the full dataset with no missing rows.
	convergedB := waitConverged(t, cluster, 60*time.Second)
	assertAcknowledgedPresent(t, convergedB, phaseBAcked)

	// Post-recovery write on node 0 replicates to all nodes.
	postName := "post-recovery-write"
	postID := rowID(1, 999999)
	if _, err := cluster.Node(0).Execute(
		"INSERT INTO contention(id, name, phone) VALUES($1, $2, $3)", postID, postName, ""); err != nil {
		t.Fatalf("post-recovery insert: %v", err)
	}
	if err := cluster.Node(0).Flush(); err != nil {
		t.Fatalf("flush post-recovery: %v", err)
	}

	expectedFinal := append(append([][]string(nil), expectedSurvivors...), []string{postName})
	sort.Slice(expectedFinal, func(a, b int) bool { return expectedFinal[a][0] < expectedFinal[b][0] })
	if err := goharness.AssertRows(cluster, []int{0, 1, 2},
		"SELECT name FROM contention ORDER BY name", expectedFinal); err != nil {
		t.Fatalf("final converge: %v", err)
	}
}

func TestGracefulShutdownMidWriteUnderLoad(t *testing.T) {
	goharness.SkipUnlessLive(t)
	cluster := setupCluster(t)
	failed := true
	defer func() { cluster.Finish(failed) }()
	acknowledged := seedBaseline(t, cluster)
	runPhaseA(t, cluster, acknowledged)
	failed = false
}

func TestGracefulShutdownMidSnapshotDuringRejoin(t *testing.T) {
	goharness.SkipUnlessLive(t)
	// Unblocked by the automatic snapshot fallback (pruned pull cursor
	// triggers a trust-gated snapshot request) plus the QUIC stream-id
	// reservation fix: stale rejoins now converge via snapshot.
	cluster := setupCluster(t)
	failed := true
	defer func() { cluster.Finish(failed) }()
	acknowledged := seedBaseline(t, cluster)
	ackedSnapshot := runPhaseA(t, cluster, acknowledged)
	runPhaseB(t, cluster, ackedSnapshot)
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
