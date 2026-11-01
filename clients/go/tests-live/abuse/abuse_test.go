// Live scenario: real SQL writers cross healthy, partition, outage and
// whole-mesh crash phases.
//
// Port of MURMUR-SQL abuse: N nodes (default 10) with static fanout-2
// peering and full snapshot-donor trust take a baseline row, min(N,8)
// concurrent writers insert paced rows while the mesh crosses healthy,
// partition, partial-outage and whole-mesh-restart quarters, and every
// node must converge exactly on the acknowledged set. Nodes are native
// replication drivers over VFS stores in child processes; stop legs are
// graceful process exits plus reboot-on-dir (SIGKILL loses all local
// state on this stack, so crash stops cannot preserve the acknowledged
// set). The partition uses per-node allowed_peers allow-lists plus
// restarts (the partition-port technique) instead of runtime PEER
// REMOVE/ADD.
package abuse

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	goharness "github.com/marcgauthier/libmurmur/clients/go/tests-live/goharness"
)

// slot is one node's writer target. A writer holds the read lock
// through SQL+FLUSH; stop takes the write lock to drain acknowledged
// writes before stopping that node only.
type slot struct {
	mu     sync.RWMutex
	client *goharness.Node
}

func number(name string, def uint64) uint64 {
	if s, err := strconv.ParseUint(os.Getenv(name), 10, 64); err == nil && s > 0 {
		return s
	}
	return def
}

func mesh(t *testing.T, cluster *goharness.Cluster) {
	t.Helper()
	if err := cluster.PeerMesh(); err != nil {
		t.Fatalf("mesh: %v", err)
	}
}

func stopNodes(t *testing.T, cluster *goharness.Cluster, slots []*slot, nodes []int) {
	t.Helper()
	for _, i := range nodes {
		// A writer holds this read lock through SQL+FLUSH. Taking the
		// write lock drains acknowledged writes before stopping that
		// server only. The stop is a graceful process exit (which
		// persists the store), not SIGKILL: on this stack SIGKILL
		// loses all local state, so crash stops cannot preserve the
		// acknowledged set (see the README).
		slots[i].mu.Lock()
		func() {
			defer slots[i].mu.Unlock()
			slots[i].client = nil
			if err := cluster.Node(i).Flush(); err != nil {
				t.Fatalf("node %d pre-stop flush: %v", i, err)
			}
			if err := cluster.Node(i).Close(); err != nil {
				t.Fatalf("stop node %d: %v", i, err)
			}
		}()
	}
}

func restartNodes(t *testing.T, cluster *goharness.Cluster, slots []*slot, nodes []int) {
	t.Helper()
	for _, i := range nodes {
		if err := cluster.RestartNode(i); err != nil {
			t.Fatalf("restart node %d: %v", i, err)
		}
		slots[i].mu.Lock()
		slots[i].client = cluster.Node(i)
		slots[i].mu.Unlock()
	}
	mesh(t, cluster)
}

// restartWithConfig writes per-node config through the live children's
// SQL, gracefully exits every child (which persists the stores), and
// reboots every node on its existing dir.
func restartWithConfig(t *testing.T, cluster *goharness.Cluster, write func(i int) string) {
	t.Helper()
	for i := 0; i < cluster.Len(); i++ {
		if _, err := cluster.Node(i).Simple(write(i)); err != nil {
			t.Fatalf("node %d write config: %v", i, err)
		}
		if err := cluster.Node(i).Flush(); err != nil {
			t.Fatalf("node %d flush config: %v", i, err)
		}
	}
	for i := 0; i < cluster.Len(); i++ {
		if err := cluster.Node(i).Close(); err != nil {
			t.Fatalf("stop node %d: %v", i, err)
		}
	}
	for i := 0; i < cluster.Len(); i++ {
		if err := cluster.RestartNode(i); err != nil {
			t.Fatalf("restart node %d: %v", i, err)
		}
	}
}

// setAllowedPeers restarts every node with the given per-node
// allow-lists (nil entries clear the list, allowing all identities).
// Writers stall on the slot locks across the close+restart and resume
// on the rebooted children.
func setAllowedPeers(t *testing.T, cluster *goharness.Cluster, slots []*slot, allowed [][]string) {
	t.Helper()
	for _, s := range slots {
		s.mu.Lock()
	}
	defer func() {
		for _, s := range slots {
			s.mu.Unlock()
		}
	}()
	restartWithConfig(t, cluster, func(i int) string {
		if allowed[i] == nil {
			return "DELETE FROM murmur_config WHERE name='allowed_peers'"
		}
		list := `["` + allowed[i][0] + `"`
		for _, id := range allowed[i][1:] {
			list += `,"` + id + `"`
		}
		list += `]`
		return "INSERT INTO murmur_config(name,value) VALUES('allowed_peers','" + list +
			"') ON CONFLICT(name) DO UPDATE SET value=excluded.value"
	})
	for i, s := range slots {
		s.client = cluster.Node(i)
	}
}

func phase(name string, duration, status time.Duration) {
	fmt.Fprintf(os.Stderr, "abuse phase=%s duration=%v\n", name, duration)
	end := time.Now().Add(duration)
	for time.Now().Before(end) {
		left := time.Until(end)
		wait := status
		if wait > left {
			wait = left
		}
		time.Sleep(wait)
		fmt.Fprintf(os.Stderr, "abuse phase=%s remaining=%v\n", name, time.Until(end))
	}
}

func TestAbuseMeshPreservesAcknowledgedWrites(t *testing.T) {
	goharness.SkipUnlessLive(t)
	nodes := int(number("MURMUR_ABUSE_NODES", 10))
	nodes = min(max(nodes, 3), 256)
	duration := time.Duration(number("MURMUR_ABUSE_DURATION_SECONDS", 600)) * time.Second
	quarter := duration / 4
	pace := time.Duration(number("MURMUR_ABUSE_WRITE_INTERVAL_MS", 100)) * time.Millisecond
	status := time.Duration(number("MURMUR_ABUSE_STATUS_SECONDS", 15)) * time.Second
	settle := time.Duration(number("MURMUR_ABUSE_SETTLE_SECONDS", 900)) * time.Second
	seed := int(number("MURMUR_ABUSE_SEED", 1))

	cluster, err := goharness.NewCluster(goharness.ClusterOptions{
		Name:       "abuse",
		NumNodes:   nodes,
		ChildNodes: true,
	})
	if err != nil {
		t.Fatalf("start cluster: %v", err)
	}
	failed := true
	defer func() { cluster.Finish(failed) }()

	// Static fanout-2 peering (reference: replication YAML
	// `membership: false, fanout: 2`). Full snapshot-donor trust is
	// already the harness default (snapshot_trusted_sources covers
	// every node id).
	restartWithConfig(t, cluster, func(i int) string {
		return "INSERT INTO murmur_config(name,value) VALUES('gossip_fanout','2')" +
			" ON CONFLICT(name) DO UPDATE SET value=excluded.value"
	})

	all := make([]int, nodes)
	for i := range all {
		all[i] = i
	}
	for i := 0; i < nodes; i++ {
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
	mesh(t, cluster)
	if _, err := cluster.Node(0).Execute("INSERT INTO contention(id,name,phone,score) VALUES('baseline','baseline','',0)"); err != nil {
		t.Fatalf("insert baseline: %v", err)
	}
	if err := cluster.Node(0).Flush(); err != nil {
		t.Fatalf("flush baseline: %v", err)
	}
	if err := goharness.AssertRows(cluster, all,
		"SELECT id,name,phone,score FROM contention ORDER BY id",
		[][]string{{"baseline", "baseline", "", "0"}}); err != nil {
		t.Fatalf("converge baseline: %v", err)
	}

	slots := make([]*slot, nodes)
	for i := 0; i < nodes; i++ {
		slots[i] = &slot{client: cluster.Node(i)}
	}
	var stopWriters atomic.Bool
	var ackedMu sync.Mutex
	acked := map[string]string{"baseline": "baseline"}

	workers := min(nodes, 8)
	var wg sync.WaitGroup
	writerErrs := make([]error, workers)
	for worker := 0; worker < workers; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			seq := 0
			for !stopWriters.Load() {
				target := (seed + worker + seq) % len(slots)
				seq++
				s := slots[target]
				s.mu.RLock()
				client := s.client
				if client != nil {
					id := fmt.Sprintf("w%02d-%010d", worker, seq)
					name := fmt.Sprintf("writer-%d", worker)
					_, err := client.Execute(
						"INSERT INTO contention(id,name,phone,score) VALUES($1,$2,'',0)", id, name)
					if err == nil {
						err = client.Flush()
					}
					if err != nil {
						writerErrs[worker] = err
						s.mu.RUnlock()
						return
					}
					ackedMu.Lock()
					acked[id] = name
					ackedMu.Unlock()
				}
				s.mu.RUnlock()
				time.Sleep(pace)
			}
		}(worker)
	}

	phase("healthy", quarter, status)
	half := nodes / 2
	ids := make([]string, nodes)
	for i := range ids {
		ids[i] = cluster.NodeID(i)
	}
	allowed := make([][]string, nodes)
	for a := 0; a < half; a++ {
		for b := 0; b < half; b++ {
			if a != b {
				allowed[a] = append(allowed[a], ids[b])
			}
		}
	}
	for a := half; a < nodes; a++ {
		for b := half; b < nodes; b++ {
			if a != b {
				allowed[a] = append(allowed[a], ids[b])
			}
		}
	}
	setAllowedPeers(t, cluster, slots, allowed)
	for from := 0; from < nodes; from++ {
		// Re-mesh within each side only.
		lo, hi := 0, half
		if from >= half {
			lo, hi = half, nodes
		}
		for to := lo; to < hi; to++ {
			if from != to {
				if err := cluster.Node(from).PeerAdd(cluster.Node(to).Addr); err != nil {
					t.Fatalf("mesh %d->%d: %v", from, to, err)
				}
			}
		}
	}
	phase("partition", quarter, status)
	left, err := cluster.Node(0).Simple("SELECT id FROM contention ORDER BY id")
	if err != nil {
		t.Fatalf("read left side: %v", err)
	}
	right, err := cluster.Node(nodes - 1).Simple("SELECT id FROM contention ORDER BY id")
	if err != nil {
		t.Fatalf("read right side: %v", err)
	}
	if equalRows(left, right) {
		t.Fatal("partition failed to isolate acknowledged writes")
	}
	setAllowedPeers(t, cluster, slots, make([][]string, nodes))
	mesh(t, cluster)
	outage := make([]int, 0)
	for i := nodes - (nodes+3)/4; i < nodes; i++ {
		outage = append(outage, i)
	}
	stopNodes(t, cluster, slots, outage)
	ackedMu.Lock()
	before := len(acked)
	ackedMu.Unlock()
	phase("partial-outage", quarter, status)
	ackedMu.Lock()
	after := len(acked)
	ackedMu.Unlock()
	if after <= before {
		t.Fatal("survivors made no progress during outage")
	}
	restartNodes(t, cluster, slots, outage)
	stopNodes(t, cluster, slots, all)
	restartNodes(t, cluster, slots, all)
	phase("whole-mesh-restart", quarter, status)
	stopWriters.Store(true)
	wg.Wait()
	for _, err := range writerErrs {
		if err != nil {
			t.Fatalf("SQL writer failed: %v", err)
		}
	}
	ackedMu.Lock()
	ids = make([]string, 0, len(acked))
	for id := range acked {
		ids = append(ids, id)
	}
	ackedMu.Unlock()
	sort.Strings(ids)
	var expected [][]string
	for _, id := range ids {
		ackedMu.Lock()
		name := acked[id]
		ackedMu.Unlock()
		expected = append(expected, []string{id, name, "", "0"})
	}
	if len(expected) <= 1 {
		t.Fatal("no writes acknowledged during abuse")
	}
	deadline := time.Now().Add(settle)
	for {
		equal := true
		for i := 0; i < nodes; i++ {
			rows, err := cluster.Node(i).Simple("SELECT id,name,phone,score FROM contention ORDER BY id")
			if err != nil {
				t.Fatalf("node %d read contention: %v", i, err)
			}
			equal = equal && equalRows(rows, expected)
		}
		if equal {
			break
		}
		if !time.Now().Before(deadline) {
			for i := 0; i < nodes; i++ {
				rows, err := cluster.Node(i).Simple("SELECT id,name,phone,score FROM contention ORDER BY id")
				if err != nil {
					t.Fatalf("node %d read contention: %v", i, err)
				}
				missing, extra := diffIDs(rows, expected)
				fmt.Fprintf(os.Stderr, "node %d at timeout: rows=%d missing=%d extra=%d missingSample=%q extraSample=%q\n",
					i, len(rows), len(missing), len(extra), sample(missing, 5), sample(extra, 5))
			}
			t.Fatalf("mesh failed exact convergence on %d acknowledged rows", len(expected))
		}
		time.Sleep(200 * time.Millisecond)
	}
	fmt.Fprintf(os.Stderr, "abuse verified %d acknowledged rows on %d nodes\n", len(expected), nodes)
	failed = false
}

// diffIDs returns the ids in want missing from got, and the ids in got
// beyond want.
func diffIDs(got, want [][]string) (missing, extra []string) {
	have := map[string]bool{}
	for _, r := range got {
		have[r[0]] = true
	}
	wantSet := map[string]bool{}
	for _, r := range want {
		wantSet[r[0]] = true
		if !have[r[0]] {
			missing = append(missing, r[0])
		}
	}
	for _, r := range got {
		if !wantSet[r[0]] {
			extra = append(extra, r[0])
		}
	}
	return missing, extra
}

func sample(ids []string, n int) []string {
	if len(ids) > n {
		return ids[:n]
	}
	return ids
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
