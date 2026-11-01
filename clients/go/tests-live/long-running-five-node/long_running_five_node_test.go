// Live scenario: five nodes keep writing through two rolling restarts
// without losing acknowledged rows.
//
// Port of MURMUR-SQL long-running-five-node: five writers insert paced
// rows for MURMUR_FIVE_NODE_DURATION_SECONDS (default 30 s); node 1
// restarts at one third and node 3 at two thirds (acknowledged rows
// must survive); all five converge, then flush with zero pending work,
// bounded spool, and no storage error; one post-soak write converges
// everywhere. Nodes run as child processes (MURMUR_NODE_BIN), like the
// reference servers; restarts are graceful replication Stop/Start with
// the store staying open (real process restarts are covered by
// rolling-restart).
// The reference status legs remap to native snapshots: pending bytes
// become fully-applied replication progress on every origin, the spool
// budget becomes data-dir bytes, and the storage error becomes the
// engine failure triple (last_error_code/kind/message absent); the soft
// last_error text conflates restart-teardown transport noise and is
// forensics only.
package longrunningfivenode

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"sync"
	"testing"
	"time"

	goharness "github.com/marcgauthier/libmurmur/clients/go/tests-live/goharness"
)

// wait is the final convergence deadline (reference: WAIT = 120 s).
const wait = 120 * time.Second

// slot holds one writer's client across restarts (reference:
// Arc<RwLock<Option<Client>>>).
type slot struct {
	mu     sync.RWMutex
	client *goharness.Node
}

// dirBytes sums the file sizes under root, recursing into
// subdirectories.
func dirBytes(t *testing.T, root string) uint64 {
	t.Helper()
	var total uint64
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("read dir %s: %v", root, err)
	}
	for _, e := range entries {
		p := filepath.Join(root, e.Name())
		info, err := os.Stat(p)
		if err != nil {
			t.Fatalf("stat %s: %v", p, err)
		}
		if info.IsDir() {
			total += dirBytes(t, p)
			continue
		}
		total += uint64(info.Size())
	}
	return total
}

func TestLongRunningFiveNode(t *testing.T) {
	goharness.SkipUnlessLive(t)
	cluster, err := goharness.NewCluster(goharness.ClusterOptions{
		Name:       "five-node-sql",
		NumNodes:   5,
		ChildNodes: true, // separate processes, like the reference servers
	})
	if err != nil {
		t.Fatalf("start cluster: %v", err)
	}
	failed := true
	defer func() { cluster.Finish(failed) }()

	if err := goharness.Fixture(cluster); err != nil {
		t.Fatalf("fixture: %v", err)
	}
	duration := goharness.EnvSeconds("MURMUR_FIVE_NODE_DURATION_SECONDS", 30)
	if duration < 3*time.Second {
		t.Fatalf("duration = %v, want >= 3s", duration)
	}
	interval := 50 * time.Millisecond
	if raw := os.Getenv("MURMUR_FIVE_NODE_INTERVAL_MS"); raw != "" {
		ms, err := strconv.Atoi(raw)
		if err != nil {
			t.Fatalf("MURMUR_FIVE_NODE_INTERVAL_MS = %q: %v", raw, err)
		}
		interval = time.Duration(ms) * time.Millisecond
	}
	started := time.Now()
	end := started.Add(duration)
	slots := make([]*slot, 5)
	for i := range slots {
		slots[i] = &slot{client: cluster.Node(i)}
	}
	type workerOut struct {
		acked [][]string
		err   error
	}
	outs := make([]workerOut, 5)
	var wg sync.WaitGroup
	for node := 0; node < 5; node++ {
		wg.Add(1)
		go func(node int) {
			defer wg.Done()
			var acked [][]string
			n := 0
			for time.Now().Before(end) {
				time.Sleep(interval)
				slots[node].mu.RLock()
				client := slots[node].client
				slots[node].mu.RUnlock()
				if client != nil {
					id := fmt.Sprintf("n%d-%09d", node, n)
					name := fmt.Sprintf("capacity-%s", id)
					if _, err := client.Execute(
						"INSERT INTO records(id,name) VALUES($1,$2)", id, name); err != nil {
						outs[node].err = err
						return
					}
					if err := client.Flush(); err != nil {
						outs[node].err = err
						return
					}
					acked = append(acked, []string{id, name})
					n++
				}
			}
			if n < 10 {
				outs[node].err = fmt.Errorf("node %d made insufficient progress", node)
				return
			}
			outs[node].acked = acked
		}(node)
	}
	for _, round := range []struct {
		round uint32
		node  int
	}{{1, 1}, {2, 3}} {
		time.Sleep(time.Until(started.Add(duration * time.Duration(round.round) / 3)))
		slots[round.node].mu.Lock()
		slots[round.node].client = nil
		before, err := goharness.Rows(cluster.Node(round.node))
		if err != nil {
			slots[round.node].mu.Unlock()
			t.Fatalf("node %d pre-restart rows: %v", round.node, err)
		}
		if err := cluster.StopNode(round.node); err != nil {
			slots[round.node].mu.Unlock()
			t.Fatalf("node %d stop: %v", round.node, err)
		}
		if err := cluster.StartNode(round.node); err != nil {
			slots[round.node].mu.Unlock()
			t.Fatalf("node %d restart: %v", round.node, err)
		}
		if err := cluster.PeerMesh(); err != nil {
			slots[round.node].mu.Unlock()
			t.Fatalf("remesh: %v", err)
		}
		recovered, err := goharness.Rows(cluster.Node(round.node))
		if err != nil {
			slots[round.node].mu.Unlock()
			t.Fatalf("node %d post-restart rows: %v", round.node, err)
		}
		for _, row := range before {
			if !containsRow(recovered, row) {
				slots[round.node].mu.Unlock()
				t.Fatal("acknowledged row lost on restart")
			}
		}
		slots[round.node].client = cluster.Node(round.node)
		slots[round.node].mu.Unlock()
	}
	var expected [][]string
	wg.Wait()
	for node, out := range outs {
		if out.err != nil {
			t.Fatalf("node %d writer: %v", node, out.err)
		}
		expected = append(expected, out.acked...)
	}
	if len(expected) < 100 {
		t.Fatalf("expected %d rows, want >= 100", len(expected))
	}
	sortRows(expected)
	if err := goharness.Converge(cluster, []int{0, 1, 2, 3, 4}, expected,
		goharness.EnvSeconds("MURMUR_FIVE_NODE_SETTLE_SECONDS", 120)); err != nil {
		t.Fatalf("converge: %v", err)
	}
	for i := 0; i < 5; i++ {
		if err := cluster.Node(i).Flush(); err != nil {
			t.Fatalf("node %d flush: %v", i, err)
		}
		// Zero pending work: every origin fully applied.
		progress, err := cluster.Node(i).ShowReplication()
		if err != nil {
			t.Fatalf("node %d progress: %v", i, err)
		}
		heads, ok := progress.([]any)
		if !ok {
			t.Fatalf("node %d progress is %T, want array", i, progress)
		}
		if len(heads) == 0 {
			t.Fatalf("node %d progress holds no origins", i)
		}
		for _, h := range heads {
			head, ok := h.(map[string]any)
			if !ok {
				t.Fatalf("node %d progress head is %T", i, h)
			}
			applied, aok := head["applied"].(float64)
			observed, ook := head["observed"].(float64)
			if !aok || !ook || applied != observed {
				t.Fatalf("node %d origin %v pending: applied=%v observed=%v",
					i, head["origin"], head["applied"], head["observed"])
			}
		}
		// Bounded spool: data-dir bytes under the 2 GiB budget.
		// (Child nodes leave DataDir empty; the store lives under
		// <dir>/data in both modes.)
		dataDir := cluster.Node(i).DataDir
		if dataDir == "" {
			dataDir = filepath.Join(cluster.Node(i).Dir, "data")
		}
		if disk := dirBytes(t, dataDir); disk > 2<<30 {
			t.Fatalf("node %d disk_bytes = %d, want <= 2GiB", i, disk)
		}
		// No storage error: no engine failure latched. The soft
		// last_error text is forensics only: stopping a node under
		// load tears live sessions, and the survivors record
		// transport noise ("Protocol: truncated frame header") into
		// the same latch the reference's storage-scoped field does
		// not see.
		status, err := cluster.Node(i).ShowStatus()
		if err != nil {
			t.Fatalf("node %d status: %v", i, err)
		}
		for _, key := range []string{"last_error_code", "last_error_kind", "last_error_message"} {
			if v := statusValue(status, key); v != nil {
				t.Fatalf("node %d %s = %v, want absent", i, key, v)
			}
		}
		t.Logf("node %d last_error=%v", i, statusValue(status, "last_error"))
	}
	if _, err := cluster.Node(0).Execute(
		"INSERT INTO records(id,name) VALUES('post-soak','ready')"); err != nil {
		t.Fatalf("insert post-soak: %v", err)
	}
	if err := cluster.Node(0).Flush(); err != nil {
		t.Fatalf("flush post-soak: %v", err)
	}
	expected = append(expected, []string{"post-soak", "ready"})
	sortRows(expected)
	if err := goharness.Converge(cluster, []int{0, 1, 2, 3, 4}, expected, wait); err != nil {
		t.Fatalf("converge post-soak: %v", err)
	}
	failed = false
}

func sortRows(rows [][]string) {
	sort.Slice(rows, func(a, b int) bool {
		if rows[a][0] != rows[b][0] {
			return rows[a][0] < rows[b][0]
		}
		return rows[a][1] < rows[b][1]
	})
}

func containsRow(rows [][]string, want []string) bool {
	for _, r := range rows {
		if len(r) == len(want) {
			eq := true
			for i := range r {
				if r[i] != want[i] {
					eq = false
					break
				}
			}
			if eq {
				return true
			}
		}
	}
	return false
}

// statusValue walks a MURMUR SHOW STATUS JSON snapshot along path, reporting
// nil for a missing key or an explicit JSON null (matching serde_json
// indexing, where a missing key reads as Null).
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
