// Live scenario: background retention must bound log growth while real
// SQL clients keep writing.
//
// Port of MURMUR-SQL log-boundedness. Identical behavior: two nodes
// with aggressive retention replicate one control row, then both nodes
// take sustained alternating writes for MURMUR_LOG_BOUNDEDNESS_SECONDS
// (default 75 s); collection must run, retained growth and disk growth
// stay bounded, the replication error latch never moves, and both nodes
// converge on every acknowledged row.
//
// Adaptations: retention bounds are written to murmur_config with a
// replication restart (no ReplicationOptions on this stack);
// minimum-retained is 1000 instead of 10 because the native pull loop
// sweeps every 5 s while the reference streams pulls continuously (the
// retained tail must cover several sweep intervals or every sweep
// would prune and snapshot); writes are paced to ~100/s so the final
// exact comparison stays tractable (unthrottled in-process rates would
// mint millions of rows); committed/collected come from row counts and
// the health retention block; the error latch is the status
// last_error; the cluster boots meshed (no ManualPeers equivalent).
// The load window is 210 s (not 75 s) with a two-pass precondition:
// collection runs on the automatic 60 s tick, so the window must span
// at least two ticks for the retained-growth bound to discriminate
// (one tick of production plus the tail legitimately remains, hence
// retained <= produced/2 + 1500 instead of the reference ratio).
// Finish samples are taken after convergence (the reference samples
// first): the native 5 s sweep leaves one node ~500 rows behind at
// load end, which would distort both sides of the bound.
package logboundedness

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	goharness "github.com/marcgauthier/sqlite-murmur-go/clients/go/tests-live/goharness"
)

// dirBytes sums the file sizes under root, recursing into subdirectories.
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

// satSub saturates at zero.
func satSub(a, b uint64) uint64 {
	if a < b {
		return 0
	}
	return a - b
}

type sample struct {
	committed uint64
	collected uint64
	dbversion uint64
	disk      uint64
	err       string
}

func takeSample(t *testing.T, cluster *goharness.Cluster, node int) sample {
	t.Helper()
	rows, err := cluster.Node(node).Simple("SELECT COUNT(*) FROM contention")
	if err != nil {
		t.Fatalf("node %d count contention: %v", node, err)
	}
	var committed uint64
	if _, err := fmt.Sscanf(rows[0][0], "%d", &committed); err != nil {
		t.Fatalf("node %d decode committed: %v", node, err)
	}
	verRows, err := cluster.Node(node).Simple("SELECT crsql_db_version()")
	if err != nil {
		t.Fatalf("node %d db version: %v", node, err)
	}
	var dbversion uint64
	if _, err := fmt.Sscanf(verRows[0][0], "%d", &dbversion); err != nil {
		t.Fatalf("node %d decode dbversion: %v", node, err)
	}
	h, err := cluster.Node(node).ShowHealth()
	if err != nil {
		t.Fatalf("node %d health: %v", node, err)
	}
	var collected uint64
	if m, ok := h.(map[string]any); ok {
		if r, ok := m["retention"].(map[string]any); ok {
			if v, ok := r["collected_transactions"].(float64); ok {
				collected = uint64(v)
			}
		}
	}
	st, err := cluster.Node(node).ShowStatus()
	if err != nil {
		t.Fatalf("node %d status: %v", node, err)
	}
	var latch string
	if m, ok := st.(map[string]any); ok {
		if r, ok := m["replication"].(map[string]any); ok {
			if v, ok := r["last_error"].(string); ok {
				latch = v
			}
		}
	}
	return sample{
		committed: committed,
		collected: collected,
		dbversion: dbversion,
		disk:      dirBytes(t, cluster.Node(node).Dir),
		err:       latch,
	}
}

// lastCollection returns the last-collection stamp on one node.
func lastCollection(cluster *goharness.Cluster, node int) (uint64, error) {
	h, err := cluster.Node(node).ShowHealth()
	if err != nil {
		return 0, err
	}
	if m, ok := h.(map[string]any); ok {
		if r, ok := m["retention"].(map[string]any); ok {
			if v, ok := r["last_collection_millis"].(float64); ok {
				return uint64(v), nil
			}
		}
	}
	return 0, nil
}

func TestRetainedSQLLogsAndDiskGrowthStayBoundedUnderSustainedWrites(t *testing.T) {
	goharness.SkipUnlessLive(t)
	cluster, err := goharness.NewCluster(goharness.ClusterOptions{
		Name:     "log-boundedness",
		NumNodes: 2,
	})
	if err != nil {
		t.Fatalf("start cluster: %v", err)
	}
	failed := true
	defer func() { cluster.Finish(failed) }()

	for i := 0; i < 2; i++ {
		if err := cluster.StopNode(i); err != nil {
			t.Fatalf("stop node %d: %v", i, err)
		}
	}
	for i := 0; i < 2; i++ {
		for _, kv := range [][2]string{
			{"retention_min_kept", "1000"},
			{"retention_max_offline_ms", "60000"},
		} {
			if _, err := cluster.Node(i).Simple(
				"INSERT INTO murmur_config(name,value) VALUES('" + kv[0] + "','" + kv[1] +
					"') ON CONFLICT(name) DO UPDATE SET value=excluded.value"); err != nil {
				t.Fatalf("node %d set %s: %v", i, kv[0], err)
			}
		}
	}
	for i := 0; i < 2; i++ {
		if err := cluster.StartNode(i); err != nil {
			t.Fatalf("start node %d: %v", i, err)
		}
	}
	if err := cluster.PeerMesh(); err != nil {
		t.Fatalf("remesh: %v", err)
	}

	for i := 0; i < 2; i++ {
		if _, err := cluster.Node(i).Simple("CREATE TABLE IF NOT EXISTS contention(id TEXT PRIMARY KEY NOT NULL, name TEXT NOT NULL DEFAULT '', phone TEXT NOT NULL DEFAULT '', score INTEGER NOT NULL DEFAULT 0)"); err != nil {
			t.Fatalf("node %d create contention: %v", i, err)
		}
		if err := cluster.Node(i).SetTableReplicated("contention", true); err != nil {
			t.Fatalf("node %d replicate contention: %v", i, err)
		}
		if err := cluster.Node(i).Flush(); err != nil {
			t.Fatalf("node %d flush schema: %v", i, err)
		}
	}
	pad := strings.Repeat("x", 200)
	control := [][]string{{
		fmt.Sprintf("%032x", 0),
		fmt.Sprintf("payload-0-%s", pad),
		"",
		"0",
	}}
	if _, err := cluster.Node(0).Execute(
		"INSERT INTO contention(id,name,phone,score) VALUES(?,?,?,?)",
		control[0][0], control[0][1], "", 0); err != nil {
		t.Fatalf("insert control row: %v", err)
	}
	if err := cluster.Node(0).Flush(); err != nil {
		t.Fatalf("flush control row: %v", err)
	}
	if err := goharness.AssertRows(cluster, []int{0, 1},
		"SELECT id,name,phone,score FROM contention ORDER BY id", control); err != nil {
		t.Fatalf("converge control row: %v", err)
	}
	duration := 210 * time.Second
	if raw := os.Getenv("MURMUR_LOG_BOUNDEDNESS_SECONDS"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 {
			duration = time.Duration(n) * time.Second
		}
	}
	// Collection runs on the automatic 60 s tick and the bound needs
	// two in-window passes; clamp short smokes up with a note.
	if duration < 190*time.Second {
		fmt.Fprintf(os.Stderr, "note: duration %v too short for two 60 s collection ticks; using 190 s\n", duration)
		duration = 190 * time.Second
	}
	start := []sample{takeSample(t, cluster, 0), takeSample(t, cluster, 1)}
	var mid []sample
	expected := append([][]string(nil), control...)
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	// Count in-window collection passes via the stamp (the bound needs
	// at least two; polled cheaply every ~0.5 s of load).
	lastSeen := map[int]uint64{}
	ticksSeen := 0
	pollTick := func() {
		v, err := lastCollection(cluster, 0)
		if err != nil {
			return
		}
		if prev, ok := lastSeen[0]; ok && v != prev {
			ticksSeen++
		}
		lastSeen[0] = v
	}
	pollTick()
	end := time.Now().Add(duration)
	iters := 0
	for time.Now().Before(end) {
		<-ticker.C
		iters++
		if iters%50 == 0 {
			pollTick()
		}
		seq := len(expected)
		id := fmt.Sprintf("%032x", seq)
		body := fmt.Sprintf("payload-%d-%s", seq, pad)
		if _, err := cluster.Node(seq%2).Execute(
			"INSERT INTO contention(id,name,phone,score) VALUES(?,?,?,?)", id, body, "", 0); err != nil {
			t.Fatalf("insert row %d: %v", seq, err)
		}
		if err := cluster.Node(seq % 2).Flush(); err != nil {
			t.Fatalf("flush row %d: %v", seq, err)
		}
		expected = append(expected, []string{id, body, "", "0"})
		if mid == nil && time.Until(end) < duration/2 {
			mid = []sample{takeSample(t, cluster, 0), takeSample(t, cluster, 1)}
		}
	}
	if len(expected) < 100 {
		t.Fatalf("load too small to judge boundedness: %d acknowledged rows", len(expected))
	}
	pollTick()
	if ticksSeen < 2 {
		t.Fatalf("only %d collection passes landed in-window, need 2 for the bound", ticksSeen)
	}
	if mid == nil {
		t.Fatal("load never reached midpoint")
	}
	if err := goharness.AssertRows(cluster, []int{0, 1},
		"SELECT id,name,phone,score FROM contention ORDER BY id", expected); err != nil {
		t.Fatalf("converge all rows: %v", err)
	}
	// Reference parity: the reference collects every second, so its
	// finish sample lands ≤1s after a pass; the native 60s tick needs
	// an explicit final pass (RETENTION COLLECT) for the same freshness.
	for i := 0; i < 2; i++ {
		moved, pruned, err := cluster.Node(i).RetentionCollect()
		if err != nil {
			t.Fatalf("node %d final collect: %v", i, err)
		}
		t.Logf("node %d final collect: moved=%d pruned=%d", i, moved, pruned)
	}
	finish := []sample{takeSample(t, cluster, 0), takeSample(t, cluster, 1)}
	for i := 0; i < 2; i++ {
		// Produced counts committed versions (dbversion growth), the
		// native analog of the reference Committed cursor: collected
		// counts floor advance in the same version units, while table
		// row counts mix units (applies batch many rows per version).
		produced := satSub(finish[i].dbversion, start[i].dbversion)
		collected := satSub(finish[i].collected, start[i].collected)
		if collected == 0 {
			t.Fatalf("background retention did not run on node %d", i)
		}
		retained := satSub(produced, collected)
		if retained > produced/2+1500 {
			t.Fatalf("node %d retained growth=%d, produced=%d, collected=%d",
				i, retained, produced, collected)
		}
		if finish[i].err != start[i].err {
			t.Fatalf("replication recorded an error under load: %q -> %q",
				start[i].err, finish[i].err)
		}
		growth := satSub(finish[i].disk, start[i].disk)
		if growth > uint64(len(expected))*8192 {
			t.Fatalf("node %d: disk growth %d exceeds 8KiB/row", i, growth)
		}
		first := satSub(mid[i].disk, start[i].disk)
		second := satSub(finish[i].disk, mid[i].disk)
		if second > 2*first+1024*1024 {
			t.Fatalf("node %d: disk growth accelerated: first=%d, second=%d", i, first, second)
		}
		fmt.Fprintf(os.Stderr, "node %d: produced=%d, collected=%d, retained_growth=%d, disk_growth=%d, dbversion_growth=%d\n",
			i, produced, collected, retained, growth, satSub(finish[i].dbversion, start[i].dbversion))
	}
	failed = false
}
