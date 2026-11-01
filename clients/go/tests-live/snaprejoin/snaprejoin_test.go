package snaprejoin

import (
	"testing"
	"time"

	goharness "github.com/marcgauthier/libmurmur/clients/go/tests-live/goharness"
)

// Regression: force "cursor pruned" via gc_watermark and require the
// automatic snapshot fallback to converge the stale node, across an
// in-process restart (see README).
func TestSnapshotFallbackAfterRestart(t *testing.T) {
	goharness.SkipUnlessLive(t)
	cluster, err := goharness.NewCluster(goharness.ClusterOptions{
		Name:     "snaprejoin",
		NumNodes: 2,
	})
	if err != nil {
		t.Fatalf("cluster setup: %v", err)
	}
	failed := true
	defer func() { cluster.Finish(failed) }()

	for i := 0; i < 2; i++ {
		if _, err := cluster.Node(i).Simple(
			"CREATE TABLE IF NOT EXISTS stale(id INTEGER PRIMARY KEY NOT NULL, v TEXT NOT NULL DEFAULT '')"); err != nil {
			t.Fatalf("node%d create: %v", i, err)
		}
		if err := cluster.Node(i).SetTableReplicated("stale", true); err != nil {
			t.Fatalf("node%d replicate: %v", i, err)
		}
	}
	if _, err := cluster.Node(0).Execute("INSERT INTO stale(id,v) VALUES(0,'seed')"); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := cluster.Node(0).Flush(); err != nil {
		t.Fatalf("flush seed: %v", err)
	}
	if err := goharness.AssertRows(cluster, []int{0, 1},
		"SELECT id FROM stale", [][]string{{"0"}}); err != nil {
		t.Fatalf("converge seed: %v", err)
	}
	for i := 1; i <= 50; i++ {
		if _, err := cluster.Node(0).Execute(
			"INSERT INTO stale(id,v) VALUES(?,?)", i, "bulk"); err != nil {
			t.Fatalf("insert %d: %v", i, err)
		}
	}
	if err := cluster.Node(0).Flush(); err != nil {
		t.Fatalf("flush bulk: %v", err)
	}
	if err := cluster.StopNode(1); err != nil {
		t.Fatalf("stop node1: %v", err)
	}
	if err := cluster.StartNode(1); err != nil {
		t.Fatalf("restart node1: %v", err)
	}
	if err := cluster.PeerMesh(); err != nil {
		t.Fatalf("remesh: %v", err)
	}
	// Force node1's next pull to report "cursor pruned".
	if _, err := cluster.Node(0).Simple(
		"INSERT INTO murmur_config(name,value) VALUES('gc_watermark','999999999') " +
			"ON CONFLICT(name) DO UPDATE SET value=excluded.value"); err != nil {
		t.Fatalf("force watermark: %v", err)
	}
	deadline := time.Now().Add(120 * time.Second)
	lastLog := time.Now()
	for {
		rows, err := cluster.Node(1).Simple("SELECT COUNT(*) FROM stale")
		if err != nil {
			t.Fatalf("count: %v", err)
		}
		if rows[0][0] == "51" {
			break
		}
		if time.Since(lastLog) > 10*time.Second {
			st, _ := cluster.Node(1).ShowStatus()
			t.Logf("node1 count=%s status=%v", rows[0][0], st)
			lastLog = time.Now()
		}
		if !time.Now().Before(deadline) {
			st, _ := cluster.Node(1).ShowStatus()
			t.Fatalf("stale rejoin never converged; status=%v", st)
		}
		time.Sleep(2 * time.Second)
	}
	t.Log("converged via snapshot path")
	failed = false
}
