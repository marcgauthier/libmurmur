package overwatch

import (
	"testing"
	"time"

	goharness "github.com/marcgauthier/sqlite-murmur-go/clients/go/tests-live/goharness"
)

// Replication metrics required by OVERWATCH health and replication
// management: engine counters plus per-peer diagnostics, read from a
// live two-node cluster through the same status/peers surface the Go
// client exposes.

// wantMetrics are the OVERWATCH ReplicationMetrics fields libmurmur
// must emit (the need-phase chunk counters have no pull-model
// equivalent and are intentionally absent).
var wantMetrics = []string{
	"pushed_transactions",
	"received_transactions",
	"applied_transactions",
	"staged_transactions",
	"snapshots_applied",
	"gossip_rounds",
	"probes_sent",
	"probes_failed",
	"anti_entropy_runs",
	"schema_pushes",
	"schema_adoptions",
	"retention_runs",
	"retention_pruned",
	"queue_available_bytes",
	"apply_batches",
	"apply_bytes",
	"apply_nanos",
}

func statusMetrics(t *testing.T, cluster *goharness.Cluster, idx int) map[string]any {
	t.Helper()
	st, err := cluster.Node(idx).ShowStatus()
	if err != nil {
		t.Fatalf("node %d status: %v", idx, err)
	}
	m, ok := st.(map[string]any)
	if !ok {
		t.Fatalf("node %d status is not an object", idx)
	}
	metrics, ok := m["metrics"].(map[string]any)
	if !ok {
		t.Fatalf("node %d status has no metrics block", idx)
	}
	return metrics
}

func metricNumber(t *testing.T, metrics map[string]any, key string) float64 {
	t.Helper()
	v, ok := metrics[key].(float64)
	if !ok {
		t.Fatalf("metrics has no numeric %q (keys present: %v)", key, keysOf(metrics))
	}
	return v
}

func keysOf(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

func TestReplicationMetricsExposed(t *testing.T) {
	skipUnlessNodeBin(t)
	master := 0
	cluster, err := goharness.NewCluster(goharness.ClusterOptions{
		Name:         "overwatch-metrics",
		NumNodes:     2,
		SchemaMaster: &master,
	})
	if err != nil {
		t.Fatalf("start cluster: %v", err)
	}
	failed := true
	defer func() { cluster.Finish(failed) }()

	for i := 0; i < 2; i++ {
		if _, err := cluster.Node(i).Simple(
			"CREATE TABLE IF NOT EXISTS contacts(id TEXT PRIMARY KEY NOT NULL DEFAULT '', name TEXT NOT NULL DEFAULT '')"); err != nil {
			t.Fatalf("node %d ddl: %v", i, err)
		}
		if err := cluster.Node(i).SetTableReplicated("contacts", true); err != nil {
			t.Fatalf("node %d replicate: %v", i, err)
		}
	}
	// Writes on both sides so each peer receives as well as sends.
	for n := 0; n < 2; n++ {
		if _, err := cluster.Node(0).Simple(
			"INSERT INTO contacts(id,name) VALUES('m-0-" + string(rune('0'+n)) + "','m')"); err != nil {
			t.Fatalf("insert node0 %d: %v", n, err)
		}
	}
	if _, err := cluster.Node(1).Simple(
		"INSERT INTO contacts(id,name) VALUES('m-1-0','m')"); err != nil {
		t.Fatalf("insert node1: %v", err)
	}
	if err := cluster.Node(0).Flush(); err != nil {
		t.Fatalf("flush 0: %v", err)
	}
	if err := cluster.Node(1).Flush(); err != nil {
		t.Fatalf("flush 1: %v", err)
	}
	if err := goharness.AssertRows(cluster, []int{0, 1},
		"SELECT COUNT(*) FROM contacts", [][]string{{"3"}}); err != nil {
		t.Fatalf("converge: %v", err)
	}
	// Periodic ticks (gossip/probe) need a moment on a fresh cluster.
	deadline := time.Now().Add(15 * time.Second)
	for {
		m := statusMetrics(t, cluster, 0)
		missing := false
		for _, k := range wantMetrics {
			if _, ok := m[k].(float64); !ok {
				missing = true
				break
			}
		}
		gossip, _ := m["gossip_rounds"].(float64)
		probes, _ := m["probes_sent"].(float64)
		if !missing && gossip >= 1 && probes >= 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("metrics incomplete after 15s (missing=%v gossip=%v probes=%v)",
				missing, gossip, probes)
		}
		time.Sleep(500 * time.Millisecond)
	}
	m := statusMetrics(t, cluster, 0)
	if v := metricNumber(t, m, "anti_entropy_runs"); v < 1 {
		t.Fatalf("anti_entropy_runs = %v, want >= 1 after sync", v)
	}
	if v := metricNumber(t, m, "applied_transactions"); v < 1 {
		t.Fatalf("applied_transactions = %v, want >= 1 after sync", v)
	}
	if v := metricNumber(t, m, "received_transactions"); v < 1 {
		t.Fatalf("received_transactions = %v, want >= 1 on the converging peer", v)
	}
	if v := metricNumber(t, m, "schema_pushes"); v < 1 {
		t.Fatalf("schema_pushes = %v, want >= 1 on the schema master", v)
	}
	failed = false
}

func TestPeerDiagnosticsExposed(t *testing.T) {
	skipUnlessNodeBin(t)
	master := 0
	cluster, err := goharness.NewCluster(goharness.ClusterOptions{
		Name:         "overwatch-peerdiag",
		NumNodes:     2,
		SchemaMaster: &master,
	})
	if err != nil {
		t.Fatalf("start cluster: %v", err)
	}
	failed := true
	defer func() { cluster.Finish(failed) }()

	for i := 0; i < 2; i++ {
		if _, err := cluster.Node(i).Simple(
			"CREATE TABLE IF NOT EXISTS contacts(id TEXT PRIMARY KEY NOT NULL DEFAULT '', name TEXT NOT NULL DEFAULT '')"); err != nil {
			t.Fatalf("node %d ddl: %v", i, err)
		}
		if err := cluster.Node(i).SetTableReplicated("contacts", true); err != nil {
			t.Fatalf("node %d replicate: %v", i, err)
		}
	}
	if _, err := cluster.Node(0).Simple("INSERT INTO contacts(id,name) VALUES('p-1','p')"); err != nil {
		t.Fatalf("insert: %v", err)
	}
	if err := cluster.Node(0).Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}
	if err := goharness.AssertRows(cluster, []int{0, 1},
		"SELECT COUNT(*) FROM contacts", [][]string{{"1"}}); err != nil {
		t.Fatalf("converge: %v", err)
	}
	peerID := cluster.NodeID(1)
	deadline := time.Now().Add(15 * time.Second)
	for {
		peers, err := cluster.Node(0).ShowPeers()
		if err != nil {
			t.Fatalf("peers: %v", err)
		}
		var row *goharness.PeerRow
		for i := range peers {
			if peers[i].NodeID == peerID {
				row = &peers[i]
				break
			}
		}
		if row != nil && row.Connected && row.SchemaAgreed {
			if row.PushMode {
				t.Fatal("push_mode = true, want false on the pull-only stack")
			}
			if row.LastSeenMillisAgo == nil {
				t.Fatal("last_seen_millis_ago missing")
			}
			// Watermarks and lag are numeric once acks flow.
			_ = row.SentWatermark
			_ = row.LagTxns
			_ = row.OriginsBehind
			failed = false
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("peer diagnostics never showed connected+agreed: %+v", peers)
		}
		time.Sleep(500 * time.Millisecond)
	}
}
