// Live scenario: hostile peer attacks are rejected.
//
// Port of MURMUR-SQL hostile-peer: a malicious authenticated peer
// fires forged batches, invalid identities, a replayed handshake, a
// 256 MiB allocation-claim frame, a compressed snapshot bomb, and a
// far-future-HLC batch at an honest 2-node cluster. The honest setup
// and pre-attack positive control run here; every attack leg needs a
// raw-QUIC peer speaking the replication wire protocol (framed
// sends, raw frame injection, session teardown and wire-error
// observation) plus a background error-latch recorder, which have no
// harness equivalent, so the test skips with a named gap after the
// portable prefix passes.
//
// Deviations from the reference: 2 nodes instead of 3 (no stopped
// credential-donor node is needed without the attacker fixture); no
// max_transaction_bytes overlay (the harness exposes no replication
// tuning knobs); AssertRows convergence (60 s) instead of the 30 s
// per-leg waits.
package hostilepeer

import (
	"fmt"
	"testing"

	goharness "github.com/marcgauthier/libmurmur/clients/go/tests-live/goharness"
)

// appliedSum reads the cumulative log-applied transactions on one
// node: the sum of per-origin applied counters in the progress
// snapshot.
func appliedSum(cluster *goharness.Cluster, idx int) (uint64, error) {
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
		v, ok := m["applied"].(float64)
		if !ok {
			return 0, fmt.Errorf("node%d SHOW REPLICATION: no applied counter", idx+1)
		}
		sum += uint64(v)
	}
	return sum, nil
}

func TestHostilePeerAttacksRejected(t *testing.T) {
	goharness.SkipUnlessLive(t)
	cluster, err := goharness.NewCluster(goharness.ClusterOptions{
		Name:     "hostile-peer",
		NumNodes: 2,
	})
	if err != nil {
		t.Fatalf("cluster setup: %v", err)
	}
	failed := true
	defer func() { cluster.Finish(failed) }()

	// Initialize replicated table on honest nodes.
	for i := 0; i < 2; i++ {
		if _, err := cluster.Node(i).Simple(
			"CREATE TABLE IF NOT EXISTS records(id INTEGER PRIMARY KEY NOT NULL, name TEXT NOT NULL DEFAULT '')"); err != nil {
			t.Fatalf("node %d create records: %v", i, err)
		}
		if err := cluster.Node(i).SetTableReplicated("records", true); err != nil {
			t.Fatalf("node %d replicate records: %v", i, err)
		}
		if err := cluster.Node(i).Flush(); err != nil {
			t.Fatalf("node %d flush schema: %v", i, err)
		}
	}

	// Positive control (pre-attack): honest writes replicate both ways.
	if _, err := cluster.Node(0).Execute(
		"INSERT INTO records(id, name) VALUES($1, $2)", int64(1), "honest-1"); err != nil {
		t.Fatalf("insert honest-1: %v", err)
	}
	if err := cluster.Node(0).Flush(); err != nil {
		t.Fatalf("flush honest-1: %v", err)
	}
	if err := goharness.AssertRows(cluster, []int{0, 1},
		"SELECT name FROM records ORDER BY name", [][]string{{"honest-1"}}); err != nil {
		t.Fatalf("converge honest-1: %v", err)
	}
	if _, err := cluster.Node(1).Execute(
		"INSERT INTO records(id, name) VALUES($1, $2)", int64(2), "honest-2"); err != nil {
		t.Fatalf("insert honest-2: %v", err)
	}
	if err := cluster.Node(1).Flush(); err != nil {
		t.Fatalf("flush honest-2: %v", err)
	}
	preAttack := [][]string{{"honest-1"}, {"honest-2"}}
	if err := goharness.AssertRows(cluster, []int{0, 1},
		"SELECT name FROM records ORDER BY name", preAttack); err != nil {
		t.Fatalf("converge pre-attack: %v", err)
	}

	if _, err := appliedSum(cluster, 0); err != nil {
		t.Fatalf("baseline counters: %v", err)
	}
	failed = false

	// Blocked: every attack leg (schema-learn/control dials, P1a
	// invalid identities, P2 replayed handshake, P1b forged batch,
	// P3 allocation-claim frame, P4 snapshot bomb, P-HLC far-future
	// batch, and the post-attack controls that require attacks to
	// have run) needs a raw-QUIC peer speaking the replication wire
	// protocol with raw frame injection plus a background
	// error-latch recorder, which have no harness equivalent.
	t.Skip("harness: raw-QUIC wire attacker fixture with frame injection and error-latch recorder unavailable (no wire-protocol peer; no attack leg can run)")
}
