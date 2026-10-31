// Live scenario: hostile schema manifests are refused and quarantined.
//
// Port of MURMUR-SQL hostile-schema: a malicious authenticated peer
// serves hostile signed schema manifests at an honest 3-node
// cluster (corrupted signature, untrusted signer, oversized
// revision, zero-sequence revision). The honest setup and
// pre-attack positive control run here; every forgery leg needs a
// raw-QUIC peer speaking the replication wire protocol (schema
// manifest fetch/serve, stream-death observation) plus a background
// error-latch recorder, which have no harness equivalent, so the
// test skips with a named gap after the portable prefix passes.
//
// Deviations from the reference: 3 nodes instead of 4 (no stopped
// credential-donor node is needed without the attacker fixture); no
// max_transaction_bytes overlay (the harness exposes no replication
// tuning knobs); AssertRows convergence (60 s) instead of the 30 s
// per-leg waits.
package hostileschema

import (
	"testing"

	goharness "github.com/marcgauthier/sqlite-murmur-go/clients/go/tests-live/goharness"
)

func TestHostileSchemaManifestsQuarantined(t *testing.T) {
	goharness.SkipUnlessLive(t)
	cluster, err := goharness.NewCluster(goharness.ClusterOptions{
		Name:     "hostile-schema",
		NumNodes: 3,
	})
	if err != nil {
		t.Fatalf("cluster setup: %v", err)
	}
	failed := true
	defer func() { cluster.Finish(failed) }()

	honest := []int{0, 1, 2}

	// Initialize replicated table on honest nodes.
	for _, i := range honest {
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

	// Positive control (pre-attack): honest writes replicate everywhere.
	if _, err := cluster.Node(0).Execute(
		"INSERT INTO records(id, name) VALUES($1, $2)", int64(1), "baseline"); err != nil {
		t.Fatalf("insert baseline: %v", err)
	}
	if err := cluster.Node(0).Flush(); err != nil {
		t.Fatalf("flush baseline: %v", err)
	}
	preAttack := [][]string{{"baseline"}}
	if err := goharness.AssertRows(cluster, honest,
		"SELECT name FROM records ORDER BY name", preAttack); err != nil {
		t.Fatalf("converge baseline: %v", err)
	}
	failed = false

	// Blocked: every forgery leg (S1 corrupted signature, S2
	// untrusted signer, S3 oversized revision, S4 zero-sequence
	// revision, plus the quarantine wire checks, served-schema
	// comparisons, and post-attack controls) needs a raw-QUIC peer
	// speaking the replication wire protocol (schema manifest
	// fetch/serve, stream-death observation) plus a background
	// error-latch recorder, which have no harness equivalent.
	t.Skip("harness: raw-QUIC wire attacker fixture for schema manifests and error-latch recorder unavailable (no wire-protocol peer; no forgery leg can run)")
}
