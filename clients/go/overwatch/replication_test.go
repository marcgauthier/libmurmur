package overwatch

import (
	"os"
	"os/exec"
	"testing"

	goharness "github.com/marcgauthier/sqlite-murmur-go/clients/go/tests-live/goharness"
)

// Two-node application replication: domain collections converge
// across nodes while node-local tables stay put, and soft deletes
// propagate. Requires the live engine (node binary + opt-in), like
// the tests-live suites.

func skipUnlessNodeBin(t *testing.T) {
	t.Helper()
	goharness.SkipUnlessLive(t)
	bin := os.Getenv("MURMUR_NODE_BIN")
	if bin == "" {
		bin = "murmur-test-node"
	}
	if _, err := exec.LookPath(bin); err != nil {
		t.Skipf("live node binary %q not on PATH", bin)
	}
}

func TestAppCollectionsConvergeAcrossNodes(t *testing.T) {
	skipUnlessNodeBin(t)
	cluster, err := goharness.NewCluster(goharness.ClusterOptions{
		Name:     "overwatch-app",
		NumNodes: 2,
	})
	if err != nil {
		t.Fatalf("start cluster: %v", err)
	}
	failed := true
	defer func() { cluster.Finish(failed) }()

	// Same application DDL on both nodes, same replicated scope.
	for i := 0; i < 2; i++ {
		for _, ddl := range appTables {
			if _, err := cluster.Node(i).Simple(ddl); err != nil {
				t.Fatalf("node %d ddl: %v", i, err)
			}
		}
		for _, table := range replicatedTables {
			if err := cluster.Node(i).SetTableReplicated(table, true); err != nil {
				t.Fatalf("node %d replicate %s: %v", i, table, err)
			}
		}
		if err := cluster.Node(i).Flush(); err != nil {
			t.Fatalf("node %d flush schema: %v", i, err)
		}
	}
	// Domain writes on node 0 converge to node 1.
	writes := []string{
		"INSERT INTO contacts(id,name,email,score) VALUES('c-1','Ada','ada@example.com',7)",
		"INSERT INTO sites(id,name,smc_id) VALUES('s-1','HQ','smc-a')",
		"INSERT INTO tasks(id,title) VALUES('t-1','Audit')",
		"INSERT INTO task_site(task_id,site_id) VALUES('t-1','s-1')",
		"INSERT INTO issues(id,title) VALUES('i-1','Outage')",
		"INSERT INTO issue_updates(id,issue_id,body) VALUES('iu-1','i-1','triaged')",
	}
	for _, sql := range writes {
		if _, err := cluster.Node(0).Simple(sql); err != nil {
			t.Fatalf("node 0 write: %v", err)
		}
	}
	if err := cluster.Node(0).Flush(); err != nil {
		t.Fatalf("node 0 flush: %v", err)
	}
	checks := []struct {
		query string
		want  [][]string
	}{
		{"SELECT id,name FROM contacts ORDER BY id", [][]string{{"c-1", "Ada"}}},
		{"SELECT id,smc_id FROM sites ORDER BY id", [][]string{{"s-1", "smc-a"}}},
		{"SELECT task_id,site_id FROM task_site", [][]string{{"t-1", "s-1"}}},
		{"SELECT id,body FROM issue_updates ORDER BY id", [][]string{{"iu-1", "triaged"}}},
	}
	for _, c := range checks {
		if err := goharness.AssertRows(cluster, []int{0, 1}, c.query, c.want); err != nil {
			t.Fatalf("converge %s: %v", c.query, err)
		}
	}
	// Node-local sessions on node 1 never reach node 0.
	if _, err := cluster.Node(1).Simple(
		"INSERT INTO sessions(id,user_id,expires) VALUES('sess-x','u1',999)"); err != nil {
		t.Fatalf("node 1 session: %v", err)
	}
	if err := cluster.Node(1).Flush(); err != nil {
		t.Fatalf("node 1 flush: %v", err)
	}
	if err := goharness.AssertRows(cluster, []int{1},
		"SELECT COUNT(*) FROM sessions", [][]string{{"1"}}); err != nil {
		t.Fatalf("node 1 session visible: %v", err)
	}
	// Give any leak a chance to arrive, then prove absence.
	AssertRowsEmpty := func() {
		rows, err := cluster.Node(0).Simple("SELECT COUNT(*) FROM sessions")
		if err != nil {
			t.Fatalf("node 0 sessions read: %v", err)
		}
		if len(rows) != 1 || len(rows[0]) != 1 || rows[0][0] != "0" {
			t.Fatalf("local sessions leaked to node 0: %v", rows)
		}
	}
	AssertRowsEmpty()
	// A soft delete on node 1 converges back to node 0.
	if _, err := cluster.Node(1).Simple(
		"UPDATE contacts SET deleted_at=1700000000 WHERE id='c-1'"); err != nil {
		t.Fatalf("node 1 soft delete: %v", err)
	}
	if err := cluster.Node(1).Flush(); err != nil {
		t.Fatalf("node 1 flush delete: %v", err)
	}
	if err := goharness.AssertRows(cluster, []int{0, 1},
		"SELECT COUNT(*) FROM contacts WHERE deleted_at IS NULL",
		[][]string{{"0"}}); err != nil {
		t.Fatalf("converge soft delete: %v", err)
	}
	// The local session still never crossed.
	AssertRowsEmpty()
	failed = false
}
