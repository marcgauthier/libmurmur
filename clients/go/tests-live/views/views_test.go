// Live scenario: SQL projections reflect replicated updates and survive a
// real node restart.
//
// Port of MURMUR-SQL views: three native nodes share a replicated contacts
// table, each node inserts one row, two rows are promoted into a score>0
// projection, every node converges on the projection, and node 2 rebuilds
// it after a restart.
package views

import (
	"testing"
	"time"

	goharness "github.com/marcgauthier/libmurmur/clients/go/tests-live/goharness"
)

// projection is the tracked SQL projection (reference: PROJECTION).
const projection = "SELECT name FROM contacts WHERE score>0 ORDER BY name"

// enabled waits until every listed node reads ann and bob from the
// projection (reference: enabled; 30 s deadline, 50 ms polls).
func enabled(t *testing.T, cluster *goharness.Cluster, nodes []int) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	want := [][]string{{"ann"}, {"bob"}}
	for {
		matches := true
		for _, i := range nodes {
			rows, err := cluster.Node(i).Simple(projection)
			if err != nil {
				t.Fatalf("node %d projection: %v", i, err)
			}
			matches = matches && equalRows(rows, want)
		}
		if matches {
			return
		}
		if !time.Now().Before(deadline) {
			t.Fatal("projection did not converge on ann and bob")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestSQLProjectionTracksReplicatedRowsAndRebuilds(t *testing.T) {
	goharness.SkipUnlessLive(t)
	cluster, err := goharness.NewCluster(goharness.ClusterOptions{
		Name:     "views",
		NumNodes: 3,
	})
	if err != nil {
		t.Fatalf("start cluster: %v", err)
	}
	failed := true
	defer func() { cluster.Finish(failed) }()

	for i := 0; i < 3; i++ {
		if _, err := cluster.Node(i).Simple(
			"CREATE TABLE IF NOT EXISTS contacts(name TEXT PRIMARY KEY NOT NULL DEFAULT '', score INTEGER NOT NULL DEFAULT 0)"); err != nil {
			t.Fatalf("node %d create contacts: %v", i, err)
		}
		if err := cluster.Node(i).SetTableReplicated("contacts", true); err != nil {
			t.Fatalf("node %d replicate contacts: %v", i, err)
		}
	}
	for i, name := range []string{"ann", "bob", "hidden"} {
		if _, err := cluster.Node(i).Execute(
			"INSERT INTO contacts(name,score) VALUES($1,0)", name); err != nil {
			t.Fatalf("node %d insert %s: %v", i, name, err)
		}
		if i < 2 {
			n, err := cluster.Node(i).Execute(
				"UPDATE contacts SET score=score+1 WHERE name=$1", name)
			if err != nil {
				t.Fatalf("node %d promote %s: %v", i, name, err)
			}
			if n != 1 {
				t.Fatalf("node %d promote %s affected %d rows, want 1", i, name, n)
			}
		}
		if err := cluster.Node(i).Flush(); err != nil {
			t.Fatalf("node %d flush: %v", i, err)
		}
	}
	enabled(t, cluster, []int{0, 1, 2})
	if err := cluster.Node(2).Flush(); err != nil {
		t.Fatalf("node 2 pre-restart flush: %v", err)
	}
	if err := cluster.StopNode(2); err != nil {
		t.Fatalf("stop node 2: %v", err)
	}
	if err := cluster.StartNode(2); err != nil {
		t.Fatalf("restart node 2: %v", err)
	}
	enabled(t, cluster, []int{2})
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
