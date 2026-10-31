// Live scenario: four nodes retain independent writes across an
// isolated two-pair topology.
//
// Port of MURMUR-SQL partition: four nodes converge on a baseline row,
// restart into isolated pairs with independent writes that must not leak
// across the partition, then re-mesh, heal, and converge on every row
// including a post-heal write. The reference has no peer-removal or
// membership switch on this stack, so isolation uses per-node
// allowed_peers identity allow-lists (pair members only) applied with a
// replication restart; the QUIC transport refuses cross-pair sessions in
// both directions. Healing clears the allow-lists and remeshes.
package partition

import (
	"testing"
	"time"

	goharness "github.com/marcgauthier/sqlite-murmur-go/clients/go/tests-live/goharness"
)

func insert(t *testing.T, cluster *goharness.Cluster, node int, id int64, name string) {
	t.Helper()
	if _, err := cluster.Node(node).Execute(
		"INSERT INTO records(id,name) VALUES($1,$2)", id, name); err != nil {
		t.Fatalf("node %d insert %s: %v", node, name, err)
	}
	if err := cluster.Node(node).Flush(); err != nil {
		t.Fatalf("node %d flush %s: %v", node, name, err)
	}
}

// setAllowedPeers restarts every node with the given per-node
// allow-lists (nil entries clear the list, allowing all identities).
func setAllowedPeers(t *testing.T, cluster *goharness.Cluster, allowed [4][]string) {
	t.Helper()
	for i := 0; i < 4; i++ {
		if err := cluster.StopNode(i); err != nil {
			t.Fatalf("stop node %d: %v", i, err)
		}
	}
	for i := 0; i < 4; i++ {
		var err error
		if allowed[i] == nil {
			_, err = cluster.Node(i).Simple("DELETE FROM murmur_config WHERE name='allowed_peers'")
		} else {
			list := `["` + allowed[i][0] + `"`
			for _, id := range allowed[i][1:] {
				list += `,"` + id + `"`
			}
			list += `]`
			_, err = cluster.Node(i).Simple(
				"INSERT INTO murmur_config(name,value) VALUES('allowed_peers','" + list +
					"') ON CONFLICT(name) DO UPDATE SET value=excluded.value")
		}
		if err != nil {
			t.Fatalf("node %d set allowed_peers: %v", i, err)
		}
	}
	for i := 0; i < 4; i++ {
		if err := cluster.StartNode(i); err != nil {
			t.Fatalf("start node %d: %v", i, err)
		}
	}
}

func TestFourNodePartitionIsolationAndHealing(t *testing.T) {
	goharness.SkipUnlessLive(t)
	cluster, err := goharness.NewCluster(goharness.ClusterOptions{
		Name:     "partition",
		NumNodes: 4,
	})
	if err != nil {
		t.Fatalf("start cluster: %v", err)
	}
	failed := true
	defer func() { cluster.Finish(failed) }()

	for i := 0; i < 4; i++ {
		if _, err := cluster.Node(i).Simple(
			"CREATE TABLE IF NOT EXISTS records(id INTEGER PRIMARY KEY NOT NULL, name TEXT NOT NULL DEFAULT '')"); err != nil {
			t.Fatalf("node %d create records: %v", i, err)
		}
		if err := cluster.Node(i).SetTableReplicated("records", true); err != nil {
			t.Fatalf("node %d replicate records: %v", i, err)
		}
	}
	if err := cluster.PeerMesh(); err != nil {
		t.Fatalf("mesh: %v", err)
	}
	insert(t, cluster, 0, 1, "baseline")
	if err := goharness.AssertRows(cluster, []int{0, 1, 2, 3},
		"SELECT name FROM records ORDER BY id", [][]string{{"baseline"}}); err != nil {
		t.Fatalf("converge baseline: %v", err)
	}
	// Restart into isolated pairs: {0,1} and {2,3}.
	for i := 0; i < 4; i++ {
		if err := cluster.Node(i).Flush(); err != nil {
			t.Fatalf("node %d pre-partition flush: %v", i, err)
		}
	}
	id := [4]string{cluster.NodeID(0), cluster.NodeID(1), cluster.NodeID(2), cluster.NodeID(3)}
	setAllowedPeers(t, cluster, [4][]string{{id[1]}, {id[0]}, {id[3]}, {id[2]}})
	if err := cluster.PeerMesh(); err != nil {
		t.Fatalf("remesh pairs: %v", err)
	}
	if err := goharness.PeerCounts(cluster, []int{0, 1, 2, 3}, []int{1, 1, 1, 1}, 60*time.Second); err != nil {
		t.Fatalf("pair peer counts: %v", err)
	}
	insert(t, cluster, 0, 100, "side-ab")
	insert(t, cluster, 2, 200, "side-cd")
	if err := goharness.AssertRows(cluster, []int{0, 1},
		"SELECT name FROM records ORDER BY id",
		[][]string{{"baseline"}, {"side-ab"}}); err != nil {
		t.Fatalf("converge left pair: %v", err)
	}
	if err := goharness.AssertRows(cluster, []int{2, 3},
		"SELECT name FROM records ORDER BY id",
		[][]string{{"baseline"}, {"side-cd"}}); err != nil {
		t.Fatalf("converge right pair: %v", err)
	}
	time.Sleep(500 * time.Millisecond)
	left, err := cluster.Node(0).Simple("SELECT name FROM records ORDER BY id")
	if err != nil {
		t.Fatalf("node 0 read partition rows: %v", err)
	}
	right, err := cluster.Node(2).Simple("SELECT name FROM records ORDER BY id")
	if err != nil {
		t.Fatalf("node 2 read partition rows: %v", err)
	}
	if equalRows(left, right) {
		t.Fatalf("partition leaked: both sides read %v", left)
	}
	for i := 0; i < 4; i++ {
		if err := cluster.Node(i).Flush(); err != nil {
			t.Fatalf("node %d pre-heal flush: %v", i, err)
		}
	}
	setAllowedPeers(t, cluster, [4][]string{nil, nil, nil, nil})
	if err := cluster.PeerMesh(); err != nil {
		t.Fatalf("remesh healed: %v", err)
	}
	healed := [][]string{{"baseline"}, {"side-ab"}, {"side-cd"}}
	if err := goharness.AssertRows(cluster, []int{0, 1, 2, 3},
		"SELECT name FROM records ORDER BY id", healed); err != nil {
		t.Fatalf("converge healed: %v", err)
	}
	insert(t, cluster, 1, 300, "post-heal")
	healed = append(healed, []string{"post-heal"})
	if err := goharness.AssertRows(cluster, []int{0, 1, 2, 3},
		"SELECT name FROM records ORDER BY id", healed); err != nil {
		t.Fatalf("converge post-heal: %v", err)
	}
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
