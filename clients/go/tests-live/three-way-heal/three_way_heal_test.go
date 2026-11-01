// Live scenario: three-way heal order does not affect the final digest.
//
// Port of MURMUR-SQL three-way-heal: a 4-node cluster converges on 10
// base rows, splits into two islands that diverge (10 new rows plus
// conflicting renames per side), heals link by link in the order named
// by MURMUR_THREE_WAY_HEAL_ORDER(_B), and both heal orders must produce
// the identical final row set with side B winning every conflict. The
// reference RemovePeer/AddPeer link surgery has no native counterpart,
// so splits and heals use per-node allowed_peers identity allow-lists
// applied with a replication restart (the partition-suite mechanism);
// each heal step widens the two endpoints' allow-lists to admit each
// other and remeshes.
package threewayheal

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	goharness "github.com/marcgauthier/libmurmur/clients/go/tests-live/goharness"
)

// wait is the convergence deadline (reference: WAIT = 120 s).
const wait = 120 * time.Second

// links are the cross-island links healed one at a time (reference: links).
var links = [][2]int{{0, 2}, {0, 3}, {1, 2}, {1, 3}}

// setAllowedPeers restarts every node with the given per-node
// allow-lists and remeshes. Each list holds node-id hex strings.
func setAllowedPeers(t *testing.T, cluster *goharness.Cluster, allowed [4][]string) {
	t.Helper()
	for i := 0; i < 4; i++ {
		if err := cluster.StopNode(i); err != nil {
			t.Fatalf("stop node %d: %v", i, err)
		}
	}
	for i := 0; i < 4; i++ {
		list := `["` + strings.Join(allowed[i], `","`) + `"]`
		if _, err := cluster.Node(i).Simple(
			"INSERT INTO murmur_config(name,value) VALUES('allowed_peers','" + list +
				"') ON CONFLICT(name) DO UPDATE SET value=excluded.value"); err != nil {
			t.Fatalf("node %d set allowed_peers: %v", i, err)
		}
	}
	for i := 0; i < 4; i++ {
		if err := cluster.StartNode(i); err != nil {
			t.Fatalf("start node %d: %v", i, err)
		}
	}
	if err := cluster.PeerMesh(); err != nil {
		t.Fatalf("remesh: %v", err)
	}
}

// heal runs one full split-diverge-heal cycle and returns the final rows
// on node 0 (reference: heal).
func heal(t *testing.T, order []int, tag string) [][]string {
	t.Helper()
	cluster, err := goharness.NewCluster(goharness.ClusterOptions{
		Name:     "three-way-sql-" + tag,
		NumNodes: 4,
	})
	if err != nil {
		t.Fatalf("start cluster: %v", err)
	}
	failed := true
	defer func() { cluster.Finish(failed) }()

	if err := goharness.Fixture(cluster); err != nil {
		t.Fatalf("fixture: %v", err)
	}
	var base [][]string
	for n := 0; n < 10; n++ {
		id := fmt.Sprintf("base-%03d", n)
		name := fmt.Sprintf("baseline-%d", n)
		if _, err := cluster.Node(0).Execute(
			"INSERT INTO records(id,name) VALUES($1,$2)", id, name); err != nil {
			t.Fatalf("insert %s: %v", id, err)
		}
		base = append(base, []string{id, name})
	}
	if err := cluster.Node(0).Flush(); err != nil {
		t.Fatalf("flush base rows: %v", err)
	}
	if err := goharness.Converge(cluster, []int{0, 1, 2, 3}, base, wait); err != nil {
		t.Fatalf("converge base rows: %v", err)
	}
	id := [4]string{cluster.NodeID(0), cluster.NodeID(1), cluster.NodeID(2), cluster.NodeID(3)}
	allowed := [4][]string{{id[1]}, {id[0]}, {id[3]}, {id[2]}}
	setAllowedPeers(t, cluster, allowed)
	if err := goharness.PeerCounts(cluster, []int{0, 1, 2, 3}, []int{1, 1, 1, 1}, wait); err != nil {
		t.Fatalf("peer counts after split: %v", err)
	}
	var expected [][]string
	for _, side := range []struct {
		node int
		tag  string
	}{{1, "A"}, {3, "B"}} {
		for n := 0; n < 10; n++ {
			sid := fmt.Sprintf("side%s-%03d", side.tag, n)
			name := fmt.Sprintf("side-%s-%d", side.tag, n)
			if _, err := cluster.Node(side.node).Execute(
				"INSERT INTO records(id,name) VALUES($1,$2)", sid, name); err != nil {
				t.Fatalf("insert %s: %v", sid, err)
			}
			expected = append(expected, []string{sid, name})
		}
		for n := 0; n < 10; n++ {
			sid := fmt.Sprintf("base-%03d", n)
			name := fmt.Sprintf("conflict-%s-%d", side.tag, n)
			if _, err := cluster.Node(side.node).Execute(
				"UPDATE records SET name=$1 WHERE id=$2", name, sid); err != nil {
				t.Fatalf("conflict %s on node %d: %v", sid, side.node, err)
			}
		}
		if err := cluster.Node(side.node).Flush(); err != nil {
			t.Fatalf("node %d flush diverged rows: %v", side.node, err)
		}
		// Capture times are ordered; side B must be the same conflict winner in both runs.
		time.Sleep(20 * time.Millisecond)
	}
	if !goharness.WaitUntil(wait, 50*time.Millisecond, func() bool {
		a, err := goharness.Rows(cluster.Node(0))
		if err != nil {
			return false
		}
		b, err := goharness.Rows(cluster.Node(2))
		if err != nil {
			return false
		}
		return len(a) == 20 && len(b) == 20 && !equalRows(a, b)
	}) {
		t.Fatal("islands did not diverge on 20 differing rows each")
	}
	for _, index := range order {
		a, b := links[index][0], links[index][1]
		allowed[a] = append(allowed[a], id[b])
		allowed[b] = append(allowed[b], id[a])
		setAllowedPeers(t, cluster, allowed)
		nodeB := cluster.NodeID(b)
		if !goharness.WaitUntil(wait, 50*time.Millisecond, func() bool {
			peers, err := goharness.Peers(cluster.Node(a))
			if err != nil {
				return false
			}
			connected := false
			for _, p := range peers {
				if p.NodeID == nodeB && p.Connected {
					connected = true
					break
				}
			}
			if !connected {
				return false
			}
			rows, err := goharness.Rows(cluster.Node(a))
			if err != nil {
				return false
			}
			return len(rows) == 30
		}) {
			t.Fatalf("link %d->%d did not heal to 30 rows", a, b)
		}
	}
	for n := 0; n < 10; n++ {
		expected = append(expected, []string{fmt.Sprintf("base-%03d", n), fmt.Sprintf("conflict-B-%d", n)})
	}
	sort.Slice(expected, func(a, b int) bool {
		if expected[a][0] != expected[b][0] {
			return expected[a][0] < expected[b][0]
		}
		return expected[a][1] < expected[b][1]
	})
	if err := goharness.Converge(cluster, []int{0, 1, 2, 3}, expected, wait); err != nil {
		t.Fatalf("converge after heal: %v", err)
	}
	finalRows, err := goharness.Rows(cluster.Node(0))
	if err != nil {
		t.Fatalf("read final rows: %v", err)
	}
	failed = false
	return finalRows
}

// order parses a comma-separated heal-link order env knob (reference: order).
func order(t *testing.T, variable, fallback string) []int {
	t.Helper()
	raw := os.Getenv(variable)
	if raw == "" {
		raw = fallback
	}
	var values []int
	for _, s := range strings.Split(raw, ",") {
		n, err := strconv.Atoi(strings.TrimSpace(s))
		if err != nil {
			t.Fatalf("heal link index %q: %v", s, err)
		}
		values = append(values, n)
	}
	sorted := append([]int(nil), values...)
	sort.Ints(sorted)
	if !equalInts(sorted, []int{0, 1, 2, 3}) {
		t.Fatalf("heal order %v is not a permutation of 0,1,2,3", values)
	}
	return values
}

func TestHealOrderDoesNotAffectFinalDigest(t *testing.T) {
	goharness.SkipUnlessLive(t)
	a := order(t, "MURMUR_THREE_WAY_HEAL_ORDER", "0,1,2,3")
	b := order(t, "MURMUR_THREE_WAY_HEAL_ORDER_B", "3,2,1,0")
	first := heal(t, a, "a")
	second := heal(t, b, "b")
	if !equalRows(first, second) {
		t.Fatalf("heal orders diverged:\n%v\n%v", first, second)
	}
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

func equalInts(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
