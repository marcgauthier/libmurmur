// Live scenario: node3 is excluded on the survivors, the exclusion
// survives a survivor restart, and re-adding heals replication.
//
// Port of MURMUR-SQL churn-retirement: three meshed native nodes
// converge on 5 rows, node3 is excluded on both survivors (sessions
// drop, its writes stop arriving), the exclusion survives a survivor
// restart with no rediscovery re-mesh, and re-adding heals to 6 rows.
// This stack has no runtime peer-removal verb, so exclusion uses
// per-node allowed_peers allow-lists plus replication restarts (the
// partition-port technique). The final retirement leg (retire verb +
// retention introspection) has no native binding and is skipped (see
// the README).
package churnretirement

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	goharness "github.com/marcgauthier/libmurmur/clients/go/tests-live/goharness"
)

// excluded is the excluded node.
const excluded = 2

const (
	// waitTimeout is the convergence/session deadline.
	waitTimeout = 60 * time.Second
	// poll is the poll interval.
	poll = 200 * time.Millisecond
	// isolationHold is the isolation hold after the excluded node's write.
	isolationHold = 5 * time.Second
	// remeshWatch is the post-restart rediscovery watch.
	remeshWatch = 5 * time.Second
)

// names returns the sorted names on one node.
func names(cluster *goharness.Cluster, idx int) ([]string, error) {
	rows, err := cluster.Node(idx).Simple("SELECT name FROM records")
	if err != nil {
		return nil, fmt.Errorf("node%d SELECT names: %w", idx+1, err)
	}
	out := make([]string, 0, len(rows))
	for _, row := range rows {
		out = append(out, row[0])
	}
	sort.Strings(out)
	return out, nil
}

// insert inserts one row plus a durability barrier.
func insert(cluster *goharness.Cluster, node int, id int64, name string) error {
	if _, err := cluster.Node(node).Execute(
		"INSERT INTO records(id, name) VALUES($1, $2)", id, name); err != nil {
		return fmt.Errorf("node%d insert %q: %w", node+1, name, err)
	}
	if err := cluster.Node(node).Flush(); err != nil {
		return fmt.Errorf("node%d flush after %q: %w", node+1, name, err)
	}
	return nil
}

// waitConverged waits until every node holds exactly want rows with equal
// contents.
func waitConverged(cluster *goharness.Cluster, want int, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		var first []string
		seen := false
		ok := true
		for i := 0; i < cluster.Len(); i++ {
			nodeNames, err := names(cluster, i)
			if err != nil {
				return err
			}
			if len(nodeNames) != want {
				ok = false
				break
			}
			if !seen {
				first, seen = nodeNames, true
			} else if !equalStrings(first, nodeNames) {
				ok = false
				break
			}
		}
		if ok {
			return nil
		}
		if !time.Now().Before(deadline) {
			return fmt.Errorf("nodes did not converge on %d rows within %v", want, timeout)
		}
		time.Sleep(poll)
	}
}

// peerConnected reports whether from currently holds an open session to
// target.
func peerConnected(cluster *goharness.Cluster, from, target int) (bool, error) {
	want := cluster.NodeID(target)
	peers, err := cluster.Node(from).ShowPeers()
	if err != nil {
		return false, fmt.Errorf("node%d SHOW PEERS: %w", from+1, err)
	}
	for _, p := range peers {
		if strings.EqualFold(p.NodeID, want) && p.Connected {
			return true, nil
		}
	}
	return false, nil
}

// connectedCount returns the open sessions on one node (only rows with
// connected=true count).
func connectedCount(cluster *goharness.Cluster, idx int) (int, error) {
	peers, err := cluster.Node(idx).ShowPeers()
	if err != nil {
		return 0, fmt.Errorf("node%d SHOW PEERS: %w", idx+1, err)
	}
	count := 0
	for _, p := range peers {
		if p.Connected {
			count++
		}
	}
	return count, nil
}

// waitSessionsDrop waits until sessions to node3 drop on both survivors.
func waitSessionsDrop(cluster *goharness.Cluster, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		c0, err := peerConnected(cluster, 0, excluded)
		if err != nil {
			return err
		}
		c1, err := peerConnected(cluster, 1, excluded)
		if err != nil {
			return err
		}
		if !c0 && !c1 {
			return nil
		}
		if !time.Now().Before(deadline) {
			return fmt.Errorf("sessions to node3 did not drop within %v", timeout)
		}
		time.Sleep(poll)
	}
}

// setAllowedPeers restarts every node with the given per-node
// allow-lists (nil entries clear the list, allowing all identities).
func setAllowedPeers(cluster *goharness.Cluster, allowed [3][]string) error {
	for i := 0; i < 3; i++ {
		if err := cluster.StopNode(i); err != nil {
			return fmt.Errorf("stop node %d: %w", i, err)
		}
	}
	for i := 0; i < 3; i++ {
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
			return fmt.Errorf("node %d set allowed_peers: %w", i, err)
		}
	}
	for i := 0; i < 3; i++ {
		if err := cluster.StartNode(i); err != nil {
			return fmt.Errorf("start node %d: %w", i, err)
		}
	}
	return nil
}

// addPeer dials to from from (one direction).
func addPeer(cluster *goharness.Cluster, from, to int) error {
	return cluster.Node(from).PeerAdd(cluster.Node(to).Addr)
}

func runBody(cluster *goharness.Cluster) error {
	for i := 0; i < cluster.Len(); i++ {
		if _, err := cluster.Node(i).Simple(
			"CREATE TABLE IF NOT EXISTS records(id INTEGER PRIMARY KEY NOT NULL, name TEXT NOT NULL DEFAULT '')"); err != nil {
			return fmt.Errorf("migrate node%d: %w", i+1, err)
		}
	}
	for i := 0; i < cluster.Len(); i++ {
		if err := cluster.Node(i).SetTableReplicated("records", true); err != nil {
			return fmt.Errorf("node%d SET TABLE REPLICATED: %w", i+1, err)
		}
		if err := cluster.Node(i).Flush(); err != nil {
			return fmt.Errorf("node%d flush after SET TABLE: %w", i+1, err)
		}
	}
	if err := cluster.PeerMesh(); err != nil {
		return fmt.Errorf("mesh: %w", err)
	}

	for i := int64(0); i < 5; i++ {
		if err := insert(cluster, 0, i+1, fmt.Sprintf("a-%d", i)); err != nil {
			return err
		}
	}
	if err := waitConverged(cluster, 5, waitTimeout); err != nil {
		return err
	}

	// Exclude node3 on both survivors.
	id0, id1 := cluster.NodeID(0), cluster.NodeID(1)
	if err := setAllowedPeers(cluster, [3][]string{{id1}, {id0}, nil}); err != nil {
		return fmt.Errorf("exclude node3: %w", err)
	}
	if err := addPeer(cluster, 0, 1); err != nil {
		return fmt.Errorf("re-mesh 0->1: %w", err)
	}
	if err := addPeer(cluster, 1, 0); err != nil {
		return fmt.Errorf("re-mesh 1->0: %w", err)
	}
	// The survivor link comes up; sessions to node3 stay down.
	if err := goharness.PeerCounts(cluster, []int{0, 1}, []int{1, 1}, waitTimeout); err != nil {
		return fmt.Errorf("survivor link: %w", err)
	}
	// Sessions to node3 drop on both survivors.
	if err := waitSessionsDrop(cluster, waitTimeout); err != nil {
		return err
	}
	for _, i := range []int{0, 1} {
		count, err := connectedCount(cluster, i)
		if err != nil {
			return err
		}
		if count != 1 {
			return fmt.Errorf("node%d peers = %d, want 1 after exclusion", i+1, count)
		}
	}
	// Node3's writes no longer arrive on survivors.
	if err := insert(cluster, excluded, 100, "isolated"); err != nil {
		return err
	}
	time.Sleep(isolationHold)
	for _, i := range []int{0, 1} {
		survivor, err := names(cluster, i)
		if err != nil {
			return err
		}
		if len(survivor) != 5 {
			return fmt.Errorf("node%d names after isolation = %v; want five survivors", i+1, survivor)
		}
	}

	// Exclusion survives a survivor restart (no rediscovery re-mesh): the
	// restarted node re-meshes only its fellow survivor, never the
	// excluded node.
	if err := cluster.StopNode(0); err != nil {
		return fmt.Errorf("stop node1: %w", err)
	}
	if err := cluster.StartNode(0); err != nil {
		return fmt.Errorf("restart node1: %w", err)
	}
	if err := addPeer(cluster, 0, 1); err != nil {
		return fmt.Errorf("re-mesh 0->1: %w", err)
	}
	if err := addPeer(cluster, 1, 0); err != nil {
		return fmt.Errorf("re-mesh 1->0: %w", err)
	}
	if err := goharness.PeerCounts(cluster, []int{0, 1}, []int{1, 1}, waitTimeout); err != nil {
		return fmt.Errorf("survivor link after restart: %w", err)
	}
	time.Sleep(remeshWatch)
	if remeshed, err := peerConnected(cluster, 0, excluded); err != nil {
		return err
	} else if remeshed {
		return fmt.Errorf("node1 re-meshed excluded node3 after restart")
	}
	if count, err := connectedCount(cluster, 0); err != nil {
		return err
	} else if count != 1 {
		return fmt.Errorf("node1 peers after restart = %d, want 1 (exclusion lost?)", count)
	}

	// Re-adding heals replication (removal was not destructive).
	if err := setAllowedPeers(cluster, [3][]string{nil, nil, nil}); err != nil {
		return fmt.Errorf("clear exclusion: %w", err)
	}
	for _, pair := range [][2]int{{0, 2}, {2, 0}, {1, 2}, {2, 1}} {
		if err := addPeer(cluster, pair[0], pair[1]); err != nil {
			return fmt.Errorf("re-add peer %d->%d: %w", pair[0], pair[1], err)
		}
	}
	if err := addPeer(cluster, 0, 1); err != nil {
		return fmt.Errorf("re-add peer 0->1: %w", err)
	}
	if err := addPeer(cluster, 1, 0); err != nil {
		return fmt.Errorf("re-add peer 1->0: %w", err)
	}
	if err := waitConverged(cluster, 6, waitTimeout); err != nil {
		return err
	}
	return nil
}

func TestExcludePersistsAndReaddHeals(t *testing.T) {
	goharness.SkipUnlessLive(t)
	cluster, err := goharness.NewCluster(goharness.ClusterOptions{
		Name:     "churn-retirement",
		NumNodes: 3,
	})
	if err != nil {
		t.Fatalf("cluster setup: %v", err)
	}
	if cluster.Len() != 3 {
		cluster.Finish(true)
		t.Fatalf("this scenario is written for 3 nodes, got %d", cluster.Len())
	}
	failed := true
	defer func() { cluster.Finish(failed) }()
	if resultErr := runBody(cluster); resultErr != nil {
		fmt.Fprintf(os.Stderr, "scenario failed: %v\n", resultErr)
		t.Fatalf("scenario failed: %v; artifacts retained under tests-live/failures/", resultErr)
	}
	failed = false
}

// TestRetirementReleasesRetentionPin is the reference's final leg (the
// retired peer releases its GC retention pin). Blocked: the native
// stack exposes no retire verb and no retention introspection (the C
// engine implements both behind an unregistered SQL surface with no Go
// binding).
func TestRetirementReleasesRetentionPin(t *testing.T) {
	goharness.SkipUnlessLive(t)
	t.Skip("harness: peer retirement + retention introspection (no retire verb or SHOW RETENTION binding)")
}

func equalStrings(a, b []string) bool {
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
