// Live scenario: runtime peer removal is enforced in both dial
// directions and survives a survivor restart with no re-mesh.
package excluderejoin

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	goharness "github.com/marcgauthier/libmurmur/clients/go/tests-live/goharness"
)

// removed is the removed node.
const removed = 2

const (
	waitTimeout   = 60 * time.Second
	poll          = 200 * time.Millisecond
	isolationHold = 5 * time.Second
	remeshWatch   = 5 * time.Second
)

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

func waitConverged(cluster *goharness.Cluster, nodes []int, want int, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		var first []string
		seen := false
		ok := true
		for _, i := range nodes {
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
			return fmt.Errorf("nodes %v did not converge on %d rows within %v", nodes, want, timeout)
		}
		time.Sleep(poll)
	}
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

func waitSessionsDrop(cluster *goharness.Cluster, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		c0, err := peerConnected(cluster, 0, removed)
		if err != nil {
			return err
		}
		c1, err := peerConnected(cluster, 1, removed)
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

// excludedRow reports whether node idx durably excludes target.
func excludedRow(cluster *goharness.Cluster, idx, target int) (bool, error) {
	rows, err := cluster.Node(idx).Simple(
		"SELECT count(*) FROM murmur_excluded WHERE node=x'" + cluster.NodeID(target) + "'")
	if err != nil {
		return false, fmt.Errorf("node%d read murmur_excluded: %w", idx+1, err)
	}
	return len(rows) == 1 && len(rows[0]) == 1 && rows[0][0] == "1", nil
}

func removePeer(cluster *goharness.Cluster, idx, target int) error {
	if err := cluster.Node(idx).RemovePeer(cluster.Node(target).ID); err != nil {
		return fmt.Errorf("node%d remove peer: %w", idx+1, err)
	}
	return nil
}

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
	if err := waitConverged(cluster, []int{0, 1, 2}, 5, waitTimeout); err != nil {
		return err
	}

	// Remove node3 on both survivors (runtime verb, durable table).
	for _, i := range []int{0, 1} {
		if err := removePeer(cluster, i, removed); err != nil {
			return err
		}
		if ok, err := excludedRow(cluster, i, removed); err != nil || !ok {
			return fmt.Errorf("node%d missing murmur_excluded row: %v", i+1, err)
		}
	}
	// Sessions to node3 drop; the survivor link stays up.
	if err := waitSessionsDrop(cluster, waitTimeout); err != nil {
		return err
	}
	if err := goharness.PeerCounts(cluster, []int{0, 1}, []int{1, 1}, waitTimeout); err != nil {
		return fmt.Errorf("survivor link: %w", err)
	}
	// Isolation holds in both directions: neither side's writes cross.
	if err := insert(cluster, removed, 100, "isolated"); err != nil {
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
	if err := insert(cluster, 0, 101, "survivor-only"); err != nil {
		return err
	}
	if err := waitConverged(cluster, []int{0, 1}, 6, waitTimeout); err != nil {
		return err
	}
	time.Sleep(isolationHold)
	if got, err := names(cluster, removed); err != nil {
		return err
	} else if len(got) != 6 {
		return fmt.Errorf("node3 names = %v; want six without survivor-only", got)
	} else {
		for _, n := range got {
			if n == "survivor-only" {
				return fmt.Errorf("node3 received survivor-only after removal: %v", got)
			}
		}
	}

	// The exclusion survives a survivor restart with no re-mesh.
	if err := cluster.StopNode(0); err != nil {
		return fmt.Errorf("stop node1: %w", err)
	}
	if err := cluster.StartNode(0); err != nil {
		return fmt.Errorf("restart node1: %w", err)
	}
	if ok, err := excludedRow(cluster, 0, removed); err != nil || !ok {
		return fmt.Errorf("node1 lost murmur_excluded row across restart: %v", err)
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
	if remeshed, err := peerConnected(cluster, 0, removed); err != nil {
		return err
	} else if remeshed {
		return fmt.Errorf("node1 re-meshed removed node3 after restart")
	}
	if count, err := connectedCount(cluster, 0); err != nil {
		return err
	} else if count != 1 {
		return fmt.Errorf("node1 peers after restart = %d, want 1 (exclusion lost?)", count)
	}
	// Data still does not cross after the restart, either direction.
	if err := insert(cluster, removed, 102, "isolated-2"); err != nil {
		return err
	}
	time.Sleep(isolationHold)
	if got, err := names(cluster, 0); err != nil {
		return err
	} else if len(got) != 6 {
		return fmt.Errorf("node1 names after restart = %v; want six", got)
	}
	if err := insert(cluster, 1, 103, "survivor-only-2"); err != nil {
		return err
	}
	if err := waitConverged(cluster, []int{0, 1}, 7, waitTimeout); err != nil {
		return err
	}
	time.Sleep(isolationHold)
	if got, err := names(cluster, removed); err != nil {
		return err
	} else {
		for _, n := range got {
			if n == "survivor-only-2" {
				return fmt.Errorf("node3 received survivor-only-2 after restart: %v", got)
			}
		}
	}
	return nil
}

func TestRemovePeerBlocksRejoinAcrossRestart(t *testing.T) {
	goharness.SkipUnlessLive(t)
	cluster, err := goharness.NewCluster(goharness.ClusterOptions{
		Name:     "exclude-rejoin",
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
