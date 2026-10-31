// Live test: nodes from two distinct databases (different
// database_id) must never peer or replicate across databases, even when
// CAs are mutually trusted.
//
// Port of MURMUR-SQL dbid-isolation: two 2-node clusters cross-trust CA
// files and cross-peer every node, then each cluster must converge
// internally on its own marker while a 10 s observation window proves
// no cross-database row ever arrives, and every node latches a session
// group/identity mismatch (the anti-vacuity leg: TLS admits the cross
// dials, so only the database-id check can refuse them).
//
// The reference SetConfig bootstrap writes become runtime PeerAdd calls
// (no config surface exists natively); CA cross-trust stays a ca.pem
// append plus replication restart.
//
// NewCluster cannot serve here: it assigns every cluster the same
// deterministic node ids (index+1), and cross-cluster id aliasing makes
// isolation vacuous — the engine's accept path silently drops dials
// from self or already-sessioned ids before the group check ever runs.
// The port therefore boots both pairs through goharness.BootNode with
// four distinct node ids (the reference Rust port fixes distinct ids
// for the same reason), using only exported harness API.
package dbidisolation

import (
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	goharness "github.com/marcgauthier/sqlite-murmur-go/clients/go/tests-live/goharness"
)

// pairCluster is a 2-node cluster booted with explicit node ids.
type pairCluster struct {
	name  string
	dir   string
	group [16]byte
	key   [32]byte
	nodes [2]*goharness.Node
}

// bootPair boots a 2-node cluster with the given node ids; node 1
// seeds node 0, mirroring NewCluster.
func bootPair(t *testing.T, name string, id0, id1 [16]byte) *pairCluster {
	t.Helper()
	dir, err := goharness.PrepareRuntimeDir(name)
	if err != nil {
		t.Fatalf("prepare %s: %v", name, err)
	}
	c := &pairCluster{name: name, dir: dir}
	if _, err := rand.Read(c.group[:]); err != nil {
		t.Fatalf("group %s: %v", name, err)
	}
	if _, err := rand.Read(c.key[:]); err != nil {
		t.Fatalf("key %s: %v", name, err)
	}
	ca, err := goharness.GenerateCa()
	if err != nil {
		t.Fatalf("ca %s: %v", name, err)
	}
	ids := [2][16]byte{id0, id1}
	addrs := make([]string, 2)
	for i := range addrs {
		ap, err := goharness.FreeUDPAddr()
		if err != nil {
			t.Fatalf("addr %s node %d: %v", name, i, err)
		}
		addrs[i] = ap.String()
	}
	for i := 0; i < 2; i++ {
		nodeDir := filepath.Join(dir, fmt.Sprintf("node%d", i))
		if err := os.MkdirAll(nodeDir, 0o755); err != nil {
			t.Fatalf("dir %s node %d: %v", name, i, err)
		}
		issued, err := ca.Issue(ids[i], nil)
		if err != nil {
			t.Fatalf("issue %s node %d: %v", name, i, err)
		}
		tls, err := ca.WriteTLSDir(issued, nodeDir)
		if err != nil {
			t.Fatalf("tls %s node %d: %v", name, i, err)
		}
		var seeds []string
		if i > 0 {
			seeds = []string{addrs[0]}
		}
		n, err := goharness.BootNode(goharness.NodeConfig{
			Dir: nodeDir, ID: ids[i], Group: c.group,
			Addr: addrs[i], TLS: tls, Key: c.key,
			Seeds: seeds, Trust: [][16]byte{ids[0], ids[1]},
		})
		if err != nil {
			t.Fatalf("boot %s node %d: %v", name, i, err)
		}
		c.nodes[i] = n
	}
	return c
}

// finish dumps forensics on failure, closes both nodes, and retires
// the runtime dir.
func (c *pairCluster) finish(failed bool) {
	if failed {
		for i, n := range c.nodes {
			if n != nil {
				goharness.DumpNodeForensics(fmt.Sprintf("node%d", i), n.Dir, "scenario failed")
			}
		}
	}
	for _, n := range c.nodes {
		if n != nil {
			n.Close()
		}
	}
	goharness.FinishArtifacts(c.name, c.dir, failed)
}

func TestCrossDatabasePeersNeverReplicate(t *testing.T) {
	goharness.SkipUnlessLive(t)
	// Four distinct node ids: cross-cluster aliasing would let the
	// accept path drop cross dials as self/duplicate sessions before
	// the database-id check runs, making isolation vacuous.
	var idA0, idA1, idB0, idB1 [16]byte
	idA0[15] = 0xA0
	idA1[15] = 0xA1
	idB0[15] = 0xB0
	idB1[15] = 0xB1
	clusterA := bootPair(t, "dbid-iso-a", idA0, idA1)
	failedA := true
	defer func() { clusterA.finish(failedA) }()
	clusterB := bootPair(t, "dbid-iso-b", idB0, idB1)
	failedB := true
	defer func() { clusterB.finish(failedB) }()

	if clusterA.group == clusterB.group {
		t.Fatal("clusters share a database id; isolation test is vacuous")
	}

	// Initialize tables on both clusters.
	for _, cluster := range []*pairCluster{clusterA, clusterB} {
		for i := 0; i < 2; i++ {
			client := cluster.nodes[i]
			if _, err := client.Simple("CREATE TABLE IF NOT EXISTS records(id INTEGER PRIMARY KEY NOT NULL, name TEXT NOT NULL DEFAULT '')"); err != nil {
				t.Fatalf("create records: %v", err)
			}
			if err := client.SetTableReplicated("records", true); err != nil {
				t.Fatalf("replicate records: %v", err)
			}
			if err := client.Flush(); err != nil {
				t.Fatalf("flush schema: %v", err)
			}
		}
	}

	// Stop nodes on both clusters to cross-trust CAs and configure
	// cross-peering.
	for i := 0; i < 2; i++ {
		if err := clusterA.nodes[i].Stop(); err != nil {
			t.Fatalf("stop cluster A node %d: %v", i, err)
		}
		if err := clusterB.nodes[i].Stop(); err != nil {
			t.Fatalf("stop cluster B node %d: %v", i, err)
		}
	}

	caA, err := os.ReadFile(clusterA.nodes[0].TLS.Ca)
	if err != nil {
		t.Fatalf("read cluster A CA: %v", err)
	}
	caB, err := os.ReadFile(clusterB.nodes[0].TLS.Ca)
	if err != nil {
		t.Fatalf("read cluster B CA: %v", err)
	}

	// Cross-trust CAs by appending the peer CA to each node's ca.pem.
	for i := 0; i < 2; i++ {
		pathA := clusterA.nodes[i].TLS.Ca
		if err := os.WriteFile(pathA, []byte(fmt.Sprintf("%s\n%s", caA, caB)), 0o644); err != nil {
			t.Fatalf("cross-trust cluster A node %d: %v", i, err)
		}
		pathB := clusterB.nodes[i].TLS.Ca
		if err := os.WriteFile(pathB, []byte(fmt.Sprintf("%s\n%s", caB, caA)), 0o644); err != nil {
			t.Fatalf("cross-trust cluster B node %d: %v", i, err)
		}
	}

	// Restart all nodes (Start re-reads the CA file, so cross-trust
	// takes effect).
	for i := 0; i < 2; i++ {
		if err := clusterA.nodes[i].Start(); err != nil {
			t.Fatalf("restart cluster A node %d: %v", i, err)
		}
		if err := clusterB.nodes[i].Start(); err != nil {
			t.Fatalf("restart cluster B node %d: %v", i, err)
		}
	}

	// Cross-peer: node A[i] dials all B nodes and node B[i] dials all
	// A nodes (full bipartite); internal edges persist from the
	// bootstrap seeds.
	for i := 0; i < 2; i++ {
		for j := 0; j < 2; j++ {
			if err := clusterA.nodes[i].PeerAdd(clusterB.nodes[j].Addr); err != nil {
				t.Fatalf("cross-peer A%d->B%d: %v", i, j, err)
			}
			if err := clusterB.nodes[i].PeerAdd(clusterA.nodes[j].Addr); err != nil {
				t.Fatalf("cross-peer B%d->A%d: %v", i, j, err)
			}
		}
	}

	// Positive controls: write marker inside cluster A, write marker
	// inside cluster B.
	if _, err := clusterA.nodes[0].Execute("INSERT INTO records(id, name) VALUES($1, $2)", int64(1), "cluster-a-marker"); err != nil {
		t.Fatalf("insert cluster A marker: %v", err)
	}
	if err := clusterA.nodes[0].Flush(); err != nil {
		t.Fatalf("flush cluster A marker: %v", err)
	}

	if _, err := clusterB.nodes[0].Execute("INSERT INTO records(id, name) VALUES($1, $2)", int64(2), "cluster-b-marker"); err != nil {
		t.Fatalf("insert cluster B marker: %v", err)
	}
	if err := clusterB.nodes[0].Flush(); err != nil {
		t.Fatalf("flush cluster B marker: %v", err)
	}

	// Verify cluster A converges internally on marker A.
	expectedA := [][]string{{"cluster-a-marker"}}
	if err := assertRows(clusterA, "SELECT name FROM records ORDER BY id", expectedA); err != nil {
		t.Fatalf("cluster A converge: %v", err)
	}

	// Verify cluster B converges internally on marker B.
	expectedB := [][]string{{"cluster-b-marker"}}
	if err := assertRows(clusterB, "SELECT name FROM records ORDER BY id", expectedB); err != nil {
		t.Fatalf("cluster B converge: %v", err)
	}

	// Observation window: observe that cross-cluster replication never
	// happens.
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		rowsA0, err := clusterA.nodes[0].Simple("SELECT name FROM records ORDER BY id")
		if err != nil {
			t.Fatalf("read cluster A node 0: %v", err)
		}
		rowsA1, err := clusterA.nodes[1].Simple("SELECT name FROM records ORDER BY id")
		if err != nil {
			t.Fatalf("read cluster A node 1: %v", err)
		}
		rowsB0, err := clusterB.nodes[0].Simple("SELECT name FROM records ORDER BY id")
		if err != nil {
			t.Fatalf("read cluster B node 0: %v", err)
		}
		rowsB1, err := clusterB.nodes[1].Simple("SELECT name FROM records ORDER BY id")
		if err != nil {
			t.Fatalf("read cluster B node 1: %v", err)
		}

		if !reflect.DeepEqual(rowsA0, expectedA) {
			t.Fatalf("Cluster A node 0 received cross-database data! got %v", rowsA0)
		}
		if !reflect.DeepEqual(rowsA1, expectedA) {
			t.Fatalf("Cluster A node 1 received cross-database data! got %v", rowsA1)
		}
		if !reflect.DeepEqual(rowsB0, expectedB) {
			t.Fatalf("Cluster B node 0 received cross-database data! got %v", rowsB0)
		}
		if !reflect.DeepEqual(rowsB1, expectedB) {
			t.Fatalf("Cluster B node 1 received cross-database data! got %v", rowsB1)
		}

		time.Sleep(500 * time.Millisecond)
	}

	// Anti-vacuity leg: a session group/identity mismatch must be
	// observed, proving the cross dials passed TLS and died on the
	// database-id check (the engine's 5 s seed-redial tick recurs those
	// dials for as long as the cross edge is configured). The latch
	// holds only the last error per node — an outbound dial latches
	// "truncated frame header" when the refusing peer hangs up, which
	// overwrites that node's inbound mismatch — but every redial round
	// ends with a mismatch latched on at least the last acceptor, so
	// one sighting anywhere is deterministic.
	grace := time.Now().Add(15 * time.Second)
	seen := false
	for time.Now().Before(grace) && !seen {
		for _, cl := range []*pairCluster{clusterA, clusterB} {
			for i := 0; i < 2; i++ {
				s, err := cl.nodes[i].ShowStatus()
				if err != nil {
					t.Fatalf("status node: %v", err)
				}
				if lastErr, _ := statusValue(s, "last_error").(string); strings.Contains(lastErr, "mismatch") {
					seen = true
				}
			}
		}
		if !seen {
			time.Sleep(500 * time.Millisecond)
		}
	}
	if !seen {
		t.Fatal("no session group/identity mismatch observed on any node")
	}
	failedA = false
	failedB = false
}

// assertRows waits until both nodes of a pair read expected rows for
// query (60 s deadline, 50 ms polls).
func assertRows(cluster *pairCluster, query string, expected [][]string) error {
	deadline := time.Now().Add(60 * time.Second)
	for {
		all := true
		for i := 0; i < 2; i++ {
			rows, err := cluster.nodes[i].Simple(query)
			if err != nil {
				if goharness.ErrorCode(err) == "noparam" {
					all = false
					continue
				}
				return fmt.Errorf("poll SQL state: %w", err)
			}
			if !reflect.DeepEqual(rows, expected) {
				all = false
			}
		}
		if all {
			return nil
		}
		if !time.Now().Before(deadline) {
			return fmt.Errorf("SQL convergence timed out: %s; expected=%v", query, expected)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// statusValue walks a status snapshot along path, reporting nil for a
// missing key or an explicit JSON null.
func statusValue(s any, path ...string) any {
	cur := s
	for _, p := range path {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur, ok = m[p]
		if !ok {
			return nil
		}
	}
	return cur
}
