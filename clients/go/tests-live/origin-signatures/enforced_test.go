// Live proof for origin-signed cells: a 3-node enforced mesh
// converges (honest forwarding passes end to end over QUIC), a
// rogue origin's rows never land, and a tampered forward of an
// honest cell is refused while the victim still converges through
// a clean path.
package originsignatures

import (
	"fmt"
	"testing"
	"time"

	goharness "github.com/marcgauthier/libmurmur/clients/go/tests-live/goharness"
)

const (
	enforceConvergeTimeout = 60 * time.Second
	enforceAbsentWindow    = 8 * time.Second
)

// remesh wires x<->y, retrying: post-restart peer attach usually
// lands in milliseconds but occasionally exceeds one 5s budget.
func remesh(cluster *goharness.Cluster, x, y int) error {
	var err error
	for i := 0; i < 3; i++ {
		if err = meshBoth(cluster, x, y); err == nil {
			return nil
		}
	}
	return err
}

// waitAbsent asserts `want` never appears on `node` for window.
func waitAbsent(cluster *goharness.Cluster, node int, want []string, window time.Duration) error {
	deadline := time.Now().Add(window)
	for time.Now().Before(deadline) {
		got, err := names(cluster, node)
		if err != nil {
			return err
		}
		for _, w := range want {
			for _, g := range got {
				if g == w {
					return fmt.Errorf("node%d unexpectedly holds %q (has %v)", node+1, w, got)
				}
			}
		}
		time.Sleep(poll)
	}
	return nil
}

func TestEnforcedMeshConvergesAndRefusesForgery(t *testing.T) {
	goharness.SkipUnlessLive(t)
	seeds, err := goharness.GenerateOriginSeeds(3)
	if err != nil {
		t.Fatalf("seeds: %v", err)
	}
	cluster, err := goharness.NewCluster(goharness.ClusterOptions{
		Name:        "origin-signatures-enforced",
		NumNodes:    3,
		OriginSeeds: seeds,
	})
	if err != nil {
		t.Fatalf("start cluster: %v", err)
	}
	failed := true
	defer func() { cluster.Finish(failed) }()

	for i := 0; i < 3; i++ {
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
	if err := cluster.EnforceOrigins(seeds); err != nil {
		t.Fatalf("enforce origins: %v", err)
	}

	// Leg 1: honest enforced mesh converges.
	if err := insert(cluster, 0, 1, "from-A"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err := waitNames(cluster, i, []string{"from-A"}, enforceConvergeTimeout); err != nil {
			t.Fatal(err)
		}
	}
	// v2 proof: the relay stored a verified origin signature
	// (legacy v1 batches store nothing).
	rows, err := cluster.Node(1).Simple("SELECT COUNT(*) FROM murmur_cell_sigs")
	if err != nil || len(rows) != 1 || rows[0][0] == "0" {
		t.Fatalf("node1 stored sigs = %v, %v (want >0)", rows, err)
	}

	// Leg 2: rogue origin refused. Node 0's site is pinned to a
	// wrong key on nodes 1-2; its new row must never land there.
	site0, err := cluster.Node(0).SiteHex()
	if err != nil {
		t.Fatal(err)
	}
	site1, err := cluster.Node(1).SiteHex()
	if err != nil {
		t.Fatal(err)
	}
	site2, err := cluster.Node(2).SiteHex()
	if err != nil {
		t.Fatal(err)
	}
	pub0, err := goharness.OriginPubHex(seeds[0])
	if err != nil {
		t.Fatal(err)
	}
	pub1, err := goharness.OriginPubHex(seeds[1])
	if err != nil {
		t.Fatal(err)
	}
	pub2, err := goharness.OriginPubHex(seeds[2])
	if err != nil {
		t.Fatal(err)
	}
	rogue, err := goharness.OriginPubHex([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	good := map[string]string{site0: pub0, site1: pub1, site2: pub2}
	roguePins := map[string]string{site0: rogue, site1: pub1, site2: pub2}
	if err := cluster.SetOrigins(roguePins, 1, 2); err != nil {
		t.Fatalf("rogue pins: %v", err)
	}
	if err := insert(cluster, 0, 2, "rogue-row"); err != nil {
		t.Fatal(err)
	}
	if err := waitAbsent(cluster, 1, []string{"rogue-row"}, enforceAbsentWindow); err != nil {
		t.Fatal(err)
	}
	if err := waitAbsent(cluster, 2, []string{"rogue-row"}, time.Second); err != nil {
		t.Fatal(err)
	}
	// Control: restore the true pin and the row converges.
	if err := cluster.SetOrigins(good, 1, 2); err != nil {
		t.Fatalf("restore pins: %v", err)
	}
	for i := 0; i < 3; i++ {
		if err := waitNames(cluster, i, []string{"from-A", "rogue-row"}, enforceConvergeTimeout); err != nil {
			t.Fatal(err)
		}
	}

	// Leg 3: honest forward through a relay with the origin
	// offline (path proof before tampering).
	if err := cluster.StopNode(2); err != nil {
		t.Fatalf("stop node2: %v", err)
	}
	if err := insert(cluster, 0, 3, "via-relay"); err != nil {
		t.Fatal(err)
	}
	if err := waitNames(cluster, 1, []string{"from-A", "rogue-row", "via-relay"}, enforceConvergeTimeout); err != nil {
		t.Fatal(err)
	}
	if err := cluster.StopNode(0); err != nil {
		t.Fatalf("stop node0: %v", err)
	}
	if err := cluster.StartNode(2); err != nil {
		t.Fatalf("start node2: %v", err)
	}
	if err := remesh(cluster, 1, 2); err != nil {
		t.Fatalf("remesh 1-2: %v", err)
	}
	if err := waitNames(cluster, 2, []string{"from-A", "rogue-row", "via-relay"}, enforceConvergeTimeout); err != nil {
		t.Fatalf("node2 missed honest forward: %v", err)
	}

	// Leg 4: tampered forward refused. Node 0 writes one more row,
	// node 1 stores it, then node 1's stored signature is
	// corrupted: node 2 must refuse the re-export.
	if err := cluster.StartNode(0); err != nil {
		t.Fatalf("restart node0: %v", err)
	}
	if err := cluster.StopNode(2); err != nil {
		t.Fatalf("stop node2: %v", err)
	}
	if err := remesh(cluster, 0, 1); err != nil {
		t.Fatalf("remesh 0-1: %v", err)
	}
	if err := insert(cluster, 0, 4, "tampered-row"); err != nil {
		t.Fatal(err)
	}
	if err := waitNames(cluster, 1, []string{"from-A", "rogue-row", "tampered-row", "via-relay"}, enforceConvergeTimeout); err != nil {
		t.Fatal(err)
	}
	n, err := cluster.Node(1).Execute("UPDATE murmur_cell_sigs SET sig=randomblob(64)")
	if err != nil {
		t.Fatalf("tamper sigs: %v", err)
	}
	if n == 0 {
		t.Fatal("tamper touched 0 sig rows")
	}
	if err := cluster.StopNode(0); err != nil {
		t.Fatalf("stop node0: %v", err)
	}
	if err := cluster.StartNode(2); err != nil {
		t.Fatalf("start node2: %v", err)
	}
	if err := remesh(cluster, 1, 2); err != nil {
		t.Fatalf("remesh 1-2: %v", err)
	}
	// Node 2's only source for tampered-row is node 1's corrupt
	// re-export: it must stay absent.
	if err := waitAbsent(cluster, 2, []string{"tampered-row"}, enforceAbsentWindow); err != nil {
		t.Fatal(err)
	}
	// Control: the clean origin returns and node 2 converges.
	if err := cluster.StartNode(0); err != nil {
		t.Fatalf("restart node0: %v", err)
	}
	if err := remesh(cluster, 0, 2); err != nil {
		t.Fatalf("remesh 0-2: %v", err)
	}
	if err := waitNames(cluster, 2, []string{"from-A", "rogue-row", "tampered-row", "via-relay"}, enforceConvergeTimeout); err != nil {
		t.Fatalf("node2 missed recovery: %v", err)
	}

	failed = false
}
