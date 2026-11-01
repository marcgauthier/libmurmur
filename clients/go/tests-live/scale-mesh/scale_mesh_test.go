// Live scenario: a 10-node mesh converges 400 rows from two origins.
//
// Port of MURMUR-SQL scale-mesh: ten native nodes converge 400 rows (300
// on node 0, 100 on node 7) within 300 s with identical ordered values
// everywhere. The reference's concurrent fanout sampler (connected
// push-mode peers never exceed fanout 4) is skipped: the harness
// exposes no gossip_fanout setting and ShowPeers reports no
// selected-push-peer field, so the bound cannot be observed.
package scalemesh

import (
	"fmt"
	"testing"
	"time"

	goharness "github.com/marcgauthier/libmurmur/clients/go/tests-live/goharness"
)

func TestScaleMesh(t *testing.T) {
	goharness.SkipUnlessLive(t)
	cluster, err := goharness.NewCluster(goharness.ClusterOptions{
		Name:     "scale-mesh",
		NumNodes: 10,
	})
	if err != nil {
		t.Fatalf("start cluster: %v", err)
	}
	failed := true
	defer func() { cluster.Finish(failed) }()

	if err := goharness.Fixture(cluster); err != nil {
		t.Fatalf("fixture: %v", err)
	}
	var expected [][]string
	for n := 0; n < 400; n++ {
		node := 0
		if n >= 300 {
			node = 7
		}
		id := fmt.Sprintf("%06d", n)
		name := fmt.Sprintf("origin-%d-%d", node, n)
		if _, err := cluster.Node(node).Execute(
			"INSERT INTO records(id,name) VALUES($1,$2)", id, name); err != nil {
			t.Fatalf("insert %s: %v", id, err)
		}
		expected = append(expected, []string{id, name})
	}
	for _, node := range []int{0, 7} {
		if err := cluster.Node(node).Flush(); err != nil {
			t.Fatalf("node %d flush: %v", node, err)
		}
	}
	all := []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}
	if err := goharness.Converge(cluster, all, expected, 300*time.Second); err != nil {
		t.Fatalf("converge: %v", err)
	}
	failed = false
}

func TestScaleMeshFanoutBound(t *testing.T) {
	goharness.SkipUnlessLive(t)
	// Blocked: no gossip_fanout setting is plumbed through the
	// harness, and peer rows carry no selected-push-peer flag, so the
	// "never push to more than 4 peers" sampler cannot observe
	// anything.
	t.Skip("harness: gossip fanout setting and selected-push-peer introspection")
}
