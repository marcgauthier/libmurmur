// Live scenario: a forwarded origin survives an offline origin.
//
// Port of MURMUR-SQL origin-signatures: three native nodes share one
// database id; A commits, B receives, A stops, and C receives A's
// transaction exclusively through B. The honest forwarding,
// C-restart durability, and B-rejoin idempotent re-offer legs run
// here; the hostile-relay legs (served-origin capture, modified /
// unsigned / cross-DBID / fabricated / chunk-identity attacks,
// availability probe, signed-duplicate replay over the relay, and
// untrusted snapshot manifest) need a raw-QUIC peer speaking the
// replication wire protocol plus origin-seed access, which has no
// harness equivalent, so the test skips with a named gap after the
// portable legs pass.
//
// Deviations from the reference: quiescence and stillness use the
// applied-transaction sum from the progress snapshot (this stack
// exposes no staged gauge, no last_error rejection latch, and no
// commit cursor); the C restart is a replication stop/start with the
// store open (in-process nodes); the restart and rejoin legs run
// before the blocked relay legs instead of interleaved with them;
// the fresh-process counters premise is re-baselined, not asserted
// at zero.
package originsignatures

import (
	"fmt"
	"os"
	"testing"
	"time"

	goharness "github.com/marcgauthier/sqlite-murmur-go/clients/go/tests-live/goharness"
)

const (
	a = 0
	b = 1
	c = 2
)

// Convergence deadline per phase (reference: 30 s).
const convergeTimeout = 30 * time.Second

// Convergence poll interval (reference: 200 ms).
const poll = 200 * time.Millisecond

// Session attach/teardown observation bound (reference: 5 s).
const peerTimeout = 5 * time.Second

// Settle window after the idempotent re-offer (reference: 5 s).
const settle = 5 * time.Second

// names returns the canonical ordered names on one node.
func names(cluster *goharness.Cluster, idx int) ([]string, error) {
	rows, err := cluster.Node(idx).Simple("SELECT name FROM records ORDER BY name")
	if err != nil {
		return nil, fmt.Errorf("node%d read names: %w", idx+1, err)
	}
	out := make([]string, 0, len(rows))
	for _, row := range rows {
		out = append(out, row[0])
	}
	return out, nil
}

// insert writes one single-row transaction.
func insert(cluster *goharness.Cluster, node int, id int64, name string) error {
	if _, err := cluster.Node(node).Execute(
		"INSERT INTO records(id, name) VALUES($1, $2)", id, name); err != nil {
		return fmt.Errorf("node%d insert failed: %w", node, err)
	}
	if err := cluster.Node(node).Flush(); err != nil {
		return fmt.Errorf("node%d flush after insert: %w", node, err)
	}
	return nil
}

// waitNames waits until `node` holds exactly `want`.
func waitNames(cluster *goharness.Cluster, node int, want []string, timeout time.Duration) error {
	converged := goharness.WaitUntil(timeout, poll, func() bool {
		got, err := names(cluster, node)
		if err != nil || len(got) != len(want) {
			return false
		}
		for i := range got {
			if got[i] != want[i] {
				return false
			}
		}
		return true
	})
	if !converged {
		got, _ := names(cluster, node)
		return fmt.Errorf("node%d did not converge on %v within %v (has %v)", node+1, want, timeout, got)
	}
	return nil
}

// connectedPeers returns the connected replication sessions on one node.
func connectedPeers(cluster *goharness.Cluster, idx int) (int, error) {
	peers, err := cluster.Node(idx).ShowPeers()
	if err != nil {
		return 0, fmt.Errorf("node%d SHOW PEERS: %w", idx+1, err)
	}
	n := 0
	for _, p := range peers {
		if p.Connected {
			n++
		}
	}
	return n, nil
}

// waitQuiet waits until `idx` has no connected sessions.
func waitQuiet(cluster *goharness.Cluster, idx int, what string) error {
	converged := goharness.WaitUntil(peerTimeout, 50*time.Millisecond, func() bool {
		n, err := connectedPeers(cluster, idx)
		return err == nil && n == 0
	})
	if !converged {
		return fmt.Errorf("%s: node%d sessions did not tear down", what, idx+1)
	}
	return nil
}

// appliedSum reads the cumulative log-applied transactions on one
// node: the sum of per-origin applied counters in the progress
// snapshot.
func appliedSum(cluster *goharness.Cluster, idx int) (uint64, error) {
	snap, err := cluster.Node(idx).ShowReplication()
	if err != nil {
		return 0, fmt.Errorf("node%d SHOW REPLICATION: %w", idx+1, err)
	}
	arr, ok := snap.([]any)
	if !ok {
		return 0, fmt.Errorf("node%d SHOW REPLICATION: unexpected shape %T", idx+1, snap)
	}
	var sum uint64
	for _, e := range arr {
		m, ok := e.(map[string]any)
		if !ok {
			return 0, fmt.Errorf("node%d SHOW REPLICATION: bad entry %T", idx+1, e)
		}
		v, ok := m["applied"].(float64)
		if !ok {
			return 0, fmt.Errorf("node%d SHOW REPLICATION: no applied counter", idx+1)
		}
		sum += uint64(v)
	}
	return sum, nil
}

// waitAppliedQuiet waits until the applied cursor holds still across
// consecutive polls (this stack has no staged gauge, so stillness of
// the applied sum is the quiescence signal).
func waitAppliedQuiet(cluster *goharness.Cluster, idx int, what string) (uint64, error) {
	start := time.Now()
	last, err := appliedSum(cluster, idx)
	if err != nil {
		return 0, err
	}
	var stable uint32
	for {
		current, err := appliedSum(cluster, idx)
		if err != nil {
			return 0, err
		}
		if current == last {
			stable++
			if stable >= 3 {
				return current, nil
			}
		} else {
			stable = 0
		}
		last = current
		if time.Since(start) >= 30*time.Second {
			return 0, fmt.Errorf("%s: node%d applied cursor never quiesced (applied=%d)",
				what, idx+1, last)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// assertProtected requires rows and the applied cursor unchanged.
func assertProtected(cluster *goharness.Cluster, applied uint64, ctx string) error {
	got, err := appliedSum(cluster, c)
	if err != nil {
		return err
	}
	if got != applied {
		return fmt.Errorf("node%d applied cursor moved %s: %d -> %d",
			c+1, ctx, applied, got)
	}
	rows, err := names(cluster, c)
	if err != nil {
		return err
	}
	if len(rows) != 1 || rows[0] != "from-A" {
		return fmt.Errorf("node%d rows changed %s: %v", c+1, ctx, rows)
	}
	return nil
}

// meshBoth wires x<->y and waits for the sessions to attach.
func meshBoth(cluster *goharness.Cluster, x, y int) error {
	if err := cluster.Node(x).PeerAdd(cluster.Node(y).Addr); err != nil {
		return fmt.Errorf("mesh %d->%d: %w", x, y, err)
	}
	if err := cluster.Node(y).PeerAdd(cluster.Node(x).Addr); err != nil {
		return fmt.Errorf("mesh %d->%d: %w", y, x, err)
	}
	if err := cluster.WaitPeers([]int{x, y}, 1, peerTimeout); err != nil {
		return fmt.Errorf("mesh %d<->%d attach: %w", x, y, err)
	}
	return nil
}

func runBody(cluster *goharness.Cluster) error {
	// Same table on every node, flagged replicated on each node
	// (forwarding needs the per-node flag).
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

	// A commits; B receives; A stops.
	if err := meshBoth(cluster, a, b); err != nil {
		return err
	}
	if err := insert(cluster, a, 1, "from-A"); err != nil {
		return err
	}
	if err := waitNames(cluster, b, []string{"from-A"}, convergeTimeout); err != nil {
		return err
	}
	if err := cluster.StopNode(a); err != nil {
		return fmt.Errorf("stop node1: %w", err)
	}

	// C learns A's transaction exclusively from B while A remains stopped.
	if err := meshBoth(cluster, b, c); err != nil {
		return err
	}
	if err := waitNames(cluster, c, []string{"from-A"}, convergeTimeout); err != nil {
		return err
	}
	bNames, err := names(cluster, b)
	if err != nil {
		return err
	}
	cNames, err := names(cluster, c)
	if err != nil {
		return err
	}
	if len(bNames) != len(cNames) || (len(bNames) > 0 && bNames[0] != cNames[0]) {
		return fmt.Errorf("forwarded state differs between B and C")
	}

	// Honest baseline on C. Drain first: a baseline sampled
	// mid-flight would demand in-flight data never apply.
	if _, err := waitAppliedQuiet(cluster, c, "honest convergence"); err != nil {
		return err
	}
	base, err := appliedSum(cluster, c)
	if err != nil {
		return err
	}
	honest, err := names(cluster, c)
	if err != nil {
		return err
	}
	if len(honest) != 1 || honest[0] != "from-A" {
		return fmt.Errorf("honest transaction missing on C")
	}

	// B stops; from here C is alone with its forwarded state.
	// Batches B sent before dying still apply afterwards (verified
	// data must never be dropped), so drain to quiescence and
	// require only that the applied cursor never moves backwards.
	if err := cluster.StopNode(b); err != nil {
		return fmt.Errorf("stop node2: %w", err)
	}
	if err := waitQuiet(cluster, c, "B shutdown"); err != nil {
		return err
	}
	drained, err := waitAppliedQuiet(cluster, c, "B shutdown drain")
	if err != nil {
		return err
	}
	if drained < base {
		return fmt.Errorf("node%d applied cursor moved backwards after B shutdown: %d -> %d",
			c+1, base, drained)
	}
	fmt.Fprintf(os.Stderr, "forwarded origin reached C through B only (applied=%d)\n", drained)

	// Restart C: the honest row is durable (A and B stay stopped).
	if err := cluster.StopNode(c); err != nil {
		return fmt.Errorf("stop node3: %w", err)
	}
	if err := cluster.StartNode(c); err != nil {
		return fmt.Errorf("restart node3: %w", err)
	}
	restarted, err := names(cluster, c)
	if err != nil {
		return err
	}
	if len(restarted) != 1 || restarted[0] != "from-A" {
		return fmt.Errorf("honest row lost on restart")
	}
	post, err := appliedSum(cluster, c)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "honest row durable across C restart (applied=%d)\n", post)

	// B rejoins and re-offers the transaction C already holds; C must
	// absorb the duplicate idempotently: rows and applied cursor
	// unchanged.
	if err := cluster.StartNode(b); err != nil {
		return fmt.Errorf("restart node2: %w", err)
	}
	if err := meshBoth(cluster, b, c); err != nil {
		return err
	}
	time.Sleep(settle)
	if err := assertProtected(cluster, post, "after the idempotent re-offer"); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "honest re-offer absorbed idempotently")
	return nil
}

func TestForwardedOriginSurvivesOfflineOriginAndHostileRelay(t *testing.T) {
	goharness.SkipUnlessLive(t)
	cluster, err := goharness.NewCluster(goharness.ClusterOptions{
		Name:     "origin-signatures",
		NumNodes: 3,
		NoMesh:   true,
	})
	if err != nil {
		t.Fatalf("cluster setup: %v", err)
	}
	if cluster.Len() != 3 {
		t.Fatalf("this scenario is written for 3 nodes, got %d", cluster.Len())
	}
	failed := true
	defer func() { cluster.Finish(failed) }()
	if err := runBody(cluster); err != nil {
		t.Fatalf("scenario failed: %v", err)
	}
	failed = false
	// Blocked: the hostile-relay legs (served-origin capture over a
	// Need session, modified / unsigned / cross-DBID / fabricated /
	// chunk-identity attacks with last_error rejection proof,
	// chunk-availability probe, signed-duplicate replay over the
	// relay, and untrusted snapshot manifest) need a raw-QUIC peer
	// speaking the replication wire protocol plus origin-seed
	// access, which has no harness equivalent.
	t.Skip("harness: raw-QUIC relay attacker fixture and origin signing keys unavailable (no wire-protocol peer; served-origin capture and forgery legs cannot run)")
}
