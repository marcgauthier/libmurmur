// Live scenario: a partitioned node repairs its missed tail from peer
// logs, not from a snapshot.
//
// Port of MURMUR-SQL tail-repair: three native nodes converge on 10
// baseline rows, node 2 is partitioned away in both directions, an
// isolation probe proves the partition holds, the survivors take a
// 100-row burst, the partition heals, every node converges with equal
// digests while the healed node's applied-transactions counter proves
// the missed range arrived as log transactions, and a post-heal write
// on the healed node replicates everywhere.
//
// The reference removes QUIC links at runtime; this stack has no
// peer-removal switch, so isolation uses per-node allowed_peers
// identity allow-lists (the established partition-suite pattern)
// applied with a replication restart: nodes 0 and 1 allow only each
// other, node 2 allows only itself, and the transport refuses
// cross-partition sessions in both directions. Healing clears the
// lists and remeshes. The no-snapshot proof reads the cumulative
// per-origin applied counters from ShowReplication (the decoded
// MURMUR SHOW REPLICATION progress snapshot); snapshot application
// bypasses that counter, so advancement across the heal proves the
// missed range arrived as log transactions.
package tailrepair

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"testing"
	"time"

	goharness "github.com/marcgauthier/sqlite-murmur-go/clients/go/tests-live/goharness"
)

const (
	// pollInterval is the convergence poll interval (Rust: 100 ms).
	pollInterval = 100 * time.Millisecond
	// baselineTimeout is the baseline convergence deadline (Rust: 30 s).
	baselineTimeout = 30 * time.Second
	// splitPeersTimeout and healPeersTimeout are the connected-peers
	// settle deadlines (Rust: 15 s / 30 s).
	splitPeersTimeout = 15 * time.Second
	healPeersTimeout  = 30 * time.Second
	// probeTimeout is the isolation-probe reach deadline (Rust: 15 s).
	probeTimeout = 15 * time.Second
	// settleMargin is the negative-check settle margin (Rust: 2 s).
	settleMargin = 2 * time.Second
	// burstTimeout is the burst convergence deadline (Rust: 30 s).
	burstTimeout = 30 * time.Second
	// healTimeout is the full post-heal convergence deadline (Rust: 60 s).
	healTimeout = 60 * time.Second
	// postHealTimeout is the post-heal write deadline (Rust: 30 s).
	postHealTimeout = 30 * time.Second
)

const (
	// baselineRows are written on node 0 (Rust: 10, ids i, base-i).
	baselineRows = 10
	// probeID is the isolation-probe row id (Rust: 9000, probe).
	probeID = 9000
	// burstID is the burst row id base (Rust: 10000+i, burst-i).
	burstID = 10000
	// postHealID is the post-heal row id (Rust: 20000, post-heal).
	postHealID = 20000
)

// markerRow is one marker row (Rust: MarkerRow).
type markerRow struct {
	id   int64
	name string
}

// rows reads all marker rows on one node (Rust: rows).
func rows(cluster *goharness.Cluster, idx int) ([]markerRow, error) {
	dbRows, err := cluster.Node(idx).Simple("SELECT id, name FROM records")
	if err != nil {
		return nil, fmt.Errorf("node%d SELECT rows: %w", idx+1, err)
	}
	out := make([]markerRow, 0, len(dbRows))
	for _, row := range dbRows {
		if len(row) < 2 {
			return nil, fmt.Errorf("node%d decode row: short row", idx+1)
		}
		id, err := strconv.ParseInt(row[0], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("node%d decode id: %w", idx+1, err)
		}
		out = append(out, markerRow{id: id, name: row[1]})
	}
	return out, nil
}

// digest renders the canonical digest of a row set (Rust: digest).
func digest(rows []markerRow) string {
	sort.Slice(rows, func(a, b int) bool {
		if rows[a].id != rows[b].id {
			return rows[a].id < rows[b].id
		}
		return rows[a].name < rows[b].name
	})
	return fmt.Sprintf("%#v", rows)
}

// insertMarker inserts one marker row plus a durability barrier (Rust:
// insert_marker).
func insertMarker(cluster *goharness.Cluster, node int, id int64, name string) error {
	if _, err := cluster.Node(node).Execute(
		"INSERT INTO records(id, name) VALUES($1, $2)", id, name); err != nil {
		return fmt.Errorf("node%d insert '%s': %w", node+1, name, err)
	}
	if err := cluster.Node(node).Flush(); err != nil {
		return fmt.Errorf("node%d flush after '%s': %w", node+1, name, err)
	}
	return nil
}

// waitRowCount waits until one node holds exactly want rows (Rust:
// wait_row_count).
func waitRowCount(cluster *goharness.Cluster, idx, want int, timeout time.Duration, what string) error {
	deadline := time.Now().Add(timeout)
	for {
		got, err := rows(cluster, idx)
		if err != nil {
			return err
		}
		if len(got) == want {
			return nil
		}
		if !time.Now().Before(deadline) {
			got, err := rows(cluster, idx)
			if err != nil {
				return err
			}
			return fmt.Errorf("node%d typed row count = %d, want %d within %v (%s)",
				idx+1, len(got), want, timeout, what)
		}
		time.Sleep(pollInterval)
	}
}

// waitConverged waits until every node holds exactly want rows with
// equal digests (Rust: wait_converged).
func waitConverged(cluster *goharness.Cluster, want int, timeout time.Duration, what string) error {
	deadline := time.Now().Add(timeout)
	for {
		first := ""
		converged := true
		for i := 0; i < cluster.Len(); i++ {
			nodeRows, err := rows(cluster, i)
			if err != nil {
				return err
			}
			if len(nodeRows) != want {
				converged = false
				break
			}
			d := digest(nodeRows)
			if i == 0 {
				first = d
			} else if d != first {
				converged = false
				break
			}
		}
		if converged {
			return nil
		}
		if !time.Now().Before(deadline) {
			for i := 0; i < cluster.Len(); i++ {
				nodeRows, err := rows(cluster, i)
				if err != nil {
					return err
				}
				fmt.Fprintf(os.Stderr, "node%d at timeout: count=%d digest=%s\n",
					i+1, len(nodeRows), digest(nodeRows))
			}
			return fmt.Errorf(
				"nodes did not converge on %d rows with equal digests within %v (%s)",
				want, timeout, what)
		}
		time.Sleep(pollInterval)
	}
}

// waitConnectedPeers waits until one node reports exactly want
// connected peers (Rust: wait_connected_peers, via ShowPeers).
func waitConnectedPeers(cluster *goharness.Cluster, idx, want int, timeout time.Duration) error {
	if err := goharness.PeerCounts(cluster, []int{idx}, []int{want}, timeout); err != nil {
		return fmt.Errorf("node%d connected peers: %w", idx+1, err)
	}
	return nil
}

// appliedTransactions reads the cumulative log-applied transactions on
// one node: the sum of per-origin applied counters in the progress
// snapshot. Snapshot application bypasses this counter, so advancement
// across the heal proves the missed range arrived as log transactions.
func appliedTransactions(cluster *goharness.Cluster, idx int) (uint64, error) {
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

// envUsize reads a positive-integer env knob with fallback (Rust:
// env_usize).
func envUsize(name string, fallback int) int {
	if v, err := strconv.Atoi(os.Getenv(name)); err == nil && v > 0 {
		return v
	}
	return fallback
}

func runBody(cluster *goharness.Cluster, burstRows int) error {
	// Same schema on every node, then replicate it: row convergence
	// needs the per-table flag on each node.
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

	// Baseline: 10 rows on node 0, converged everywhere.
	for i := int64(0); i < baselineRows; i++ {
		if err := insertMarker(cluster, 0, i, fmt.Sprintf("base-%d", i)); err != nil {
			return err
		}
	}
	if err := waitConverged(cluster, baselineRows, baselineTimeout, "baseline"); err != nil {
		return err
	}
	node2Rows, err := rows(cluster, 2)
	if err != nil {
		return err
	}
	baselineDigest := digest(node2Rows)

	// Log-path baseline on the soon-isolated node.
	appliedBefore, err := appliedTransactions(cluster, 2)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "node3 pre-partition applied_transactions=%d\n", appliedBefore)

	// Partition node3 away from both peers in both directions.
	// Nodes 0 and 1 allow only each other; node3 allows only itself,
	// so the transport refuses every cross-partition session.
	id := [3]string{cluster.NodeID(0), cluster.NodeID(1), cluster.NodeID(2)}
	if err := setAllowedPeers(cluster, [3][]string{{id[1]}, {id[0]}, {id[2]}}); err != nil {
		return err
	}
	if err := cluster.PeerMesh(); err != nil {
		return fmt.Errorf("remesh split: %w", err)
	}
	if err := waitConnectedPeers(cluster, 2, 0, splitPeersTimeout); err != nil {
		return err
	}

	// Isolation probe: one row on node 0 must reach node 1 but never
	// node3.
	if err := insertMarker(cluster, 0, probeID, "probe"); err != nil {
		return err
	}
	if err := waitRowCount(cluster, 1, baselineRows+1, probeTimeout, "probe on survivor"); err != nil {
		return err
	}
	time.Sleep(settleMargin) // negative check needs a settle margin
	isolated, err := rows(cluster, 2)
	if err != nil {
		return err
	}
	if len(isolated) != baselineRows {
		return fmt.Errorf("partition leaked: node3 count = %d, want %d", len(isolated), baselineRows)
	}
	if digest(isolated) != baselineDigest {
		return fmt.Errorf("partition leaked: node3 digest changed while partitioned")
	}

	// Write burst on the survivors while node3 is isolated.
	for i := 0; i < burstRows; i++ {
		node := i % 2
		if err := insertMarker(cluster, node, burstID+int64(i), fmt.Sprintf("burst-%d", i)); err != nil {
			return err
		}
	}
	want := baselineRows + 1 + burstRows
	if err := waitRowCount(cluster, 0, want, burstTimeout, "burst on node1"); err != nil {
		return err
	}
	if err := waitRowCount(cluster, 1, want, burstTimeout, "burst on node2"); err != nil {
		return err
	}
	// Anti-vacuity: node3 must actually be missing the contiguous range.
	isolated, err = rows(cluster, 2)
	if err != nil {
		return err
	}
	if len(isolated) != baselineRows {
		return fmt.Errorf("node3 count = %d, want %d (it must miss the burst range)",
			len(isolated), baselineRows)
	}
	missed := want - baselineRows
	fmt.Fprintf(os.Stderr, "node3 missed %d rows while partitioned\n", missed)

	// Heal and require full convergence.
	if err := setAllowedPeers(cluster, [3][]string{nil, nil, nil}); err != nil {
		return err
	}
	if err := cluster.PeerMesh(); err != nil {
		return fmt.Errorf("remesh healed: %w", err)
	}
	for i := 0; i < cluster.Len(); i++ {
		if err := waitConnectedPeers(cluster, i, 2, healPeersTimeout); err != nil {
			return err
		}
	}
	if err := waitConverged(cluster, want, healTimeout, "post-heal"); err != nil {
		return err
	}

	// The healing must have used log range repair, not the snapshot
	// path. Every burst row is its own flushed transaction, so the
	// missed row count is also the missed transaction count; snapshot
	// application bypasses the applied counter, so advancement by at
	// least the missed count proves the range arrived and applied as
	// log transactions.
	appliedAfter, err := appliedTransactions(cluster, 2)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "node3 log repair: applied %d->%d (missed %d rows)\n",
		appliedBefore, appliedAfter, missed)
	advanced := appliedAfter - appliedBefore
	if appliedAfter < appliedBefore {
		advanced = 0
	}
	if advanced < uint64(missed) {
		return fmt.Errorf(
			"node3 applied_transactions advanced by %d, want at least %d (healing must apply the missed range from peer logs)",
			advanced, missed)
	}

	// Post-heal write on the healed node replicates everywhere.
	if err := insertMarker(cluster, 2, postHealID, "post-heal"); err != nil {
		return err
	}
	return waitConverged(cluster, want+1, postHealTimeout, "post-heal write")
}

func TestPartitionedNodeRepairsTailFromPeerLogs(t *testing.T) {
	goharness.SkipUnlessLive(t)
	burstRows := envUsize("MURMUR_TAIL_REPAIR_BURST_ROWS", 100)
	cluster, err := goharness.NewCluster(goharness.ClusterOptions{
		Name:     "tail-repair",
		NumNodes: 3,
	})
	if err != nil {
		t.Fatalf("cluster setup: %v", err)
	}
	failed := true
	defer func() { cluster.Finish(failed) }()
	if err := runBody(cluster, burstRows); err != nil {
		t.Logf("scenario failed: %v", err)
		t.Fatal("scenario failed; artifacts retained under tests-live/failures/")
	}
	failed = false
}
