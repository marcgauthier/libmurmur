// Live scenario: a migrated peer crashes at the schema-manifest store
// boundary, recovers, rejoins, and converges with both peers.
//
// Port of MURMUR-SQL migration-crash: two cases (`before-store` and
// `after-store`) seed 24 rows, isolate node 0, stop/restart it on
// either side of the synchronous migration store, rejoin, adopt the
// new schema on the peers, and converge on a migrated-field write.
// The reference RemovePeer/AddPeer control plane becomes a
// murmur_config allowed_peers update plus replication restart (the
// established partition/allow-nodes pattern; QUIC settings reload on
// every Start). The migration itself uses the cr-sqlite
// begin/commit-alter protocol (a bare ALTER on a CRR leaves stale
// triggers; see schema-evolution). After-store restarts node 0 once
// to enable isolation before the migration and once more as the crash
// itself; what the case verifies (crash after the store) is unchanged.
package migrationcrash

import (
	"fmt"
	"sort"
	"testing"
	"time"

	goharness "github.com/marcgauthier/libmurmur/clients/go/tests-live/goharness"
)

// Base table.
const table = "live_typed_records"

// Seeded rows.
const seedRows = 24

// Seed convergence deadline.
const seedTimeout = 45 * time.Second

// Post-rejoin convergence deadline.
const rejoinTimeout = 90 * time.Second

// Peer-adoption deadline.
const epochTimeout = 45 * time.Second

// Final epoch+field convergence deadline.
const finalTimeout = 45 * time.Second

// Poll interval.
const poll = 250 * time.Millisecond

// names returns the canonical ordered names on one node.
func names(cluster *goharness.Cluster, idx int) ([]string, error) {
	rows, err := cluster.Node(idx).Simple(
		"SELECT name FROM live_typed_records ORDER BY name")
	if err != nil {
		return nil, fmt.Errorf("node%d read names: %w", idx+1, err)
	}
	out := make([]string, 0, len(rows))
	for _, row := range rows {
		if len(row) == 0 {
			return nil, fmt.Errorf("node%d read names: short row", idx+1)
		}
		out = append(out, row[0])
	}
	return out, nil
}

// insertRow inserts one record.
func insertRow(cluster *goharness.Cluster, idx int, name string) error {
	if _, err := cluster.Node(idx).Execute(
		"INSERT INTO live_typed_records(name, counter) VALUES($1, 0)", name); err != nil {
		return fmt.Errorf("node%d insert failed: %w", idx+1, err)
	}
	if err := cluster.Node(idx).Flush(); err != nil {
		return fmt.Errorf("node%d flush after insert failed: %w", idx+1, err)
	}
	return nil
}

// setNote writes the migrated note field.
func setNote(cluster *goharness.Cluster, idx int, name, note string) error {
	changed, err := cluster.Node(idx).Execute(
		"UPDATE live_typed_records SET note = $1 WHERE name = $2", note, name)
	if err != nil {
		return fmt.Errorf("node%d set note failed: %w", idx+1, err)
	}
	if changed != 1 {
		return fmt.Errorf("node%d set note hit %d rows", idx+1, changed)
	}
	if err := cluster.Node(idx).Flush(); err != nil {
		return fmt.Errorf("node%d flush after set note failed: %w", idx+1, err)
	}
	return nil
}

// hasColumn reports column presence. Absent = epoch 1, present =
// epoch 2.
func hasColumn(cluster *goharness.Cluster, idx int, table, column string) bool {
	rows, err := cluster.Node(idx).Simple(
		"SELECT name FROM pragma_table_info('" + table + "')")
	if err != nil {
		return false
	}
	for _, r := range rows {
		if len(r) > 0 && r[0] == column {
			return true
		}
	}
	return false
}

// epoch returns the schema epoch of one node.
func epoch(cluster *goharness.Cluster, idx int) uint64 {
	if hasColumn(cluster, idx, table, "note") {
		return 2
	}
	return 1
}

// assertEpoch requires an exact epoch.
func assertEpoch(cluster *goharness.Cluster, idx int, want uint64) error {
	if got := epoch(cluster, idx); got != want {
		return fmt.Errorf("node%d schema epoch = %d, want %d", idx+1, got, want)
	}
	return nil
}

// tryReadNote reads the note for one row. It returns (nil, nil) for a
// missing row or a NULL note.
func tryReadNote(cluster *goharness.Cluster, idx int, name string) (*string, error) {
	rows, err := cluster.Node(idx).Simple(
		"SELECT note, note IS NULL FROM live_typed_records WHERE name = '" + name + "'")
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 || len(rows[0]) < 2 || rows[0][1] == "1" {
		return nil, nil
	}
	note := rows[0][0]
	return &note, nil
}

// migrateUnlessAdopted applies the additive migration unless the column
// is already present. The ALTER runs inside the cr-sqlite
// begin/commit-alter protocol so the migrating node's triggers are
// rebuilt.
func migrateUnlessAdopted(cluster *goharness.Cluster, idx int) error {
	if hasColumn(cluster, idx, table, "note") {
		return nil
	}
	for _, sql := range []string{
		"SELECT crsql_begin_alter('" + table + "')",
		"ALTER TABLE " + table + " ADD COLUMN note TEXT",
		"SELECT crsql_commit_alter('" + table + "')",
	} {
		if _, err := cluster.Node(idx).Simple(sql); err != nil {
			return fmt.Errorf("migrate node%d %q: %w", idx+1, sql, err)
		}
	}
	if err := cluster.Node(idx).Flush(); err != nil {
		return fmt.Errorf("flush migration on node%d: %w", idx+1, err)
	}
	return nil
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

// waitConverged waits until every node holds exactly want.
func waitConverged(cluster *goharness.Cluster, want []string, timeout time.Duration) error {
	converged := goharness.WaitUntil(timeout, poll, func() bool {
		for i := 0; i < cluster.Len(); i++ {
			got, err := names(cluster, i)
			if err != nil || !equalStrings(got, want) {
				return false
			}
		}
		return true
	})
	if !converged {
		return fmt.Errorf("nodes did not converge on %d managed record names within %v", len(want), timeout)
	}
	return nil
}

// waitEpoch waits until the listed nodes adopt want.
func waitEpoch(cluster *goharness.Cluster, nodes []int, want uint64, timeout time.Duration) error {
	converged := goharness.WaitUntil(timeout, poll, func() bool {
		for _, i := range nodes {
			if epoch(cluster, i) != want {
				return false
			}
		}
		return true
	})
	if !converged {
		return fmt.Errorf("nodes %v did not adopt schema epoch %d within %v", nodes, want, timeout)
	}
	return nil
}

// isolateNode0 restarts node 0 with an allow-list containing only its
// own identity, refusing sessions in both directions. Peers keep their
// mesh.
func isolateNode0(t *testing.T, cluster *goharness.Cluster) {
	t.Helper()
	if err := cluster.StopNode(0); err != nil {
		t.Fatalf("stop node 0: %v", err)
	}
	allow := fmt.Sprintf(`["%s"]`, cluster.NodeID(0))
	if _, err := cluster.Node(0).Simple(
		"INSERT INTO murmur_config(name,value) VALUES('allowed_peers','" + allow +
			"') ON CONFLICT(name) DO UPDATE SET value=excluded.value"); err != nil {
		t.Fatalf("node 0 isolate: %v", err)
	}
	if err := cluster.StartNode(0); err != nil {
		t.Fatalf("restart node 0: %v", err)
	}
}

// rejoinNode0 clears node 0's allow-list, restarts it, and remeshes.
func rejoinNode0(t *testing.T, cluster *goharness.Cluster) {
	t.Helper()
	if err := cluster.StopNode(0); err != nil {
		t.Fatalf("stop node 0: %v", err)
	}
	if _, err := cluster.Node(0).Simple(
		"DELETE FROM murmur_config WHERE name='allowed_peers'"); err != nil {
		t.Fatalf("node 0 clear allow-list: %v", err)
	}
	if err := cluster.StartNode(0); err != nil {
		t.Fatalf("restart node 0: %v", err)
	}
	if err := cluster.PeerMesh(); err != nil {
		t.Fatalf("remesh: %v", err)
	}
}

// runSchemaCrashCase is one crash-boundary case. When
// migrateBeforeRestart is false the isolated node stops before the
// store (recovery reopens at epoch 1 and retries); when true it
// stores the migration first (recovery reopens at epoch 2).
func runSchemaCrashCase(t *testing.T, phase string, migrateBeforeRestart bool) {
	t.Helper()
	cluster, err := goharness.NewCluster(goharness.ClusterOptions{
		Name:     "migration-crash-" + phase,
		NumNodes: 3,
	})
	if err != nil {
		t.Fatalf("cluster setup: %v", err)
	}
	failed := true
	defer func() { cluster.Finish(failed) }()
	if err := runBody(t, cluster, phase, migrateBeforeRestart); err != nil {
		t.Fatalf("scenario failed: %v", err)
	}
	failed = false
}

func runBody(t *testing.T, cluster *goharness.Cluster, phase string, migrateBeforeRestart bool) error {
	t.Helper()
	// Same base schema on every node, flagged replicated on each node.
	for i := 0; i < cluster.Len(); i++ {
		if _, err := cluster.Node(i).Simple(
			"CREATE TABLE IF NOT EXISTS live_typed_records(name TEXT PRIMARY KEY NOT NULL DEFAULT '', counter INTEGER NOT NULL DEFAULT 0)"); err != nil {
			return fmt.Errorf("migrate node%d: %w", i+1, err)
		}
	}
	for i := 0; i < cluster.Len(); i++ {
		if err := cluster.Node(i).SetTableReplicated(table, true); err != nil {
			return fmt.Errorf("node%d SET TABLE REPLICATED: %w", i+1, err)
		}
		if err := cluster.Node(i).Flush(); err != nil {
			return fmt.Errorf("node%d flush after SET TABLE: %w", i+1, err)
		}
	}

	// Seed on node 2, converge, all old.
	wantNames := make([]string, 0, seedRows)
	for i := 0; i < seedRows; i++ {
		name := fmt.Sprintf("seed-%02d", i)
		if err := insertRow(cluster, 1, name); err != nil {
			return err
		}
		wantNames = append(wantNames, name)
	}
	sort.Strings(wantNames)
	if err := waitConverged(cluster, wantNames, seedTimeout); err != nil {
		return err
	}
	for idx := 0; idx < cluster.Len(); idx++ {
		if err := assertEpoch(cluster, idx, 1); err != nil {
			return err
		}
	}

	// Isolate node 0; the restart enabling the allow-list doubles as
	// the crash stop/start for before-store. After-store isolates
	// first, migrates, then crashes again past the store.
	isolateNode0(t, cluster)
	if migrateBeforeRestart {
		if err := migrateUnlessAdopted(cluster, 0); err != nil {
			return err
		}
		if err := cluster.StopNode(0); err != nil {
			return fmt.Errorf("crash node 0: %w", err)
		}
		if err := cluster.StartNode(0); err != nil {
			return fmt.Errorf("restart node 0: %w", err)
		}
	}
	restartEpoch := uint64(1)
	if migrateBeforeRestart {
		restartEpoch = 2
	}
	if err := assertEpoch(cluster, 0, restartEpoch); err != nil {
		return err
	}
	for _, idx := range []int{1, 2} {
		if err := assertEpoch(cluster, idx, 1); err != nil {
			return err
		}
	}

	// Recovered rows readable before reconnect.
	got, err := names(cluster, 0)
	if err != nil {
		return err
	}
	if !equalStrings(got, wantNames) {
		return fmt.Errorf("recovered rows = %v, want %v", got, wantNames)
	}
	if restartEpoch == 1 {
		if err := migrateUnlessAdopted(cluster, 0); err != nil {
			return err
		}
	}
	if err := assertEpoch(cluster, 0, 2); err != nil {
		return err
	}
	if note, err := tryReadNote(cluster, 0, wantNames[0]); err != nil {
		return err
	} else if note != nil {
		return fmt.Errorf("new field after local recovery = %q; want empty (NULL) default", *note)
	}

	// Rejoin and converge.
	rejoinNode0(t, cluster)
	if err := waitConverged(cluster, wantNames, rejoinTimeout); err != nil {
		return err
	}
	if err := waitEpoch(cluster, []int{1, 2}, 2, epochTimeout); err != nil {
		return err
	}
	for _, idx := range []int{1, 2} {
		if err := migrateUnlessAdopted(cluster, idx); err != nil {
			return err
		}
		if !hasColumn(cluster, idx, table, "note") {
			return fmt.Errorf("node%d did not rebind to the adopted v2 schema", idx+1)
		}
	}

	// A migrated-field write converges with both peers at epoch 2.
	if err := setNote(cluster, 0, wantNames[0], phase+"-recovered"); err != nil {
		return err
	}
	wantNote := phase + "-recovered"
	deadline := time.Now().Add(finalTimeout)
	converged := false
	var lastState string
	for {
		var states []string
		ready := true
		for idx := 0; idx < cluster.Len(); idx++ {
			ep := epoch(cluster, idx)
			note, noteErr := tryReadNote(cluster, idx, wantNames[0])
			noteDesc := "<error>"
			if noteErr == nil {
				if note == nil {
					noteDesc = "<nil>"
				} else {
					noteDesc = *note
				}
			}
			states = append(states, fmt.Sprintf("node%d epoch=%d note=%s", idx+1, ep, noteDesc))
			noteOK := noteErr == nil && note != nil && *note == wantNote
			if ep != 2 || !noteOK {
				ready = false
			}
		}
		if ready {
			converged = true
			lastState = fmt.Sprintf("%v", states)
			break
		}
		if !time.Now().Before(deadline) {
			lastState = fmt.Sprintf("%v", states)
			break
		}
		time.Sleep(poll)
	}
	if !converged {
		return fmt.Errorf("schema epoch and migrated field did not converge after %s crash: %s",
			phase, lastState)
	}
	return nil
}

func TestMigratedPeerCrashBeforeStoreReopensAndConverges(t *testing.T) {
	goharness.SkipUnlessLive(t)
	runSchemaCrashCase(t, "before-store", false)
}

func TestMigratedPeerCrashAfterStoreReopensAndConverges(t *testing.T) {
	goharness.SkipUnlessLive(t)
	runSchemaCrashCase(t, "after-store", true)
}
