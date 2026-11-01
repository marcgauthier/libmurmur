// Live scenario: version churn under aggressive log retention converges
// with no loss, and GC collects at least 90% of what a measurement
// window produced.
//
// Port of MURMUR-SQL gc-balance: three nodes mesh with aggressive log
// retention (minimum retained 10, maximum offline 20 s) while one node
// updates a fixed 200-key set with eight parallel updaters over disjoint
// ranges. The portable legs run in TestGCChurnConvergesLosslessly: seed,
// paced churn with zero update errors and at least 5 full sweeps per
// updater, end-to-end churned-value flow, exact row counts, and identical
// contents on all nodes (no loss). TestLogGCKeepsUpWithChurn adds the
// balance proof: commits produced map to node 0's own-origin applied
// head, collected maps to the health retention.collected_transactions
// counter, and the drain drives on-demand Node.RetentionCollect.
// Scope (same as the reference): version churn only; deletes are out
// of scope.
package gcbalance

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	goharness "github.com/marcgauthier/libmurmur/clients/go/tests-live/goharness"
)

const (
	// keys is the fixed working set (200).
	keys = 200
	// updaters is the parallel updater count over disjoint ranges (8).
	updaters = 8
	// minSweeps is the minimum full sweeps per updater (5).
	minSweeps uint64 = 5
	// updaterPace paces churn ops (140 ms, reference value).
	updaterPace = 140 * time.Millisecond
	// countsTimeout bounds row-count convergence (60 s).
	countsTimeout = 60 * time.Second
	// digestTimeout bounds digest agreement (60 s).
	digestTimeout = 60 * time.Second
	// valueTimeout bounds churned-value flow (30 s).
	valueTimeout = 30 * time.Second
	// pollInterval is the convergence poll interval (200 ms).
	pollInterval = 200 * time.Millisecond
	// updaterCap guards updater goroutines if the driver fails before
	// signalling stop (600 s).
	updaterCap = 600 * time.Second
	// defaultChurnSecs is the default churn phase length (30 s).
	defaultChurnSecs = 30
)

// contentionRow is one application row.
type contentionRow struct {
	id    string
	name  string
	phone string
	score int64
}

// keyID renders a 1-based 32-hex-char key.
func keyID(i int) string {
	return fmt.Sprintf("%032x", i+1)
}

// churnDuration reads the churn phase length override.
func churnDuration() time.Duration {
	return goharness.EnvSeconds("MURMUR_GC_BALANCE_CHURN_SECONDS", defaultChurnSecs)
}

// insertSeed runs a seed insert on node 0 (name v-0; phone/score keep
// their zero values).
func insertSeed(cluster *goharness.Cluster, id, name string) error {
	if _, err := cluster.Node(0).Execute(
		"INSERT INTO contention(id, name, phone, score) VALUES($1, $2, $3, $4)", id, name, "", int64(0)); err != nil {
		return fmt.Errorf("seed insert failed: %w", err)
	}
	if err := cluster.Node(0).Flush(); err != nil {
		return fmt.Errorf("flush after seed insert: %w", err)
	}
	return nil
}

// tryUpdateName churns one update: set name and publish to replication.
// Errors are returned (and counted by the caller) instead of failing,
// so one bad op cannot kill an updater.
func tryUpdateName(cluster *goharness.Cluster, id, name string) error {
	changed, err := cluster.Node(0).Execute("UPDATE contention SET name = $1 WHERE id = $2", name, id)
	if err != nil {
		return err
	}
	if changed != 1 {
		return fmt.Errorf("update hit %d rows", changed)
	}
	if err := cluster.Node(0).Flush(); err != nil {
		return err
	}
	return nil
}

// readName reads one row on one node: ("", false) when absent.
func readName(cluster *goharness.Cluster, idx int, id string) (string, bool, error) {
	rows, err := cluster.Node(idx).Simple("SELECT name FROM contention WHERE id = " + goharness.SQLLiteral(id))
	if err != nil {
		return "", false, fmt.Errorf("node%d read row failed: %w", idx+1, err)
	}
	if len(rows) == 0 {
		return "", false, nil
	}
	return rows[0][0], true, nil
}

// allRows returns canonical PK-ordered rows on one node (compared
// directly instead of hashing).
func allRows(cluster *goharness.Cluster, idx int) ([]contentionRow, error) {
	rows, err := cluster.Node(idx).Simple("SELECT id, name, phone, score FROM contention ORDER BY id")
	if err != nil {
		return nil, fmt.Errorf("node%d read all rows failed: %w", idx+1, err)
	}
	out := make([]contentionRow, 0, len(rows))
	for _, row := range rows {
		if len(row) != 4 {
			return nil, fmt.Errorf("node%d row has %d columns, want 4", idx+1, len(row))
		}
		var score int64
		if _, err := fmt.Sscanf(row[3], "%d", &score); err != nil {
			return nil, fmt.Errorf("node%d decode score %q: %w", idx+1, row[3], err)
		}
		out = append(out, contentionRow{id: row[0], name: row[1], phone: row[2], score: score})
	}
	return out, nil
}

// waitAllCounts waits until every node holds exactly want rows.
func waitAllCounts(cluster *goharness.Cluster, want int, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	last := make([]string, cluster.Len())
	for {
		converged := true
		for i := 0; i < cluster.Len(); i++ {
			rows, err := allRows(cluster, i)
			if err != nil {
				return err
			}
			count := len(rows)
			last[i] = fmt.Sprintf("count=%d", count)
			if count != want {
				converged = false
				break
			}
		}
		if converged {
			return nil
		}
		if !time.Now().Before(deadline) {
			return fmt.Errorf("counts did not reach %d within %v; last=%v", want, timeout, last)
		}
		time.Sleep(pollInterval)
	}
}

// waitDigestsAgreed polls until every node reports the same table
// contents.
func waitDigestsAgreed(cluster *goharness.Cluster, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		want, err := allRows(cluster, 0)
		if err != nil {
			return err
		}
		agreed := true
		for i := 1; i < cluster.Len(); i++ {
			got, err := allRows(cluster, i)
			if err != nil {
				return err
			}
			if !equalRows(got, want) {
				agreed = false
				break
			}
		}
		if agreed {
			return nil
		}
		if !time.Now().Before(deadline) {
			return fmt.Errorf("digests did not agree within %v", timeout)
		}
		time.Sleep(pollInterval)
	}
}

// waitValueChanged polls followers until one reports a value other than
// seed for the given key, proving churned updates flow end to end.
func waitValueChanged(cluster *goharness.Cluster, id, seed string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		for i := 1; i < cluster.Len(); i++ {
			name, ok, err := readName(cluster, i, id)
			if err != nil {
				return err
			}
			if ok && name != seed {
				return nil
			}
		}
		if !time.Now().Before(deadline) {
			return fmt.Errorf("no follower observed a churned value for %s within %v (updates may not match)", id, timeout)
		}
		time.Sleep(pollInterval)
	}
}

// updater churns a disjoint key range: sequential sweeps until stopped
// is set.
func updater(cluster *goharness.Cluster, w int, stopped *atomic.Bool, updateErrs, updates *atomic.Uint64, sweeps *atomic.Uint64, wg *sync.WaitGroup) {
	defer wg.Done()
	updaterDeadline := time.Now().Add(updaterCap)
	var round uint64 = 1
	lo := w * keys / updaters
	hi := lo + keys/updaters
	for !stopped.Load() && time.Now().Before(updaterDeadline) {
		for i := lo; i < hi; i++ {
			if stopped.Load() {
				break
			}
			if err := tryUpdateName(cluster, keyID(i), fmt.Sprintf("v-%d-%d", w, round)); err != nil {
				fmt.Fprintf(os.Stderr, "updater %d key %d: %v\n", w, i, err)
				updateErrs.Add(1)
			} else {
				updates.Add(1)
			}
			time.Sleep(updaterPace)
		}
		sweeps.Store(round)
		round++
	}
}

func runBody(cluster *goharness.Cluster, churn time.Duration) error {
	// Same schema on every node, then replicate it: convergence needs
	// the per-table flag on each node.
	for i := 0; i < cluster.Len(); i++ {
		if _, err := cluster.Node(i).Simple(
			"CREATE TABLE IF NOT EXISTS contention(id TEXT PRIMARY KEY NOT NULL DEFAULT '', name TEXT NOT NULL DEFAULT '', phone TEXT NOT NULL DEFAULT '', score INTEGER NOT NULL DEFAULT 0)"); err != nil {
			return fmt.Errorf("migrate node%d: %w", i+1, err)
		}
	}
	for i := 0; i < cluster.Len(); i++ {
		if err := cluster.Node(i).SetTableReplicated("contention", true); err != nil {
			return fmt.Errorf("node%d SET TABLE REPLICATED: %w", i+1, err)
		}
		if err := cluster.Node(i).Flush(); err != nil {
			return fmt.Errorf("node%d flush after SET TABLE: %w", i+1, err)
		}
	}
	if err := cluster.PeerMesh(); err != nil {
		return fmt.Errorf("mesh peers: %w", err)
	}

	for i := 0; i < keys; i++ {
		if err := insertSeed(cluster, keyID(i), "v-0"); err != nil {
			return err
		}
	}
	if err := waitAllCounts(cluster, keys, countsTimeout); err != nil {
		return err
	}

	var stopped atomic.Bool
	var updateErrs, updates atomic.Uint64
	var sweeps [updaters]atomic.Uint64

	// Eight updaters over disjoint key ranges. The driver sets stopped
	// on every exit path so a failed phase cannot hang the join.
	var wg sync.WaitGroup
	for w := 0; w < updaters; w++ {
		wg.Add(1)
		go updater(cluster, w, &stopped, &updateErrs, &updates, &sweeps[w], &wg)
	}
	time.Sleep(churn)
	stopped.Store(true)
	wg.Wait()

	if updateErrs.Load() != 0 {
		return fmt.Errorf("%d update errors during churn", updateErrs.Load())
	}
	var totalSweeps uint64
	for w := 0; w < updaters; w++ {
		got := sweeps[w].Load()
		totalSweeps += got
		if got < minSweeps {
			return fmt.Errorf("updater %d completed only %d sweeps, want >= %d for GC pressure", w, got, minSweeps)
		}
	}
	fmt.Fprintf(os.Stderr, "churn: %d updater sweeps (%d test-counted updates)\n",
		totalSweeps, updates.Load())

	// End-to-end update flow: a follower must observe a churned value.
	if err := waitValueChanged(cluster, keyID(0), "v-0", valueTimeout); err != nil {
		return err
	}

	// No data loss: exact key set with identical contents everywhere.
	if err := waitAllCounts(cluster, keys, countsTimeout); err != nil {
		return err
	}
	if err := waitDigestsAgreed(cluster, digestTimeout); err != nil {
		return err
	}
	want, err := allRows(cluster, 0)
	if err != nil {
		return err
	}
	for i := 1; i < cluster.Len(); i++ {
		digest, err := allRows(cluster, i)
		if err != nil {
			return err
		}
		if !equalRows(digest, want) {
			return fmt.Errorf("node%d contents differ after GC churn", i+1)
		}
	}
	return nil
}

// setRetention writes aggressive retention bounds (minimum_retained 10,
// maximum_offline 20 s, mirroring the reference replication config)
// and restarts replication so the bounds take effect.
func setRetention(t *testing.T, cluster *goharness.Cluster) {
	t.Helper()
	for i := 0; i < cluster.Len(); i++ {
		if err := cluster.StopNode(i); err != nil {
			t.Fatalf("stop node %d: %v", i, err)
		}
	}
	for i := 0; i < cluster.Len(); i++ {
		for _, kv := range [][2]string{
			{"retention_min_kept", "10"},
			{"retention_max_offline_ms", "20000"},
		} {
			if _, err := cluster.Node(i).Simple(
				"INSERT INTO murmur_config(name,value) VALUES('" + kv[0] + "','" + kv[1] +
					"') ON CONFLICT(name) DO UPDATE SET value=excluded.value"); err != nil {
				t.Fatalf("node %d set %s: %v", i, kv[0], err)
			}
		}
	}
	for i := 0; i < cluster.Len(); i++ {
		if err := cluster.StartNode(i); err != nil {
			t.Fatalf("start node %d: %v", i, err)
		}
	}
	if err := cluster.PeerMesh(); err != nil {
		t.Fatalf("remesh: %v", err)
	}
}

func TestGCChurnConvergesLosslessly(t *testing.T) {
	goharness.SkipUnlessLive(t)
	churn := churnDuration()
	cluster, err := goharness.NewCluster(goharness.ClusterOptions{
		Name:     "gc-balance",
		NumNodes: 3,
	})
	if err != nil {
		t.Fatalf("cluster setup: %v", err)
	}
	setRetention(t, cluster)
	result := runBody(cluster, churn)
	failed := result != nil
	if result != nil {
		fmt.Fprintf(os.Stderr, "scenario failed: %v\n", result)
	}
	cluster.Finish(failed)
	if failed {
		t.Fatal("scenario failed; artifacts retained under tests-live/failures/")
	}
}

// TestLogGCKeepsUpWithChurn is the reference's balance proof: after a
// warmup, a measurement window must show GC collecting at least 90% of
// the origin-log batches the window produced, with zero GC failures.
// Commits produced map to node 0's own-origin applied head (every
// update flushes, so every commit appends one origin-log batch);
// collected maps to the health retention.collected_transactions
// counter; the drain drives on-demand Node.RetentionCollect.
func TestLogGCKeepsUpWithChurn(t *testing.T) {
	goharness.SkipUnlessLive(t)
	cluster, err := goharness.NewCluster(goharness.ClusterOptions{
		Name:     "gc-balance-ratio",
		NumNodes: 3,
	})
	if err != nil {
		t.Fatalf("cluster setup: %v", err)
	}
	setRetention(t, cluster)
	failed := true
	defer func() { cluster.Finish(failed) }()
	if err := runBalanceBody(t, cluster); err != nil {
		t.Fatalf("scenario failed: %v", err)
	}
	failed = false
}

const (
	// balanceWarmup steadies the mesh before measurement (20 s).
	balanceWarmup = 20 * time.Second
	// balanceWindow is the measurement window (40 s).
	balanceWindow = 40 * time.Second
	// balanceStretchStep extends slow windows (5 s).
	balanceStretchStep = 5 * time.Second
	// balanceWindowCap caps window stretching (150 s).
	balanceWindowCap = 150 * time.Second
	// balanceCommitFloor is the minimum window commits for GC
	// pressure (2000).
	balanceCommitFloor uint64 = 2000
	// balanceDrainStable polls of stable collection end the drain (2).
	balanceDrainStable = 2
	// balanceDrainCap bounds the drain (120 s, scaled by slowdown).
	balanceDrainCap = 120 * time.Second
)

// gcSnapshot holds commit/GC balance counters sampled from node 0.
type gcSnapshot struct {
	// commits are local commits produced (node 0's own-origin
	// applied head).
	commits uint64
	// collected are origin-log transactions collected (durable
	// health counter).
	collected uint64
	// lastError is the latest replication-engine error, if any.
	lastError *string
}

// gcCounters samples the balance counters from node 0.
func gcCounters(cluster *goharness.Cluster) (gcSnapshot, error) {
	var zero gcSnapshot
	snap, err := cluster.Node(0).ShowReplication()
	if err != nil {
		return zero, fmt.Errorf("node1 SHOW REPLICATION: %w", err)
	}
	arr, ok := snap.([]any)
	if !ok {
		return zero, fmt.Errorf("node1 SHOW REPLICATION: unexpected shape %T", snap)
	}
	own := cluster.NodeID(0)
	var commits uint64
	found := false
	for _, e := range arr {
		m, ok := e.(map[string]any)
		if !ok {
			continue
		}
		origin, _ := m["origin"].(string)
		if !strings.EqualFold(origin, own) {
			continue
		}
		applied, ok := m["applied"].(float64)
		if !ok {
			return zero, fmt.Errorf("node1 SHOW REPLICATION: own origin has no applied head")
		}
		commits = uint64(applied)
		found = true
		break
	}
	if !found {
		return zero, fmt.Errorf("node1 SHOW REPLICATION: no own-origin head")
	}
	h, err := cluster.Node(0).ShowHealth()
	if err != nil {
		return zero, fmt.Errorf("node1 health: %w", err)
	}
	hm, ok := h.(map[string]any)
	if !ok {
		return zero, fmt.Errorf("node1 health is not an object")
	}
	ret, ok := hm["retention"].(map[string]any)
	if !ok {
		return zero, fmt.Errorf("node1 health has no retention block")
	}
	collected, ok := ret["collected_transactions"].(float64)
	if !ok {
		return zero, fmt.Errorf("node1 health has no collected counter")
	}
	var lastError *string
	if repl, ok := hm["replication"].(map[string]any); ok {
		if s, ok := repl["last_error"].(string); ok && s != "" {
			e := s
			lastError = &e
		}
	}
	return gcSnapshot{commits: commits, collected: uint64(collected), lastError: lastError}, nil
}

// isBalanceGCError reports whether an engine error string is
// GC-shaped (reference matcher).
func isBalanceGCError(err *string) bool {
	if err == nil {
		return false
	}
	e := strings.ToLower(*err)
	return strings.Contains(e, "retention") || strings.Contains(e, "collect") ||
		strings.Contains(e, "prune") || strings.Contains(e, "gc ") ||
		strings.Contains(e, "snapshot")
}

func saturatingSub(a, b uint64) uint64 {
	if a < b {
		return 0
	}
	return a - b
}

func runBalanceBody(t *testing.T, cluster *goharness.Cluster) error {
	t.Helper()
	for i := 0; i < cluster.Len(); i++ {
		if _, err := cluster.Node(i).Simple(
			"CREATE TABLE IF NOT EXISTS contention(id TEXT PRIMARY KEY NOT NULL DEFAULT '', name TEXT NOT NULL DEFAULT '', phone TEXT NOT NULL DEFAULT '', score INTEGER NOT NULL DEFAULT 0)"); err != nil {
			return fmt.Errorf("migrate node%d: %w", i+1, err)
		}
	}
	for i := 0; i < cluster.Len(); i++ {
		if err := cluster.Node(i).SetTableReplicated("contention", true); err != nil {
			return fmt.Errorf("node%d SET TABLE REPLICATED: %w", i+1, err)
		}
		if err := cluster.Node(i).Flush(); err != nil {
			return fmt.Errorf("node%d flush after SET TABLE: %w", i+1, err)
		}
	}
	if err := cluster.PeerMesh(); err != nil {
		return fmt.Errorf("mesh peers: %w", err)
	}

	for i := 0; i < keys; i++ {
		if err := insertSeed(cluster, keyID(i), "v-0"); err != nil {
			return err
		}
	}
	if err := waitAllCounts(cluster, keys, countsTimeout); err != nil {
		return err
	}

	var stopped atomic.Bool
	var updateErrs, updates atomic.Uint64
	var sweeps [updaters]atomic.Uint64
	var wg sync.WaitGroup
	for w := 0; w < updaters; w++ {
		wg.Add(1)
		go updater(cluster, w, &stopped, &updateErrs, &updates, &sweeps[w], &wg)
	}
	// Warm up to steady state, then measure one window: every commit
	// in the window appends an origin-log batch, so (commits -
	// collected) is the retained set's growth over the window.
	time.Sleep(balanceWarmup)
	before, err := gcCounters(cluster)
	if err != nil {
		stopped.Store(true)
		wg.Wait()
		return err
	}
	time.Sleep(balanceWindow)
	after, err := gcCounters(cluster)
	if err != nil {
		stopped.Store(true)
		wg.Wait()
		return err
	}
	elapsed := balanceWindow
	for after.commits-before.commits < balanceCommitFloor && elapsed < balanceWindowCap {
		time.Sleep(balanceStretchStep)
		elapsed += balanceStretchStep
		after, err = gcCounters(cluster)
		if err != nil {
			stopped.Store(true)
			wg.Wait()
			return err
		}
	}
	fmt.Fprintf(os.Stderr, "window commits=%d over the measurement period\n", after.commits-before.commits)
	stopped.Store(true)
	wg.Wait()

	// Drain: the window's tail stays uncollected until a GC pass runs
	// after the updaters stop. First flush everywhere so node 0's
	// retention floor advances past the final acks.
	for i := 0; i < cluster.Len(); i++ {
		if err := cluster.Node(i).Flush(); err != nil {
			return fmt.Errorf("node%d drain flush: %w", i+1, err)
		}
	}
	if err := waitDigestsAgreed(cluster, digestTimeout); err != nil {
		return err
	}
	slowdown := elapsed.Seconds() / balanceWindow.Seconds()
	if slowdown < 1.0 {
		slowdown = 1.0
	}
	drainDeadline := time.Now().Add(time.Duration(float64(balanceDrainCap) * slowdown))
	stable := 0
	for time.Now().Before(drainDeadline) {
		if _, _, err := cluster.Node(0).RetentionCollect(); err != nil {
			return fmt.Errorf("node1 drain collect: %w", err)
		}
		time.Sleep(500 * time.Millisecond)
		next, err := gcCounters(cluster)
		if err != nil {
			return err
		}
		commits := next.commits - before.commits
		collected := next.collected - before.collected
		if next.collected == after.collected {
			stable++
		} else {
			stable = 0
		}
		after = next
		if saturatingSub(commits, collected) <= commits/10 && stable >= balanceDrainStable {
			break
		}
		if stable >= 60 {
			return fmt.Errorf("collection stalled: %d/%d collected with no progress for 30s", collected, commits)
		}
	}

	if updateErrs.Load() != 0 {
		return fmt.Errorf("%d update errors during churn", updateErrs.Load())
	}
	var totalSweeps uint64
	for w := 0; w < updaters; w++ {
		got := sweeps[w].Load()
		totalSweeps += got
		if got < minSweeps {
			return fmt.Errorf("updater %d completed only %d sweeps, want >= %d for GC pressure", w, got, minSweeps)
		}
	}
	commits := after.commits - before.commits
	collected := after.collected - before.collected
	fmt.Fprintf(os.Stderr, "churn: %d updater sweeps (%d test-counted updates), %d commits produced, %d log batches collected\n",
		totalSweeps, updates.Load(), commits, collected)

	if commits < balanceCommitFloor {
		return fmt.Errorf("only %d commits in the window, want >= %d for GC pressure", commits, balanceCommitFloor)
	}
	if collected == 0 {
		return fmt.Errorf("no GC collection during the window; test cannot observe GC")
	}
	if !equalOptString(after.lastError, before.lastError) &&
		(isBalanceGCError(before.lastError) || isBalanceGCError(after.lastError)) {
		return fmt.Errorf("replication engine GC error during the window: before=%s after=%s",
			optString(before.lastError), optString(after.lastError))
	}
	if saturatingSub(commits, collected) > commits/10 {
		return fmt.Errorf("GC fell behind: produced %d commits but collected %d (retained grew by %d, want <= %d)",
			commits, collected, saturatingSub(commits, collected), commits/10)
	}

	if err := waitValueChanged(cluster, keyID(0), "v-0", valueTimeout); err != nil {
		return err
	}
	if err := waitAllCounts(cluster, keys, countsTimeout); err != nil {
		return err
	}
	if err := waitDigestsAgreed(cluster, digestTimeout); err != nil {
		return err
	}
	want, err := allRows(cluster, 0)
	if err != nil {
		return err
	}
	for i := 1; i < cluster.Len(); i++ {
		digest, err := allRows(cluster, i)
		if err != nil {
			return err
		}
		if !equalRows(digest, want) {
			return fmt.Errorf("node%d contents differ after GC churn", i+1)
		}
	}
	return nil
}

func equalOptString(a, b *string) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

func optString(s *string) string {
	if s == nil {
		return "None"
	}
	return strconv.Quote(*s)
}

func equalRows(a, b []contentionRow) bool {
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
