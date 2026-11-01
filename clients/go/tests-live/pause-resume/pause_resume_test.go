// Live scenario: node 2 is frozen with SIGSTOP while the survivors keep
// writing, then resumes with zero data loss and converging contents.
//
// Port of MURMUR-SQL pause-resume: three seed-meshed nodes take
// continuous writes on every node, node 2 freezes for 15-30 s while
// survivors keep acknowledging writes, the freeze must be detected (the
// frozen peer goes suspect/dead or its session drops), the frozen member
// must not be evicted, catch-up must arrive over the log path, and a
// post-resume write replicates everywhere.
//
// Nodes are native replication drivers over VFS stores; the frozen node
// runs as a child process (ChildSet) so the freeze is a true process
// freeze: SIGSTOP/SIGCONT on the child, whose PID is discovered via
// /proc (linux only). Peer/member assertions use the decoded SHOW PEERS
// rows (per-peer connected/state; the rows persist through the freeze,
// so the alive-view dip is the frozen row leaving "alive") and the
// log-path proof sums per-origin applied counters over non-self origins
// (local commits move the own-origin row on this stack, so the frozen
// node's own row is excluded). Writers skip the per-write flush in the
// hot loop (the graceful-shutdown precedent: committed state ships on
// the engine tick) and flush at phase boundaries.
//
// Env-gated like the reference: SKIPs on Windows, where process suspend
// needs signals that do not exist, and off linux, where PID discovery
// has no /proc.
package pauseresume

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	goharness "github.com/marcgauthier/libmurmur/clients/go/tests-live/goharness"
)

// Table DDL (cr-sqlite form: NOT NULL primary key, DEFAULT on every
// NOT NULL column; only names matter here).
const tableDDL = "CREATE TABLE live_typed_records(name TEXT NOT NULL PRIMARY KEY DEFAULT '')"

// Frozen node (node 2).
const frozen = 1

// Freeze-window knob (`MURMUR_PAUSE_RESUME_STOP_SECONDS`, default 20,
// 15 s floor).
const (
	stopEnv        = "MURMUR_PAUSE_RESUME_STOP_SECONDS"
	defaultStopSec = 20
	minStopSec     = 15
)

// Baseline rows (5).
const baselineRows = 5

// Writer cadence (25 ms ticker on every node).
const writeTick = 25 * time.Millisecond

// In-flight drain before freezing (300 ms).
const drain = 300 * time.Millisecond

// Pre-roll before the freeze (2 s).
const preRoll = 2 * time.Second

// Mesh waits (60 s peers + membership, 30 s baseline converge).
const (
	meshTimeout     = 60 * time.Second
	baselineTimeout = 30 * time.Second
)

// Freeze-detection sample cadence (1 s).
const sampleTick = time.Second

// Post-resume convergence bound (180 s).
const convergeTimeout = 180 * time.Second

// Re-admission waits (90 s sessions + membership).
const readmitTimeout = 90 * time.Second

// Post-resume convergence (60 s).
const postTimeout = 60 * time.Second

// Convergence poll interval (200 ms).
const poll = 200 * time.Millisecond

// Membership/session poll interval (250 ms).
const memberPoll = 250 * time.Millisecond

// names returns the canonical ordered names on one node.
func names(cluster *goharness.Cluster, idx int) ([]string, error) {
	rows, err := cluster.Node(idx).Simple("SELECT name FROM live_typed_records ORDER BY name")
	if err != nil {
		return nil, fmt.Errorf("node%d read names: %w", idx+1, err)
	}
	out := make([]string, 0, len(rows))
	for _, row := range rows {
		if len(row) == 0 {
			continue
		}
		out = append(out, row[0])
	}
	return out, nil
}

// tryInsert is a best-effort insert; it reports true when acknowledged.
func tryInsert(cluster *goharness.Cluster, idx int, name string) bool {
	_, err := cluster.Node(idx).Execute("INSERT INTO live_typed_records(name) VALUES($1)", name)
	return err == nil
}

// peerCount returns the live session count to other nodes (connected
// non-self peer rows).
func peerCount(cluster *goharness.Cluster, node int) (uint64, error) {
	peers, err := cluster.Node(node).ShowPeers()
	if err != nil {
		return 0, fmt.Errorf("node%d SHOW PEERS: %w", node+1, err)
	}
	self := cluster.NodeID(node)
	var n uint64
	for _, p := range peers {
		if p.NodeID != self && p.Connected {
			n++
		}
	}
	return n, nil
}

// alivePeers returns the alive-member count excluding self (alive
// non-self peer rows).
func alivePeers(cluster *goharness.Cluster, node int) (uint64, error) {
	peers, err := cluster.Node(node).ShowPeers()
	if err != nil {
		return 0, fmt.Errorf("node%d SHOW PEERS: %w", node+1, err)
	}
	self := cluster.NodeID(node)
	var n uint64
	for _, p := range peers {
		if p.NodeID != self && p.State == "alive" {
			n++
		}
	}
	return n, nil
}

// appliedRemote returns cumulative log-applied transactions from remote
// origins on one node: the sum of per-origin applied counters excluding
// the node's own origin. Local commits move the own-origin row on this
// stack (unlike the reference wire counter), so it is excluded; the
// frozen node's writer is paused while frozen, and snapshot application
// bypasses the applied counter, so a post-resume delta proves log-path
// catch-up.
func appliedRemote(cluster *goharness.Cluster, node int) (uint64, error) {
	snap, err := cluster.Node(node).ShowReplication()
	if err != nil {
		return 0, fmt.Errorf("node%d SHOW REPLICATION: %w", node+1, err)
	}
	rows, ok := snap.([]any)
	if !ok {
		return 0, fmt.Errorf("node%d SHOW REPLICATION: unexpected shape %T", node+1, snap)
	}
	self := strings.ToLower(cluster.NodeID(node))
	var total uint64
	for _, r := range rows {
		m, ok := r.(map[string]any)
		if !ok {
			continue
		}
		origin, _ := m["origin"].(string)
		if strings.ToLower(origin) == self {
			continue
		}
		v, ok := m["applied"].(float64)
		if !ok {
			return 0, fmt.Errorf("node%d SHOW REPLICATION: no applied counter", node+1)
		}
		total += uint64(v)
	}
	return total, nil
}

// frozenView reports how one survivor currently sees the frozen peer:
// (row_present, connected, alive).
func frozenView(cluster *goharness.Cluster, idx int, frozenHex string) (present, connected, alive bool, err error) {
	peers, err := cluster.Node(idx).ShowPeers()
	if err != nil {
		return false, false, false, fmt.Errorf("node%d SHOW PEERS: %w", idx+1, err)
	}
	for _, p := range peers {
		if p.NodeID == frozenHex {
			return true, p.Connected, p.State == "alive", nil
		}
	}
	return false, false, false, nil
}

// waitConnectedPeers waits until every node reports `want` live sessions.
func waitConnectedPeers(cluster *goharness.Cluster, want uint64, timeout time.Duration) error {
	converged := goharness.WaitUntil(timeout, memberPoll, func() bool {
		for i := 0; i < cluster.Len(); i++ {
			n, err := peerCount(cluster, i)
			if err != nil || n != want {
				return false
			}
		}
		return true
	})
	if !converged {
		return fmt.Errorf("nodes did not reach %d connected peers within %v", want, timeout)
	}
	return nil
}

// waitAllAlive waits until every node sees `want` alive members
// (excl. self).
func waitAllAlive(cluster *goharness.Cluster, want uint64, timeout time.Duration) error {
	converged := goharness.WaitUntil(timeout, memberPoll, func() bool {
		for i := 0; i < cluster.Len(); i++ {
			n, err := alivePeers(cluster, i)
			if err != nil || n != want {
				return false
			}
		}
		return true
	})
	if !converged {
		return fmt.Errorf("nodes did not reach alive membership %d (excl. self) within %v", want, timeout)
	}
	return nil
}

// waitConverged polls exact counts plus ordered-name equality.
func waitConverged(cluster *goharness.Cluster, want int, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		var first []string
		hasFirst := false
		ok := true
		for i := 0; i < cluster.Len(); i++ {
			got, err := names(cluster, i)
			if err != nil || len(got) != want {
				ok = false
				break
			}
			if !hasFirst {
				first, hasFirst = got, true
			} else if !equalStrings(first, got) {
				ok = false
				break
			}
		}
		if ok {
			return nil
		}
		if !time.Now().Before(deadline) {
			for i := 0; i < cluster.Len(); i++ {
				n := -1
				if got, err := names(cluster, i); err == nil {
					n = len(got)
				}
				fmt.Fprintf(os.Stderr, "node%d at timeout: count=%d\n", i+1, n)
			}
			return fmt.Errorf("nodes did not converge on %d records with equal contents within %v",
				want, timeout)
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

// acknowledgedSet is the mutex-guarded set of acknowledged writes.
type acknowledgedSet struct {
	mu sync.Mutex
	m  map[string]bool
}

func (s *acknowledgedSet) add(value string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[value] = true
}

func (s *acknowledgedSet) len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.m)
}

func (s *acknowledgedSet) snapshot() map[string]bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]bool, len(s.m))
	for k, v := range s.m {
		out[k] = v
	}
	return out
}

// assertAcknowledgedPresent requires every acknowledged value present on
// every node.
func assertAcknowledgedPresent(cluster *goharness.Cluster, acknowledged map[string]bool) error {
	for i := 0; i < cluster.Len(); i++ {
		got, err := names(cluster, i)
		if err != nil {
			return err
		}
		present := make(map[string]bool, len(got))
		for _, v := range got {
			present[v] = true
		}
		for value := range acknowledged {
			if !present[value] {
				return fmt.Errorf("node%d lost acknowledged write %q after resume", i+1, value)
			}
		}
	}
	return nil
}

// assertNoEviction proves the frozen member was not permanently evicted:
// every node holds a live session to both peers and the member view is
// full and alive again.
func assertNoEviction(cluster *goharness.Cluster) error {
	for i := 0; i < cluster.Len(); i++ {
		peers, err := cluster.Node(i).ShowPeers()
		if err != nil {
			return fmt.Errorf("node%d SHOW PEERS: %w", i+1, err)
		}
		self := cluster.NodeID(i)
		others := 0
		for _, p := range peers {
			if p.NodeID == self {
				continue
			}
			others++
			if !p.Connected {
				return fmt.Errorf("node%d peer %q not connected after resume (evicted?)", i+1, p.NodeID)
			}
			if p.State != "alive" {
				return fmt.Errorf("node%d peer %q state %q after resume (evicted?)", i+1, p.NodeID, p.State)
			}
		}
		if others != 2 {
			return fmt.Errorf("node%d sees %d peers, want 2 (a peer was evicted)", i+1, others)
		}
		members, err := alivePeers(cluster, i)
		if err != nil {
			return err
		}
		if members != 2 {
			return fmt.Errorf("node%d alive members = %d, want 2 (frozen member never re-admitted)", i+1, members)
		}
	}
	return nil
}

// findChildPID discovers the child-process node behind nodeDir by
// scanning /proc for the `--dir <nodeDir>` argv pair (linux only).
func findChildPID(nodeDir string) (int, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return 0, fmt.Errorf("read /proc: %w", err)
	}
	self := os.Getpid()
	var found []int
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid == self {
			continue
		}
		raw, err := os.ReadFile(filepath.Join("/proc", e.Name(), "cmdline"))
		if err != nil {
			continue
		}
		args := bytes.Split(raw, []byte{0})
		for i := 0; i+1 < len(args); i++ {
			if string(args[i]) == "--dir" && string(args[i+1]) == nodeDir {
				found = append(found, pid)
				break
			}
		}
	}
	if len(found) != 1 {
		return 0, fmt.Errorf("found %d processes for node dir %s, want 1", len(found), nodeDir)
	}
	return found[0], nil
}

// procState reports the single-letter /proc state of pid.
func procState(pid int) (string, error) {
	raw, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat"))
	if err != nil {
		return "", err
	}
	// stat is "pid (comm) state ..."; comm may contain parens/spaces.
	idx := bytes.LastIndexByte(raw, ')')
	if idx < 0 || idx+2 >= len(raw) {
		return "", fmt.Errorf("unparseable stat for pid %d", pid)
	}
	return string(raw[idx+2]), nil
}

// waitProcState polls until pid reaches (or leaves, when want=false)
// the stopped state.
func waitProcState(pid int, stopped bool, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		st, err := procState(pid)
		if err != nil {
			return fmt.Errorf("stat pid %d: %w", pid, err)
		}
		isStopped := st == "T" || st == "t"
		if isStopped == stopped {
			return nil
		}
		if !time.Now().Before(deadline) {
			return fmt.Errorf("pid %d state %q, want stopped=%v", pid, st, stopped)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// suspendNode freezes the child-process node with SIGSTOP.
func suspendNode(cluster *goharness.Cluster, idx int) error {
	pid, err := findChildPID(cluster.Node(idx).Dir)
	if err != nil {
		return fmt.Errorf("discover node%d child pid: %w", idx+1, err)
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		return fmt.Errorf("find node%d pid %d: %w", idx+1, pid, err)
	}
	if err := proc.Signal(syscall.SIGSTOP); err != nil {
		return fmt.Errorf("SIGSTOP node%d pid %d: %w", idx+1, pid, err)
	}
	if err := waitProcState(pid, true, 5*time.Second); err != nil {
		return fmt.Errorf("node%d did not stop: %w", idx+1, err)
	}
	return nil
}

// resumeNode thaws the child-process node with SIGCONT.
func resumeNode(cluster *goharness.Cluster, idx int) error {
	pid, err := findChildPID(cluster.Node(idx).Dir)
	if err != nil {
		return fmt.Errorf("discover node%d child pid: %w", idx+1, err)
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		return fmt.Errorf("find node%d pid %d: %w", idx+1, pid, err)
	}
	if err := proc.Signal(syscall.SIGCONT); err != nil {
		return fmt.Errorf("SIGCONT node%d pid %d: %w", idx+1, pid, err)
	}
	if err := waitProcState(pid, false, 5*time.Second); err != nil {
		return fmt.Errorf("node%d did not resume: %w", idx+1, err)
	}
	return nil
}

// writer runs one continuous writer. The frozen node's writer pauses
// while it is suspended (a frozen node accepts nothing by definition).
func writer(cluster *goharness.Cluster, node int, acknowledged *acknowledgedSet, paused, stop *atomic.Bool, seq *atomic.Int64) {
	for {
		time.Sleep(writeTick)
		if stop.Load() {
			return
		}
		if paused.Load() {
			continue
		}
		n := seq.Add(1)
		value := fmt.Sprintf("flow-n%d-%08d", node+1, n)
		if tryInsert(cluster, node, value) {
			acknowledged.add(value)
		}
	}
}

func runBody(cluster *goharness.Cluster, stopSecs uint64) error {
	// Same schema on every node, flagged replicated on each node (row
	// convergence needs the per-node flag).
	for i := 0; i < cluster.Len(); i++ {
		if _, err := cluster.Node(i).Simple(tableDDL); err != nil {
			return fmt.Errorf("migrate node%d: %w", i+1, err)
		}
	}
	for i := 0; i < cluster.Len(); i++ {
		if err := cluster.Node(i).SetTableReplicated("live_typed_records", true); err != nil {
			return fmt.Errorf("node%d SET TABLE REPLICATED: %w", i+1, err)
		}
		if err := cluster.Node(i).Flush(); err != nil {
			return fmt.Errorf("node%d flush after SET TABLE: %w", i+1, err)
		}
	}
	if err := cluster.PeerMesh(); err != nil {
		return fmt.Errorf("mesh peers: %w", err)
	}

	// Positive control baseline: full mesh (sessions + membership).
	if err := waitConnectedPeers(cluster, 2, meshTimeout); err != nil {
		return err
	}
	if err := waitAllAlive(cluster, 2, meshTimeout); err != nil {
		return err
	}
	for i := 0; i < baselineRows; i++ {
		if !tryInsert(cluster, 0, fmt.Sprintf("base-%d", i)) {
			return fmt.Errorf("baseline write failed")
		}
		if err := cluster.Node(0).Flush(); err != nil {
			return fmt.Errorf("flush baseline: %w", err)
		}
	}
	if err := waitConverged(cluster, baselineRows, baselineTimeout); err != nil {
		return err
	}

	acknowledged := &acknowledgedSet{m: map[string]bool{
		"base-0": true, "base-1": true, "base-2": true, "base-3": true, "base-4": true,
	}}
	appliedBefore, err := appliedRemote(cluster, frozen)
	if err != nil {
		return err
	}
	frozenHex := cluster.NodeID(frozen)

	var paused [3]atomic.Bool
	var stop atomic.Bool
	var seqs [3]atomic.Int64

	// The driver sets `stop` on every exit path so a failed phase cannot
	// hang the join.
	driver := func() error {
		result := func() error {
			time.Sleep(preRoll)

			// Freeze node 2 mid-replication: the process stops cold.
			paused[frozen].Store(true)
			time.Sleep(drain) // drain in-flight requests first
			for i := 0; i < cluster.Len(); i++ {
				if err := cluster.Node(i).Flush(); err != nil {
					return fmt.Errorf("flush node%d before freeze: %w", i+1, err)
				}
			}
			ackedAtStop := acknowledged.len()
			fmt.Fprintf(os.Stderr, "freezing node2 with %d rows acknowledged so far\n", ackedAtStop)
			if err := suspendNode(cluster, frozen); err != nil {
				return fmt.Errorf("suspend node2: %w", err)
			}

			// While frozen: survivors keep writing; sample the alive view
			// from the outside. Healthy reads 2 (excludes self); detection
			// of the frozen member may dip survivors below 2, move the
			// frozen row out of "alive" (suspect/dead), or drop its
			// session.
			minAlive := uint64(2)
			sawNotAlive := false
			sawDisconnected := false
			sampleEnd := time.Now().Add(time.Duration(stopSecs) * time.Second)
			for time.Now().Before(sampleEnd) {
				for _, idx := range []int{0, 2} {
					if m, err := alivePeers(cluster, idx); err == nil && m < minAlive {
						minAlive = m
					}
					if present, connected, alive, err := frozenView(cluster, idx, frozenHex); err == nil {
						if !alive {
							sawNotAlive = true
						}
						if !present || !connected {
							sawDisconnected = true
						}
					}
				}
				time.Sleep(sampleTick)
			}
			ackedDuringPause := acknowledged.len() - ackedAtStop
			fmt.Fprintf(os.Stderr,
				"during %ds freeze: minAlivePeers=%d notAlive=%v disconnected=%v ackedDuringPause=%d\n",
				stopSecs, minAlive, sawNotAlive, sawDisconnected, ackedDuringPause)
			// Freeze detection proof: survivors must notice the frozen
			// member. Without this, broken probing would pass silently.
			// (The decoded peer rows carry no last-seenMillis stamp, so
			// suspect/dead state and session state take the place of the
			// reference's staleness leg.)
			if !(minAlive < 2 || sawNotAlive || sawDisconnected) {
				return fmt.Errorf("freeze undetected: survivors kept alive=%d with a fresh connected peer view during %ds (probing ineffective?)",
					minAlive, stopSecs)
			}
			if ackedDuringPause == 0 {
				return fmt.Errorf("no writes acknowledged while node2 was frozen; pause proved nothing")
			}

			// Resume and prove streams come back.
			if err := resumeNode(cluster, frozen); err != nil {
				return fmt.Errorf("resume node2: %w", err)
			}
			// Health: the node answers reads immediately.
			resumeStart := time.Now()
			if _, err := names(cluster, frozen); err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "node2 healthy %v after resume\n", time.Since(resumeStart))
			// Sessions re-establish over the reopened path (explicit
			// re-mesh: the freeze killed the QUIC sessions and there is
			// no auto-redial).
			if err := cluster.PeerMesh(); err != nil {
				return fmt.Errorf("re-mesh after resume: %w", err)
			}
			paused[frozen].Store(false)
			return nil
		}()
		stop.Store(true)
		return result
	}
	var wg sync.WaitGroup
	var driverErr error
	wg.Add(4)
	for node := 0; node < 3; node++ {
		go func(node int) {
			defer wg.Done()
			writer(cluster, node, acknowledged, &paused[node], &stop, &seqs[node])
		}(node)
	}
	go func() {
		defer wg.Done()
		driverErr = driver()
	}()
	wg.Wait()
	if driverErr != nil {
		return driverErr
	}

	total := acknowledged.len()
	// 180 s bound (post-resume range-repair normally lands fast, but the
	// reference keeps 180 s for cold page cache).
	if err := waitConverged(cluster, total, convergeTimeout); err != nil {
		return err
	}
	if err := assertAcknowledgedPresent(cluster, acknowledged.snapshot()); err != nil {
		return err
	}

	// Sessions resumed on every link; membership re-admitted the member.
	if err := waitConnectedPeers(cluster, 2, readmitTimeout); err != nil {
		return err
	}
	if err := waitAllAlive(cluster, 2, readmitTimeout); err != nil {
		return err
	}
	if err := assertNoEviction(cluster); err != nil {
		return err
	}

	// Record the rejoin path: with default retention the log still holds
	// everything, so catch-up must arrive over the log path (remote
	// applied advances; a snapshot here would mean ranges vanished early,
	// and snapshot application bypasses the applied counter while the
	// frozen writer's pause keeps local commits out of the remote sum).
	appliedAfter, err := appliedRemote(cluster, frozen)
	if err != nil {
		return err
	}
	if appliedAfter <= appliedBefore {
		return fmt.Errorf("node2 rejoined with no log-path apply (applied %d->%d); catch-up path unproven",
			appliedBefore, appliedAfter)
	}
	fmt.Fprintf(os.Stderr, "node2 rejoin path: log apply (applied %d->%d)\n", appliedBefore, appliedAfter)

	// Post-resume honest write still replicates everywhere.
	if !tryInsert(cluster, frozen, "post-resume") {
		return fmt.Errorf("post-resume write failed")
	}
	if err := cluster.Node(frozen).Flush(); err != nil {
		return fmt.Errorf("flush post-resume: %w", err)
	}
	acknowledged.add("post-resume")
	total = acknowledged.len()
	if err := waitConverged(cluster, total, postTimeout); err != nil {
		return err
	}
	if err := assertAcknowledgedPresent(cluster, acknowledged.snapshot()); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "pause/resume proven: %ds freeze, %d rows intact, contents converge\n", stopSecs, total)
	return nil
}

func TestPauseResumeLosesNoWrites(t *testing.T) {
	goharness.SkipUnlessLive(t)
	if runtime.GOOS == "windows" {
		t.Skip("pause-resume needs unix signals (SIGSTOP/SIGCONT) to freeze a node")
	}
	if runtime.GOOS != "linux" {
		t.Skip("harness: child suspend needs SIGSTOP with /proc discovery (linux only)")
	}
	if os.Getenv("MURMUR_NODE_BIN") == "" {
		if _, err := exec.LookPath("murmur-test-node"); err != nil {
			t.Fatal("pause-resume freezes a child-process node: go build -o /tmp/murmur-test-node ./tests-live/node and set MURMUR_NODE_BIN=/tmp/murmur-test-node")
		}
	}
	stopSecs := uint64(goharness.EnvSeconds(stopEnv, defaultStopSec) / time.Second)
	if stopSecs < minStopSec {
		fmt.Fprintf(os.Stderr, "stop window %ds below the 15s floor; using 15s\n", stopSecs)
		stopSecs = minStopSec
	}

	cluster, err := goharness.NewCluster(goharness.ClusterOptions{
		Name:     "pause-resume",
		NumNodes: 3,
		ChildSet: map[int]bool{frozen: true},
	})
	if err != nil {
		t.Fatalf("cluster setup: %v", err)
	}
	if cluster.Len() != 3 {
		t.Fatalf("this scenario is written for 3 nodes, got %d", cluster.Len())
	}
	for i := 0; i < cluster.Len(); i++ {
		fmt.Fprintf(os.Stderr, "node%d dir=%s\n", i, cluster.Node(i).Dir)
	}
	failed := true
	defer func() { cluster.Finish(failed) }()
	if err := runBody(cluster, stopSecs); err != nil {
		fmt.Fprintf(os.Stderr, "scenario failed: %v\n", err)
		t.Fatalf("scenario failed: %v", err)
	}
	failed = false
}
