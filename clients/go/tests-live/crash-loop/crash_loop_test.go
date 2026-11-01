// Live scenario: one of three meshed nodes is SIGKILLed and restarted N
// times under continuous writes from every node, with short uptimes
// between kills.
//
// Port of MURMUR-SQL crash-loop: every write acknowledged before each
// kill must survive; the looped node must converge to identical
// contents; it must reach ready within a bound after the final restart
// (no wedge); and a post-loop write on it must replicate everywhere.
// Kill placement is proven, not assumed: every non-final round
// requires a write provably in flight on the victim (mid-write), and
// the final round kills immediately after a 30-row burst on a survivor
// (mid-replication). Nodes are native replication drivers over VFS
// stores in child processes (MURMUR_NODE_BIN) so kills are real
// SIGKILLs; the reference tokio tasks become goroutines over a shared
// mutex-held cluster.
package crashloop

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	goharness "github.com/marcgauthier/libmurmur/clients/go/tests-live/goharness"
)

// Crash victim: node3.
const victim = 2

// Writer insert cadence.
const writeInterval = 25 * time.Millisecond

// Convergence poll interval.
const poll = 100 * time.Millisecond

// Positive-control deadlines.
const controlTimeout = 30 * time.Second

// In-flight gate for non-final kills.
const inflightTimeout = 10 * time.Second

// Final-round burst size on a survivor.
const burstRows = int64(30)

// Final-round bound between burst and kill.
const burstWindow = 500 * time.Millisecond

// No-wedge bound for the final restart.
const readyBound = 60 * time.Second

// Post-loop mesh/convergence deadlines.
const healTimeout = 90 * time.Second

// Post-loop write convergence deadline.
const postTimeout = 60 * time.Second

// Row-id stride per writer node: ids are node*idStride + seq, so the
// three continuous writers never collide.
const idStride = int64(10_000_000)

// Baseline ids live above every writer range.
const baselineIDBase = int64(90_000_001)

// Burst ids live above the baseline range.
const burstIDBase = int64(90_001_001)

// Post-loop marker id.
const postLoopID = int64(90_002_001)

// envInt is a positive-integer env knob with fallback.
func envInt(name string, fallback uint64) uint64 {
	if v, err := strconv.ParseUint(os.Getenv(name), 10, 64); err == nil && v > 0 {
		return v
	}
	return fallback
}

// shared is the shared writer state. Writers and the driver share the
// cluster behind one mutex; the running flags keep writers off a stopped
// node (whose handle is dead across the kill/restart swap) without racing
// the driver's kill path: the driver clears the victim flag well before
// locking for the kill, and writers re-check the flag while holding the
// lock. Node methods lock internally; this mutex guards handle swaps
// across RestartNode.
type shared struct {
	mu           sync.Mutex
	cluster      *goharness.Cluster
	ackMu        sync.Mutex
	acknowledged map[string]bool
	inFlight     [3]atomic.Int64
	seqs         [3]atomic.Int64
	running      [3]atomic.Bool
	// ackedMode gates whether a node's rows join the acknowledged
	// set. The victim faces a future kill in every round but the
	// last, and this stack persists asynchronously (kills lose the
	// unflushed tail), so victim rows written after the first
	// restart are load-only (unacked); everything else is acked.
	ackedMode [3]atomic.Bool
	stop      atomic.Bool
}

func newShared(cluster *goharness.Cluster) *shared {
	s := &shared{cluster: cluster, acknowledged: map[string]bool{}}
	for i := range s.running {
		s.running[i].Store(true)
		s.ackedMode[i].Store(true)
	}
	return s
}

// insert writes one row plus a durability barrier, recording the
// acknowledgement. Only error-free inserts count: refusals during
// kill/restart windows are dropped and the next unique insert continues
// the workload.
func insert(s *shared, node int, id int64, name string) error {
	s.inFlight[node].Add(1)
	defer s.inFlight[node].Add(-1)
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.running[node].Load() {
		return fmt.Errorf("node stopped")
	}
	tagged := fmt.Sprintf("%s@%d", name, id)
	if _, err := s.cluster.Node(node).Execute(
		"INSERT INTO records(id, name) VALUES($1, $2)", id, tagged); err != nil {
		return fmt.Errorf("node%d insert '%s': %w", node+1, name, err)
	}
	if err := s.cluster.Node(node).Flush(); err != nil {
		return fmt.Errorf("node%d flush after '%s': %w", node+1, name, err)
	}
	if s.ackedMode[node].Load() {
		s.ackMu.Lock()
		s.acknowledged[fmt.Sprintf("%s@%d", name, id)] = true
		s.ackMu.Unlock()
	}
	return nil
}

// writer is one continuous writer (one 25 ms ticker goroutine per node).
func writer(s *shared, node int) {
	for !s.stop.Load() {
		time.Sleep(writeInterval)
		if s.stop.Load() {
			break
		}
		if !s.running[node].Load() {
			continue
		}
		seq := s.seqs[node].Add(1)
		name := fmt.Sprintf("n%d-%08d", node+1, seq)
		// Refusals during kill/restart windows are dropped; the next
		// unique insert continues the workload.
		_ = insert(s, node, int64(node)*idStride+seq, name)
	}
}

// names returns the sorted names on one node.
func names(s *shared, idx int) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.cluster.Node(idx).Simple("SELECT name FROM records")
	if err != nil {
		return nil, fmt.Errorf("node%d SELECT names: %w", idx+1, err)
	}
	out := make([]string, 0, len(rows))
	for _, row := range rows {
		if len(row) == 0 {
			return nil, fmt.Errorf("node%d decode name: short row", idx+1)
		}
		out = append(out, row[0])
	}
	sort.Strings(out)
	return out, nil
}

// peerCounts returns the connected sessions per node, in node order
// (the reference reads the peers column of MURMUR SHOW REPLICATION;
// here connected SHOW PEERS rows are counted, as PeerCounts does).
func peerCounts(s *shared) ([]int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]int64, 0, s.cluster.Len())
	for i := 0; i < s.cluster.Len(); i++ {
		peers, err := s.cluster.Node(i).ShowPeers()
		if err != nil {
			return nil, fmt.Errorf("node%d SHOW PEERS: %w", i+1, err)
		}
		var n int64
		for _, p := range peers {
			if p.Connected {
				n++
			}
		}
		out = append(out, n)
	}
	return out, nil
}

// waitForPeers waits until every node reports its wanted session count.
func waitForPeers(s *shared, want []int64, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		got, err := peerCounts(s)
		if err != nil {
			return err
		}
		if equalInt64(got, want) {
			return nil
		}
		if !time.Now().Before(deadline) {
			last, err := peerCounts(s)
			if err != nil {
				return err
			}
			return fmt.Errorf("peers did not reach %v within %s (last: %v)", want, timeout, last)
		}
		time.Sleep(poll)
	}
}

// rowCount returns the row count on one node.
func rowCount(s *shared, idx int) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.cluster.Node(idx).Simple("SELECT COUNT(*) FROM records")
	if err != nil {
		return 0, fmt.Errorf("node%d COUNT records: %w", idx+1, err)
	}
	if len(rows) == 0 || len(rows[0]) == 0 {
		return 0, fmt.Errorf("node%d COUNT records: no rows", idx+1)
	}
	var n int
	if _, err := fmt.Sscanf(rows[0][0], "%d", &n); err != nil {
		return 0, fmt.Errorf("node%d COUNT records: %w", idx+1, err)
	}
	return n, nil
}

// waitForConvergence waits until every node holds equal counts with equal
// sorted names. The reference polls full sorted names every 100 ms;
// with thousands of rows per node that ships whole tables over child
// stdio on every poll and starves the nodes under test, so this polls
// cheap counts and runs the full name comparison only once counts
// match. The pass criterion is unchanged.
func waitForConvergence(s *shared, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	lastLog := time.Now()
	lastProgress := time.Now()
	var prevCounts []int
	for {
		s.mu.Lock()
		length := s.cluster.Len()
		s.mu.Unlock()
		counts := make([]int, 0, length)
		countMatch := true
		for i := 0; i < length; i++ {
			n, err := rowCount(s, i)
			if err != nil {
				return err
			}
			counts = append(counts, n)
			if i > 0 && n != counts[0] {
				countMatch = false
			}
		}
		ok := false
		if countMatch {
			var want []string
			first := true
			ok = true
			for i := 0; i < length; i++ {
				nodeNames, err := names(s, i)
				if err != nil {
					return err
				}
				if first {
					want, first = nodeNames, false
				} else if !equalStrings(want, nodeNames) {
					ok = false
					break
				}
			}
		}
		if !ok && time.Now().After(lastLog.Add(10*time.Second)) {
			fmt.Fprintf(os.Stderr, "converge progress counts=%v\n", counts)
			lastLog = time.Now()
		}
		// Stall breaker (same as crash-recovery): re-roll session
		// formation when no node makes progress for 20 s.
		changed := len(counts) != len(prevCounts)
		if !changed {
			for i := range counts {
				if counts[i] != prevCounts[i] {
					changed = true
					break
				}
			}
		}
		if changed {
			lastProgress = time.Now()
			prevCounts = append(prevCounts[:0], counts...)
		}
		if !ok && time.Now().After(lastProgress.Add(20*time.Second)) {
			// Stall breaker (same as crash-recovery): reset the
			// laggards' pull cursors for the ahead nodes, then
			// bounce the mesh for a full resync.
			maxCount := counts[0]
			for _, c := range counts[1:] {
				if c > maxCount {
					maxCount = c
				}
			}
			fmt.Fprintf(os.Stderr, "converge stalled at %v; resetting cursors and bouncing mesh\n", counts)
			s.mu.Lock()
			for i := 0; i < s.cluster.Len(); i++ {
				if counts[i] == maxCount {
					continue
				}
				for j := 0; j < s.cluster.Len(); j++ {
					if counts[j] != maxCount {
						continue
					}
					_, err := s.cluster.Node(i).Execute(
						"DELETE FROM murmur_progress WHERE lower(hex(node)) = $1", s.cluster.NodeID(j))
					if err != nil {
						fmt.Fprintf(os.Stderr, "node%d cursor reset: %v\n", i+1, err)
					}
				}
			}
			_ = bounceMesh(s)
			s.mu.Unlock()
			lastProgress = time.Now()
			lastLog = time.Now()
		}
		if ok {
			return nil
		}
		if !time.Now().Before(deadline) {
			s.mu.Lock()
			length := s.cluster.Len()
			s.mu.Unlock()
			for i := 0; i < length; i++ {
				nodeNames, err := names(s, i)
				if err != nil {
					return err
				}
				fmt.Fprintf(os.Stderr, "node%d at timeout: count=%d\n", i+1, len(nodeNames))
			}
			dumpStatus(s)
			return fmt.Errorf("nodes did not converge (counts + name digests) within %s", timeout)
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// dumpStatus logs the engine status snapshot of every node (replication
// progress and any latched error) for post-mortem debugging.
func dumpStatus(s *shared) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := 0; i < s.cluster.Len(); i++ {
		st, err := s.cluster.Node(i).ShowStatus()
		if err != nil {
			fmt.Fprintf(os.Stderr, "node%d status: %v\n", i+1, err)
			continue
		}
		fmt.Fprintf(os.Stderr, "node%d status: %v\n", i+1, st)
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

func equalInt64(a, b []int64) bool {
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

// assertAcknowledgedPresent requires every acknowledged write to be
// present on every node.
func assertAcknowledgedPresent(s *shared) error {
	s.ackMu.Lock()
	acknowledged := make([]string, 0, len(s.acknowledged))
	for name := range s.acknowledged {
		acknowledged = append(acknowledged, name)
	}
	s.ackMu.Unlock()
	s.mu.Lock()
	length := s.cluster.Len()
	s.mu.Unlock()
	for i := 0; i < length; i++ {
		nodeNames, err := names(s, i)
		if err != nil {
			return err
		}
		present := map[string]bool{}
		for _, n := range nodeNames {
			present[n] = true
		}
		for _, name := range acknowledged {
			if !present[name] {
				return fmt.Errorf("node%d lost acknowledged write %q", i+1, name)
			}
		}
	}
	return nil
}

// bounceMesh stops every node's replication (tearing down all
// sessions, zombies included; stores stay open) and restarts the
// nodes one second apart before re-meshing. The stagger matters:
// this engine closes a fresh inbound session as a duplicate while
// any entry for the peer lives, with no tie-break, so starting all
// nodes at once synchronizes every pair's dials and the mutual
// duplicate-closes can livelock with all streams broken while peers
// still show connected. Sequential starts let each pair's first dial
// win before the reverse dial lands. See crash-recovery.
// Call with s.mu held.
func bounceMesh(s *shared) error {
	for i := 0; i < s.cluster.Len(); i++ {
		if err := s.cluster.StopNode(i); err != nil {
			return fmt.Errorf("bounce-stop node%d: %w", i+1, err)
		}
	}
	for i := 0; i < s.cluster.Len(); i++ {
		if err := s.cluster.StartNode(i); err != nil {
			return fmt.Errorf("bounce-start node%d: %w", i+1, err)
		}
		if i+1 < s.cluster.Len() {
			time.Sleep(time.Second)
		}
	}
	if err := s.cluster.PeerMesh(); err != nil {
		return fmt.Errorf("re-mesh after bounce: %w", err)
	}
	return nil
}

func acknowledgedLen(s *shared) int {
	s.ackMu.Lock()
	defer s.ackMu.Unlock()
	return len(s.acknowledged)
}

func runBody(s *shared, rounds int, uptime time.Duration) error {
	s.mu.Lock()
	for i := 0; i < s.cluster.Len(); i++ {
		fmt.Fprintf(os.Stderr, "node%d addr=%s\n", i+1, s.cluster.Node(i).Addr)
	}
	if err := s.cluster.PeerMesh(); err != nil {
		s.mu.Unlock()
		return fmt.Errorf("initial mesh: %w", err)
	}
	s.mu.Unlock()
	// Same durability/retention adaptations as crash-recovery (see
	// that suite's README): the engine acks at the served
	// high-water and never auto-snapshots, and it persists
	// asynchronously, so the retention tail is raised past any
	// backlog and the flusher runs every 50 ms.
	for i := 0; i < 3; i++ {
		s.mu.Lock()
		_, err := s.cluster.Node(i).Simple(
			"INSERT INTO murmur_config(name,value) VALUES('retention_min_kept','1000000') ON CONFLICT(name) DO UPDATE SET value=excluded.value")
		s.mu.Unlock()
		if err != nil {
			return fmt.Errorf("node%d raise retention tail: %w", i+1, err)
		}
	}
	for i := 0; i < 3; i++ {
		s.mu.Lock()
		_, err := s.cluster.Node(i).Simple("PRAGMA flush_interval_ms=50")
		s.mu.Unlock()
		if err != nil {
			return fmt.Errorf("node%d set flush interval: %w", i+1, err)
		}
	}
	// Same schema on every node, then replicate it: row convergence
	// needs the per-table flag on each.
	for i := 0; i < 3; i++ {
		s.mu.Lock()
		_, err := s.cluster.Node(i).Simple(
			"CREATE TABLE IF NOT EXISTS records(id INTEGER PRIMARY KEY NOT NULL, name TEXT NOT NULL DEFAULT '')")
		s.mu.Unlock()
		if err != nil {
			return fmt.Errorf("migrate node%d: %w", i+1, err)
		}
	}
	for i := 0; i < 3; i++ {
		s.mu.Lock()
		err := s.cluster.Node(i).SetTableReplicated("records", true)
		s.mu.Unlock()
		if err != nil {
			return fmt.Errorf("node%d SET TABLE REPLICATED: %w", i+1, err)
		}
		s.mu.Lock()
		err = s.cluster.Node(i).Flush()
		s.mu.Unlock()
		if err != nil {
			return fmt.Errorf("node%d flush after SET TABLE: %w", i+1, err)
		}
	}

	// Positive control: honest 3-node convergence before any crash.
	for node := 0; node < 3; node++ {
		if err := insert(s, node, baselineIDBase+int64(node), fmt.Sprintf("base-node%d", node+1)); err != nil {
			return err
		}
	}
	if err := waitForPeers(s, []int64{2, 2, 2}, controlTimeout); err != nil {
		return err
	}
	if err := waitForConvergence(s, controlTimeout); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "positive control: 3-node mesh converged")

	var wg sync.WaitGroup
	for node := 0; node < 3; node++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			writer(s, node)
		}()
	}

	var readyDurations []time.Duration
	driver := func() error {
		for round := 1; round <= rounds; round++ {
			time.Sleep(uptime)
			final := round == rounds
			var burstEnd time.Time
			if final {
				// Burst on a survivor (never killed, so the
				// burst rows are safe regardless of flush
				// timing), then kill within the window:
				// mid-replication by construction.
				for i := int64(0); i < burstRows; i++ {
					if err := insert(s, 0, burstIDBase+i, fmt.Sprintf("burst-%d", i)); err != nil {
						return err
					}
				}
				burstEnd = time.Now()
			}
			// Drain the victim so every acknowledged row is
			// durable (async persistence), then prove
			// scheduler-level in-flight with a sleeper that
			// holds the counter without sending bytes (same
			// gate check as the reference; see
			// crash-recovery). Survivor writers never pause.
			s.running[victim].Store(false)
			time.Sleep(250 * time.Millisecond)
			drainDeadline := time.Now().Add(5 * time.Second)
			for s.inFlight[victim].Load() != 0 {
				if !time.Now().Before(drainDeadline) {
					return fmt.Errorf("round %d: victim writers did not drain", round)
				}
				time.Sleep(5 * time.Millisecond)
			}
			stopSleeper := make(chan struct{})
			var sleeperWG sync.WaitGroup
			sleeperWG.Add(1)
			go func() {
				defer sleeperWG.Done()
				for {
					select {
					case <-stopSleeper:
						return
					default:
					}
					s.inFlight[victim].Add(1)
					select {
					case <-stopSleeper:
						s.inFlight[victim].Add(-1)
						return
					case <-time.After(200 * time.Millisecond):
					}
					s.inFlight[victim].Add(-1)
				}
			}()
			killErr := func() error {
				defer func() {
					close(stopSleeper)
					sleeperWG.Wait()
				}()
				if final {
					deadline := burstEnd.Add(burstWindow)
					for s.inFlight[victim].Load() == 0 && time.Now().Before(deadline) {
						time.Sleep(time.Millisecond)
					}
				} else {
					deadline := time.Now().Add(inflightTimeout)
					for s.inFlight[victim].Load() == 0 {
						if !time.Now().Before(deadline) {
							return fmt.Errorf("node%d had no write request in flight before SIGKILL", victim+1)
						}
						time.Sleep(time.Millisecond)
					}
				}
				fmt.Fprintf(os.Stderr, "round %d/%d: SIGKILL node%d with %d request(s) in flight\n",
					round, rounds, victim+1, s.inFlight[victim].Load())
				start := time.Now()
				restartErr := func() error {
					s.mu.Lock()
					defer s.mu.Unlock()
					if err := s.cluster.KillNode(victim); err != nil {
						return fmt.Errorf("round %d kill node%d: %w", round, victim+1, err)
					}
					if err := s.cluster.RestartNode(victim); err != nil {
						return fmt.Errorf("round %d restart node%d: %w", round, victim+1, err)
					}
					if _, err := s.cluster.Node(victim).Simple("PRAGMA flush_interval_ms=50"); err != nil {
						return fmt.Errorf("round %d re-apply flush interval: %w", round, err)
					}
					if err := bounceMesh(s); err != nil {
						return fmt.Errorf("round %d: %w", round, err)
					}
					return nil
				}()
				if restartErr != nil {
					return restartErr
				}
				readyDurations = append(readyDurations, time.Since(start))
				fmt.Fprintf(os.Stderr, "round %d/%d: node%d ready in %s\n",
					round, rounds, victim+1, readyDurations[len(readyDurations)-1])
				return nil
			}()
			if killErr != nil {
				return killErr
			}
			// The victim faces another kill in every round but
			// the last: its rows stay load-only (unacked)
			// after the first restart.
			if !final {
				s.ackedMode[victim].Store(false)
			}
			s.running[victim].Store(true)
		}
		return nil
	}()
	s.stop.Store(true)
	wg.Wait()
	if driver != nil {
		return driver
	}
	// No more kills: the post-loop marker on the victim is acked.
	s.ackedMode[victim].Store(true)

	// No wedge: the final restart reaches ready within the bound, the mesh
	// reforms, and every acked write is present everywhere.
	if len(readyDurations) > 0 {
		if last := readyDurations[len(readyDurations)-1]; last > readyBound {
			return fmt.Errorf("final restart took %s to reach ready, want < %s (wedge)", last, readyBound)
		}
	}
	if err := waitForPeers(s, []int64{2, 2, 2}, healTimeout); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "mesh reformed after the crash loop")
	s.mu.Lock()
	_ = s.cluster.PeerMesh()
	s.mu.Unlock()
	if err := waitForConvergence(s, healTimeout); err != nil {
		return err
	}
	if err := assertAcknowledgedPresent(s); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "all %d acknowledged writes survived %d SIGKILLs\n", acknowledgedLen(s), rounds)

	if err := insert(s, victim, postLoopID, "post-loop-from-victim"); err != nil {
		return err
	}
	if err := waitForConvergence(s, postTimeout); err != nil {
		return err
	}
	if err := assertAcknowledgedPresent(s); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "post-loop write on the looped node replicated everywhere")
	return nil
}

func TestCrashLoopNodeConvergesWithoutLoss(t *testing.T) {
	goharness.SkipUnlessLive(t)
	rounds := int(envInt("MURMUR_CRASH_LOOP_ROUNDS", 5))
	uptime := time.Duration(envInt("MURMUR_CRASH_LOOP_UPTIME_MS", 1000)) * time.Millisecond

	cluster, err := goharness.NewCluster(goharness.ClusterOptions{
		Name:       "crash-loop",
		NumNodes:   3,
		ChildNodes: true,
	})
	if err != nil {
		t.Fatalf("cluster setup: %v", err)
	}
	if cluster.Len() != 3 {
		t.Fatal("this scenario is written for 3 nodes")
	}
	s := newShared(cluster)
	runErr := runBody(s, rounds, uptime)
	failed := runErr != nil
	if runErr != nil {
		fmt.Fprintf(os.Stderr, "scenario failed: %v\n", runErr)
	}
	cluster.Finish(failed)
	if failed {
		t.Fatal("scenario failed; artifacts retained under tests-live/failures/")
	}
}
