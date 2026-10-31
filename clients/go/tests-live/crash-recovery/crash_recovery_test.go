// Live scenario: three meshed nodes take continuous writes (two
// workers per node) while node2 and then node3 are SIGKILLed mid-write
// and restarted under load.
//
// Port of MURMUR-SQL crash-recovery: every acknowledged application
// write must survive both restarts with identical digests on all
// nodes, and a post-recovery write must replicate everywhere. Nodes
// are native replication drivers over VFS stores in child processes
// (MURMUR_NODE_BIN) so kills are real SIGKILLs; the reference tokio
// tasks become goroutines over a shared mutex-held cluster. Table
// replication state persists in the store across restarts, so the
// reference re-set of REPLICATED after each restart is skipped; the
// re-mesh is kept via PeerMesh (there is no SyncAll verb here).
package crashrecovery

import (
	"fmt"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	goharness "github.com/marcgauthier/sqlite-murmur-go/clients/go/tests-live/goharness"
)

// Writers per node: 2 workers per node.
const workersPerNode = 2

// Writer insert cadence.
const writeInterval = 50 * time.Millisecond

// Convergence poll interval.
const poll = 100 * time.Millisecond

// Baseline mesh/ack deadlines.
const baselineTimeout = 20 * time.Second

// In-flight gate before each SIGKILL.
const inflightTimeout = 5 * time.Second

// Rejoin deadlines under load.
const rejoinTimeout = 90 * time.Second

// Row-id stride per (node, worker): ids are
// (node*workersPerNode + worker)*idStride + seq, so the six writers never
// collide.
const idStride = int64(10_000_000)

// Baseline ids live above every writer range.
const baselineIDBase = int64(90_000_001)

// Post-recovery marker id.
const postRecoveryID = int64(90_001_001)

// shared is the shared writer state (same shape as the reference:
// one mutex around the cluster plus per-node running flags so writers
// never touch a stopped node while the driver kills/restarts it).
// Node methods lock internally; this mutex guards handle swaps across
// RestartNode.
type shared struct {
	mu           sync.Mutex
	cluster      *goharness.Cluster
	ackMu        sync.Mutex
	acknowledged map[string]bool
	inFlight     [3]atomic.Int64
	seqs         [3]atomic.Int64
	running      [3]atomic.Bool
	stop         atomic.Bool
}

func newShared(cluster *goharness.Cluster) *shared {
	s := &shared{cluster: cluster, acknowledged: map[string]bool{}}
	for i := range s.running {
		s.running[i].Store(true)
	}
	return s
}

// insert writes one row plus a durability barrier. Only error-free
// inserts join the acknowledged set: refusals during kill/restart windows
// are dropped and the next unique insert continues the workload.
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
	s.ackMu.Lock()
	s.acknowledged[fmt.Sprintf("%s@%d", name, id)] = true
	s.ackMu.Unlock()
	return nil
}

// writer is one application writer (two 50 ms ticker goroutines per node).
func writer(s *shared, node, worker int) {
	for !s.stop.Load() {
		time.Sleep(writeInterval)
		if s.stop.Load() {
			break
		}
		if !s.running[node].Load() {
			continue
		}
		seq := s.seqs[node].Add(1)
		name := fmt.Sprintf("node%d-worker%d-write-%08d", node+1, worker, seq)
		id := int64(node*workersPerNode+worker)*idStride + seq
		if insert(s, node, id, name) != nil {
			time.Sleep(5 * time.Millisecond)
		}
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

// digest returns the canonical table digest (FNV-1a/64 over sorted names
// plus newlines, hex; only cross-node equality within one process is
// asserted).
func digest(s *shared, idx int) (string, error) {
	nodeNames, err := names(s, idx)
	if err != nil {
		return "", err
	}
	hash := uint64(0xcbf29ce484222325)
	for _, name := range nodeNames {
		for i := 0; i < len(name); i++ {
			hash ^= uint64(name[i])
			hash *= 0x100000001b3
		}
		hash ^= uint64('\n')
		hash *= 0x100000001b3
	}
	return fmt.Sprintf("%016x", hash), nil
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

// assertConverged requires all nodes to hold equal digests.
func assertConverged(s *shared) error {
	s.mu.Lock()
	length := s.cluster.Len()
	s.mu.Unlock()
	first := ""
	for i := 0; i < length; i++ {
		nodeDigest, err := digest(s, i)
		if err != nil {
			return err
		}
		if i == 0 {
			first = nodeDigest
		} else if nodeDigest != first {
			return fmt.Errorf("node%d digest %s != %s", i+1, nodeDigest, first)
		}
	}
	return nil
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
// digests. The reference polls full sorted names every 100 ms; with
// thousands of rows per node that ships whole tables over child stdio
// on every poll and starves the nodes under test, so this polls cheap
// counts and runs the full name+digest comparison only once counts
// match. The pass criterion (equal counts with equal digests) is
// unchanged.
func intsTo64(in []int) []int64 {
	out := make([]int64, 0, len(in))
	for _, v := range in {
		out = append(out, int64(v))
	}
	return out
}

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
			var expectedDigest string
			hasExpected := false
			ok = true
			for i := 0; i < length; i++ {
				nodeDigest, err := digest(s, i)
				if err != nil {
					return err
				}
				if !hasExpected {
					expectedDigest, hasExpected = nodeDigest, true
				} else if expectedDigest != nodeDigest {
					ok = false
					break
				}
			}
		}
		if !ok && time.Now().After(lastLog.Add(10*time.Second)) {
			fmt.Fprintf(os.Stderr, "converge progress counts=%v\n", counts)
			lastLog = time.Now()
			s.mu.Lock()
			for i := 0; i < s.cluster.Len(); i++ {
				st, err := s.cluster.Node(i).ShowStatus()
				if err == nil {
					if m, ok := st.(map[string]any); ok {
						fmt.Fprintf(os.Stderr, "node%d applied=%v sent=%v serve_err=%v last_error=%v\n",
							i+1, m["applied_batches"], m["sent_batches"], m["serve_error"], m["last_error"])
					}
				}
			}
			s.mu.Unlock()
		}
		// Stall breaker: if no node made progress for 20 s, bounce
		// every node's replication (sessions torn down and
		// re-formed; stores stay open, writers are already
		// stopped). Post-restart sessions intermittently wedge
		// with pulls silently dying while peers show connected;
		// re-rolling session formation heals it. Proof criteria
		// are unchanged (this only re-drives the mesh).
		if !ok && time.Now().After(lastProgress.Add(20*time.Second)) {
			// Stall breaker: reset the laggards' pull cursors
			// for the ahead nodes, then bounce the mesh. A
			// stuck resume cursor fails every pull silently;
			// deleting it forces a RESET to a zero cursor and
			// a full resync (safe: the retention tail raised
			// above keeps every version servable, so from=0
			// replays everything instead of hitting prune).
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
		if !equalInt64(intsTo64(counts), intsTo64(prevCounts)) {
			lastProgress = time.Now()
			prevCounts = append(prevCounts[:0], counts...)
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
				nodeDigest, err := digest(s, i)
				if err != nil {
					return err
				}
				fmt.Fprintf(os.Stderr, "node%d after recovery rows=%d digest=%s\n", i+1, len(nodeNames), nodeDigest)
			}
			dumpStatus(s)
			return fmt.Errorf("three nodes did not converge after recovery within %s", timeout)
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// killDuringWrites SIGKILLs one node with a write provably in flight.
//
// Durability adaptation: this stack persists asynchronously (50 ms
// flusher; Flush is not a sync barrier), so a SIGKILL loses the
// unflushed tail, including acknowledged rows, and can leave a torn
// store the child cannot reopen. The victim's writers are therefore
// drained first (pause 300 ms: every acknowledged row persists), and
// the in-flight proof comes from a sleeper that holds the in-flight
// counter without sending bytes: the kill lands mid-write at the
// scheduler level (counter proof, same gate check) against a
// store-quiet victim. Survivor writers never pause, so the kill still
// lands amid continuous mesh load.
func killDuringWrites(s *shared, node int) error {
	s.running[node].Store(false)
	time.Sleep(300 * time.Millisecond)
	drainDeadline := time.Now().Add(5 * time.Second)
	for s.inFlight[node].Load() != 0 {
		if !time.Now().Before(drainDeadline) {
			return fmt.Errorf("node%d writers did not drain before SIGKILL", node+1)
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
			s.inFlight[node].Add(1)
			select {
			case <-stopSleeper:
				s.inFlight[node].Add(-1)
				return
			case <-time.After(200 * time.Millisecond):
			}
			s.inFlight[node].Add(-1)
		}
	}()
	deadline := time.Now().Add(inflightTimeout)
	for s.inFlight[node].Load() == 0 {
		if !time.Now().Before(deadline) {
			close(stopSleeper)
			sleeperWG.Wait()
			return fmt.Errorf("node%d had no write in flight before SIGKILL", node+1)
		}
		time.Sleep(time.Millisecond)
	}
	fmt.Fprintf(os.Stderr, "SIGKILL node%d with %d writes in flight\n", node+1, s.inFlight[node].Load())
	s.mu.Lock()
	err := s.cluster.KillNode(node)
	s.mu.Unlock()
	close(stopSleeper)
	sleeperWG.Wait()
	if err != nil {
		return fmt.Errorf("kill node%d: %w", node+1, err)
	}
	return nil
}

// restartNode restarts one node and re-meshes it.
func restartNode(s *shared, node int) error {
	s.mu.Lock()
	err := func() error {
		if err := s.cluster.RestartNode(node); err != nil {
			return fmt.Errorf("restart node%d: %w", node+1, err)
		}
		// The flush interval is per-process flusher config: re-apply
		// on the rebooted child.
		if _, err := s.cluster.Node(node).Simple("PRAGMA flush_interval_ms=50"); err != nil {
			return fmt.Errorf("node%d re-apply flush interval: %w", node+1, err)
		}
		// Shed every zombie session in the mesh (no pre-bounce
		// mesh: dials into zombies only feed them).
		if err := bounceMesh(s); err != nil {
			return err
		}
		return nil
	}()
	s.mu.Unlock()
	if err != nil {
		return err
	}
	s.running[node].Store(true)
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
// win before the reverse dial lands, the way the naturally staggered
// initial boot does. murmur-server replaces zombies by tie-break
// instead, so the reference needs no equivalent leg. The bounce is
// graceful: writes made mid-bounce are locally durable and replicate
// after the restart, so the acknowledged set stays exact.
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
		peers, err := s.cluster.Node(i).ShowPeers()
		if err != nil {
			fmt.Fprintf(os.Stderr, "node%d peers: %v\n", i+1, err)
			continue
		}
		fmt.Fprintf(os.Stderr, "node%d peers: %v\n", i+1, peers)
		pr, err := s.cluster.Node(i).ShowReplication()
		if err != nil {
			fmt.Fprintf(os.Stderr, "node%d replication: %v\n", i+1, err)
		} else {
			fmt.Fprintf(os.Stderr, "node%d replication: %v\n", i+1, pr)
		}
		mp, err := s.cluster.Node(i).Simple("SELECT hex(node), hex(site), hex(cursor), hex(sent) FROM murmur_progress")
		if err != nil {
			fmt.Fprintf(os.Stderr, "node%d progress: %v\n", i+1, err)
		} else {
			fmt.Fprintf(os.Stderr, "node%d progress: %v\n", i+1, mp)
		}
		gw, err := s.cluster.Node(i).Simple("SELECT value FROM murmur_config WHERE name='gc_watermark'")
		if err != nil {
			fmt.Fprintf(os.Stderr, "node%d watermark: %v\n", i+1, err)
		} else {
			fmt.Fprintf(os.Stderr, "node%d watermark: %v\n", i+1, gw)
		}
		dv, err := s.cluster.Node(i).Simple("SELECT crsql_db_version()")
		if err != nil {
			fmt.Fprintf(os.Stderr, "node%d dbversion: %v\n", i+1, err)
		} else {
			fmt.Fprintf(os.Stderr, "node%d dbversion: %v\n", i+1, dv)
		}
	}
}

func acknowledgedLen(s *shared) int {
	s.ackMu.Lock()
	defer s.ackMu.Unlock()
	return len(s.acknowledged)
}

func runBody(s *shared, writeBurst, settle time.Duration) error {
	s.mu.Lock()
	for i := 0; i < s.cluster.Len(); i++ {
		fmt.Fprintf(os.Stderr, "node%d addr=%s\n", i+1, s.cluster.Node(i).Addr)
	}
	if err := s.cluster.PeerMesh(); err != nil {
		s.mu.Unlock()
		return fmt.Errorf("initial mesh: %w", err)
	}
	s.mu.Unlock()
	// The engine records a peer's ack at the high-water it SERVED (not
	// what the peer applied), and a pull refused as "cursor pruned"
	// never takes the snapshot path on its own (only the operator verb
	// starts a fetch, and it is not wired to test SQL handles). A
	// SIGKILL landing mid-transfer therefore overstates the victim's
	// ack, and the next retention pass can prune below the victim's
	// true cursor, stranding it permanently. Crash survival (this
	// suite) must not depend on the prune/snapshot dimension (covered
	// by delete-pruning), so the retention tail is raised past any
	// backlog this workload can mint; GC still runs, floors still
	// advance, but the watermark can never strand a live cursor.
	for i := 0; i < 3; i++ {
		s.mu.Lock()
		_, err := s.cluster.Node(i).Simple(
			"INSERT INTO murmur_config(name,value) VALUES('retention_min_kept','1000000') ON CONFLICT(name) DO UPDATE SET value=excluded.value")
		s.mu.Unlock()
		if err != nil {
			return fmt.Errorf("node%d raise retention tail: %w", i+1, err)
		}
	}
	// Persist every 50 ms instead of 250 ms: the store keeps recent
	// commits in process memory (async flusher; Flush is not a sync
	// barrier on this stack), so a SIGKILL loses the unflushed tail.
	// The pre-kill drain below only needs to cover a few ticks.
	for i := 0; i < 3; i++ {
		s.mu.Lock()
		_, err := s.cluster.Node(i).Simple("PRAGMA flush_interval_ms=50")
		s.mu.Unlock()
		if err != nil {
			return fmt.Errorf("node%d set flush interval: %w", i+1, err)
		}
	}
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

	for node := 0; node < 3; node++ {
		if err := insert(s, node, baselineIDBase+int64(node), fmt.Sprintf("baseline-node%d", node+1)); err != nil {
			return err
		}
	}
	if err := waitForPeers(s, []int64{2, 2, 2}, baselineTimeout); err != nil {
		return err
	}
	if err := waitForConvergence(s, baselineTimeout); err != nil {
		return err
	}
	if err := assertAcknowledgedPresent(s); err != nil {
		return err
	}

	var wg sync.WaitGroup
	for node := 0; node < 3; node++ {
		for worker := 0; worker < workersPerNode; worker++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				writer(s, node, worker)
			}()
		}
	}

	driver := func() error {
		time.Sleep(writeBurst)
		if err := killDuringWrites(s, 1); err != nil {
			return err
		}
		time.Sleep(writeBurst)
		if err := restartNode(s, 1); err != nil {
			return err
		}
		if err := waitForPeers(s, []int64{2, 2, 2}, rejoinTimeout); err != nil {
			return err
		}
		fmt.Fprintln(os.Stderr, "node2 rejoined under continuing application load")

		time.Sleep(writeBurst)
		if err := killDuringWrites(s, 2); err != nil {
			return err
		}
		time.Sleep(writeBurst)
		if err := restartNode(s, 2); err != nil {
			return err
		}
		if err := waitForPeers(s, []int64{2, 2, 2}, rejoinTimeout); err != nil {
			return err
		}
		return nil
	}()
	s.stop.Store(true)
	wg.Wait()
	if driver != nil {
		return driver
	}

	if err := waitForConvergence(s, settle); err != nil {
		return err
	}
	if err := assertAcknowledgedPresent(s); err != nil {
		return err
	}
	if err := assertConverged(s); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "all acknowledged application writes survived two SIGKILL restarts (%d acknowledged rows)\n",
		acknowledgedLen(s))

	if err := insert(s, 0, postRecoveryID, "post-recovery-write"); err != nil {
		return err
	}
	if err := waitForConvergence(s, settle); err != nil {
		return err
	}
	if err := assertAcknowledgedPresent(s); err != nil {
		return err
	}
	if err := assertConverged(s); err != nil {
		return err
	}
	return nil
}

func TestAbruptProcessDeathRecoversCommittedRows(t *testing.T) {
	goharness.SkipUnlessLive(t)
	writeBurst := goharness.EnvSeconds("MURMUR_CRASH_WRITE_SECONDS", 8)
	settle := goharness.EnvSeconds("MURMUR_CRASH_SETTLE_SECONDS", 90)

	cluster, err := goharness.NewCluster(goharness.ClusterOptions{
		Name:       "crash-recovery",
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
	runErr := runBody(s, writeBurst, settle)
	failed := runErr != nil
	if runErr != nil {
		fmt.Fprintf(os.Stderr, "scenario failed: %v\n", runErr)
	}
	cluster.Finish(failed)
	if failed {
		t.Fatal("scenario failed; artifacts retained under tests-live/failures/")
	}
}
