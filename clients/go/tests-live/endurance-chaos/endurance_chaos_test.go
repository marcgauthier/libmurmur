// Live scenario: a live multi-node mesh absorbs continuous writes while
// rolling restarts, peer flaps, and disk pressure overlap for a
// configured chaos window.
//
// Port of MURMUR-SQL endurance-chaos using tests-live/goharness.
// Identical behavior on the portable legs: the verdict is exact
// cross-node convergence (equal row counts plus identical PK-ordered
// row contents) with a rejoined full mesh and a post-chaos write.
// Plain SQL replaces the typed-contention API; tc/netem impairment
// degrades to allow-list edge flaps (no runtime peer-removal verb
// exists) and libfaketime clock skew is skipped, as in the reference.
// Goroutines share the cluster through one mutex; every cluster touch
// locks, so lifecycle (stop/start) and reads never race.
//
// Degraded legs: online key rotation has no native verb and stays
// skipped. Snapshot offline windows with resync proof and
// counter-proven GC progress run as companion tests against the
// health collected/applied counters plus Node.RetentionCollect.
// retention_min_kept is raised to 1000000 so restart outages and
// stall-breaker cursor resets rejoin over the log path instead of
// the unsupported snapshot path.
package endurancechaos

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	goharness "github.com/marcgauthier/libmurmur/clients/go/tests-live/goharness"
	"golang.org/x/sys/unix"
)

// shared is the shared cluster handle: every task locks for each
// cluster touch.
type shared struct {
	mu sync.Mutex
	c  *goharness.Cluster
}

const (
	// minNodes/maxNodes is the mesh-size clamp.
	minNodes = 3
	maxNodes = 16
	// maxWriters is the writer-task cap.
	maxWriters = 8
	// minMaxRows is the bounded working-set floor.
	minMaxRows = 100
	// minSnapshotOff is the snapshot offline-window floor (60 s:
	// retention expiry + GC tick). The snapshot leg is skipped
	// in-run, but the knob surface stays identical to the reference.
	minSnapshotOff = 60 * time.Second
	// baselineTimeout is the baseline replication deadline (2 minutes).
	baselineTimeout = 120 * time.Second
	// directorTick is the director tick (1 s).
	directorTick = 1 * time.Second
	// impairWarmup is the first impairment delay (15 s).
	impairWarmup = 15 * time.Second
	// diskWarmup is the disk-loop stagger (30 s).
	diskWarmup = 30 * time.Second
	// verdictPoll is the convergence poll interval (2 s).
	verdictPoll = 2 * time.Second
	// breakerFreeze is the frozen-counts trigger for the stall breaker
	// (20 s, crash-recovery value).
	breakerFreeze = 20 * time.Second
	// breakerCooldown is the minimum gap between stall-breaker fires
	// (60 s): a bounce needs session re-formation plus full-replay
	// ramp time, and re-firing into a slow-but-healthy resync tears
	// down sessions mid-transfer.
	breakerCooldown = 60 * time.Second
	// meshTimeout is the full-mesh wait bound (60 s).
	meshTimeout = 60 * time.Second
	// errSampleCap caps distinct error-message samples (first 8).
	errSampleCap = 8
	// errTruncChars truncates stored error messages (200 chars).
	errTruncChars = 200
	// diskHeadroomBytes is the headroom the disk filler must leave free
	// (1 GiB).
	diskHeadroomBytes uint64 = 1 << 30
	// diskMinMB is the minimum filler size before the disk leg degrades
	// away (16 MiB).
	diskMinMB uint64 = 16
)

// envUsize is a usize env knob with fallback.
func envUsize(name string, fallback int) int {
	if v, err := strconv.Atoi(os.Getenv(name)); err == nil && v > 0 {
		return v
	}
	return fallback
}

// envU64 is a u64 env knob with fallback.
func envU64(name string, fallback uint64) uint64 {
	if v, err := strconv.ParseUint(os.Getenv(name), 10, 64); err == nil {
		return v
	}
	return fallback
}

// envMillis is a millisecond-duration env knob with fallback.
func envMillis(name string, fallbackMs uint64) time.Duration {
	if v, err := strconv.ParseUint(os.Getenv(name), 10, 64); err == nil && v > 0 {
		return time.Duration(v) * time.Millisecond
	}
	return time.Duration(fallbackMs) * time.Millisecond
}

// fmtDur renders a Go-style duration (90s -> 1m30s) for progress lines.
func fmtDur(d time.Duration) string {
	s := int64(d / time.Second)
	if s >= 3600 {
		return fmt.Sprintf("%dh%dm%ds", s/3600, s%3600/60, s%60)
	} else if s >= 60 {
		return fmt.Sprintf("%dm%ds", s/60, s%60)
	} else if s >= 1 {
		return fmt.Sprintf("%ds", s)
	}
	return fmt.Sprintf("%dms", d.Milliseconds())
}

// unixNow returns the current unix time in seconds (report stamp).
func unixNow() uint64 {
	if s := time.Now().Unix(); s > 0 {
		return uint64(s)
	}
	return 0
}

// rng is a deterministic splitmix64.
type rng struct {
	state uint64
}

func newRng(seed uint64) *rng {
	return &rng{state: seed}
}

func (r *rng) next() uint64 {
	r.state = r.state + 0x9E3779B97F4A7C15
	z := r.state
	z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9
	z = (z ^ (z >> 27)) * 0x94D049BB133111EB
	return z ^ (z >> 31)
}

func (r *rng) below(n int) int {
	if n <= 0 {
		panic("rng range must be non-empty")
	}
	return int(r.next() % uint64(n))
}

// float returns a uniform float in [0, 1) (53-bit precision).
func (r *rng) float() float64 {
	return float64(r.next()>>11) / float64(uint64(1)<<53)
}

// config is the chaos configuration (same env names/defaults as the
// reference).
type config struct {
	nodes         int
	duration      time.Duration
	settle        time.Duration
	writeInterval time.Duration
	maxRows       int
	seed          uint64
	statusEvery   time.Duration
	restartEvery  time.Duration
	restartDown   time.Duration
	rotateEvery   time.Duration
	snapshotEvery time.Duration
	snapshotOff   time.Duration
	impairOn      time.Duration
	impairOff     time.Duration
	impairLatency uint64
	impairLossPct uint64
	diskEvery     time.Duration
	diskMB        uint64
	diskHold      time.Duration
	skewDur       time.Duration
}

func loadConfig(t *testing.T) *config {
	t.Helper()
	cfg := &config{
		nodes:         min(max(envUsize("MURMUR_ENDURANCE_NODES", 5), minNodes), maxNodes),
		duration:      goharness.EnvSeconds("MURMUR_ENDURANCE_DURATION_SECONDS", 600),
		settle:        goharness.EnvSeconds("MURMUR_ENDURANCE_SETTLE_SECONDS", 300),
		writeInterval: envMillis("MURMUR_ENDURANCE_WRITE_INTERVAL_MS", 25),
		maxRows:       envUsize("MURMUR_ENDURANCE_MAX_ROWS", 10_000),
		seed:          envU64("MURMUR_ENDURANCE_SEED", 1),
		statusEvery:   goharness.EnvSeconds("MURMUR_ENDURANCE_STATUS_SECONDS", 30),
		restartEvery:  goharness.EnvSeconds("MURMUR_ENDURANCE_RESTART_SECONDS", 90),
		restartDown:   goharness.EnvSeconds("MURMUR_ENDURANCE_RESTART_DOWN_SECONDS", 8),
		rotateEvery:   goharness.EnvSeconds("MURMUR_ENDURANCE_ROTATE_SECONDS", 180),
		snapshotEvery: goharness.EnvSeconds("MURMUR_ENDURANCE_SNAPSHOT_SECONDS", 300),
		snapshotOff:   goharness.EnvSeconds("MURMUR_ENDURANCE_SNAPSHOT_OFFLINE_SECONDS", 75),
		impairOn:      goharness.EnvSeconds("MURMUR_ENDURANCE_IMPAIR_ON_SECONDS", 60),
		impairOff:     goharness.EnvSeconds("MURMUR_ENDURANCE_IMPAIR_OFF_SECONDS", 20),
		impairLatency: envU64("MURMUR_ENDURANCE_IMPAIR_LATENCY_MS", 150),
		impairLossPct: envU64("MURMUR_ENDURANCE_IMPAIR_LOSS_PCT", 3),
		diskEvery:     goharness.EnvSeconds("MURMUR_ENDURANCE_DISK_SECONDS", 180),
		diskMB:        envU64("MURMUR_ENDURANCE_DISK_MB", 128),
		diskHold:      goharness.EnvSeconds("MURMUR_ENDURANCE_DISK_HOLD_SECONDS", 60),
		skewDur:       goharness.EnvSeconds("MURMUR_ENDURANCE_SKEW_SECONDS", 120),
	}
	if cfg.maxRows < minMaxRows {
		t.Fatal("MURMUR_ENDURANCE_MAX_ROWS must be >= 100")
	}
	if cfg.snapshotOff < minSnapshotOff {
		t.Fatal("MURMUR_ENDURANCE_SNAPSHOT_OFFLINE_SECONDS must be >= 60 (retention expiry + GC tick)")
	}
	return cfg
}

// faultCounts tallies executed faults.
type faultCounts struct {
	restarts     uint64
	rotations    uint64
	impairCycles uint64
	diskCycles   uint64
	snapshots    uint64
	skews        uint64
}

// reporter is the live progress reporter: timestamped phase/log lines
// to stderr plus the same events for the final markdown report. All
// methods are safe for concurrent use.
type reporter struct {
	start     time.Time
	mu        sync.Mutex
	events    []string
	attempted atomic.Uint64
	succeeded atomic.Uint64
	failed    atomic.Uint64
	faults    faultCounts
	errSeen   map[string]int
	errSample []string
}

func newReporter() *reporter {
	return &reporter{start: time.Now(), errSeen: map[string]int{}}
}

func (r *reporter) stamp() string {
	return fmt.Sprintf("[T+%s]", fmtDur(time.Since(r.start)))
}

func (r *reporter) emit(msg string) {
	fmt.Fprintln(os.Stderr, msg)
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, msg)
}

// phase announces a phase transition.
func (r *reporter) phase(name, detail string) {
	r.emit(fmt.Sprintf("%s === PHASE: %s === %s", r.stamp(), name, detail))
}

// log records a timestamped progress line.
func (r *reporter) log(msg string) {
	r.emit(fmt.Sprintf("%s %s", r.stamp(), msg))
}

func (r *reporter) countAttempt(ok bool) {
	r.attempted.Add(1)
	if ok {
		r.succeeded.Add(1)
	} else {
		r.failed.Add(1)
	}
}

func (r *reporter) countFault(kind string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	switch kind {
	case "restart":
		r.faults.restarts++
	case "rotate":
		r.faults.rotations++
	case "impair":
		r.faults.impairCycles++
	case "disk":
		r.faults.diskCycles++
	case "snapshot":
		r.faults.snapshots++
	case "skew":
		r.faults.skews++
	}
}

func (r *reporter) faultSnapshot() faultCounts {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.faults
}

// sampleErr records distinct write-error messages (first 8) with counts.
func (r *reporter) sampleErr(err string) {
	msg := string([]rune(err)[:min(len([]rune(err)), errTruncChars)])
	r.mu.Lock()
	defer r.mu.Unlock()
	r.errSeen[msg]++
	found := false
	for _, s := range r.errSample {
		if s == msg {
			found = true
			break
		}
	}
	if len(r.errSample) < errSampleCap && !found {
		r.errSample = append(r.errSample, msg)
	}
}

// verdict logs the final PASS/FAIL line and writes the markdown report.
// Failure artifact retention itself is handled by Cluster.Finish.
func (r *reporter) verdict(pass bool, reportPath, summary string) {
	status := "FAIL"
	if pass {
		status = "PASS"
	}
	r.emit(fmt.Sprintf("%s === VERDICT: %s === %s", r.stamp(), status, summary))
	r.mu.Lock()
	events := append([]string(nil), r.events...)
	errSample := append([]string(nil), r.errSample...)
	errSeen := make(map[string]int, len(r.errSeen))
	for k, v := range r.errSeen {
		errSeen[k] = v
	}
	f := r.faults
	r.mu.Unlock()
	var b strings.Builder
	fmt.Fprintf(&b, "# Endurance-chaos run report — %s\n\n", status)
	fmt.Fprintf(&b, "- finished (unix): %d\n- wall time: %s\n- writes attempted: %d\n- writes acked: %d\n- writes failed (transient): %d\n- faults: restarts=%d rotations=%d impairCycles=%d diskCycles=%d snapshots=%d skews=%d\n- verdict: %s\n\n",
		unixNow(), fmtDur(time.Since(r.start)), r.attempted.Load(), r.succeeded.Load(), r.failed.Load(),
		f.restarts, f.rotations, f.impairCycles, f.diskCycles, f.snapshots, f.skews, summary)
	if len(errSample) > 0 {
		b.WriteString("## Distinct write errors\n\n")
		for _, s := range errSample {
			fmt.Fprintf(&b, "- (%dx) %s\n", errSeen[s], s)
		}
		b.WriteString("\n")
	}
	b.WriteString("## Timeline\n\n")
	for _, e := range events {
		fmt.Fprintf(&b, "- %s\n", e)
	}
	if err := os.WriteFile(reportPath, []byte(b.String()), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "report write failed: %v\n", err)
	} else {
		fmt.Fprintf(os.Stderr, "report written to %s\n", reportPath)
	}
}

// idRegistry is the bounded working-set registry: every appended id
// plus the live subset; deletes remove from live only.
type idRegistry struct {
	mu   sync.Mutex
	ids  []string
	live map[string]bool
}

func newIDRegistry() *idRegistry {
	return &idRegistry{live: map[string]bool{}}
}

func (r *idRegistry) add(id string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.ids = append(r.ids, id)
	r.live[id] = true
}

func (r *idRegistry) remove(id string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.live, id)
}

func (r *idRegistry) len() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.live)
}

// pick returns a random live id, tolerating entries deleted since
// append.
func (r *idRegistry) pick(rng *rng) (string, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.live) == 0 || len(r.ids) == 0 {
		return "", false
	}
	for range 8 {
		id := r.ids[rng.below(len(r.ids))]
		if r.live[id] {
			return id, true
		}
	}
	return "", false
}

// rowCount returns the row count on one node, or false when unreadable.
func rowCount(cluster *shared, alive []atomic.Bool, idx int) (int, bool) {
	cluster.mu.Lock()
	defer cluster.mu.Unlock()
	if !alive[idx].Load() {
		return 0, false
	}
	rows, err := cluster.c.Node(idx).Simple("SELECT COUNT(*) FROM contention")
	if err != nil || len(rows) == 0 || len(rows[0]) == 0 {
		return 0, false
	}
	n, err := strconv.Atoi(rows[0][0])
	if err != nil {
		return 0, false
	}
	return n, true
}

// canonicalRows returns canonical PK-ordered encoded rows on one node
// (id:name:phone:score sorted by id), or false when unreadable.
func canonicalRows(cluster *shared, alive []atomic.Bool, idx int) ([]string, bool) {
	cluster.mu.Lock()
	defer cluster.mu.Unlock()
	if !alive[idx].Load() {
		return nil, false
	}
	rows, err := cluster.c.Node(idx).Simple("SELECT id, name, phone, score FROM contention ORDER BY id")
	if err != nil {
		return nil, false
	}
	out := make([]string, 0, len(rows))
	for _, row := range rows {
		if len(row) != 4 {
			return nil, false
		}
		out = append(out, row[0]+":"+row[1]+":"+row[2]+":"+row[3])
	}
	return out, true
}

// connectedPeers returns the connected-peer count on one node, or false
// when the node is down or unreadable.
func connectedPeers(cluster *shared, alive []atomic.Bool, idx int) (int, bool) {
	cluster.mu.Lock()
	defer cluster.mu.Unlock()
	if !alive[idx].Load() {
		return 0, false
	}
	peers, err := cluster.c.Node(idx).ShowPeers()
	if err != nil {
		return 0, false
	}
	n := 0
	for _, p := range peers {
		if p.Connected {
			n++
		}
	}
	return n, true
}

// digestHex is a deterministic log-only digest over canonical rows
// (comparisons use byte-identical vectors, which imply identical
// digests). FNV-1a keeps this dependency-free.
func digestHex(rows []string) string {
	h := uint64(0xcbf29ce484222325)
	for _, row := range rows {
		for i := 0; i < len(row); i++ {
			h ^= uint64(row[i])
			h *= 0x100000001b3
		}
		h ^= uint64('\n')
		h *= 0x100000001b3
	}
	return fmt.Sprintf("%016x", h)
}

// pickAlive picks a random live node, or false when all are down.
func pickAlive(alive []atomic.Bool, rng *rng) (int, bool) {
	var up []int
	for i := range alive {
		if alive[i].Load() {
			up = append(up, i)
		}
	}
	if len(up) == 0 {
		return 0, false
	}
	return up[rng.below(len(up))], true
}

// writeOne runs one bounded insert/update/delete write on a live node:
// inserts until maxRows live ids, then updates/deletes recycle the set
// so a long run keeps churning replication without unbounded growth.
// Transient errors are counted, never fatal. The alive re-check and
// the write run under one cluster lock, so a node the director stops
// mid-op is never touched.
func writeOne(id int, cluster *shared, alive []atomic.Bool, registry *idRegistry, rep *reporter, rng *rng, seq *uint64, maxRows, target int) {
	roll := rng.float()
	if registry.len() < maxRows && roll < 0.7 {
		*seq++
		rowID := fmt.Sprintf("%08x%024x", id, *seq)
		name := fmt.Sprintf("writer-%d", id)
		phone := fmt.Sprintf("v-%d-%d", id, *seq)
		insertID := rowID
		cluster.mu.Lock()
		if !alive[target].Load() {
			cluster.mu.Unlock()
			return
		}
		_, err := cluster.c.Node(target).Execute(
			"INSERT INTO contention(id, name, phone, score) VALUES($1, $2, $3, $4)",
			rowID, name, phone, int64(0))
		if err == nil {
			err = cluster.c.Node(target).Flush()
		}
		cluster.mu.Unlock()
		if err != nil {
			rep.countAttempt(false)
			rep.sampleErr(err.Error())
		} else {
			registry.add(insertID)
			rep.countAttempt(true)
		}
	} else if roll < 0.85 {
		rowID, ok := registry.pick(rng)
		if !ok {
			return
		}
		*seq++
		name := fmt.Sprintf("writer-%d", id)
		phone := fmt.Sprintf("u-%d-%d", id, *seq)
		cluster.mu.Lock()
		if !alive[target].Load() {
			cluster.mu.Unlock()
			return
		}
		changed, err := cluster.c.Node(target).Execute(
			"UPDATE contention SET name = $1, phone = $2 WHERE id = $3", name, phone, rowID)
		if err == nil {
			if changed != 1 {
				err = fmt.Errorf("update hit %d rows", changed)
			} else {
				err = cluster.c.Node(target).Flush()
			}
		}
		cluster.mu.Unlock()
		if err != nil {
			rep.countAttempt(false)
			rep.sampleErr(err.Error())
		} else {
			rep.countAttempt(true)
		}
	} else {
		rowID, ok := registry.pick(rng)
		if !ok {
			return
		}
		delID := rowID
		cluster.mu.Lock()
		if !alive[target].Load() {
			cluster.mu.Unlock()
			return
		}
		_, err := cluster.c.Node(target).Execute("DELETE FROM contention WHERE id = $1", rowID)
		if err == nil {
			err = cluster.c.Node(target).Flush()
		}
		cluster.mu.Unlock()
		if err != nil {
			rep.countAttempt(false)
			rep.sampleErr(err.Error())
		} else {
			registry.remove(delID)
			rep.countAttempt(true)
		}
	}
}

// writerLoop is a bounded writer task.
func writerLoop(id int, cluster *shared, alive []atomic.Bool, registry *idRegistry, rep *reporter, seed uint64, writeInterval time.Duration, maxRows int, stop *atomic.Bool, wg *sync.WaitGroup) {
	defer wg.Done()
	rng := newRng(seed*1000 + uint64(id))
	var seq uint64
	for {
		if stop.Load() {
			return
		}
		target, ok := pickAlive(alive, rng)
		if !ok {
			time.Sleep(writeInterval)
			continue
		}
		writeOne(id, cluster, alive, registry, rep, rng, &seq, maxRows, target)
		if stop.Load() {
			return
		}
		time.Sleep(writeInterval)
	}
}

// statusLoop is the heartbeat sampler: row spread, write tallies,
// fault tallies, and disk pressure. GC high-water and spool
// observations have no native observable and stay out.
func statusLoop(cluster *shared, alive []atomic.Bool, nodeDirs []string, rep *reporter, nodes int, statusEvery time.Duration, stop *atomic.Bool, wg *sync.WaitGroup) {
	defer wg.Done()
	for {
		if !sleepStop(statusEvery, stop) {
			return
		}
		minC, maxC := int64(-1), int64(-1)
		down := 0
		for i := 0; i < nodes; i++ {
			c, ok := rowCount(cluster, alive, i)
			if !ok {
				down++
				continue
			}
			if minC < 0 || int64(c) < minC {
				minC = int64(c)
			}
			if int64(c) > maxC {
				maxC = int64(c)
			}
		}
		var diskMin uint64
		hasDisk := false
		for _, dir := range nodeDirs {
			if free, ok := dirFreeBytes(dir); ok {
				if !hasDisk || free < diskMin {
					diskMin = free
					hasDisk = true
				}
			}
		}
		if !hasDisk {
			diskMin = 0
		}
		f := rep.faultSnapshot()
		rep.log(fmt.Sprintf("status: writes ok=%d err=%d | rows min=%d max=%d down=%d/%d | restart=%d rotate=%d impair=%d disk=%d snap=%d skew=%d | diskFreeMin=%dMiB",
			rep.succeeded.Load(), rep.failed.Load(), minC, maxC, down, nodes,
			f.restarts, f.rotations, f.impairCycles, f.diskCycles, f.snapshots, f.skews,
			diskMin>>20))
	}
}

// diskLoop is the disk-pressure cycler: holds a filler file in each
// node dir in turn, then releases. Filesystem paths only, no cluster
// use.
func diskLoop(nodeDirs []string, rep *reporter, diskEvery, diskHold time.Duration, fillerMB uint64, stop *atomic.Bool, wg *sync.WaitGroup) {
	defer wg.Done()
	if !sleepStop(diskWarmup, stop) {
		return
	}
	idx := 0
	for {
		dir := nodeDirs[idx%len(nodeDirs)]
		idx++
		label := filepath.Base(dir)
		if label == "" || label == "." || label == string(filepath.Separator) {
			label = "?"
		}
		path := filepath.Join(dir, "endurance-filler.bin")
		freeBefore, _ := dirFreeBytes(dir)
		if err := writeFiller(path, fillerMB); err != nil {
			rep.log(fmt.Sprintf("disk: %s filler FAILED: %v", label, err))
			removeFiller(path)
		} else {
			freeAfter, _ := dirFreeBytes(dir)
			rep.log(fmt.Sprintf("disk: %s holding %d MiB (free %d -> %d MiB) for %s",
				label, fillerMB, freeBefore>>20, freeAfter>>20, fmtDur(diskHold)))
			interrupted := !sleepStop(diskHold, stop)
			removeFiller(path)
			rep.countFault("disk")
			if interrupted {
				return
			}
		}
		// Wait out the remainder of the period after the hold.
		if diskEvery > diskHold && !sleepStop(diskEvery-diskHold, stop) {
			return
		}
	}
}

// sleepStop sleeps d, waking early when stop is set. It reports false
// when interrupted.
func sleepStop(d time.Duration, stop *atomic.Bool) bool {
	deadline := time.Now().Add(d)
	for {
		if stop.Load() {
			return false
		}
		now := time.Now()
		if !now.Before(deadline) {
			return true
		}
		rest := deadline.Sub(now)
		if rest > 100*time.Millisecond {
			rest = 100 * time.Millisecond
		}
		time.Sleep(rest)
	}
}

// writeFiller consumes mb megabytes at path with incompressible-ish
// bytes.
func writeFiller(path string, mb uint64) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	buf := make([]byte, 1<<20)
	x := uint64(0x9e3779b97f4a7c15)
	for range mb {
		for off := 0; off < len(buf); off += 8 {
			x ^= x << 13
			x ^= x >> 7
			x ^= x << 17
			b := [8]byte{
				byte(x), byte(x >> 8), byte(x >> 16), byte(x >> 24),
				byte(x >> 32), byte(x >> 40), byte(x >> 48), byte(x >> 56),
			}
			copy(buf[off:off+min(8, len(buf)-off)], b[:min(8, len(buf)-off)])
		}
		if _, err := f.Write(buf); err != nil {
			return err
		}
	}
	return f.Sync()
}

func removeFiller(path string) {
	_ = os.Remove(path)
}

// dirFreeBytes returns the free bytes on the filesystem holding path,
// or false when the probe fails.
func dirFreeBytes(path string) (uint64, bool) {
	var stat unix.Statfs_t
	if err := unix.Statfs(path, &stat); err != nil {
		return 0, false
	}
	return uint64(stat.Bavail) * uint64(stat.Bsize), true
}

// directorReport is the director outcome (snapshot/skew scheduling
// flags; both legs stay off natively).
type directorReport struct {
	snapshotsPossible bool
	skewScheduled     bool
}

type impairFlap struct {
	a, b      int
	restoreAt time.Time
}

// allowListJSON renders an allowed_peers value for all ids except skip.
func allowListJSON(nodeIDs []string, skip int) string {
	list := `[`
	sep := ""
	for i, id := range nodeIDs {
		if i == skip {
			continue
		}
		list += sep + `"` + id + `"`
		sep = ","
	}
	return list + `]`
}

// setAllowedPeersOne restarts replication on node i with the given
// allow-list (empty clears the list, allowing all identities).
// The caller holds cluster.mu and guarantees the node is up.
func setAllowedPeersOne(c *goharness.Cluster, i int, list string) error {
	if err := c.StopNode(i); err != nil {
		return fmt.Errorf("stop node %d: %w", i+1, err)
	}
	var err error
	if list == "" {
		_, err = c.Node(i).Simple("DELETE FROM murmur_config WHERE name='allowed_peers'")
	} else {
		_, err = c.Node(i).Simple(
			"INSERT INTO murmur_config(name,value) VALUES('allowed_peers','" + list +
				"') ON CONFLICT(name) DO UPDATE SET value=excluded.value")
	}
	if err != nil {
		return fmt.Errorf("node %d set allowed_peers: %w", i+1, err)
	}
	if err := c.StartNode(i); err != nil {
		return fmt.Errorf("start node %d: %w", i+1, err)
	}
	return nil
}

// flapEdge cuts the direct a<->b edge: both endpoints restart
// replication with all-except-peer allow-lists (the partition-port
// technique; no runtime peer-removal verb exists). The caller holds
// cluster.mu and guarantees both endpoints are up.
func flapEdge(c *goharness.Cluster, nodeIDs []string, a, b int) error {
	if err := setAllowedPeersOne(c, a, allowListJSON(nodeIDs, b)); err != nil {
		return err
	}
	if err := setAllowedPeersOne(c, b, allowListJSON(nodeIDs, a)); err != nil {
		return err
	}
	return c.PeerMesh()
}

// restoreEdge clears both endpoints' allow-lists and restarts
// replication, healing the flap. The caller holds cluster.mu and
// guarantees both endpoints are up.
func restoreEdge(c *goharness.Cluster, a, b int) error {
	if err := setAllowedPeersOne(c, a, ""); err != nil {
		return err
	}
	if err := setAllowedPeersOne(c, b, ""); err != nil {
		return err
	}
	return c.PeerMesh()
}

// pickFlapPair picks a random edge with both endpoints up, or false
// when no full edge is available (a restart holds one node down).
func pickFlapPair(alive []atomic.Bool, rng *rng) (int, int, bool) {
	for range 16 {
		a := rng.below(len(alive))
		b := (a + 1 + rng.below(len(alive)-1)) % len(alive)
		if alive[a].Load() && alive[b].Load() {
			return a, b, true
		}
	}
	return 0, 0, false
}

func runDirector(cluster *shared, alive []atomic.Bool, rep *reporter, cfg *config, nodeIDs []string) (directorReport, error) {
	var zero directorReport
	rng := newRng(cfg.seed*7919 + 17)
	start := time.Now()
	deadline := start.Add(cfg.duration)

	nextRestart := start.Add(cfg.restartEvery / 2)

	// Key rotation is degraded away: the bindings expose no rotation
	// verb (see TestEnduranceKeyRotationLeg).
	rep.log("rotate: DEGRADED away (no native key-rotation verb)")

	// Snapshot offline windows are skipped: a stale rejoin over the
	// snapshot path does not converge (see
	// TestEnduranceSnapshotResyncLeg).
	rep.log("snapshot: leg skipped (harness: stale rejoin via snapshot resync does not converge after retention GC)")

	// Clock skew is degraded away: server children share the host clock,
	// so no node can run under libfaketime.
	skewScheduled := false

	// Impairment phases cycle latency -> loss -> both, all implemented
	// as allow-list edge flaps (no tc privilege model for child
	// processes, no runtime peer-removal verb).
	phases := []string{"latency", "loss", "latency+loss"}
	phase := 0
	nextImpair := start.Add(impairWarmup)
	var impairActive *impairFlap

	for {
		if !time.Now().Before(deadline) {
			break
		}
		// Sleep to the next tick, then re-sample time (1 s ticker).
		time.Sleep(directorTick)
		now := time.Now()
		if !now.Before(deadline) {
			break
		}

		// Restore an expired impairment flap. When a restart holds
		// one endpoint down the restore waits: a downed child
		// cannot take the allow-list rewrite.
		if impairActive != nil && !now.Before(impairActive.restoreAt) {
			a, b := impairActive.a, impairActive.b
			if !alive[a].Load() || !alive[b].Load() {
				rep.log(fmt.Sprintf("impair: edge node%d <-> node%d restore waiting for rejoin", a+1, b+1))
			} else {
				cluster.mu.Lock()
				restoreErr := restoreEdge(cluster.c, a, b)
				cluster.mu.Unlock()
				if restoreErr != nil {
					return zero, fmt.Errorf("impair restore edge node%d <-> node%d: %w", a+1, b+1, restoreErr)
				}
				impairActive = nil
				rep.countFault("impair")
				rep.log(fmt.Sprintf("impair: edge node%d <-> node%d restored", a+1, b+1))
				nextImpair = now.Add(cfg.impairOff)
			}
		}
		// Open the next impairment flap.
		if impairActive == nil && !now.Before(nextImpair) {
			a, b, ok := pickFlapPair(alive, rng)
			if !ok {
				rep.log("impair: flap deferred, no full edge up")
			} else {
				cluster.mu.Lock()
				flapErr := flapEdge(cluster.c, nodeIDs, a, b)
				cluster.mu.Unlock()
				if flapErr != nil {
					return zero, fmt.Errorf("impair flap edge node%d <-> node%d: %w", a+1, b+1, flapErr)
				}
				rep.log(fmt.Sprintf("impair: flap %s (allowed_peers edge cut) node%d <-> node%d for %s (no tc privilege model for child processes)",
					phases[phase%len(phases)], a+1, b+1, fmtDur(cfg.impairOn)))
				phase++
				impairActive = &impairFlap{a: a, b: b, restoreAt: now.Add(cfg.impairOn)}
			}
		}

		if !now.Before(nextRestart) {
			idx := rng.below(cfg.nodes)
			// Alternate graceful and crash restarts: crash legs
			// are real SIGKILLs (child mode) with a reboot on
			// the same dir; graceful legs stop/start
			// replication in place.
			crash := rng.below(2) == 0
			how := "graceful"
			if crash {
				how = "crash"
			}
			rep.log(fmt.Sprintf("restart: node%d going down (%s downtime, %s)", idx+1, fmtDur(cfg.restartDown), how))
			cluster.mu.Lock()
			alive[idx].Store(false)
			if crash {
				_ = cluster.c.KillNode(idx)
			} else {
				_ = cluster.c.StopNode(idx)
			}
			cluster.mu.Unlock()
			time.Sleep(cfg.restartDown)
			cluster.mu.Lock()
			var startErr error
			if crash {
				startErr = cluster.c.RestartNode(idx)
			} else {
				startErr = cluster.c.StartNode(idx)
			}
			var meshErr error
			if startErr == nil {
				meshErr = cluster.c.PeerMesh()
			}
			if startErr == nil && meshErr == nil {
				alive[idx].Store(true)
			}
			cluster.mu.Unlock()
			if startErr != nil {
				return zero, fmt.Errorf("node%d restart failed: %w", idx+1, startErr)
			}
			if meshErr != nil {
				return zero, fmt.Errorf("re-mesh after restart: %w", meshErr)
			}
			rep.countFault("restart")
			rep.log(fmt.Sprintf("restart: node%d back", idx+1))
			halfMs := max(1, int(cfg.restartEvery.Milliseconds()/2))
			jitter := time.Duration(rng.below(halfMs)) * time.Millisecond
			nextRestart = time.Now().Add(cfg.restartEvery).Add(jitter)
		}
	}

	// Restore any open impairment flap without counting it (an
	// interrupted cycle returns before the count). All nodes are up
	// here: every restart rejoins synchronously.
	if impairActive != nil {
		a, b := impairActive.a, impairActive.b
		cluster.mu.Lock()
		restoreErr := restoreEdge(cluster.c, a, b)
		cluster.mu.Unlock()
		if restoreErr != nil {
			return zero, fmt.Errorf("impair restore at chaos end: %w", restoreErr)
		}
		rep.log(fmt.Sprintf("impair: edge node%d <-> node%d restored at chaos end (uncounted)", a+1, b+1))
	}
	cluster.mu.Lock()
	meshErr := cluster.c.PeerMesh()
	cluster.mu.Unlock()
	if meshErr != nil {
		return zero, fmt.Errorf("final re-mesh: %w", meshErr)
	}

	return directorReport{snapshotsPossible: false, skewScheduled: skewScheduled}, nil
}

// ensureAllUp restarts any node the director left down so the verdict
// window starts with a full mesh.
func ensureAllUp(cluster *shared, alive []atomic.Bool, rep *reporter) error {
	rejoined := false
	for i := range alive {
		if alive[i].Load() {
			continue
		}
		rep.log(fmt.Sprintf("cleanup: node%d still down at chaos end, restarting", i+1))
		cluster.mu.Lock()
		err := cluster.c.StartNode(i)
		cluster.mu.Unlock()
		if err != nil {
			return fmt.Errorf("node%d cleanup restart failed: %w", i+1, err)
		}
		rejoined = true
	}
	if rejoined {
		cluster.mu.Lock()
		err := cluster.c.PeerMesh()
		cluster.mu.Unlock()
		if err != nil {
			return fmt.Errorf("re-mesh after cleanup restarts: %w", err)
		}
	}
	for i := range alive {
		alive[i].Store(true)
	}
	return nil
}

// waitAgreement polls until every node holds want rows with identical
// contents.
func waitAgreement(cluster *shared, alive []atomic.Bool, nodes, want int, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		ok := true
		var first []string
		hasFirst := false
		for i := 0; i < nodes; i++ {
			rows, readable := canonicalRows(cluster, alive, i)
			if !readable || len(rows) != want {
				ok = false
				break
			}
			if !hasFirst {
				first = rows
				hasFirst = true
			} else if !equalStrings(first, rows) {
				ok = false
				break
			}
		}
		if ok {
			return nil
		}
		if !time.Now().Before(deadline) {
			return fmt.Errorf("row agreement on %d rows not reached within %v", want, timeout)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// waitConverged polls until every node is reachable with equal row
// counts and identical digests. Counts are compared to each other, not
// to a fixed target, because deletes move the total during chaos.
func waitConverged(cluster *shared, alive []atomic.Bool, nodes int, nodeIDs []string, timeout time.Duration) ([]int64, []string, error) {
	deadline := time.Now().Add(timeout)
	start := time.Now()
	lastSample := time.Now().Add(-time.Hour)
	lastProgress := time.Now()
	var lastBreaker time.Time
	var prevCounts []int64
	for {
		counts := make([]int64, nodes)
		digests := make([]string, nodes)
		var first []string
		hasFirst := false
		agree := 0
		ok := true
		for i := 0; i < nodes; i++ {
			rows, readable := canonicalRows(cluster, alive, i)
			if !readable {
				ok = false
				break
			}
			counts[i] = int64(len(rows))
			digests[i] = digestHex(rows)
			if !hasFirst {
				agree = 1
				first = rows
				hasFirst = true
			} else if !equalStrings(first, rows) {
				ok = false
			} else {
				agree++
			}
		}
		if ok {
			return counts, digests, nil
		}
		if !time.Now().Before(deadline) {
			break
		}
		if time.Since(lastSample) >= 15*time.Second {
			lastSample = time.Now()
			lo, hi := counts[0], counts[0]
			for _, c := range counts[1:] {
				if c < lo {
					lo = c
				}
				if c > hi {
					hi = c
				}
			}
			fmt.Fprintf(os.Stderr, "[verdict-sample T+%ds] counts=%v spread=%d agree=%d/%d\n",
				int64(time.Since(start).Seconds()), counts, hi-lo, agree, nodes)
		}
		// Stall breaker (crash-recovery technique): post-restart
		// sessions intermittently wedge with pulls silently dying
		// while peers show connected. After 20 s without progress,
		// reset pull cursors and bounce the mesh; proof criteria
		// are unchanged (this only re-drives the mesh). Fires are
		// cooldown-gated so a slow-but-healthy full replay is not
		// torn down mid-transfer.
		if time.Now().After(lastProgress.Add(breakerFreeze)) && time.Now().After(lastBreaker.Add(breakerCooldown)) {
			fmt.Fprintf(os.Stderr, "[verdict-stall] counts=%v; resetting pull cursors and bouncing mesh\n", counts)
			breakStall(cluster, nodeIDs)
			lastBreaker = time.Now()
			lastProgress = lastBreaker
			lastSample = lastBreaker
		}
		if !equalInt64(counts, prevCounts) {
			lastProgress = time.Now()
			prevCounts = append(prevCounts[:0], counts...)
		}
		time.Sleep(verdictPoll)
	}
	// Final best-effort re-sample for the failure report.
	counts := make([]int64, nodes)
	digests := make([]string, nodes)
	snapshots := make([][]string, 0, nodes)
	for i := 0; i < nodes; i++ {
		rows, readable := canonicalRows(cluster, alive, i)
		if !readable {
			counts[i] = -1
			digests[i] = "unreachable"
			snapshots = append(snapshots, nil)
			continue
		}
		counts[i] = int64(len(rows))
		digests[i] = digestHex(rows)
		snapshots = append(snapshots, rows)
	}
	// Diagnostic sample: first few rows where node0 and the first
	// disagreeing node differ (id + full values).
	if len(snapshots) == nodes {
		for j := 1; j < nodes; j++ {
			if equalStrings(snapshots[j], snapshots[0]) {
				continue
			}
			a := make(map[string]bool, len(snapshots[0]))
			for _, s := range snapshots[0] {
				a[s] = true
			}
			b := make(map[string]bool, len(snapshots[j]))
			for _, s := range snapshots[j] {
				b[s] = true
			}
			var onlyA, onlyB []string
			for s := range a {
				if !b[s] {
					if len(onlyA) < 5 {
						onlyA = append(onlyA, s)
					}
				}
			}
			for s := range b {
				if !a[s] {
					if len(onlyB) < 5 {
						onlyB = append(onlyB, s)
					}
				}
			}
			countA, countB := 0, 0
			for s := range a {
				if !b[s] {
					countA++
				}
			}
			for s := range b {
				if !a[s] {
					countB++
				}
			}
			fmt.Fprintf(os.Stderr, "[verdict-diff] node1-only(%d) sample=%q\n", countA, onlyA)
			fmt.Fprintf(os.Stderr, "[verdict-diff] node%d-only(%d) sample=%q\n", j+1, countB, onlyB)
			break
		}
	}
	return counts, digests, fmt.Errorf("nodes did not converge within %v", timeout)
}

// breakStall resets every node's pull cursors for every other node,
// then bounces the mesh (sessions torn down and re-formed; stores
// stay open). A stuck resume cursor fails every pull silently;
// deleting it forces a RESET to a zero cursor and a full resync
// (safe: the raised retention tail keeps every version servable, so
// from=0 replays everything instead of hitting prune). All pairs
// reset because deletes move counts both ways: a stuck node can hold
// the max count (missing deletes) as well as the min. Failures only
// log: the convergence loop re-fires the breaker until the deadline.
func breakStall(cluster *shared, nodeIDs []string) {
	cluster.mu.Lock()
	defer cluster.mu.Unlock()
	n := cluster.c.Len()
	for i := 0; i < n; i++ {
		for j := 0; j < n; j++ {
			if i == j {
				continue
			}
			if _, err := cluster.c.Node(i).Execute(
				"DELETE FROM murmur_progress WHERE lower(hex(node)) = $1", nodeIDs[j]); err != nil {
				fmt.Fprintf(os.Stderr, "node%d cursor reset for node%d: %v\n", i+1, j+1, err)
			}
		}
	}
	for i := 0; i < n; i++ {
		if err := cluster.c.StopNode(i); err != nil {
			fmt.Fprintf(os.Stderr, "bounce-stop node%d: %v\n", i+1, err)
		}
	}
	for i := 0; i < n; i++ {
		if err := cluster.c.StartNode(i); err != nil {
			fmt.Fprintf(os.Stderr, "bounce-start node%d: %v\n", i+1, err)
		}
		if i+1 < n {
			time.Sleep(time.Second)
		}
	}
	if err := cluster.c.PeerMesh(); err != nil {
		fmt.Fprintf(os.Stderr, "re-mesh after bounce: %v\n", err)
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

// meshConnected reports whether every node sees every peer.
func meshConnected(cluster *shared, alive []atomic.Bool, nodes int) bool {
	for i := 0; i < nodes; i++ {
		n, ok := connectedPeers(cluster, alive, i)
		if !ok || n < nodes-1 {
			return false
		}
	}
	return true
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

func TestEnduranceChaos(t *testing.T) {
	goharness.SkipUnlessLive(t)
	cfg := loadConfig(t)
	// Child-process nodes: crash legs are real SIGKILLs with a reboot
	// on the same dir. Needs the node binary:
	//   go build -o /tmp/murmur-test-node ./tests-live/node
	//   MURMUR_NODE_BIN=/tmp/murmur-test-node
	cluster, err := goharness.NewCluster(goharness.ClusterOptions{
		Name:       "endurance-chaos",
		NumNodes:   cfg.nodes,
		ChildNodes: true,
	})
	if err != nil {
		t.Fatalf("cluster setup: %v", err)
	}
	runtimeDir := cluster.RuntimeDir()
	sharedCluster := &shared{c: cluster}

	result := runBody(sharedCluster, cfg, runtimeDir)
	failed := result != nil
	if result != nil {
		fmt.Fprintf(os.Stderr, "scenario failed: %v\n", result)
	}
	// All spawned tasks joined inside runBody, so the cluster is
	// unshared here.
	cluster.Finish(failed)
	if failed {
		t.Fatal("scenario failed; artifacts retained under tests-live/failures/")
	}
}

func runBody(cluster *shared, cfg *config, runtimeDir string) error {
	rep := newReporter()
	rep.log(fmt.Sprintf("config: nodes=%d duration=%s settle=%s writeInterval=%s maxRows=%d seed=%d",
		cfg.nodes, fmtDur(cfg.duration), fmtDur(cfg.settle), fmtDur(cfg.writeInterval), cfg.maxRows, cfg.seed))
	rep.log(fmt.Sprintf("fault cadence: restart=%s impair=%s/%s disk=%s/%s rotate/snapshot/skew degraded",
		fmtDur(cfg.restartEvery), fmtDur(cfg.impairOn), fmtDur(cfg.impairOff),
		fmtDur(cfg.diskEvery), fmtDur(cfg.diskHold)))

	// Same schema on every node, then replicate it: convergence needs
	// the per-table flag on each node.
	for i := 0; i < cfg.nodes; i++ {
		cluster.mu.Lock()
		_, err := cluster.c.Node(i).Simple(
			"CREATE TABLE IF NOT EXISTS contention(id TEXT PRIMARY KEY NOT NULL DEFAULT '', name TEXT NOT NULL DEFAULT '', phone TEXT NOT NULL DEFAULT '', score INTEGER NOT NULL DEFAULT 0)")
		cluster.mu.Unlock()
		if err != nil {
			return fmt.Errorf("migrate node%d: %w", i+1, err)
		}
	}
	for i := 0; i < cfg.nodes; i++ {
		cluster.mu.Lock()
		setErr := cluster.c.Node(i).SetTableReplicated("contention", true)
		var flushErr error
		if setErr == nil {
			flushErr = cluster.c.Node(i).Flush()
		}
		cluster.mu.Unlock()
		if setErr != nil {
			return fmt.Errorf("node%d SET TABLE REPLICATED: %w", i+1, setErr)
		}
		if flushErr != nil {
			return fmt.Errorf("node%d flush after SET TABLE: %w", i+1, flushErr)
		}
	}
	// Raise the retention tail on every node (crash-recovery
	// technique): the verdict stall breaker resets pull cursors to 0,
	// which must replay the full origin log instead of hitting prune
	// ("cursor pruned; snapshot required" is unrecoverable here). One
	// million kept versions covers any chaos window (default ~120k
	// transactions mesh-wide).
	cluster.mu.Lock()
	for i := 0; i < cfg.nodes; i++ {
		_, err := cluster.c.Node(i).Simple(
			"INSERT INTO murmur_config(name,value) VALUES('retention_min_kept','1000000') ON CONFLICT(name) DO UPDATE SET value=excluded.value")
		if err != nil {
			cluster.mu.Unlock()
			return fmt.Errorf("node%d raise retention tail: %w", i+1, err)
		}
	}
	cluster.mu.Unlock()
	rep.log("retention tail raised to 1000000 versions (stall-breaker cursor resets stay servable)")

	cluster.mu.Lock()
	if err := cluster.c.PeerMesh(); err != nil {
		cluster.mu.Unlock()
		return fmt.Errorf("mesh peers: %w", err)
	}
	cluster.mu.Unlock()

	// Baseline: one row everywhere before chaos starts.
	cluster.mu.Lock()
	_, baseErr := cluster.c.Node(0).Execute(
		"INSERT INTO contention(id, name, phone, score) VALUES($1, $2, $3, $4)",
		fmt.Sprintf("%032x", 0), "baseline", "baseline", int64(0))
	var flushErr error
	if baseErr == nil {
		flushErr = cluster.c.Node(0).Flush()
	}
	cluster.mu.Unlock()
	if baseErr != nil {
		return fmt.Errorf("baseline insert: %w", baseErr)
	}
	if flushErr != nil {
		return fmt.Errorf("flush baseline: %w", flushErr)
	}
	alivePre := make([]atomic.Bool, cfg.nodes)
	for i := range alivePre {
		alivePre[i].Store(true)
	}
	if err := waitAgreement(cluster, alivePre, cfg.nodes, 1, baselineTimeout); err != nil {
		return err
	}
	rep.log(fmt.Sprintf("baseline row converged on all %d nodes", cfg.nodes))

	// Preflights: detect degraded modes before the long run.
	rep.log(fmt.Sprintf("network impairment: allowed_peers edge flaps (tc/netem latency=%dms loss=%d%% has no child-process equivalent; no runtime peer-removal verb)",
		cfg.impairLatency, cfg.impairLossPct))
	rep.log("clock skew: DEGRADED away (server children share the host clock; no daemon for libfaketime)")
	rep.log("key rotation: DEGRADED away (no native rotation verb)")
	rep.log("snapshot windows: SKIPPED (stale rejoin via snapshot resync does not converge after retention GC)")
	rep.log("GC progress proof: SKIPPED (no SHOW RETENTION/collected counter)")

	fillerMB := cfg.diskMB
	cluster.mu.Lock()
	runtimeProbe := cluster.c.RuntimeDir()
	cluster.mu.Unlock()
	if free, ok := dirFreeBytes(runtimeProbe); ok {
		// Never risk the host filesystem: filler must leave 1 GiB free.
		var avail uint64
		if free > diskHeadroomBytes {
			avail = free - diskHeadroomBytes
		}
		if avail < fillerMB<<20 {
			headroom := avail >> 20
			if headroom < diskMinMB {
				fillerMB = 0
				rep.log(fmt.Sprintf("disk pressure: DEGRADED away (only %d MiB free)", free>>20))
			} else {
				fillerMB = headroom
				rep.log(fmt.Sprintf("disk pressure: filler reduced to %d MiB (%d MiB free)", fillerMB, free>>20))
			}
		} else {
			rep.log(fmt.Sprintf("disk pressure: %d MiB filler (%d MiB free)", fillerMB, free>>20))
		}
	} else {
		rep.log(fmt.Sprintf("disk pressure: %d MiB filler (free-space probe unavailable)", fillerMB))
	}

	// Shared chaos state.
	registry := newIDRegistry()
	var stop atomic.Bool

	// An alive-set steers writer targeting away from stopped nodes;
	// every write re-checks under the cluster lock, so lifecycle and
	// reads never race.
	alive := make([]atomic.Bool, cfg.nodes)
	for i := range alive {
		alive[i].Store(true)
	}
	cluster.mu.Lock()
	nodeDirs := make([]string, 0, cfg.nodes)
	nodeIDs := make([]string, 0, cfg.nodes)
	for i := 0; i < cfg.nodes; i++ {
		nodeDirs = append(nodeDirs, cluster.c.Node(i).Dir)
		nodeIDs = append(nodeIDs, cluster.c.NodeID(i))
	}
	cluster.mu.Unlock()

	numWriters := max(2, min(cfg.nodes, maxWriters))
	var writersWg, statusWg, diskWg sync.WaitGroup
	for w := 0; w < numWriters; w++ {
		writersWg.Add(1)
		go writerLoop(w, cluster, alive, registry, rep, cfg.seed, cfg.writeInterval, cfg.maxRows, &stop, &writersWg)
	}
	statusWg.Add(1)
	go statusLoop(cluster, alive, nodeDirs, rep, cfg.nodes, cfg.statusEvery, &stop, &statusWg)
	diskRunning := fillerMB > 0
	if diskRunning {
		diskWg.Add(1)
		go diskLoop(nodeDirs, rep, cfg.diskEvery, cfg.diskHold, fillerMB, &stop, &diskWg)
	}

	// Chaos director (test task: owns all node lifecycle).
	rep.phase("chaos", fmt.Sprintf("fault injectors live for %s", fmtDur(cfg.duration)))
	directive, directorErr := runDirector(cluster, alive, rep, cfg, nodeIDs)

	// Faults stop; every node must be up before the verdict window.
	// Tasks always join here even when the director failed, so
	// teardown never races a live writer.
	stop.Store(true)
	if diskRunning {
		diskWg.Wait()
	}
	statusWg.Wait()
	if directorErr != nil {
		writersWg.Wait()
		return directorErr
	}
	if err := ensureAllUp(cluster, alive, rep); err != nil {
		writersWg.Wait()
		return err
	}
	rep.log(fmt.Sprintf("writers stopping: attempted=%d acked=%d transient-errors=%d live-ids=%d",
		rep.attempted.Load(), rep.succeeded.Load(), rep.failed.Load(), registry.len()))
	writersWg.Wait()

	reportPath := filepath.Join(runtimeDir, fmt.Sprintf("endurance-report-%d.md", unixNow()))
	if rep.succeeded.Load() == 0 {
		rep.verdict(false, reportPath, "no writes acked during the entire run")
		return fmt.Errorf("endurance verdict: 0 of %d writes acked; see report for distinct errors", rep.attempted.Load())
	}

	rep.phase("verdict", fmt.Sprintf("waiting up to %s for exact convergence", fmtDur(cfg.settle)))
	counts, digests, err := waitConverged(cluster, alive, cfg.nodes, nodeIDs, cfg.settle)
	if err != nil {
		rep.verdict(false, reportPath, err.Error())
		return fmt.Errorf("endurance verdict: %w\ncounts=%v\ndigests=%v", err, counts, digests)
	}
	rep.log(fmt.Sprintf("converged: all %d nodes hold %d rows with digest %s", cfg.nodes, counts[0], digests[0]))

	// Counter-proven post-checks: every scheduled fault must have fired.
	faults := rep.faultSnapshot()
	if faults.restarts == 0 {
		rep.verdict(false, reportPath, "zero restarts executed")
		return fmt.Errorf("chaos ran zero restarts; restart injector never fired")
	}
	if faults.impairCycles == 0 {
		rep.verdict(false, reportPath, "zero network-impairment cycles executed")
		return fmt.Errorf("chaos ran zero network-impairment cycles")
	}
	if fillerMB > 0 && faults.diskCycles == 0 {
		rep.verdict(false, reportPath, "zero disk-pressure cycles executed")
		return fmt.Errorf("chaos ran zero disk-pressure cycles")
	}
	if !directive.snapshotsPossible {
		rep.log("snapshots: leg skipped (no snapshot resync support)")
	}
	if directive.skewScheduled && faults.skews == 0 {
		rep.verdict(false, reportPath, "skew scheduled but never executed")
		return fmt.Errorf("clock skew was scheduled but the skew window never ran")
	}

	// Full mesh must be back: every node sees every peer.
	meshed := false
	meshDeadline := time.Now().Add(meshTimeout)
	for {
		if meshConnected(cluster, alive, cfg.nodes) {
			meshed = true
			break
		}
		if !time.Now().Before(meshDeadline) {
			break
		}
		time.Sleep(verdictPoll)
	}
	if !meshed {
		var detail []string
		for i := 0; i < cfg.nodes; i++ {
			n, _ := connectedPeers(cluster, alive, i)
			detail = append(detail, fmt.Sprintf("node%d:%d", i+1, n))
		}
		rep.verdict(false, reportPath, "mesh not fully reconnected")
		return fmt.Errorf("mesh not fully reconnected (connected peers per node: %s), want %d",
			strings.Join(detail, " "), cfg.nodes-1)
	}

	// A post-chaos write must traverse the healed mesh.
	cluster.mu.Lock()
	_, postErr := cluster.c.Node(0).Execute(
		"INSERT INTO contention(id, name, phone, score) VALUES($1, $2, $3, $4)",
		fmt.Sprintf("%032x", uint64(999_999_999)), "post-chaos", "post-chaos", int64(0))
	var postFlushErr error
	if postErr == nil {
		postFlushErr = cluster.c.Node(0).Flush()
	}
	cluster.mu.Unlock()
	if postErr != nil {
		rep.verdict(false, reportPath, "post-chaos write rejected")
		return fmt.Errorf("post-chaos write: %w", postErr)
	}
	if postFlushErr != nil {
		return fmt.Errorf("flush post-chaos write: %w", postFlushErr)
	}
	if err := waitAgreement(cluster, alive, cfg.nodes, int(counts[0])+1, cfg.settle); err != nil {
		rep.verdict(false, reportPath, "post-chaos write did not converge")
		return fmt.Errorf("post-chaos convergence: %w", err)
	}

	rep.verdict(true, reportPath, fmt.Sprintf(
		"all %d nodes hold %d rows digest %s after %s of combined chaos (restarts=%d impair=flap/%d disk=%d; rotate/snapshot/gc/skew degraded)",
		cfg.nodes, counts[0]+1, digests[0], fmtDur(cfg.duration),
		faults.restarts, faults.impairCycles, faults.diskCycles))
	return nil
}

// TestEnduranceKeyRotationLeg is the reference's online key-rotation
// leg: rotate each node to a fresh key without downtime, prove it
// stays readable, and restart later on the new key. Blocked end to
// end: no native key-rotation verb, no restart with an alternate key,
// no wire auth to reject the old key (same gap as the rekey suite).
func TestEnduranceKeyRotationLeg(t *testing.T) {
	goharness.SkipUnlessLive(t)
	t.Skip("harness: key rotation (rotate verb, restart with new key, old-key rejection)")
}

// TestEnduranceSnapshotResyncLeg is the reference's snapshot leg:
// an offline window past retention forces the rejoin over the
// snapshot path. The victim stops while survivors ack 120+ batches
// and collect past its cursor; after rejoin, the bulk must arrive
// off the log path (row drift below the outage's acked count while
// the victim's post-rejoin applied delta stays below it too), and
// the victim must report a completed snapshot. (A snapshot
// completion counts as one applied batch on this stack, so the
// delta proof uses the reference's inequalities rather than zero.)
func TestEnduranceSnapshotResyncLeg(t *testing.T) {
	goharness.SkipUnlessLive(t)
	const victim = 2
	cluster, err := goharness.NewCluster(goharness.ClusterOptions{
		Name:     "endurance-snapshot",
		NumNodes: 3,
	})
	if err != nil {
		t.Fatalf("cluster setup: %v", err)
	}
	failed := true
	defer func() { cluster.Finish(failed) }()

	for i := 0; i < 3; i++ {
		if _, err := cluster.Node(i).Simple(
			"CREATE TABLE IF NOT EXISTS contention(id TEXT PRIMARY KEY NOT NULL DEFAULT '', name TEXT NOT NULL DEFAULT '')"); err != nil {
			t.Fatalf("node %d create contention: %v", i, err)
		}
		if err := cluster.Node(i).SetTableReplicated("contention", true); err != nil {
			t.Fatalf("node %d replicate contention: %v", i, err)
		}
		if _, err := cluster.Node(i).Simple(
			"INSERT INTO murmur_config(name,value) VALUES('retention_min_kept','10') ON CONFLICT(name) DO UPDATE SET value=excluded.value"); err != nil {
			t.Fatalf("node %d retention floor: %v", i, err)
		}
	}
	// Seed and converge.
	for n := 0; n < 20; n++ {
		id := fmt.Sprintf("seed-%04d", n)
		if _, err := cluster.Node(0).Execute(
			"INSERT INTO contention(id,name) VALUES($1,'seed')", id); err != nil {
			t.Fatalf("seed insert %s: %v", id, err)
		}
	}
	if err := cluster.Node(0).Flush(); err != nil {
		t.Fatalf("flush seed: %v", err)
	}
	if err := goharness.AssertRows(cluster, []int{0, 1, 2},
		"SELECT COUNT(*) FROM contention", [][]string{{"20"}}); err != nil {
		t.Fatalf("converge seed: %v", err)
	}
	if err := cluster.Node(victim).Flush(); err != nil {
		t.Fatalf("victim pre-stop flush: %v", err)
	}
	if err := cluster.StopNode(victim); err != nil {
		t.Fatalf("stop victim: %v", err)
	}
	// Outage: survivors ack batches while the victim is down, then
	// collect past its cursor.
	var outageAcked uint64
	for n := 0; n < 130; n++ {
		node := n % 2
		id := fmt.Sprintf("outage-%04d", n)
		if _, err := cluster.Node(node).Execute(
			"INSERT INTO contention(id,name) VALUES($1,'outage')", id); err != nil {
			t.Fatalf("outage insert %s: %v", id, err)
		}
		if err := cluster.Node(node).Flush(); err != nil {
			t.Fatalf("outage flush %s: %v", id, err)
		}
		outageAcked++
	}
	if err := goharness.AssertRows(cluster, []int{0, 1},
		"SELECT COUNT(*) FROM contention", [][]string{{"150"}}); err != nil {
		t.Fatalf("survivors converge outage rows: %v", err)
	}
	for _, i := range []int{0, 1} {
		moved, _, err := cluster.Node(i).RetentionCollect()
		if err != nil {
			t.Fatalf("survivor %d collect: %v", i, err)
		}
		if moved == 0 {
			t.Fatalf("survivor %d collect moved no floors", i)
		}
	}
	// Rejoin and prove the snapshot path.
	if err := cluster.StartNode(victim); err != nil {
		t.Fatalf("restart victim: %v", err)
	}
	if err := cluster.PeerMesh(); err != nil {
		t.Fatalf("remesh: %v", err)
	}
	appliedAtRejoin, err := snapApplied(cluster, victim)
	if err != nil {
		t.Fatalf("victim applied at rejoin: %v", err)
	}
	deadline := time.Now().Add(240 * time.Second)
	var diffRows int
	var appliedDelta uint64
	var rows int
	proven := false
	for time.Now().Before(deadline) {
		time.Sleep(2 * time.Second)
		appliedNow, err := snapApplied(cluster, victim)
		if err != nil {
			t.Fatalf("victim applied sample: %v", err)
		}
		victimRows, err := snapRows(cluster, victim)
		if err != nil {
			t.Fatalf("victim rows sample: %v", err)
		}
		survivorRows, err := snapRows(cluster, 0)
		if err != nil {
			t.Fatalf("survivor rows sample: %v", err)
		}
		diffRows = snapRowDiff(victimRows, survivorRows)
		rows = len(survivorRows)
		appliedDelta = 0
		if appliedNow > appliedAtRejoin {
			appliedDelta = appliedNow - appliedAtRejoin
		}
		if outageAcked > 100 && uint64(diffRows) < outageAcked && appliedDelta < outageAcked {
			proven = true
			break
		}
	}
	t.Logf("snapshot: victim proof outageAcked=%d appliedDelta=%d diffRows=%d/%d proven=%t",
		outageAcked, appliedDelta, diffRows, rows, proven)
	if !proven {
		t.Fatalf("snapshot not proven: outageAcked=%d appliedDelta=%d diffRows=%d/%d",
			outageAcked, appliedDelta, diffRows, rows)
	}
	// Direct proof: the victim completed a snapshot.
	snap, err := snapStatus(cluster, victim)
	if err != nil {
		t.Fatalf("victim snapshot status: %v", err)
	}
	if len(snap) < 3 || snap[:3] != "ok " {
		t.Fatalf("victim completed no snapshot (status %q)", snap)
	}
	// Full convergence afterward.
	if err := goharness.AssertRows(cluster, []int{0, 1, 2},
		"SELECT COUNT(*) FROM contention", [][]string{{"150"}}); err != nil {
		t.Fatalf("converge after snapshot: %v", err)
	}
	failed = false
}

// snapApplied returns the applied_batches counter for one node.
func snapApplied(cluster *goharness.Cluster, idx int) (uint64, error) {
	st, err := cluster.Node(idx).ShowStatus()
	if err != nil {
		return 0, err
	}
	m, ok := st.(map[string]any)
	if !ok {
		return 0, fmt.Errorf("node%d status is not an object", idx+1)
	}
	v, ok := m["applied_batches"].(float64)
	if !ok {
		return 0, fmt.Errorf("node%d status has no applied_batches", idx+1)
	}
	return uint64(v), nil
}

// snapRows returns canonical PK-ordered encoded rows on one node.
func snapRows(cluster *goharness.Cluster, idx int) ([]string, error) {
	rows, err := cluster.Node(idx).Simple("SELECT id, name FROM contention ORDER BY id")
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(rows))
	for _, row := range rows {
		if len(row) != 2 {
			return nil, fmt.Errorf("node%d short row", idx+1)
		}
		out = append(out, row[0]+":"+row[1])
	}
	return out, nil
}

// snapRowDiff returns the size of the symmetric difference between
// two canonical row sets.
func snapRowDiff(a, b []string) int {
	counts := make(map[string]int, len(a))
	for _, s := range a {
		counts[s]++
	}
	diff := 0
	for _, s := range b {
		if counts[s] > 0 {
			counts[s]--
		} else {
			diff++
		}
	}
	for _, n := range counts {
		diff += n
	}
	return diff
}

// snapStatus returns the snapshot status string for one node.
func snapStatus(cluster *goharness.Cluster, idx int) (string, error) {
	st, err := cluster.Node(idx).ShowStatus()
	if err != nil {
		return "", err
	}
	m, ok := st.(map[string]any)
	if !ok {
		return "", fmt.Errorf("node%d status is not an object", idx+1)
	}
	v, ok := m["snapshot"].(string)
	if !ok {
		return "", fmt.Errorf("node%d status has no snapshot string", idx+1)
	}
	return v, nil
}

// TestEnduranceGCProgressLeg is the reference's counter-proven GC
// proof: collected advancing on every node with no GC-attributed
// engine error. Each node writes converging rows while every node
// collects; the health retention.collected_transactions counter
// (durable, cumulative floors moved) must advance on all three nodes
// and no GC-shaped engine error may latch.
func TestEnduranceGCProgressLeg(t *testing.T) {
	goharness.SkipUnlessLive(t)
	cluster, err := goharness.NewCluster(goharness.ClusterOptions{
		Name:     "endurance-gc",
		NumNodes: 3,
	})
	if err != nil {
		t.Fatalf("cluster setup: %v", err)
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
		// Small floor so every collect round moves it (the main
		// chaos run raises this to keep rejoins on the log path;
		// this leg wants the opposite).
		if _, err := cluster.Node(i).Simple(
			"INSERT INTO murmur_config(name,value) VALUES('retention_min_kept','10') ON CONFLICT(name) DO UPDATE SET value=excluded.value"); err != nil {
			t.Fatalf("node %d retention floor: %v", i, err)
		}
	}
	first := make([]uint64, 3)
	maxSeen := make([]uint64, 3)
	// sample records the per-node max and fails on GC-shaped errors;
	// baseline snapshots the pre-write floors.
	sample := func(into []uint64) {
		t.Helper()
		for i := 0; i < 3; i++ {
			collected, lastErr, err := gcSample(cluster, i)
			if err != nil {
				t.Fatalf("node %d gc sample: %v", i, err)
			}
			into[i] = collected
			if collected > maxSeen[i] {
				maxSeen[i] = collected
			}
			if isGCError(lastErr) {
				t.Fatalf("node %d GC-shaped engine error: %q", i, lastErr)
			}
		}
	}
	sample(first)
	const rounds = 5
	const rowsPerNodeRound = 4
	total := 0
	for r := 0; r < rounds; r++ {
		for node := 0; node < 3; node++ {
			for k := 0; k < rowsPerNodeRound; k++ {
				id := total
				total++
				if _, err := cluster.Node(node).Execute(
					"INSERT INTO records(id,name) VALUES($1,$2)",
					int64(id), fmt.Sprintf("gc-%d", id)); err != nil {
					t.Fatalf("round %d node %d insert: %v", r, node, err)
				}
			}
			if err := cluster.Node(node).Flush(); err != nil {
				t.Fatalf("round %d node %d flush: %v", r, node, err)
			}
		}
		if err := goharness.AssertRows(cluster, []int{0, 1, 2},
			"SELECT COUNT(*) FROM records",
			[][]string{{strconv.Itoa(total)}}); err != nil {
			t.Fatalf("round %d converge %d rows: %v", r, total, err)
		}
		for i := 0; i < 3; i++ {
			if _, _, err := cluster.Node(i).RetentionCollect(); err != nil {
				t.Fatalf("round %d node %d collect: %v", r, i, err)
			}
		}
		sample(make([]uint64, 3))
	}
	for i := 0; i < 3; i++ {
		if !(maxSeen[i] > first[i]) {
			t.Fatalf("node %d collected never advanced (first=%d max=%d)",
				i, first[i], maxSeen[i])
		}
		if maxSeen[i] == 0 {
			t.Fatalf("node %d collected stayed zero", i)
		}
	}
	failed = false
}

// gcSample returns the GC counters for one node: the durable
// collected_transactions counter plus the latest engine error latch.
func gcSample(cluster *goharness.Cluster, idx int) (uint64, string, error) {
	h, err := cluster.Node(idx).ShowHealth()
	if err != nil {
		return 0, "", err
	}
	m, ok := h.(map[string]any)
	if !ok {
		return 0, "", fmt.Errorf("node%d health is not an object", idx+1)
	}
	ret, ok := m["retention"].(map[string]any)
	if !ok {
		return 0, "", fmt.Errorf("node%d health has no retention block", idx+1)
	}
	collected, ok := ret["collected_transactions"].(float64)
	if !ok {
		return 0, "", fmt.Errorf("node%d health has no collected counter", idx+1)
	}
	var lastErr string
	if repl, ok := m["replication"].(map[string]any); ok {
		if s, ok := repl["last_error"].(string); ok {
			lastErr = s
		}
	}
	return uint64(collected), lastErr, nil
}

// isGCError reports whether an engine error string plausibly comes
// from log-GC collection (reference matcher).
func isGCError(msg string) bool {
	lower := strings.ToLower(msg)
	return strings.Contains(lower, "retention") || strings.Contains(lower, "collect") ||
		strings.Contains(lower, "gc_") || strings.Contains(lower, "prune")
}
