// Live scenario: a peer fetch of a corrupted source object must fail
// verification with no partial install.
//
// Port of MURMUR-SQL files-corrupt-source: a victim object is published
// honestly, then its stored bytes are corrupted on the source node while
// stopped (same length, flipped chunk ciphertext). A peer fetch must then
// fail verification with no partial install, fail identically on retry,
// and leave honest objects fetching afterwards. Verification failure is
// proven behaviorally: the victim never becomes locally available while
// its metadata replicates honestly, downloads fail, and no object or
// staging residue lands.
//
// Nodes are native replication drivers over VFS stores with staged
// file-object stores, in-process (Files: true). File ops use the native
// store surface (FileUpload / FileList / FileAvailable / FileDownload)
// instead of MURMUR FILE wire commands. Peer fetch is automatic on the
// driver's fetch tick, but the harness pins the fetch cadence at 30 s
// (the reference configures 100 ms), so the never-local window is 75 s
// (at least two fetch ticks) and the retry-persistence window is 35 s
// (at least one more tick). The 16-byte middle-container corruption keeps
// the reference shape; object files are <digest>.g0.spfo under files/.
//
// Before the control leg the suite converges one fixture row: seed
// sessions on this stack only establish once user-table writes give the
// sync loop something to ship, and file metadata alone never wakes the
// mesh (the files-soak gate).
package filescorruptsource

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	goharness "github.com/marcgauthier/sqlite-murmur-go/clients/go/tests-live/goharness"
)

const (
	// poll is the convergence poll interval.
	poll = 50 * time.Millisecond
	// wait bounds each metadata wait (30 s, reference value).
	wait = 30 * time.Second
	// fetchWait bounds each honest-fetch wait. Reference: 30 s on a
	// 100 ms fetch interval; here the harness pins the fetch cadence
	// at 30 s (the files-soak value).
	fetchWait = 90 * time.Second
	// neverLocalWindow is the corrupt leg: the victim must stay
	// unavailable for 75 s (at least two 30 s fetch ticks) with its
	// metadata present, proving every attempt failed verification.
	// Reference: 30 s at a 100 ms cadence (~300 attempts).
	neverLocalWindow = 75 * time.Second
	// quietBudget bounds the quiescent-staging wait: up to 65 s for a
	// moment with no fetch in flight (no *.part plus staging back at
	// its post-control baseline), spanning at least two fetch ticks.
	quietBudget = 65 * time.Second
	// retryWindow is the retry-persistence observation window: 35 s
	// (at least one more background fetch cycle). Reference: 500 ms
	// (~5 cycles at 100 ms).
	retryWindow = 35 * time.Second
)

// fileMeta is one file-metadata row: name, size, digest, availability.
type fileMeta struct {
	name      string
	size      uint64
	digestHex string
	local     bool
}

// payload is the deterministic payload unique to name.
func payload(name string, n int) []byte {
	nb := []byte(name)
	out := make([]byte, n)
	for i := range out {
		out[i] = byte((len(nb)*31 + int(nb[i%len(nb)]) + i*17) % 251)
	}
	return out
}

func envUsize(name string, fallback int) int {
	if v, err := strconv.Atoi(os.Getenv(name)); err == nil && v > 0 {
		return v
	}
	return fallback
}

// fileUpload uploads data under name on node idx and returns the
// published metadata.
func fileUpload(cluster *goharness.Cluster, idx int, name string, data []byte) (fileMeta, error) {
	var zero fileMeta
	node := cluster.Node(idx)
	if err := node.FileUpload(name, data); err != nil {
		return zero, fmt.Errorf("node%d upload %q: %w", idx+1, name, err)
	}
	if err := node.Flush(); err != nil {
		return zero, fmt.Errorf("node%d flush after upload %q: %w", idx+1, name, err)
	}
	meta, err := fileMetadata(cluster, idx, name)
	if err != nil {
		return zero, err
	}
	if meta == nil {
		return zero, fmt.Errorf("node%d upload %q: metadata missing after upload", idx+1, name)
	}
	return *meta, nil
}

// fileMetadata returns metadata for exactly name on node idx (nil when
// unlisted), with the local-availability flag.
func fileMetadata(cluster *goharness.Cluster, idx int, name string) (*fileMeta, error) {
	list, err := cluster.Node(idx).FileList()
	if err != nil {
		return nil, fmt.Errorf("node%d list files: %w", idx+1, err)
	}
	for _, m := range list {
		if m.Name != name || m.Deleted {
			continue
		}
		local, err := cluster.Node(idx).FileAvailable(name)
		if err != nil {
			return nil, fmt.Errorf("node%d available %q: %w", idx+1, name, err)
		}
		return &fileMeta{
			name:      m.Name,
			size:      m.Bytes,
			digestHex: hex.EncodeToString(m.Digest[:]),
			local:     local,
		}, nil
	}
	return nil, nil
}

// stagingCount returns the fetch-staging row count on node idx.
func stagingCount(cluster *goharness.Cluster, idx int) (int, error) {
	rows, err := cluster.Node(idx).Simple("SELECT count(*) FROM murmur_file_staging")
	if err != nil {
		return 0, fmt.Errorf("node%d read staging: %w", idx+1, err)
	}
	if len(rows) == 0 || len(rows[0]) == 0 {
		return 0, fmt.Errorf("node%d read staging: no rows", idx+1)
	}
	n, err := strconv.Atoi(rows[0][0])
	if err != nil {
		return 0, fmt.Errorf("node%d bad staging count %q: %w", idx+1, rows[0][0], err)
	}
	return n, nil
}

// findFile returns the first regular file under dir (recursive) whose
// name matches want.
func findFile(dir string, want func(string) bool) (string, bool) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", false
	}
	for _, entry := range entries {
		path := filepath.Join(dir, entry.Name())
		if entry.IsDir() {
			if hit, ok := findFile(path, want); ok {
				return hit, true
			}
			continue
		}
		if !entry.Type().IsRegular() {
			continue
		}
		if want(entry.Name()) {
			return path, true
		}
	}
	return "", false
}

// findObjectFile locates the published .spfo object file for digestHex.
func findObjectFile(dir, digestHex string) (string, bool) {
	return findFile(dir, func(base string) bool {
		return strings.HasSuffix(base, ".spfo") && strings.Contains(base, digestHex)
	})
}

// findPartFile locates any fetch-staging *.part file.
func findPartFile(dir string) (string, bool) {
	return findFile(dir, func(base string) bool { return strings.HasSuffix(base, ".part") })
}

func checkDownload(cluster *goharness.Cluster, idx int, name string, want []byte) error {
	got, err := cluster.Node(idx).FileDownload(name)
	if err != nil {
		return fmt.Errorf("node%d download %s: %w", idx+1, name, err)
	}
	if !equalBytes(got, want) {
		return fmt.Errorf("node%d %s bytes differ", idx+1, name)
	}
	meta, err := fileMetadata(cluster, idx, name)
	if err != nil {
		return err
	}
	if meta == nil {
		return fmt.Errorf("node%d %s metadata missing", idx+1, name)
	}
	if meta.size != uint64(len(want)) {
		return fmt.Errorf("node%d %s size %d", idx+1, name, meta.size)
	}
	return nil
}

// waitMetadata waits until node idx carries metadata for name with the
// expected digest.
func waitMetadata(cluster *goharness.Cluster, idx int, name, wantDigest, what string) error {
	deadline := time.Now().Add(wait)
	for {
		meta, err := fileMetadata(cluster, idx, name)
		if err != nil {
			return err
		}
		if meta != nil && meta.digestHex == wantDigest {
			return nil
		}
		if !time.Now().Before(deadline) {
			return fmt.Errorf("%s: metadata never arrived", what)
		}
		time.Sleep(poll)
	}
}

// waitAvailable waits until node idx holds the object locally.
func waitAvailable(cluster *goharness.Cluster, idx int, name, what string) error {
	deadline := time.Now().Add(fetchWait)
	for {
		meta, err := fileMetadata(cluster, idx, name)
		if err != nil {
			return err
		}
		if meta != nil && meta.local {
			return nil
		}
		if !time.Now().Before(deadline) {
			return fmt.Errorf("%s: object never became available", what)
		}
		time.Sleep(poll)
	}
}

// assertNeverLocal asserts node idx never holds the object locally for
// a full window (the corrupt leg: background fetch ticks every 30 s, so
// a 75 s window of unavailability with present metadata proves at least
// two attempts failed verification).
func assertNeverLocal(cluster *goharness.Cluster, idx int, name, what string) error {
	deadline := time.Now().Add(neverLocalWindow)
	for {
		meta, err := fileMetadata(cluster, idx, name)
		if err != nil {
			return err
		}
		if meta != nil && meta.local {
			return fmt.Errorf("%s: corrupt object became available (partial install)", what)
		}
		if !time.Now().Before(deadline) {
			return nil
		}
		time.Sleep(poll)
	}
}

// meshGate converges one fixture row so the seed session establishes
// before the first upload (see the package comment).
func meshGate(cluster *goharness.Cluster) error {
	for i := 0; i < cluster.Len(); i++ {
		if _, err := cluster.Node(i).Simple(
			"CREATE TABLE IF NOT EXISTS meshgate(id INTEGER PRIMARY KEY NOT NULL)"); err != nil {
			return fmt.Errorf("node%d create meshgate: %w", i+1, err)
		}
		if err := cluster.Node(i).SetTableReplicated("meshgate", true); err != nil {
			return fmt.Errorf("node%d replicate meshgate: %w", i+1, err)
		}
	}
	if _, err := cluster.Node(0).Execute("INSERT INTO meshgate(id) VALUES(1)"); err != nil {
		return fmt.Errorf("insert meshgate row: %w", err)
	}
	if err := cluster.Node(0).Flush(); err != nil {
		return fmt.Errorf("flush meshgate row: %w", err)
	}
	if err := cluster.PeerMesh(); err != nil {
		return fmt.Errorf("mesh peers: %w", err)
	}
	if err := goharness.AssertRows(cluster, []int{0, 1},
		"SELECT id FROM meshgate", [][]string{{"1"}}); err != nil {
		return fmt.Errorf("converge meshgate row: %w", err)
	}
	return goharness.PeerCounts(cluster, []int{0, 1}, []int{1, 1}, 30*time.Second)
}

func runBody(cluster *goharness.Cluster) error {
	victimSize := envUsize("MURMUR_FILES_CORRUPT_VICTIM_KB", 256) << 10

	if err := meshGate(cluster); err != nil {
		return err
	}

	// Positive control: honest upload replicates, fetches, verifies.
	ctrl := payload("ctrl/a.bin", 64<<10)
	st, err := fileUpload(cluster, 0, "ctrl/a.bin", ctrl)
	if err != nil {
		return fmt.Errorf("control upload: %w", err)
	}
	if st.size != uint64(len(ctrl)) {
		return fmt.Errorf("control upload byte count mismatch")
	}
	if err := waitMetadata(cluster, 1, "ctrl/a.bin", st.digestHex, "control metadata"); err != nil {
		return err
	}
	if err := waitAvailable(cluster, 1, "ctrl/a.bin", "control fetch"); err != nil {
		return err
	}
	if err := checkDownload(cluster, 1, "ctrl/a.bin", ctrl); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "positive control: upload/replicate/fetch/verify works")
	stageBase, err := stagingCount(cluster, 1)
	if err != nil {
		return err
	}

	// Publish the victim object honestly, then stop the source at once so
	// no fetch can start before the corruption lands: with the source's
	// replication down, victim metadata cannot escape to the fetcher.
	// (The reference stops the fetcher instead, but an in-process node
	// that completed a fetch cannot restart -- driver start fails with
	// "File exists" -- so the fetcher stays up throughout.)
	victim := payload("victim/blob.bin", victimSize)
	vst, err := fileUpload(cluster, 0, "victim/blob.bin", victim)
	if err != nil {
		return fmt.Errorf("victim upload: %w", err)
	}
	if vst.size != uint64(len(victim)) {
		return fmt.Errorf("victim upload byte count mismatch")
	}
	victimDigest := vst.digestHex
	fmt.Fprintf(os.Stderr, "victim published: digest=%s size=%d\n", victimDigest, len(victim))
	if err := cluster.StopNode(0); err != nil {
		return fmt.Errorf("stop source: %w", err)
	}
	if meta, err := fileMetadata(cluster, 1, "victim/blob.bin"); err != nil {
		return err
	} else if meta != nil {
		return fmt.Errorf("victim metadata escaped to the fetcher before the source stopped; fetch race unproven")
	}

	// Locate the source-side object file while the node is stopped.
	srcObj, ok := findObjectFile(cluster.Node(0).Dir, victimDigest)
	if !ok {
		return fmt.Errorf("no .spfo object file for digest %s", victimDigest)
	}
	before, err := os.ReadFile(srcObj)
	if err != nil {
		return fmt.Errorf("read source object: %w", err)
	}
	fmt.Fprintf(os.Stderr, "source object: %s (%d container bytes)\n", srcObj, len(before))
	if len(before) < 1024 {
		return fmt.Errorf("source object unexpectedly small (%d bytes); refusing to corrupt", len(before))
	}

	// Corrupt the published bytes while the source node is stopped
	// (honest disk-corruption simulation: same length, flipped bytes in
	// the middle of the container, i.e. inside chunk ciphertext).
	flip := append([]byte(nil), before...)
	for i := 0; i < 16; i++ {
		off := len(flip)/2 + i
		flip[off] ^= 0xFF
	}
	if err := os.WriteFile(srcObj, flip, 0o644); err != nil {
		return fmt.Errorf("write corrupted object: %w", err)
	}
	after, err := os.ReadFile(srcObj)
	if err != nil {
		return fmt.Errorf("re-read corrupted object: %w", err)
	}
	if len(after) != len(before) {
		return fmt.Errorf("corrupted object length changed")
	}
	fmt.Fprintf(os.Stderr, "flipped 16 bytes at container offset %d (length preserved)\n", len(flip)/2)

	// Restart the source and re-mesh.
	if err := cluster.StartNode(0); err != nil {
		return fmt.Errorf("restart source: %w", err)
	}
	if err := cluster.PeerMesh(); err != nil {
		return fmt.Errorf("re-mesh after restart: %w", err)
	}

	// Victim metadata must replicate honestly to the fetcher.
	if err := waitMetadata(cluster, 1, "victim/blob.bin", victimDigest, "victim metadata"); err != nil {
		return err
	}

	// The peer fetch must FAIL verification with no partial install.
	if err := assertNeverLocal(cluster, 1, "victim/blob.bin", "corrupt fetch"); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "corrupt fetch failed closed as required: never available across a full window")

	// No partial install on the fetching node.
	pst, err := fileMetadata(cluster, 1, "victim/blob.bin")
	if err != nil {
		return err
	}
	if pst == nil {
		return fmt.Errorf("victim metadata wrongly altered by failed fetch")
	}
	if pst.digestHex != victimDigest {
		return fmt.Errorf("victim digest altered by failed fetch")
	}
	if pst.local {
		return fmt.Errorf("victim reports local after a failed-verification fetch (partial install)")
	}
	if _, err := cluster.Node(1).FileDownload("victim/blob.bin"); err == nil {
		return fmt.Errorf("victim downloads after a failed-verification fetch (partial install)")
	}

	// Background retries run every fetch tick, so wait for a quiescent
	// moment (no transfer in flight: no *.part plus staging back at its
	// post-control baseline) and require no staging residue and no
	// object file for the unverified digest then.
	node1Dir := cluster.Node(1).Dir
	quietDeadline := time.Now().Add(quietBudget)
	for {
		quiescent := true
		if _, ok := findPartFile(node1Dir); ok {
			quiescent = false
		} else if n, err := stagingCount(cluster, 1); err != nil {
			return err
		} else if n > stageBase {
			quiescent = false
		}
		if quiescent {
			break
		}
		if !time.Now().Before(quietDeadline) {
			return fmt.Errorf("fetch staging never quiesced")
		}
		time.Sleep(100 * time.Millisecond)
	}
	if _, ok := findObjectFile(node1Dir, victimDigest); ok {
		return fmt.Errorf("fetching node holds an object file for an unverified digest (partial install)")
	}
	if _, ok := findPartFile(node1Dir); ok {
		return fmt.Errorf("fetching node holds a staging file after failed verification (staging not discarded)")
	}
	if n, err := stagingCount(cluster, 1); err != nil {
		return err
	} else if n > stageBase {
		return fmt.Errorf("fetching node holds %d staging rows (baseline %d) after failed verification", n, stageBase)
	} else {
		fmt.Fprintf(os.Stderr, "staging quiesced at %d rows (baseline %d); no residue\n", n, stageBase)
	}

	// No phantom metadata: the listing still shows the victim with its
	// original honest digest/size on both nodes.
	for i := 0; i < cluster.Len(); i++ {
		list, err := cluster.Node(i).FileList()
		if err != nil {
			return fmt.Errorf("node%d list files: %w", i+1, err)
		}
		var f *fileMeta
		for _, m := range list {
			if m.Deleted || m.Name != "victim/blob.bin" {
				continue
			}
			f = &fileMeta{name: m.Name, size: m.Bytes, digestHex: hex.EncodeToString(m.Digest[:])}
		}
		if f == nil {
			return fmt.Errorf("node%d lost victim metadata after failed fetch", i+1)
		}
		if !(f.digestHex == victimDigest && f.size == uint64(len(victim))) {
			return fmt.Errorf("node%d victim metadata altered: %s %s %d", i+1, f.name, f.digestHex, f.size)
		}
	}

	// The corruption is persistent, not transient: after more background
	// retry cycles the victim is still unavailable.
	time.Sleep(retryWindow)
	meta, err := fileMetadata(cluster, 1, "victim/blob.bin")
	if err != nil {
		return err
	}
	if meta != nil && meta.local {
		return fmt.Errorf("victim became available across retries (partial install)")
	}
	fmt.Fprintln(os.Stderr, "retried fetch failed closed again: still unavailable")

	// Honest objects must still fetch afterwards.
	honest := payload("honest/b.bin", 128<<10)
	hst, err := fileUpload(cluster, 0, "honest/b.bin", honest)
	if err != nil {
		return fmt.Errorf("honest upload after corruption: %w", err)
	}
	if err := waitMetadata(cluster, 1, "honest/b.bin", hst.digestHex, "honest metadata after corruption"); err != nil {
		return err
	}
	if err := waitAvailable(cluster, 1, "honest/b.bin", "honest fetch after corruption"); err != nil {
		return err
	}
	if err := checkDownload(cluster, 1, "honest/b.bin", honest); err != nil {
		return err
	}
	if err := checkDownload(cluster, 1, "ctrl/a.bin", ctrl); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "corrupt-source proven: bad bytes fail verification, honest objects unaffected")
	return nil
}

func TestCorruptSourceFetchFailsVerification(t *testing.T) {
	goharness.SkipUnlessLive(t)
	cluster, err := goharness.NewCluster(goharness.ClusterOptions{
		Name:     "files-corrupt-source",
		NumNodes: 2,
		Files:    true,
	})
	if err != nil {
		t.Fatalf("cluster setup: %v", err)
	}
	result := runBody(cluster)
	failed := result != nil
	if result != nil {
		fmt.Fprintf(os.Stderr, "scenario failed: %v\n", result)
	}
	cluster.Finish(failed)
	if failed {
		t.Fatal("scenario failed; artifacts retained under tests-live/failures/")
	}
}

func equalBytes(a, b []byte) bool {
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
