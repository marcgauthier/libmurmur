// Live scenario: file crash consistency across mid-upload and
// mid-fetch kills.
//
// Port of MURMUR-SQL files-crash: the positive control
// (upload/replicate/fetch/verify plus a clean baseline inventory)
// and the full recovery proof (metadata settles identically, every
// listed object downloads byte-complete and digest-verified on both
// nodes, every on-disk payload is attributable to a known attempt
// and bounded in count) run over multi-round honest uploads. Both
// kill legs are skipped with named harness gaps: the mid-upload kill
// needs a kill to land between chunked UPLOAD APPENDs, but UploadOne
// is a single RPC and KillNode serializes behind the in-flight call,
// so a kill can never land mid-upload; the mid-fetch kill needs the
// killed fetcher to resume, but a child restart drops the files
// staging, so the rebooted node cannot fetch. Nodes are native
// replication drivers over VFS stores with staged file-object
// stores, in-process (no kill legs remain to need child mode).
package filescrash

import (
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
	// wait bounds each metadata wait (30 s).
	wait = 30 * time.Second
	// fetchWait bounds each fetch wait. Reference: 30 s on a 100 ms
	// fetch interval; here the harness pins the fetch cadence at
	// 30 s (no interval knob), so 90 s covers ~3 ticks (the
	// files-soak bound).
	fetchWait = 90 * time.Second
	// settleWait is the final metadata-settle bound (60 s).
	settleWait = 60 * time.Second
	// uploadBytes is the upload size in the volume rounds (1 MiB).
	uploadBytes = 1 << 20
	// rounds is the volume rounds (2). The reference runs 3 rounds
	// of 8; volume is scaled to the 30 s fetch tick (peer fetch
	// completes ~2 objects per tick, so the reference 26 objects
	// would idle ~7 minutes on tick boundaries alone).
	rounds = 2
	// uploadsPerRound is the honest uploads per round (4).
	uploadsPerRound = 4
)

// fileMeta is one file-metadata row (name, size, digest; the native
// list carries no local flag, so availability is queried per file).
type fileMeta struct {
	name      string
	size      uint64
	digestHex string
}

// attempt is one upload try: the digest is known only for acknowledged
// uploads (errored uploads must leave no debris at all). No kill
// legs run here, so every attempt below is acknowledged; errored
// stays zero and the inventory bounds are strict.
type attempt struct {
	digest *string
	size   uint64
	ok     bool
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

// fileUpload uploads data under name on node idx. Returns the
// published metadata.
func fileUpload(cluster *goharness.Cluster, idx int, name string, data []byte) (fileMeta, error) {
	var zero fileMeta
	if err := cluster.Node(idx).FileUpload(name, data); err != nil {
		return zero, fmt.Errorf("node%d upload %q: %w", idx+1, name, err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		meta, err := fileMetadata(cluster, idx, name)
		if err != nil {
			return zero, err
		}
		if meta != nil {
			return *meta, nil
		}
		if !time.Now().Before(deadline) {
			return zero, fmt.Errorf("node%d upload %q never listed", idx+1, name)
		}
		time.Sleep(poll)
	}
}

// fileDownload downloads the full verified bytes of name from node idx.
func fileDownload(cluster *goharness.Cluster, idx int, name string) ([]byte, error) {
	got, err := cluster.Node(idx).FileDownload(name)
	if err != nil {
		return nil, fmt.Errorf("node%d download %q: %w", idx+1, name, err)
	}
	return got, nil
}

// fileList returns the full metadata listing on node idx (non-deleted
// files only, like the reference wire LIST).
func fileList(cluster *goharness.Cluster, idx int) ([]fileMeta, error) {
	list, err := cluster.Node(idx).FileList()
	if err != nil {
		return nil, fmt.Errorf("node%d FILE LIST: %w", idx+1, err)
	}
	var out []fileMeta
	for _, m := range list {
		if m.Deleted {
			continue
		}
		out = append(out, fileMeta{
			name:      m.Name,
			size:      m.Bytes,
			digestHex: goharness.Hex(m.Digest[:]),
		})
	}
	return out, nil
}

// fileMetadata returns metadata for exactly name on node idx (nil when
// unlisted).
func fileMetadata(cluster *goharness.Cluster, idx int, name string) (*fileMeta, error) {
	list, err := fileList(cluster, idx)
	if err != nil {
		return nil, err
	}
	for i := range list {
		if list[i].name == name {
			return &list[i], nil
		}
	}
	return nil, nil
}

// fileLocal reports whether name is locally available on node idx.
func fileLocal(cluster *goharness.Cluster, idx int, name string) (bool, error) {
	ok, err := cluster.Node(idx).FileAvailable(name)
	if err != nil {
		return false, fmt.Errorf("node%d available %q: %w", idx+1, name, err)
	}
	return ok, nil
}

// parseObjectDigest parses `<hex64>.g<gen>.spfo` to its digest hex.
func parseObjectDigest(base string) (string, bool) {
	stem, ok := strings.CutSuffix(base, ".spfo")
	if !ok {
		return "", false
	}
	// rsplit_once(".g"): cut at the LAST ".g".
	idx := strings.LastIndex(stem, ".g")
	if idx < 0 {
		return "", false
	}
	if !isHex64(stem[:idx]) {
		return "", false
	}
	return stem[:idx], true
}

// parsePartDigest parses `<source>-<digest64>.g<gen>.part` to its digest
// hex.
func parsePartDigest(base string) (string, bool) {
	stem, ok := strings.CutSuffix(base, ".part")
	if !ok {
		return "", false
	}
	_, rest, ok := strings.Cut(stem, "-")
	if !ok {
		return "", false
	}
	idx := strings.LastIndex(rest, ".g")
	if idx < 0 {
		return "", false
	}
	if !isHex64(rest[:idx]) {
		return "", false
	}
	return rest[:idx], true
}

func isHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}

// collectPayloads collects on-disk payloads under a node dir: published
// objects (.spfo), upload staging (.upload-*/.rotate-*), and fetch
// staging (*.part).
func collectPayloads(dir string, spfo, stage, part *[]string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, entry := range entries {
		path := filepath.Join(dir, entry.Name())
		if entry.IsDir() {
			collectPayloads(path, spfo, stage, part)
			continue
		}
		if !entry.Type().IsRegular() {
			continue
		}
		base := entry.Name()
		switch {
		case strings.HasSuffix(base, ".spfo"):
			*spfo = append(*spfo, base)
		case strings.HasPrefix(base, ".upload-") || strings.HasPrefix(base, ".rotate-"):
			*stage = append(*stage, base)
		case strings.HasSuffix(base, ".part"):
			*part = append(*part, base)
		}
	}
}

func metadataCanonical(list []fileMeta) string {
	sorted := append([]fileMeta(nil), list...)
	for i := 1; i < len(sorted); i++ {
		for j := i; j > 0 && sorted[j].name < sorted[j-1].name; j-- {
			sorted[j], sorted[j-1] = sorted[j-1], sorted[j]
		}
	}
	var sb strings.Builder
	for _, m := range sorted {
		fmt.Fprintf(&sb, "%s|%s|%d;", m.name, m.digestHex, m.size)
	}
	return sb.String()
}

// waitMetadataSettled polls until both nodes list identical metadata and
// every acknowledged upload is present everywhere.
func waitMetadataSettled(cluster *goharness.Cluster, attempted map[string]attempt) error {
	end := time.Now().Add(settleWait)
	for {
		var lists [][]fileMeta
		ok := true
		for idx := 0; idx < cluster.Len(); idx++ {
			l, err := fileList(cluster, idx)
			if err != nil {
				ok = false
				break
			}
			lists = append(lists, l)
		}
		if ok && len(lists) == 2 {
			settled := metadataCanonical(lists[0]) == metadataCanonical(lists[1])
			if settled {
				for _, a := range attempted {
					if !a.ok {
						continue
					}
					found := false
					for _, m := range lists[0] {
						if a.digest != nil && m.digestHex == *a.digest && m.size == a.size {
							found = true
							break
						}
					}
					if !found {
						settled = false
						break
					}
				}
			}
			if settled {
				return nil
			}
		}
		if !time.Now().Before(end) {
			for idx := 0; idx < cluster.Len(); idx++ {
				n := 0
				if l, err := fileList(cluster, idx); err == nil {
					n = len(l)
				}
				fmt.Fprintf(os.Stderr, "node%d at timeout: %d files\n", idx, n)
			}
			return fmt.Errorf("file metadata did not settle identically on both nodes")
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// verifyAllObjects downloads every listed object on both nodes and
// requires byte-complete, digest-verified content; anything listed must
// have been attempted (no phantoms) and every acked upload must be
// listed (no lost writes).
func verifyAllObjects(cluster *goharness.Cluster, attempted map[string]attempt, fetchAttempts *int) error {
	for idx := 0; idx < cluster.Len(); idx++ {
		list, err := fileList(cluster, idx)
		if err != nil {
			return err
		}
		for _, f := range list {
			a, ok := attempted[f.name]
			if !ok {
				return fmt.Errorf("node%d lists phantom object %q", idx, f.name)
			}
			if a.digest == nil {
				return fmt.Errorf("node%d %q listed but its upload errored", idx, f.name)
			}
			if !(f.digestHex == *a.digest && f.size == a.size) {
				return fmt.Errorf("node%d %q metadata digest=%s size=%d, want %s/%d",
					idx, f.name, f.digestHex, f.size, *a.digest, a.size)
			}
			local, err := fileLocal(cluster, idx, f.name)
			if err != nil {
				return err
			}
			if !local {
				*fetchAttempts++
				deadline := time.Now().Add(fetchWait)
				for {
					fetched, err := fileLocal(cluster, idx, f.name)
					if err != nil {
						return err
					}
					if fetched {
						break
					}
					if !time.Now().Before(deadline) {
						return fmt.Errorf("node%d fetch %q never completed", idx, f.name)
					}
					time.Sleep(poll)
				}
			}
			got, err := fileDownload(cluster, idx, f.name)
			if err != nil {
				return fmt.Errorf("node%d %q listed but not downloadable (partial?): %w", idx, f.name, err)
			}
			if uint64(len(got)) != a.size {
				return fmt.Errorf("node%d %q length is partial", idx, f.name)
			}
			if !equalBytes(got, payload(f.name, int(a.size))) {
				return fmt.Errorf("node%d %q bytes differ (partial/corrupt)", idx, f.name)
			}
		}
		for name, a := range attempted {
			if !a.ok {
				continue
			}
			st, err := fileMetadata(cluster, idx, name)
			if err != nil {
				return err
			}
			if st == nil {
				return fmt.Errorf("node%d lost acked upload %q", idx, name)
			}
		}
	}
	l0, err := fileList(cluster, 0)
	if err != nil {
		return err
	}
	l1, err := fileList(cluster, 1)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "all %d listed objects byte-complete on both nodes; metadata digests equal\n", len(l0))
	if len(l0) != len(l1) {
		return fmt.Errorf("object counts differ")
	}
	return nil
}

// verifyInventory walks each node dir and requires every object payload
// (.spfo), upload stage file, and fetch stage file (*.part) to be
// attributable to a known upload/fetch attempt and bounded in count.
func verifyInventory(cluster *goharness.Cluster, attempted map[string]attempt, fetchAttempts int) error {
	known := map[string]bool{}
	errored := 0
	for _, a := range attempted {
		if a.ok && a.digest != nil {
			known[*a.digest] = true
		} else {
			errored++
		}
	}
	for idx := 0; idx < cluster.Len(); idx++ {
		var spfo, stage, part []string
		collectPayloads(cluster.Node(idx).Dir, &spfo, &stage, &part)
		meta, err := fileList(cluster, idx)
		if err != nil {
			return err
		}
		referenced := map[string]bool{}
		for _, m := range meta {
			referenced[m.digestHex] = true
		}
		orphans := 0
		for _, base := range spfo {
			digest, ok := parseObjectDigest(base)
			if !ok {
				return fmt.Errorf("node%d object file %s has a bad name", idx, base)
			}
			if referenced[digest] {
				continue
			}
			if known[digest] {
				orphans++
				continue
			}
			return fmt.Errorf("node%d object file %s unattributable to any upload", idx, base)
		}
		if orphans > errored {
			return fmt.Errorf("node%d has %d unreferenced objects from %d errored uploads", idx, orphans, errored)
		}
		if idx == 1 && len(stage) != 0 {
			return fmt.Errorf("node 1 never uploaded yet holds %d stage files", len(stage))
		}
		if len(stage) > errored {
			return fmt.Errorf("node%d holds %d stage files from %d errored uploads", idx, len(stage), errored)
		}
		if idx == 0 && len(part) != 0 {
			return fmt.Errorf("node 0 never fetched yet holds %d part files", len(part))
		}
		for _, base := range part {
			digest, ok := parsePartDigest(base)
			if !ok {
				return fmt.Errorf("node%d stage file %s has a bad name", idx, base)
			}
			if !known[digest] {
				return fmt.Errorf("node%d stage file %s unattributable to any upload", idx, base)
			}
		}
		if len(part) > fetchAttempts+2 {
			return fmt.Errorf("node%d holds %d part files from %d fetch attempts", idx, len(part), fetchAttempts)
		}
		fmt.Fprintf(os.Stderr, "node%d inventory: %d objects (%d orphans), %d stage, %d part - all attributable\n",
			idx, len(spfo), orphans, len(stage), len(part))
	}
	return nil
}

// waitMetadata polls until name lists with the expected digest on node idx.
func waitMetadata(cluster *goharness.Cluster, idx int, name, digest string, what string) error {
	deadline := time.Now().Add(wait)
	for {
		meta, err := fileMetadata(cluster, idx, name)
		if err != nil {
			return err
		}
		if meta != nil && meta.digestHex == digest {
			return nil
		}
		if !time.Now().Before(deadline) {
			return fmt.Errorf("%s: metadata never arrived", what)
		}
		time.Sleep(poll)
	}
}

// waitLocal polls until name is locally available on node idx.
func waitLocal(cluster *goharness.Cluster, idx int, name, what string, bound time.Duration) error {
	deadline := time.Now().Add(bound)
	for {
		local, err := fileLocal(cluster, idx, name)
		if err != nil {
			return err
		}
		if local {
			return nil
		}
		if !time.Now().Before(deadline) {
			return fmt.Errorf("%s: fetch never completed", what)
		}
		time.Sleep(poll)
	}
}

func runBody(cluster *goharness.Cluster) error {
	bigMB := envUsize("MURMUR_FILES_CRASH_BIG_MB", 3)
	attempted := map[string]attempt{}
	fetchAttempts := 0

	// Positive control: honest upload replicates, fetches, verifies.
	ctrl := payload("ctrl/a.bin", 64<<10)
	st, err := fileUpload(cluster, 0, "ctrl/a.bin", ctrl)
	if err != nil {
		return fmt.Errorf("control upload: %w", err)
	}
	if st.size != uint64(len(ctrl)) {
		return fmt.Errorf("control upload byte count mismatch")
	}
	ctrlDigest := st.digestHex
	attempted["ctrl/a.bin"] = attempt{digest: &ctrlDigest, size: uint64(len(ctrl)), ok: true}
	if err := waitMetadata(cluster, 1, "ctrl/a.bin", st.digestHex, "control"); err != nil {
		return err
	}
	fetchAttempts++
	if err := waitLocal(cluster, 1, "ctrl/a.bin", "control", fetchWait); err != nil {
		return err
	}
	got, err := fileDownload(cluster, 1, "ctrl/a.bin")
	if err != nil {
		return fmt.Errorf("control download: %w", err)
	}
	if !equalBytes(got, ctrl) {
		return fmt.Errorf("control download bytes differ")
	}
	fmt.Fprintln(os.Stderr, "positive control: upload/replicate/fetch/verify works")
	// Baseline inventory before any volume: the clean path must leave
	// zero unattributable payloads.
	if err := verifyInventory(cluster, attempted, fetchAttempts); err != nil {
		return err
	}

	// Volume rounds: honest multi-megabyte uploads (the reference
	// per-round shape; the mid-upload kill at slot 3 is skipped, see
	// TestFileCrashMidUploadKill).
	for round := 1; round <= rounds; round++ {
		for i := 0; i < uploadsPerRound; i++ {
			name := fmt.Sprintf("crash/u-%d-%d.bin", round, i)
			data := payload(name, uploadBytes)
			up, err := fileUpload(cluster, 0, name, data)
			if err != nil {
				return fmt.Errorf("round %d upload %s: %w", round, name, err)
			}
			if up.size != uint64(len(data)) {
				return fmt.Errorf("round %d upload %s byte count mismatch", round, name)
			}
			d := up.digestHex
			attempted[name] = attempt{digest: &d, size: uint64(len(data)), ok: true}
		}
		fmt.Fprintf(os.Stderr, "round %d: %d uploads acknowledged\n", round, uploadsPerRound)
	}

	// Big-file leg: a multi-megabyte object replicates, fetches, and
	// verifies (the reference mid-fetch-kill shape; the kill itself
	// is skipped, see TestFileCrashMidFetchKill).
	bigName := "crash/f-1.bin"
	bigData := payload(bigName, bigMB<<20)
	up, err := fileUpload(cluster, 0, bigName, bigData)
	if err != nil {
		return fmt.Errorf("big upload: %w", err)
	}
	d := up.digestHex
	attempted[bigName] = attempt{digest: &d, size: uint64(len(bigData)), ok: true}
	if err := waitMetadata(cluster, 1, bigName, up.digestHex, "big file"); err != nil {
		return err
	}
	fetchAttempts++
	if err := waitLocal(cluster, 1, bigName, "big file", fetchWait); err != nil {
		return err
	}
	got, err = fileDownload(cluster, 1, bigName)
	if err != nil {
		return fmt.Errorf("big download: %w", err)
	}
	if !equalBytes(got, bigData) {
		return fmt.Errorf("big download bytes differ")
	}

	// Full recovery proof (no crashes ran, so every bound is strict).
	if err := waitMetadataSettled(cluster, attempted); err != nil {
		return err
	}
	if err := verifyAllObjects(cluster, attempted, &fetchAttempts); err != nil {
		return err
	}
	if err := verifyInventory(cluster, attempted, fetchAttempts); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "files-crash proven (kill legs skipped): no partials, no phantoms, inventory attributable")
	return nil
}

func TestFileCrashControlAndInventory(t *testing.T) {
	goharness.SkipUnlessLive(t)
	cluster, err := goharness.NewCluster(goharness.ClusterOptions{
		Name:     "files-crash",
		NumNodes: 2,
		Files:    true,
	})
	if err != nil {
		t.Fatalf("cluster setup: %v", err)
	}
	failed := true
	defer func() { cluster.Finish(failed) }()

	// Mesh gate (the files-soak pattern): seed sessions only
	// establish once user-table writes give the sync loop something
	// to ship, and file metadata alone never wakes the mesh.
	for i := 0; i < 2; i++ {
		if _, err := cluster.Node(i).Simple(
			"CREATE TABLE IF NOT EXISTS records(id INTEGER PRIMARY KEY NOT NULL, name TEXT NOT NULL DEFAULT '')"); err != nil {
			t.Fatalf("node %d create records: %v", i, err)
		}
		if err := cluster.Node(i).SetTableReplicated("records", true); err != nil {
			t.Fatalf("node %d replicate records: %v", i, err)
		}
	}
	if _, err := cluster.Node(0).Simple(
		"INSERT INTO records(id,name) VALUES(1,'mesh-gate')"); err != nil {
		t.Fatalf("mesh gate insert: %v", err)
	}
	if err := cluster.Node(0).Flush(); err != nil {
		t.Fatalf("mesh gate flush: %v", err)
	}
	if err := goharness.AssertRows(cluster, []int{0, 1},
		"SELECT name FROM records", [][]string{{"mesh-gate"}}); err != nil {
		t.Fatalf("converge mesh gate: %v", err)
	}

	if err := runBody(cluster); err != nil {
		t.Logf("scenario failed: %v", err)
		t.Fatal("scenario failed; artifacts retained")
	}
	failed = false
}

func TestFileCrashMidUploadKill(t *testing.T) {
	goharness.SkipUnlessLive(t)
	// Blocked: the reference kills the uploader between chunked UPLOAD
	// APPENDs and requires the staged upload to be dropped, never
	// published. This stack exposes only atomic UploadOne (a single
	// RPC), and KillNode serializes behind the in-flight call, so a
	// kill can never land mid-upload.
	t.Skip("harness: no chunked upload (UploadOne is one RPC; KillNode serializes behind it, so a kill can never land mid-upload)")
}

func TestFileCrashMidFetchKill(t *testing.T) {
	goharness.SkipUnlessLive(t)
	// Blocked: the reference kills the fetcher while a .part transfer
	// file is on disk, restarts it, and requires the interrupted fetch
	// to complete cleanly. A child restart drops the files staging
	// (RestartNode reboots without files), so the killed fetcher can
	// never resume; an in-process node that completed a fetch cannot
	// restart at all ("File exists"). Both reboot paths are closed.
	t.Skip("harness: child restart drops files staging (the killed fetcher cannot resume; in-process restart after fetch fails)")
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
