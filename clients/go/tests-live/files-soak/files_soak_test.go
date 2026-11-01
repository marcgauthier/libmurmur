// Live scenario: a two-node encrypted mesh soaks 64 KiB file uploads.
//
// Port of MURMUR-SQL files-soak: upload to node 0, wait for replicated
// metadata on node 1, wait for the automatic fetch, download, verify
// the digest, and search the replicated names, one upload every
// MURMUR_FILES_SOAK_INTERVAL_SECONDS (default 1 s) for
// MURMUR_FILES_SOAK_DURATION_SECONDS (default 5 s).
//
// File ops run through the native file-object store (FileUpload /
// FileList / FileAvailable / FileDownload) instead of MURMUR FILE wire
// commands. Peer fetch is automatic on the driver's fetch tick, but the
// harness pins the fetch cadence at 30 s (the reference configures 100
// ms and the Stage call exposes no interval knob), so the fetch wait is
// 90 s and the metadata-to-verified-fetch SLO is scaled to 120 s (the
// upload SLO keeps the reference 5 s: uploads are local). Rounds are
// sequential, so a short duration still proves every leg.
//
// Before round 0 the suite converges one fixture row: seed sessions on
// this stack only establish once user-table writes give the sync loop
// something to ship, and file metadata alone never wakes the mesh
// (verified by probe: an upload-only cluster stays unmeshed past
// 120 s). The gate mirrors the reference harness handing over an
// already-meshed cluster.
package filessoak

import (
	"encoding/hex"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	goharness "github.com/marcgauthier/libmurmur/clients/go/tests-live/goharness"
)

const (
	// fileBytes is the upload size per round (64 KiB).
	fileBytes = 64 << 10
	// metaWait bounds each metadata wait (20 s, reference value).
	metaWait = 20 * time.Second
	// fetchWait bounds each fetch wait. Reference: 20 s on a 100 ms
	// fetch interval; here the harness pins the fetch cadence at 30 s.
	fetchWait = 90 * time.Second
	// poll is the convergence poll interval.
	poll = 50 * time.Millisecond
	// uploadP95SLO bounds upload p95 (5 s, reference value).
	uploadP95SLO = 5 * time.Second
	// transferP95SLO bounds metadata-to-verified-fetch p95. Reference:
	// 20 s; scaled for the harness-pinned 30 s fetch cadence.
	transferP95SLO = 120 * time.Second
)

// fileMeta is one file-metadata row: name, size, digest, availability.
type fileMeta struct {
	name      string
	size      uint64
	digestHex string
	local     bool
}

// payload is the deterministic round payload.
func payload(round int) []byte {
	out := make([]byte, fileBytes)
	for i := range out {
		out[i] = byte((round*31 + i*17) % 251)
	}
	return out
}

// p95 returns the p95 element of a sorted latency sample.
func p95(sorted []time.Duration) time.Duration {
	n := len(sorted)
	return sorted[min(n-1, (95*n+99)/100-1)]
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

// fileSearch counts live files whose name contains the substring (the
// wire SEARCH '%file-%' leg over whole names).
func fileSearch(cluster *goharness.Cluster, idx int, substr string) (int, error) {
	list, err := cluster.Node(idx).FileList()
	if err != nil {
		return 0, fmt.Errorf("node%d list files: %w", idx+1, err)
	}
	n := 0
	for _, m := range list {
		if !m.Deleted && strings.Contains(m.Name, substr) {
			n++
		}
	}
	return n, nil
}

// meshGate converges one fixture row so the seed session establishes
// before round 0 (see the package comment).
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
	if err := goharness.AssertRows(cluster, []int{0, 1},
		"SELECT id FROM meshgate", [][]string{{"1"}}); err != nil {
		return fmt.Errorf("converge meshgate row: %w", err)
	}
	return goharness.PeerCounts(cluster, []int{0, 1}, []int{1, 1}, 30*time.Second)
}

func runBody(cluster *goharness.Cluster, duration, interval time.Duration) error {
	if err := meshGate(cluster); err != nil {
		return err
	}
	deadline := time.Now().Add(duration)
	var uploadLatencies []time.Duration
	var endToEndLatencies []time.Duration
	expected := map[string]string{}
	round := 0
	for time.Now().Before(deadline) {
		name := fmt.Sprintf("soak/file-%04d.bin", round)
		data := payload(round)

		start := time.Now()
		uploaded, err := fileUpload(cluster, 0, name, data)
		if err != nil {
			return fmt.Errorf("upload round %d: %w", round, err)
		}
		if uploaded.size != uint64(len(data)) {
			return fmt.Errorf("round %d: upload byte count %d, want %d", round, uploaded.size, len(data))
		}
		uploadLatencies = append(uploadLatencies, time.Since(start))
		expected[name] = uploaded.digestHex

		endToEndStart := time.Now()
		// Metadata leg.
		metaDeadline := time.Now().Add(metaWait)
		for {
			meta, err := fileMetadata(cluster, 1, name)
			if err != nil {
				return err
			}
			if meta != nil && meta.digestHex == uploaded.digestHex {
				break
			}
			if !time.Now().Before(metaDeadline) {
				return fmt.Errorf("round %d: metadata never arrived", round)
			}
			time.Sleep(poll)
		}
		// Fetch leg: the product fetches automatically on the fetch
		// tick, so this is an availability wait on the local flag.
		fetchDeadline := time.Now().Add(fetchWait)
		for {
			meta, err := fileMetadata(cluster, 1, name)
			if err != nil {
				return err
			}
			if meta != nil && meta.local {
				break
			}
			if !time.Now().Before(fetchDeadline) {
				return fmt.Errorf("round %d: object never fetched", round)
			}
			time.Sleep(poll)
		}
		got, err := cluster.Node(1).FileDownload(name)
		if err != nil {
			return fmt.Errorf("round %d: download failed: %w", round, err)
		}
		if !equalBytes(got, data) {
			return fmt.Errorf("round %d: downloaded bytes differ", round)
		}
		endToEndLatencies = append(endToEndLatencies, time.Since(endToEndStart))

		// Search across the replicated metadata (LIKE `%file-%`: the
		// wire SEARCH matches whole names).
		found, err := fileSearch(cluster, 1, "file-")
		if err != nil {
			return err
		}
		if found != round+1 {
			return fmt.Errorf("round %d: search returned %d files, want %d", round, found, round+1)
		}

		round++
		if time.Now().Before(deadline) {
			time.Sleep(interval)
		}
	}
	if len(uploadLatencies) == 0 {
		return fmt.Errorf("soak completed no uploads")
	}

	// Fetch gate: every uploaded file must be locally available with its
	// upload digest on the peer.
	for name, digest := range expected {
		meta, err := fileMetadata(cluster, 1, name)
		if err != nil {
			return err
		}
		if meta == nil {
			return fmt.Errorf("file %s: metadata missing after the soak", name)
		}
		if !meta.local {
			return fmt.Errorf("file %s not available on the peer after the soak", name)
		}
		if meta.digestHex != digest {
			return fmt.Errorf("file %s: peer digest differs from the upload digest", name)
		}
	}

	// First-file status.
	first, err := fileMetadata(cluster, 1, "soak/file-0000.bin")
	if err != nil {
		return err
	}
	if first == nil {
		return fmt.Errorf("first file metadata missing")
	}
	if !first.local {
		return fmt.Errorf("first file not available")
	}

	sort.Slice(uploadLatencies, func(a, b int) bool { return uploadLatencies[a] < uploadLatencies[b] })
	sort.Slice(endToEndLatencies, func(a, b int) bool { return endToEndLatencies[a] < endToEndLatencies[b] })
	uploadP95 := p95(uploadLatencies)
	transferP95 := p95(endToEndLatencies)
	fmt.Fprintf(os.Stderr, "file soak duration=%v rounds=%d upload_p95=%v metadata_fetch_verify_p95=%v\n",
		duration, len(expected), uploadP95, transferP95)
	if uploadP95 > uploadP95SLO {
		return fmt.Errorf("upload p95 %v exceeded 5s SLO", uploadP95)
	}
	if transferP95 > transferP95SLO {
		return fmt.Errorf("end-to-end p95 %v exceeded 120s SLO", transferP95)
	}
	return nil
}

func TestEncryptedFileFetchSoak(t *testing.T) {
	goharness.SkipUnlessLive(t)
	duration := goharness.EnvSeconds("MURMUR_FILES_SOAK_DURATION_SECONDS", 5)
	interval := goharness.EnvSeconds("MURMUR_FILES_SOAK_INTERVAL_SECONDS", 1)
	cluster, err := goharness.NewCluster(goharness.ClusterOptions{
		Name:     "files-soak",
		NumNodes: 2,
		Files:    true,
	})
	if err != nil {
		t.Fatalf("cluster setup: %v", err)
	}
	result := runBody(cluster, duration, interval)
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
