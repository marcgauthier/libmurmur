// Live scenario: a node's certificate is swapped for a short-expiry
// cert minted for the same NodeID; the mesh must stay connected
// pre-expiry, reject the node after NotAfter passes, and fully
// reconverge on rotation to a fresh cert.
//
// Port of MURMUR-SQL cert-lifecycle: healthy-mesh positive control,
// crash plus rotation to a short cert with stale-cert guards,
// pre-expiry session and marker convergence, post-expiry rejection (no
// session, connected peers 1->0, isolation window), served-leaf
// non-vacuity checks, then fresh-cert rotation with bidirectional
// reconvergence. Nodes are native replication drivers over VFS stores;
// node B runs as a child process (MURMUR_NODE_BIN) so crashes are real
// SIGKILLs and rotations reload via process reboot. Rotation is a
// scenario-local helper (the harness has no RotateNodeCert): issue a
// fresh leaf for the same NodeID from the cluster CA and rewrite the
// node's tls/ files before rebooting it.
package certlifecycle

import (
	"bytes"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	goharness "github.com/marcgauthier/libmurmur/clients/go/tests-live/goharness"
)

// Roles.
const (
	a = 0
	b = 1
)

const (
	// pollFast is the convergence poll interval.
	pollFast = 100 * time.Millisecond
	// poll is the session poll interval.
	poll = 200 * time.Millisecond
	// windowPoll is the isolation-window poll.
	windowPoll = 500 * time.Millisecond
	// convergeTimeout is the convergence deadline.
	convergeTimeout = 60 * time.Second
	// peerTimeout is the session-establishment deadline.
	peerTimeout = 30 * time.Second
	// rejectTimeout is the rejection deadline.
	rejectTimeout = 45 * time.Second
	// preExpiryMargin is the pre-expiry safety margin before NotAfter.
	preExpiryMargin = 5 * time.Second
	// postExpirySettle is the post-expiry settle past NotAfter before
	// forcing fresh handshakes.
	postExpirySettle = 2 * time.Second
)

// names returns the sorted names on one node.
func names(cluster *goharness.Cluster, idx int) ([]string, error) {
	rows, err := cluster.Node(idx).Simple("SELECT name FROM records ORDER BY name")
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
	return out, nil
}

// insert inserts one marker row.
func insert(cluster *goharness.Cluster, node int, id int64, name string) error {
	if _, err := cluster.Node(node).Execute(
		"INSERT INTO records(id, name) VALUES($1, $2)", id, name); err != nil {
		return fmt.Errorf("node%d insert %q: %w", node+1, name, err)
	}
	if err := cluster.Node(node).Flush(); err != nil {
		return fmt.Errorf("node%d flush after %q: %w", node+1, name, err)
	}
	return nil
}

// waitConverged waits until both nodes hold exactly want rows with equal
// ordered names.
func waitConverged(cluster *goharness.Cluster, want []string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		na, err := names(cluster, a)
		if err != nil {
			return err
		}
		nb, err := names(cluster, b)
		if err != nil {
			return err
		}
		if equalStrings(na, want) && equalStrings(nb, want) {
			return nil
		}
		if !time.Now().Before(deadline) {
			return fmt.Errorf("nodes did not converge on %v within %v", want, timeout)
		}
		time.Sleep(pollFast)
	}
}

// peerConnected reports whether from currently holds an open session to
// target (SHOW PEERS).
func peerConnected(cluster *goharness.Cluster, from, target int) (bool, error) {
	want := cluster.NodeID(target)
	rows, err := cluster.Node(from).ShowPeers()
	if err != nil {
		return false, fmt.Errorf("node%d SHOW PEERS: %w", from+1, err)
	}
	for _, row := range rows {
		if strings.EqualFold(row.NodeID, want) && row.Connected {
			return true, nil
		}
	}
	return false, nil
}

// connectedPeers returns the connected sessions on one node (the
// reference reads the peers column of MURMUR SHOW REPLICATION; here
// connected SHOW PEERS rows are counted, as PeerCounts does).
func connectedPeers(cluster *goharness.Cluster, idx int) (int64, error) {
	peers, err := cluster.Node(idx).ShowPeers()
	if err != nil {
		return 0, fmt.Errorf("node%d SHOW PEERS: %w", idx+1, err)
	}
	var n int64
	for _, p := range peers {
		if p.Connected {
			n++
		}
	}
	return n, nil
}

func waitPeerConnected(cluster *goharness.Cluster, from, target int, want bool, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		got, err := peerConnected(cluster, from, target)
		if err != nil {
			return err
		}
		if got == want {
			return nil
		}
		if !time.Now().Before(deadline) {
			return fmt.Errorf("peer %s Connected != %v on node%d within %v",
				cluster.NodeID(target), want, from+1, timeout)
		}
		time.Sleep(poll)
	}
}

func waitConnectedPeers(cluster *goharness.Cluster, idx int, want int64, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		got, err := connectedPeers(cluster, idx)
		if err != nil {
			return err
		}
		if got == want {
			return nil
		}
		if !time.Now().Before(deadline) {
			return fmt.Errorf("connected_peers != %d on node%d within %v", want, idx+1, timeout)
		}
		time.Sleep(poll)
	}
}

// servedLeaf returns the leaf certificate bytes node B currently serves.
// Rotation rewrites tls/node.pem from the same material the rebooted
// child loads, so file bytes always equal the served leaf; expiry itself
// is proven against the minted TTL clock (see the scenario README.md).
func servedLeaf(cluster *goharness.Cluster) ([]byte, error) {
	path := cluster.Node(b).TLS.Chain
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read served leaf %s: %w", path, err)
	}
	return body, nil
}

func servedLeafPath(cluster *goharness.Cluster) string {
	return cluster.Node(b).TLS.Chain
}

// rotateNodeCert issues a fresh leaf for node idx's NodeID and rewrites
// its tls/ files. The caller reboots the node afterwards so the child
// process loads the new material.
func rotateNodeCert(cluster *goharness.Cluster, idx int, ttl *time.Duration) error {
	node := cluster.Node(idx)
	issued, err := cluster.Ca.Issue(node.ID, ttl)
	if err != nil {
		return fmt.Errorf("issue leaf: %w", err)
	}
	if err := os.WriteFile(node.TLS.Chain, []byte(issued.CertPEM), 0o644); err != nil {
		return fmt.Errorf("rewrite leaf: %w", err)
	}
	if err := os.WriteFile(node.TLS.Key, []byte(issued.KeyPEM), 0o600); err != nil {
		return fmt.Errorf("rewrite key: %w", err)
	}
	return nil
}

// rebootNode restarts node idx on its existing dir (crash-style: SIGKILL
// plus fresh child boot, which reloads tls/ from disk) and re-meshes.
// The survivor's replication bounces first: this engine closes a
// fresh inbound session as a duplicate while any entry for the peer
// lives, so without the bounce the rebooted node's dials die on the
// survivor's zombie entry and markers never flow (murmur-server
// replaces zombies by tie-break instead). The bounce is graceful.
func rebootNode(cluster *goharness.Cluster, idx int, what string) error {
	if err := cluster.KillNode(idx); err != nil {
		return fmt.Errorf("%s: kill node%d: %w", what, idx+1, err)
	}
	return restartHealed(cluster, idx, what)
}

// restartHealed restarts a killed node and re-meshes, bouncing the
// survivor first so the rebooted node's dials register instead of
// dying as duplicates on the survivor's zombie entry.
func restartHealed(cluster *goharness.Cluster, idx int, what string) error {
	other := a
	if idx == a {
		other = b
	}
	if err := cluster.StopNode(other); err != nil {
		return fmt.Errorf("%s: bounce-stop node%d: %w", what, other+1, err)
	}
	if err := cluster.StartNode(other); err != nil {
		return fmt.Errorf("%s: bounce-start node%d: %w", what, other+1, err)
	}
	if err := cluster.RestartNode(idx); err != nil {
		return fmt.Errorf("%s: restart node%d: %w", what, idx+1, err)
	}
	if err := cluster.PeerMesh(); err != nil {
		return fmt.Errorf("%s: re-mesh: %w", what, err)
	}
	return nil
}

func runBody(cluster *goharness.Cluster, ttl, window time.Duration) error {
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

	// Phase 0: positive control, healthy mesh converges.
	if err := insert(cluster, a, 1, "marker-init"); err != nil {
		return err
	}
	if err := waitConverged(cluster, []string{"marker-init"}, convergeTimeout); err != nil {
		return err
	}
	if err := waitPeerConnected(cluster, a, b, true, peerTimeout); err != nil {
		return err
	}
	if n, err := connectedPeers(cluster, a); err != nil {
		return err
	} else if n != 1 {
		return fmt.Errorf("pre-expiry connected_peers(A) = %d, want 1", n)
	}

	// Phase 1: crash B (no graceful QUIC close: the survivor keeps a
	// zombie session), rotate to a short-expiry cert for the same NodeID.
	leafBefore, err := servedLeaf(cluster)
	if err != nil {
		return err
	}
	if err := cluster.KillNode(b); err != nil {
		return fmt.Errorf("crash node B: %w", err)
	}
	rotateStart := time.Now()
	if err := rotateNodeCert(cluster, b, &ttl); err != nil {
		return fmt.Errorf("rotate node B to short cert: %w", err)
	}
	mintedAt := time.Now()
	if err := restartHealed(cluster, b, "short-cert restart"); err != nil {
		return err
	}
	// Stale-cert guard: the served leaf must be fresh material (rewritten
	// at rotation time), not the pre-rotation cert.
	leafShort, err := servedLeaf(cluster)
	if err != nil {
		return err
	}
	if bytes.Equal(leafShort, leafBefore) {
		return fmt.Errorf("served leaf unchanged by rotation (stale cert?)")
	}
	info, err := os.Stat(servedLeafPath(cluster))
	if err != nil {
		return fmt.Errorf("served leaf mtime: %w", err)
	}
	if time.Since(info.ModTime()) > time.Since(rotateStart)+5*time.Second {
		return fmt.Errorf("served leaf mtime predates the rotation (stale cert?)")
	}
	notAfter := mintedAt.Add(ttl)
	fmt.Fprintf(os.Stderr, "short cert expires in %v\n", ttl)

	// Assert connected pre-expiry: session plus a converged marker, all
	// within NotAfter minus the safety margin.
	preBudget := time.Until(notAfter) - preExpiryMargin
	if preBudget <= 0 {
		return fmt.Errorf("no pre-expiry budget left")
	}
	budget := min(preBudget, peerTimeout)
	if err := waitPeerConnected(cluster, a, b, true, budget); err != nil {
		return err
	}
	if err := insert(cluster, a, 2, "marker-pre-expiry"); err != nil {
		return err
	}
	preLeft := time.Until(notAfter) - preExpiryMargin
	if preLeft < 0 {
		preLeft = 0
	}
	if err := waitConverged(cluster,
		[]string{"marker-init", "marker-pre-expiry"}, preLeft); err != nil {
		return err
	}

	// Phase 2: wait out the TTL, then force fresh handshakes by
	// rebooting B on the same expired leaf. An established session is not
	// re-validated mid-connection, so the reboot forces both sides to
	// re-handshake. B's listener starts fine with an expired cert (open
	// checks the SAN identity, not validity); its handshakes must fail.
	fmt.Fprintln(os.Stderr, "waiting for cert expiry")
	expiryDeadline := notAfter.Add(postExpirySettle)
	for time.Now().Before(expiryDeadline) {
		time.Sleep(250 * time.Millisecond)
	}
	if err := rebootNode(cluster, b, "expiry restart"); err != nil {
		return err
	}

	// B is rejected: survivor sees no session and connected_peers 1->0.
	if err := waitPeerConnected(cluster, a, b, false, rejectTimeout); err != nil {
		return err
	}
	if err := waitConnectedPeers(cluster, a, 0, rejectTimeout); err != nil {
		return err
	}
	// B's own view agrees.
	if err := waitPeerConnected(cluster, b, a, false, rejectTimeout); err != nil {
		return err
	}

	// Non-vacuity: at assert time, the cert B serves is expired: the
	// served material is byte-identical to the short leaf minted in
	// phase 1, and its TTL has fully elapsed.
	current, err := servedLeaf(cluster)
	if err != nil {
		return err
	}
	if !bytes.Equal(current, leafShort) {
		return fmt.Errorf("served leaf changed across the expiry restart (wrong cert under test?)")
	}
	if time.Now().Before(notAfter) {
		return fmt.Errorf("asserting rejection before the served cert expired")
	}
	fmt.Fprintln(os.Stderr, "rejection confirmed while serving the expired short cert")

	// An A-side marker written post-expiry must never reach B during the
	// isolation window, while A keeps serving it.
	if err := insert(cluster, a, 3, "marker-post-expiry"); err != nil {
		return err
	}
	windowEnd := time.Now().Add(window)
	for {
		nb, err := names(cluster, b)
		if err != nil {
			return err
		}
		for _, n := range nb {
			if n == "marker-post-expiry" {
				return fmt.Errorf("post-expiry marker reached expired node B")
			}
		}
		if n, err := connectedPeers(cluster, a); err != nil {
			return err
		} else if n != 0 {
			return fmt.Errorf("connected_peers(A) = %d during isolation window, want 0", n)
		}
		if !time.Now().Before(windowEnd) {
			break
		}
		time.Sleep(windowPoll)
	}
	nb, err := names(cluster, b)
	if err != nil {
		return err
	}
	for _, n := range nb {
		if n == "marker-post-expiry" {
			return fmt.Errorf("post-expiry marker reached expired node B")
		}
	}
	na, err := names(cluster, a)
	if err != nil {
		return err
	}
	if len(na) != 3 {
		return fmt.Errorf("A markers = %d, want 3", len(na))
	}

	// Phase 3: rotate to a fresh cert and assert full reconvergence.
	if err := cluster.KillNode(b); err != nil {
		return fmt.Errorf("stop node B for fresh rotation: %w", err)
	}
	freshTTL := 24 * time.Hour
	if err := rotateNodeCert(cluster, b, &freshTTL); err != nil {
		return fmt.Errorf("rotate node B to fresh cert: %w", err)
	}
	if err := restartHealed(cluster, b, "fresh-cert restart"); err != nil {
		return err
	}
	if err := waitPeerConnected(cluster, a, b, true, convergeTimeout); err != nil {
		return err
	}
	if err := waitConverged(cluster, []string{
		"marker-init",
		"marker-post-expiry",
		"marker-pre-expiry",
	}, convergeTimeout); err != nil {
		return err
	}
	// Bidirectional proof: a B-side write converges too.
	if err := insert(cluster, b, 4, "marker-rotated"); err != nil {
		return err
	}
	wantAll := []string{
		"marker-init",
		"marker-post-expiry",
		"marker-pre-expiry",
		"marker-rotated",
	}
	if err := waitConverged(cluster, wantAll, convergeTimeout); err != nil {
		return err
	}
	aNames, err := names(cluster, a)
	if err != nil {
		return err
	}
	bNames, err := names(cluster, b)
	if err != nil {
		return err
	}
	if !equalStrings(aNames, bNames) {
		return fmt.Errorf("post-rotation names differ: A=%v B=%v", aNames, bNames)
	}
	fmt.Fprintf(os.Stderr, "rotation healed mesh; names=%v\n", aNames)
	return nil
}

func TestCertExpiryRejectsAndRotationHeals(t *testing.T) {
	goharness.SkipUnlessLive(t)
	ttl := goharness.EnvSeconds("MURMUR_CERT_LIFECYCLE_TTL_S", 25)
	window := goharness.EnvSeconds("MURMUR_CERT_LIFECYCLE_WINDOW_S", 10)
	if ttl < 15*time.Second {
		t.Fatalf("short-cert TTL %v too small to converge pre-expiry; raise MURMUR_CERT_LIFECYCLE_TTL_S", ttl)
	}

	// Pinned adversarial id order (survivor A < restarted B): the
	// harness issues deterministic node ids (index+1 in the last byte),
	// so A sorts first already. The survivor's pre-restart session is
	// then in its tie-break-preferred direction, so a re-mesh that keeps
	// zombies over fresh handshakes stalls every rotation leg
	// deterministically instead of flaking 50/50 on random ids.
	cluster, err := goharness.NewCluster(goharness.ClusterOptions{
		Name:     "cert-lifecycle",
		NumNodes: 2,
		ChildSet: map[int]bool{b: true},
	})
	if err != nil {
		t.Fatalf("cluster setup: %v", err)
	}
	if cluster.Len() != 2 {
		t.Fatalf("this scenario is written for 2 nodes, got %d", cluster.Len())
	}
	resultErr := runBody(cluster, ttl, window)
	failed := resultErr != nil
	if resultErr != nil {
		fmt.Fprintf(os.Stderr, "scenario failed: %v\n", resultErr)
	}
	cluster.Finish(failed)
	if failed {
		t.Fatalf("scenario failed: %v; artifacts retained under tests-live/failures/", resultErr)
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
