// Live scenario: a CRL revoking a peer's leaf is enforced on the
// live mesh in both handshake directions.
package crlrevoke

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	goharness "github.com/marcgauthier/libmurmur/clients/go/tests-live/goharness"
)

// revoked is the revoked node.
const revoked = 2

const (
	waitTimeout   = 60 * time.Second
	poll          = 200 * time.Millisecond
	isolationHold = 5 * time.Second
)

func names(cluster *goharness.Cluster, idx int) ([]string, error) {
	rows, err := cluster.Node(idx).Simple("SELECT name FROM records")
	if err != nil {
		return nil, fmt.Errorf("node%d SELECT names: %w", idx+1, err)
	}
	out := make([]string, 0, len(rows))
	for _, row := range rows {
		out = append(out, row[0])
	}
	sort.Strings(out)
	return out, nil
}

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

func waitConverged(cluster *goharness.Cluster, nodes []int, want int, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		var first []string
		seen, ok := false, true
		for _, i := range nodes {
			nodeNames, err := names(cluster, i)
			if err != nil {
				return err
			}
			if len(nodeNames) != want {
				ok = false
				break
			}
			if !seen {
				first, seen = nodeNames, true
			} else if !equalStrings(first, nodeNames) {
				ok = false
				break
			}
		}
		if ok {
			return nil
		}
		if !time.Now().Before(deadline) {
			return fmt.Errorf("nodes %v did not converge on %d rows within %v", nodes, want, timeout)
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

func peerConnected(cluster *goharness.Cluster, from, target int) (bool, error) {
	want := cluster.NodeID(target)
	peers, err := cluster.Node(from).ShowPeers()
	if err != nil {
		return false, fmt.Errorf("node%d SHOW PEERS: %w", from+1, err)
	}
	for _, p := range peers {
		if strings.EqualFold(p.NodeID, want) && p.Connected {
			return true, nil
		}
	}
	return false, nil
}

func waitSessionsDrop(cluster *goharness.Cluster, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		c0, err := peerConnected(cluster, 0, revoked)
		if err != nil {
			return err
		}
		c1, err := peerConnected(cluster, 1, revoked)
		if err != nil {
			return err
		}
		if !c0 && !c1 {
			return nil
		}
		if !time.Now().Before(deadline) {
			return fmt.Errorf("sessions to node3 did not drop within %v", timeout)
		}
		time.Sleep(poll)
	}
}

// leafSerial parses the serial of node's TLS leaf certificate.
func leafSerial(cluster *goharness.Cluster, idx int) (*big.Int, error) {
	raw, err := os.ReadFile(cluster.Node(idx).TLS.Chain)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("node%d chain has no certificate PEM", idx+1)
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	return leaf.SerialNumber, nil
}

// installCRL writes crlPEM to idx's tls dir and points crl_file at it.
func installCRL(cluster *goharness.Cluster, idx int, crlPEM []byte) error {
	path := filepath.Join(filepath.Dir(cluster.Node(idx).TLS.Ca), "crl.pem")
	if err := os.WriteFile(path, crlPEM, 0o644); err != nil {
		return fmt.Errorf("node%d write CRL: %w", idx+1, err)
	}
	_, err := cluster.Node(idx).Simple(
		"INSERT INTO murmur_config(name,value) VALUES('crl_file','" + path +
			"') ON CONFLICT(name) DO UPDATE SET value=excluded.value")
	if err != nil {
		return fmt.Errorf("node%d set crl_file: %w", idx+1, err)
	}
	return nil
}

func addPeer(cluster *goharness.Cluster, from, to int) error {
	return cluster.Node(from).PeerAdd(cluster.Node(to).Addr)
}

func runBody(cluster *goharness.Cluster) error {
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
	if err := cluster.PeerMesh(); err != nil {
		return fmt.Errorf("mesh: %w", err)
	}
	for i := int64(0); i < 5; i++ {
		if err := insert(cluster, 0, i+1, fmt.Sprintf("a-%d", i)); err != nil {
			return err
		}
	}
	if err := waitConverged(cluster, []int{0, 1, 2}, 5, waitTimeout); err != nil {
		return err
	}

	// Revoke node3's leaf; install the CRL on both survivors.
	serial, err := leafSerial(cluster, revoked)
	if err != nil {
		return fmt.Errorf("leaf serial: %w", err)
	}
	crlPEM, err := cluster.Ca.IssueCRL([]*big.Int{serial}, time.Hour)
	if err != nil {
		return fmt.Errorf("mint CRL: %w", err)
	}
	for _, i := range []int{0, 1} {
		if err := installCRL(cluster, i, crlPEM); err != nil {
			return err
		}
		if err := cluster.StopNode(i); err != nil {
			return fmt.Errorf("stop node%d: %w", i+1, err)
		}
		if err := cluster.StartNode(i); err != nil {
			return fmt.Errorf("restart node%d: %w", i+1, err)
		}
	}
	// The survivor link comes back; sessions to node3 stay down.
	if err := addPeer(cluster, 0, 1); err != nil {
		return fmt.Errorf("re-mesh 0->1: %w", err)
	}
	if err := addPeer(cluster, 1, 0); err != nil {
		return fmt.Errorf("re-mesh 1->0: %w", err)
	}
	if err := goharness.PeerCounts(cluster, []int{0, 1}, []int{1, 1}, waitTimeout); err != nil {
		return fmt.Errorf("survivor link: %w", err)
	}
	if err := waitSessionsDrop(cluster, waitTimeout); err != nil {
		return err
	}
	// Isolation holds in both directions: neither side's writes cross.
	if err := insert(cluster, revoked, 100, "isolated"); err != nil {
		return err
	}
	time.Sleep(isolationHold)
	for _, i := range []int{0, 1} {
		survivor, err := names(cluster, i)
		if err != nil {
			return err
		}
		if len(survivor) != 5 {
			return fmt.Errorf("node%d names after isolation = %v; want five survivors", i+1, survivor)
		}
	}
	if err := insert(cluster, 0, 101, "survivor-only"); err != nil {
		return err
	}
	if err := waitConverged(cluster, []int{0, 1}, 6, waitTimeout); err != nil {
		return err
	}
	time.Sleep(isolationHold)
	if got, err := names(cluster, revoked); err != nil {
		return err
	} else {
		for _, n := range got {
			if n == "survivor-only" {
				return fmt.Errorf("node3 received survivor-only after revocation: %v", got)
			}
		}
	}
	return nil
}

func TestRevokedLeafRefusedLive(t *testing.T) {
	goharness.SkipUnlessLive(t)
	cluster, err := goharness.NewCluster(goharness.ClusterOptions{
		Name:     "crl-revoke",
		NumNodes: 3,
	})
	if err != nil {
		t.Fatalf("cluster setup: %v", err)
	}
	if cluster.Len() != 3 {
		cluster.Finish(true)
		t.Fatalf("this scenario is written for 3 nodes, got %d", cluster.Len())
	}
	failed := true
	defer func() { cluster.Finish(failed) }()
	if resultErr := runBody(cluster); resultErr != nil {
		fmt.Fprintf(os.Stderr, "scenario failed: %v\n", resultErr)
		t.Fatalf("scenario failed: %v; artifacts retained under tests-live/failures/", resultErr)
	}
	failed = false
}
