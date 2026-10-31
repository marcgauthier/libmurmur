// Live scenario: SQL values and unlock credentials must never reach
// durable artifacts in plaintext.
//
// Port of MURMUR-SQL plaintext-audit: two native nodes replicate marker
// rows, node 0 takes a backup, both nodes stop, the runtime dir is
// audited byte-by-byte for the marker and the unlock key, then both
// nodes restart and converge on the same rows. The byte audit is inlined
// here (the native harness has no audit helper).
package plaintextaudit

import (
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	goharness "github.com/marcgauthier/sqlite-murmur-go/clients/go/tests-live/goharness"
)

func TestPlaintextAuditMarkersAndUnlockKeyAbsentOnDisk(t *testing.T) {
	goharness.SkipUnlessLive(t)
	cluster, err := goharness.NewCluster(goharness.ClusterOptions{
		Name:     "plaintext-audit",
		NumNodes: 2,
	})
	if err != nil {
		t.Fatalf("start cluster: %v", err)
	}
	failed := true
	defer func() { cluster.Finish(failed) }()

	for i := 0; i < 2; i++ {
		if _, err := cluster.Node(i).Simple(
			"CREATE TABLE IF NOT EXISTS secrets(id INTEGER PRIMARY KEY NOT NULL, body TEXT NOT NULL DEFAULT '')"); err != nil {
			t.Fatalf("node %d create secrets: %v", i, err)
		}
		if err := cluster.Node(i).SetTableReplicated("secrets", true); err != nil {
			t.Fatalf("node %d replicate secrets: %v", i, err)
		}
	}
	marker := fmt.Sprintf("live-sql-plaintext-audit-%s", cluster.NodeID(0))
	for i := 0; i < 2; i++ {
		if _, err := cluster.Node(i).Execute(
			"INSERT INTO secrets(id,body) VALUES($1,$2)", int64(i), marker); err != nil {
			t.Fatalf("node %d insert marker: %v", i, err)
		}
		if err := cluster.Node(i).Flush(); err != nil {
			t.Fatalf("node %d flush marker: %v", i, err)
		}
	}
	expected := [][]string{{marker}, {marker}}
	if err := goharness.AssertRows(cluster, []int{0, 1},
		"SELECT body FROM secrets ORDER BY id", expected); err != nil {
		t.Fatalf("converge markers: %v", err)
	}
	// Backup archives are included in the byte-level audit.
	if err := cluster.Backup(0, filepath.Join(cluster.RuntimeDir(), "backup")); err != nil {
		t.Fatalf("backup: %v", err)
	}
	for i := 0; i < 2; i++ {
		if err := cluster.Node(i).Flush(); err != nil {
			t.Fatalf("node %d pre-stop flush: %v", i, err)
		}
		if err := cluster.StopNode(i); err != nil {
			t.Fatalf("stop node %d: %v", i, err)
		}
	}
	key := cluster.Key
	if err := assertNoPlaintext(cluster.RuntimeDir(),
		[][]byte{[]byte(marker), key[:]}); err != nil {
		t.Fatalf("plaintext audit: %v", err)
	}
	for i := 0; i < 2; i++ {
		if err := cluster.StartNode(i); err != nil {
			t.Fatalf("start node %d: %v", i, err)
		}
	}
	if err := goharness.AssertRows(cluster, []int{0, 1},
		"SELECT body FROM secrets ORDER BY id", expected); err != nil {
		t.Fatalf("converge after restart: %v", err)
	}
	failed = false
}

// assertNoPlaintext recursively inspects durable artifacts without
// opening a database, failing when any needle appears.
func assertNoPlaintext(root string, needles [][]byte) error {
	for _, needle := range needles {
		if len(needle) == 0 {
			return fmt.Errorf("plaintext audit: empty needle")
		}
	}
	return filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !d.Type().IsRegular() {
			return nil
		}
		contents, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, needle := range needles {
			if bytes.Index(contents, needle) >= 0 {
				return fmt.Errorf("plaintext found in %s", path)
			}
		}
		return nil
	})
}
