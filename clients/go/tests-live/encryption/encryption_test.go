// Live scenario: encrypted persistence keeps rows from disk plaintext
// and survives a process restart.
//
// Port of MURMUR-SQL encryption: a single child-process node takes a
// confidential row, the node exits gracefully, the stopped dir is
// audited for plaintext, a fresh child process reopens the store on the
// same key, and the row survives. The reference's wrong-key legs
// (cold-start 28000, wrong-key wire client) have no native counterpart —
// the harness cannot restart with an alternate key and there is no wire
// auth surface — so they live in TestEncryptedSQLRejectsWrongKey, which
// skips.
package encryption

import (
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	goharness "github.com/marcgauthier/sqlite-murmur-go/clients/go/tests-live/goharness"
)

const secret = "SQL-CONFIDENTIAL-PLAINTEXT-SECRET-246813579"

func TestEncryptedSQLRowsSurviveRestart(t *testing.T) {
	goharness.SkipUnlessLive(t)
	cluster, err := goharness.NewCluster(goharness.ClusterOptions{
		Name:       "encryption",
		NumNodes:   1,
		ChildNodes: true,
	})
	if err != nil {
		t.Fatalf("start cluster: %v", err)
	}
	failed := true
	defer func() { cluster.Finish(failed) }()

	if _, err := cluster.Node(0).Simple("CREATE TABLE records(name TEXT PRIMARY KEY NOT NULL DEFAULT '')"); err != nil {
		t.Fatalf("create records: %v", err)
	}
	if _, err := cluster.Node(0).Execute("INSERT INTO records(name) VALUES($1)", secret); err != nil {
		t.Fatalf("insert secret: %v", err)
	}
	if err := cluster.Node(0).Flush(); err != nil {
		t.Fatalf("flush seed: %v", err)
	}
	expected := [][]string{{secret}}
	rows, err := cluster.Node(0).Simple("SELECT name FROM records")
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if !equalRows(rows, expected) {
		t.Fatalf("read back: got %v, want %v", rows, expected)
	}
	old := cluster.Node(0)
	dir, id, addr, tls := old.Dir, old.ID, old.Addr, old.TLS
	// Graceful child exit (mirrors the reference's graceful stop);
	// a SIGKILL here would lose flushed writes (see README).
	if err := old.Close(); err != nil {
		t.Fatalf("stop node: %v", err)
	}
	if err := assertNoPlaintext(dir, [][]byte{[]byte(secret)}); err != nil {
		t.Fatalf("plaintext audit: %v", err)
	}
	rebooted, err := goharness.BootNode(goharness.NodeConfig{
		Dir: dir, ID: id, Group: cluster.Group, Addr: addr,
		TLS: tls, Key: cluster.Key, Trust: [][16]byte{id}, Child: true,
	})
	if err != nil {
		t.Fatalf("restart node: %v", err)
	}
	defer rebooted.Close()
	rows, err = rebooted.Simple("SELECT name FROM records")
	if err != nil {
		t.Fatalf("read after restart: %v", err)
	}
	if !equalRows(rows, expected) {
		t.Fatalf("read after restart: got %v, want %v", rows, expected)
	}
	failed = false
}

func TestEncryptedSQLRejectsWrongKey(t *testing.T) {
	goharness.SkipUnlessLive(t)
	// Blocked: the harness cannot restart a node with an alternate
	// unlock key, and native nodes expose no wire auth surface that
	// could reject a wrong key with 28000.
	t.Skip("harness: restart/unlock with an alternate key and wire-level unlock auth")
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

func equalRows(a, b [][]string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if len(a[i]) != len(b[i]) {
			return false
		}
		for j := range a[i] {
			if a[i][j] != b[i][j] {
				return false
			}
		}
	}
	return true
}
