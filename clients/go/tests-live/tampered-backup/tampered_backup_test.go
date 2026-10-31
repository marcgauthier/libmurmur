// Live scenario: corrupt backups fail closed and leave the live database
// untouched.
//
// Port of MURMUR-SQL tampered-backup: a single local-only node holds 30
// rows, a backup is saved, three corruptions (bad magic, flipped payload
// byte, truncation) must be rejected at restore while the live rows stay
// intact, and the pristine backup still restores after a DELETE. The
// reference SQL archive streams (BACKUP SAVE/DOWNLOAD, upload, RESTORE)
// map to store checkpoints (cluster.Backup/cluster.Restore plus direct
// store opens): corruption targets the checkpoint files the store open
// verifies (MANIFEST header, SST payload), and restore opens reject them.
// Durability here is periodic (250 ms background flusher), so the test
// waits for the live store to land pages before backing up.
package tamperedbackup

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marcgauthier/sqlite-murmur-go/clients/go/bindings/sqlite"
	goharness "github.com/marcgauthier/sqlite-murmur-go/clients/go/tests-live/goharness"
)

func TestTamperedBackupStreamsLeaveLiveDatabaseUntouched(t *testing.T) {
	goharness.SkipUnlessLive(t)
	cluster, err := goharness.NewCluster(goharness.ClusterOptions{
		Name:     "tampered-backup",
		NumNodes: 1,
	})
	if err != nil {
		t.Fatalf("start cluster: %v", err)
	}
	failed := true
	defer func() { cluster.Finish(failed) }()

	if _, err := cluster.Node(0).Simple(
		"CREATE TABLE records(id INTEGER PRIMARY KEY NOT NULL, name TEXT NOT NULL DEFAULT '')"); err != nil {
		t.Fatalf("create records: %v", err)
	}
	for id := int64(0); id < 30; id++ {
		name := fmt.Sprintf("kept-%03d", id)
		if _, err := cluster.Node(0).Execute(
			"INSERT INTO records(id,name) VALUES($1,$2)", id, name); err != nil {
			t.Fatalf("insert %d: %v", id, err)
		}
	}
	if err := cluster.Node(0).Flush(); err != nil {
		t.Fatalf("flush records: %v", err)
	}
	// Wait for the background flusher to land pages in the store so the
	// checkpoint captures them.
	waitForStoreData(t, cluster.Node(0).DataDir)
	expected, err := cluster.Node(0).Simple("SELECT id,name FROM records ORDER BY id")
	if err != nil {
		t.Fatalf("read expected: %v", err)
	}
	backupDir := filepath.Join(cluster.RuntimeDir(), "backup-pristine")
	if err := cluster.Backup(0, backupDir); err != nil {
		t.Fatalf("backup save: %v", err)
	}
	var total int64
	if err := filepath.WalkDir(backupDir, func(_ string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			st, err := d.Info()
			if err != nil {
				return err
			}
			total += st.Size()
		}
		return nil
	}); err != nil {
		t.Fatalf("walk backup: %v", err)
	}
	if total <= 100 {
		t.Fatalf("backup is %d bytes, want > 100", total)
	}
	manifestFile := findFile(t, backupDir, "MANIFEST-")
	dataFile := findFile(t, backupDir, ".sst")
	for _, tc := range []struct {
		name string
		file string
		edit func(b []byte) []byte
	}{
		{"bad-magic", manifestFile, func(b []byte) []byte {
			b[0] ^= 0xff
			return b
		}},
		{"bad-payload", dataFile, func(b []byte) []byte {
			b[len(b)/2] ^= 0x80
			return b
		}},
		{"truncated", dataFile, func(b []byte) []byte {
			return b[:len(b)/2]
		}},
	} {
		tampered := filepath.Join(cluster.RuntimeDir(), "tampered-"+tc.name)
		restored := filepath.Join(cluster.RuntimeDir(), "restored-"+tc.name)
		if err := copyTree(backupDir, tampered); err != nil {
			t.Fatalf("copy backup for %s: %v", tc.name, err)
		}
		rel, _ := filepath.Rel(backupDir, tc.file)
		raw, err := os.ReadFile(filepath.Join(tampered, rel))
		if err != nil {
			t.Fatalf("read %s target: %v", tc.name, err)
		}
		if err := os.WriteFile(filepath.Join(tampered, rel), tc.edit(raw), 0o644); err != nil {
			t.Fatalf("corrupt %s: %v", tc.name, err)
		}
		// Restore must reject the corrupt archive.
		if err := cluster.Restore(tampered, restored, nil); err == nil {
			rows, rerr := readStoreRows(restored, cluster.Key)
			if rerr == nil && equalRows(rows, expected) {
				t.Fatalf("accepted corrupt archive %s", tc.name)
			}
			if rerr == nil {
				t.Fatalf("corrupt archive %s restored wrong rows silently", tc.name)
			}
		}
		rows, err := cluster.Node(0).Simple("SELECT id,name FROM records ORDER BY id")
		if err != nil {
			t.Fatalf("reread after %s: %v", tc.name, err)
		}
		if !equalRows(rows, expected) {
			t.Fatalf("corrupt restore modified live rows: %s", tc.name)
		}
	}
	if _, err := cluster.Node(0).Simple("DELETE FROM records"); err != nil {
		t.Fatalf("delete records: %v", err)
	}
	restoreDir := filepath.Join(cluster.RuntimeDir(), "restore-pristine")
	if err := cluster.Restore(backupDir, restoreDir, nil); err != nil {
		t.Fatalf("restore pristine backup: %v", err)
	}
	rows, err := readStoreRows(restoreDir, cluster.Key)
	if err != nil {
		t.Fatalf("reread after restore: %v", err)
	}
	if !equalRows(rows, expected) {
		t.Fatalf("restored rows = %v, want %v", rows, expected)
	}
	failed = false
}

// waitForStoreData polls until the live store holds landed pages (a
// non-empty WAL or SST), then lets one more flush interval pass.
func waitForStoreData(t *testing.T, dataDir string) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for {
		ready := false
		ents, err := os.ReadDir(dataDir)
		if err == nil {
			for _, e := range ents {
				name := e.Name()
				if e.IsDir() || (!strings.HasSuffix(name, ".log") && !strings.HasSuffix(name, ".sst")) {
					continue
				}
				if st, err := e.Info(); err == nil && st.Size() > 0 {
					ready = true
					break
				}
			}
		}
		if ready {
			time.Sleep(500 * time.Millisecond)
			return
		}
		if !time.Now().Before(deadline) {
			t.Fatal("live store landed no data within 15s")
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// findFile locates the first regular file under dir whose name carries
// the given infix (e.g. "MANIFEST-" or ".sst").
func findFile(t *testing.T, dir, infix string) string {
	t.Helper()
	var found string
	if err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || found != "" {
			return err
		}
		if strings.Contains(d.Name(), infix) {
			st, err := d.Info()
			if err != nil {
				return err
			}
			if st.Size() > 0 {
				found = p
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("walk backup for %s: %v", infix, err)
	}
	if found == "" {
		t.Fatalf("no %s file in backup", infix)
	}
	return found
}

// readStoreRows opens a restored store copy directly and reads the rows.
func readStoreRows(dir string, key [32]byte) ([][]string, error) {
	conn, err := sqlite.OpenVFS(dir, sqlite.OpenReadWrite, "sqlite-murmur")
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if rc := conn.SetKey(key); rc != 0 {
		return nil, fmt.Errorf("key store: rc=%d", rc)
	}
	st, err := conn.Prepare("SELECT id,name FROM records ORDER BY id")
	if err != nil {
		return nil, err
	}
	defer st.Close()
	var rows [][]string
	for {
		done, err := st.Step()
		if err != nil {
			return nil, err
		}
		if done {
			break
		}
		row := make([]string, st.ColumnCount())
		for i := range row {
			switch st.ColumnType(i) {
			case 1:
				row[i] = fmt.Sprintf("%d", st.ColumnInt64(i))
			case 3:
				row[i] = st.ColumnText(i)
			default:
				row[i] = st.ColumnText(i)
			}
		}
		rows = append(rows, row)
	}
	return rows, nil
}

func copyTree(src, dst string) error {
	return filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, p)
		if err != nil {
			return err
		}
		out := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(out, 0o755)
		}
		raw, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(out, raw, 0o644)
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
