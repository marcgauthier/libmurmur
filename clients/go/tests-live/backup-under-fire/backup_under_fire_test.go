// Live scenario: take streaming online backups while a separate SQL
// connection commits transactions.
//
// Port of MURMUR-SQL backup-under-fire: a writer commits 40 atomic
// five-row batches while four online backups are taken; every restored
// backup holds a transaction-aligned row prefix. The reference
// tokio::join! over the writer and the backup loop becomes a
// sync.WaitGroup with the backup loop on the test goroutine. The
// BACKUP SAVE/DOWNLOAD/UPLOAD/RESTORE archive streams map to store
// checkpoints (cluster.Backup/cluster.Restore plus direct store
// opens), following the tampered-backup port; the multi-row INSERT
// stays the atomic unit and carries ten ordered $N placeholders (the
// harness translates $N to ? only in order from 1).
package backupunderfire

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/marcgauthier/sqlite-murmur-go/clients/go/bindings/sqlite"
	goharness "github.com/marcgauthier/sqlite-murmur-go/clients/go/tests-live/goharness"
)

func TestOnlineBackupsCaptureAtomicCommits(t *testing.T) {
	goharness.SkipUnlessLive(t)
	cluster, err := goharness.NewCluster(goharness.ClusterOptions{
		Name:     "backup-under-fire",
		NumNodes: 1,
	})
	if err != nil {
		t.Fatalf("start cluster: %v", err)
	}
	failed := true
	defer func() { cluster.Finish(failed) }()

	if _, err := cluster.Node(0).Simple("CREATE TABLE records(id INTEGER PRIMARY KEY NOT NULL, batch INTEGER NOT NULL DEFAULT 0)"); err != nil {
		t.Fatalf("create records: %v", err)
	}
	// Land the schema before the first checkpoint: checkpoints read
	// store files, so an unflushed CREATE would leave the earliest
	// backup without the table.
	if err := cluster.Node(0).Flush(); err != nil {
		t.Fatalf("flush schema: %v", err)
	}
	waitForStoreData(t, cluster.Node(0).DataDir)

	var wg sync.WaitGroup
	var writerErr error
	wg.Add(1)
	go func() {
		defer wg.Done()
		for batch := int64(0); batch < 40; batch++ {
			// One multi-row INSERT is the actual atomic unit:
			// transaction control words are documented no-ops on the
			// SQL server.
			ids := [5]int64{batch * 5, batch*5 + 1, batch*5 + 2, batch*5 + 3, batch*5 + 4}
			if _, err := cluster.Node(0).Execute(
				"INSERT INTO records(id,batch) VALUES($1,$2),($3,$4),($5,$6),($7,$8),($9,$10)",
				ids[0], batch, ids[1], batch, ids[2], batch, ids[3], batch, ids[4], batch); err != nil {
				writerErr = err
				return
			}
			// Land each batch: checkpoints read store files, so only
			// landed batches are visible to concurrent backups (the
			// reference's pgwire commits land immediately).
			if err := cluster.Node(0).Flush(); err != nil {
				writerErr = err
				return
			}
			// Pacing stretched from the reference 5 ms: durability is
			// periodic (250 ms background flusher), so the write phase
			// must span several landing intervals for the backups to
			// capture growing prefixes.
			time.Sleep(30 * time.Millisecond)
		}
		if err := cluster.Node(0).Flush(); err != nil {
			writerErr = err
		}
	}()

	var archives []string
	var backupErr error
	for i := 0; i < 4 && backupErr == nil; i++ {
		dest := filepath.Join(cluster.RuntimeDir(), fmt.Sprintf("under-fire-%d", i))
		if err := cluster.Backup(0, dest); err != nil {
			backupErr = err
			break
		}
		if dirSize(dest) <= 0 {
			backupErr = fmt.Errorf("backup %d is empty", i)
			break
		}
		archives = append(archives, dest)
		// Pacing stretched from the reference 30 ms to match the
		// stretched write phase (one backup per landing interval).
		time.Sleep(300 * time.Millisecond)
	}
	wg.Wait()
	if writerErr != nil {
		t.Fatalf("writer: %v", writerErr)
	}
	if backupErr != nil {
		t.Fatalf("backup loop: %v", backupErr)
	}
	count, err := cluster.Node(0).Simple("SELECT count(*) FROM records")
	if err != nil {
		t.Fatalf("count records: %v", err)
	}
	if !equalRows(count, [][]string{{"200"}}) {
		t.Fatalf("record count = %v, want 200", count)
	}
	previous := 0
	for _, name := range archives {
		restored := name + "-restored"
		if err := cluster.Restore(name, restored, nil); err != nil {
			t.Fatalf("restore %s: %v", name, err)
		}
		rows, err := readStoreRows(restored, cluster.Key)
		if err != nil {
			t.Fatalf("read restored %s: %v", name, err)
		}
		if len(rows) < previous || len(rows) > 200 {
			t.Fatalf("backup prefix regressed: %d rows after %d", len(rows), previous)
		}
		previous = len(rows)
		if len(rows)%5 != 0 {
			t.Fatalf("snapshot split an atomic five-row transaction: %d rows", len(rows))
		}
		for id, row := range rows {
			want := []string{fmt.Sprintf("%d", id), fmt.Sprintf("%d", id/5)}
			if !equalRows([][]string{row}, [][]string{want}) {
				t.Fatalf("row %d = %v, want %v", id, row, want)
			}
		}
	}
	failed = false
}

// dirSize sums the regular-file sizes under dir.
func dirSize(dir string) int64 {
	var total int64
	_ = filepath.Walk(dir, func(_ string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			total += info.Size()
		}
		return nil
	})
	return total
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
				if e.IsDir() {
					continue
				}
				for _, suf := range []string{".log", ".sst"} {
					if len(name) > len(suf) && name[len(name)-len(suf):] == suf {
						if st, err := e.Info(); err == nil && st.Size() > 0 {
							ready = true
						}
					}
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
	st, err := conn.Prepare("SELECT id,batch FROM records ORDER BY id")
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
		rows = append(rows, []string{
			fmt.Sprintf("%d", st.ColumnInt64(0)),
			fmt.Sprintf("%d", st.ColumnInt64(1)),
		})
	}
	return rows, nil
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
