package fetchrestart

import (
	"bytes"
	"crypto/rand"
	"testing"
	"time"

	goharness "github.com/marcgauthier/sqlite-murmur-go/clients/go/tests-live/goharness"
)

// Regression: in-process StopNode/StartNode on a node that completed a
// file fetch failed with `driver start: sqlite sqlrc=0: File exists`
// (second murmur_files_open hit EEXIST); nodes that never fetched
// restarted fine.
func TestFetchRestart(t *testing.T) {
	goharness.SkipUnlessLive(t)
	cluster, err := goharness.NewCluster(goharness.ClusterOptions{
		Name:     "fetch-restart",
		NumNodes: 2,
		Files:    true,
	})
	if err != nil {
		t.Fatalf("cluster setup: %v", err)
	}
	failed := true
	defer func() { cluster.Finish(failed) }()

	// Meshgate: seed sessions only establish once user-table writes
	// give the sync loop something to ship.
	for i := 0; i < 2; i++ {
		if _, err := cluster.Node(i).Simple(
			"CREATE TABLE IF NOT EXISTS meshgate(id INTEGER PRIMARY KEY NOT NULL)"); err != nil {
			t.Fatalf("node%d create meshgate: %v", i, err)
		}
		if err := cluster.Node(i).SetTableReplicated("meshgate", true); err != nil {
			t.Fatalf("node%d replicate meshgate: %v", i, err)
		}
	}
	if _, err := cluster.Node(0).Execute("INSERT INTO meshgate(id) VALUES(1)"); err != nil {
		t.Fatalf("insert meshgate row: %v", err)
	}
	if err := cluster.Node(0).Flush(); err != nil {
		t.Fatalf("flush meshgate row: %v", err)
	}
	if err := goharness.AssertRows(cluster, []int{0, 1},
		"SELECT id FROM meshgate", [][]string{{"1"}}); err != nil {
		t.Fatalf("converge meshgate row: %v", err)
	}

	data := make([]byte, 1<<18)
	if _, err := rand.Read(data); err != nil {
		t.Fatalf("rand: %v", err)
	}
	if err := cluster.Node(0).FileUpload("restart-blob", data); err != nil {
		t.Fatalf("upload: %v", err)
	}
	deadline := time.Now().Add(150 * time.Second)
	for {
		ok, err := cluster.Node(1).FileAvailable("restart-blob")
		if err != nil {
			t.Fatalf("available: %v", err)
		}
		if ok {
			break
		}
		if !time.Now().Before(deadline) {
			t.Fatal("node1 never fetched restart-blob")
		}
		time.Sleep(time.Second)
	}
	got, err := cluster.Node(1).FileDownload("restart-blob")
	if err != nil {
		t.Fatalf("download before restart: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Fatal("download before restart mismatches upload")
	}
	if err := cluster.StopNode(1); err != nil {
		t.Fatalf("stop fetcher: %v", err)
	}
	if err := cluster.StartNode(1); err != nil {
		t.Fatalf("restart fetcher: %v", err)
	}
	got, err = cluster.Node(1).FileDownload("restart-blob")
	if err != nil {
		t.Fatalf("download after restart: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Fatal("download after restart mismatches upload")
	}
	failed = false
}
