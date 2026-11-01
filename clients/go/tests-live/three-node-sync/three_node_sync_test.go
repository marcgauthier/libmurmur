// Live scenario: concurrent SQL writers must replicate all rows.
//
// Port of MURMUR-SQL three-node-sync: three native nodes each insert
// 30 disjoint rows concurrently; the test waits for all 90 ordered
// names on every node and compares replicated keys. Managed-key
// comparison maps to full ordered-row comparison (no
// id_murmur_primary_key column exists on cr-sqlite rows here).
package threenodesync

import (
	"fmt"
	"sort"
	"sync"
	"testing"
	"time"

	goharness "github.com/marcgauthier/libmurmur/clients/go/tests-live/goharness"
)

const (
	rowsPerNode         = 30
	convergenceTimeout  = 60 * time.Second
	convergenceInterval = 50 * time.Millisecond
)

func TestThreeNodeSync(t *testing.T) {
	goharness.SkipUnlessLive(t)
	cluster, err := goharness.NewCluster(goharness.ClusterOptions{
		Name:     "three-node-sync",
		NumNodes: 3,
	})
	if err != nil {
		t.Fatalf("start cluster: %v", err)
	}
	failed := true
	defer func() { cluster.Finish(failed) }()

	for i := 0; i < cluster.Len(); i++ {
		if _, err := cluster.Node(i).Simple(
			"CREATE TABLE IF NOT EXISTS records(id INTEGER PRIMARY KEY NOT NULL, name TEXT NOT NULL DEFAULT '')"); err != nil {
			t.Fatalf("node %d create records: %v", i, err)
		}
		if err := cluster.Node(i).SetTableReplicated("records", true); err != nil {
			t.Fatalf("node %d replicate records: %v", i, err)
		}
		if err := cluster.Node(i).Flush(); err != nil {
			t.Fatalf("node %d flush schema: %v", i, err)
		}
	}

	var wg sync.WaitGroup
	errs := make([]error, cluster.Len())
	for i := 0; i < cluster.Len(); i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for row := int64(0); row < rowsPerNode; row++ {
				id := int64(i)*1000 + row
				name := fmt.Sprintf("node-%d-row-%02d", i, row)
				n, err := cluster.Node(i).Execute(
					"INSERT INTO records(id,name) VALUES($1,$2)", id, name)
				if err != nil {
					errs[i] = err
					return
				}
				if n != 1 {
					errs[i] = fmt.Errorf("insert affected %d rows, want 1", n)
					return
				}
			}
			if err := cluster.Node(i).Flush(); err != nil {
				errs[i] = err
			}
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("node %d writer: %v", i, err)
		}
	}

	var expected [][]string
	for i := 0; i < 3; i++ {
		for r := 0; r < rowsPerNode; r++ {
			expected = append(expected, []string{fmt.Sprintf("node-%d-row-%02d", i, r)})
		}
	}
	sort.Slice(expected, func(a, b int) bool { return expected[a][0] < expected[b][0] })

	deadline := time.Now().Add(convergenceTimeout)
	for {
		converged := true
		for i := 0; i < cluster.Len(); i++ {
			rows, err := cluster.Node(i).Simple("SELECT name FROM records ORDER BY name")
			if err != nil {
				t.Fatalf("node %d read names: %v", i, err)
			}
			converged = converged && equalRows(rows, expected)
		}
		if converged {
			break
		}
		if !time.Now().Before(deadline) {
			t.Fatal("three nodes failed to converge on 90 rows")
		}
		time.Sleep(convergenceInterval)
	}

	keys, err := cluster.Node(0).Simple("SELECT id,name FROM records ORDER BY id")
	if err != nil {
		t.Fatalf("node 0 read keys: %v", err)
	}
	if len(keys) != 90 {
		t.Fatalf("node 0 has %d key rows, want 90", len(keys))
	}
	for i := 1; i < 3; i++ {
		got, err := cluster.Node(i).Simple("SELECT id,name FROM records ORDER BY id")
		if err != nil {
			t.Fatalf("node %d read keys: %v", i, err)
		}
		if !equalRows(got, keys) {
			t.Fatalf("node %d replicated keys differ from node 0", i)
		}
	}
	failed = false
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
