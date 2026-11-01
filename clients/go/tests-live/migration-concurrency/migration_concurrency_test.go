// Live scenario: race additive DDL on independent nodes while
// acknowledged writes continue.
//
// Port of MURMUR-SQL migration-concurrency: a 3-node cluster converges
// on one seed row, then two racing ALTER TABLE ... ADD COLUMN
// statements run on nodes 0 and 1 while node 2 inserts 60 acknowledged
// rows; at least one migration must win, all nodes converge on every
// acknowledged row, the migrated column exists exactly once per node,
// and per-node writes to it converge. The reference's independent SQL
// connections map to the three native nodes directly (one handle each).
package migrationconcurrency

import (
	"fmt"
	"sync"
	"testing"
	"time"

	goharness "github.com/marcgauthier/libmurmur/clients/go/tests-live/goharness"
)

func TestConcurrentSQLMigrationsLeaveOneCompleteSchemaAndAllAcknowledgedRows(t *testing.T) {
	goharness.SkipUnlessLive(t)
	cluster, err := goharness.NewCluster(goharness.ClusterOptions{
		Name:     "migration-concurrency",
		NumNodes: 3,
	})
	if err != nil {
		t.Fatalf("start cluster: %v", err)
	}
	failed := true
	defer func() { cluster.Finish(failed) }()

	for i := 0; i < 3; i++ {
		if _, err := cluster.Node(i).Simple(
			"CREATE TABLE IF NOT EXISTS records(id INTEGER PRIMARY KEY NOT NULL, name TEXT NOT NULL DEFAULT '')"); err != nil {
			t.Fatalf("node %d create records: %v", i, err)
		}
		if err := cluster.Node(i).SetTableReplicated("records", true); err != nil {
			t.Fatalf("node %d replicate records: %v", i, err)
		}
	}
	if _, err := cluster.Node(0).Simple("INSERT INTO records(id,name) VALUES(0,'seed')"); err != nil {
		t.Fatalf("insert seed: %v", err)
	}
	if err := cluster.Node(0).Flush(); err != nil {
		t.Fatalf("flush seed: %v", err)
	}
	if err := goharness.AssertRows(cluster, []int{0, 1, 2},
		"SELECT name FROM records ORDER BY id", [][]string{{"seed"}}); err != nil {
		t.Fatalf("converge seed: %v", err)
	}

	a := cluster.Node(0)
	b := cluster.Node(1)
	writer := cluster.Node(2)

	var wg sync.WaitGroup
	var firstErr, secondErr, writeErr error
	var expected [][]string
	wg.Add(3)
	go func() {
		defer wg.Done()
		_, firstErr = a.Simple("ALTER TABLE records ADD COLUMN note TEXT")
	}()
	go func() {
		defer wg.Done()
		_, secondErr = b.Simple("ALTER TABLE records ADD COLUMN note TEXT")
	}()
	go func() {
		defer wg.Done()
		rows := [][]string{{"seed"}}
		for id := int64(1); id <= 60; id++ {
			name := fmt.Sprintf("acknowledged-%03d", id)
			if _, err := writer.Execute(
				"INSERT INTO records(id,name) VALUES($1,$2)", id, name); err != nil {
				writeErr = err
				return
			}
			rows = append(rows, []string{name})
			time.Sleep(5 * time.Millisecond)
		}
		if err := writer.Flush(); err != nil {
			writeErr = err
			return
		}
		expected = rows
	}()
	wg.Wait()
	if writeErr != nil {
		t.Fatalf("writer: %v", writeErr)
	}
	if firstErr != nil && secondErr != nil {
		t.Fatalf("both migrations failed: %v; %v", firstErr, secondErr)
	}
	if err := goharness.AssertRows(cluster, []int{0, 1, 2},
		"SELECT name FROM records ORDER BY id", expected); err != nil {
		t.Fatalf("converge acknowledged rows: %v", err)
	}
	for i := 0; i < 3; i++ {
		// Rebuild CRR triggers after the additive migration so writes
		// to the new column use current clock arity (bare ALTER on a
		// CRR leaves stale triggers; commit with no delta rebuilds).
		if _, err := cluster.Node(i).Simple("SELECT crsql_begin_alter('records')"); err != nil {
			t.Fatalf("node %d begin alter repair: %v", i, err)
		}
		if _, err := cluster.Node(i).Simple("SELECT crsql_commit_alter('records')"); err != nil {
			t.Fatalf("node %d commit alter repair: %v", i, err)
		}
		columns, err := cluster.Node(i).Simple(
			"SELECT name FROM pragma_table_info('records') WHERE name='note'")
		if err != nil {
			t.Fatalf("node %d read migrated column: %v", i, err)
		}
		if len(columns) != 1 || len(columns[0]) != 1 || columns[0][0] != "note" {
			t.Fatalf("node %d columns = %v, want [[note]] (duplicate or absent migration column)",
				i, columns)
		}
		if _, err := cluster.Node(i).Execute(
			"UPDATE records SET note=$1 WHERE id=$2", fmt.Sprintf("node-%d", i), int64(i)); err != nil {
			t.Fatalf("node %d set note: %v", i, err)
		}
		if err := cluster.Node(i).Flush(); err != nil {
			t.Fatalf("node %d flush note: %v", i, err)
		}
	}
	if err := goharness.AssertRows(cluster, []int{0, 1, 2},
		"SELECT note FROM records WHERE id<3 ORDER BY id",
		[][]string{{"node-0"}, {"node-1"}, {"node-2"}}); err != nil {
		t.Fatalf("converge notes: %v", err)
	}
	failed = false
}
