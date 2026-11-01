// Live scenario: additive SQL schema changes replicate to an offline
// peer; local destructive DDL stays permitted.
//
// Port of MURMUR-SQL schema-evolution. The additive migration uses
// the cr-sqlite begin/commit-alter protocol on the altering node (a
// bare ALTER TABLE ADD COLUMN on a CRR leaves stale triggers behind,
// so the very next write fails with "expected 7 values, got 5").
// Adopting nodes must rebuild their own triggers when they apply the
// adopted column. The replicated-DDL guard legs (DROP/RENAME rejected
// on replicated tables, MURMUR SHOW TABLES REPLICATION) are skipped:
// the native SQL surface has no replicated-DDL guard. The local-DDL
// leg runs: destructive DDL on a local table succeeds on node 0
// without disturbing replicated rows anywhere.
package schemaevolution

import (
	"testing"

	goharness "github.com/marcgauthier/sqlite-murmur-go/clients/go/tests-live/goharness"
)

func TestAdditiveSQLSchemaMigrationPreservesRows(t *testing.T) {
	goharness.SkipUnlessLive(t)
	cluster, err := goharness.NewCluster(goharness.ClusterOptions{
		Name:     "schema-evolution",
		NumNodes: 3,
	})
	if err != nil {
		t.Fatalf("start cluster: %v", err)
	}
	failed := true
	defer func() { cluster.Finish(failed) }()

	for i := 0; i < 3; i++ {
		if _, err := cluster.Node(i).Simple(
			"CREATE TABLE IF NOT EXISTS records(name TEXT PRIMARY KEY NOT NULL DEFAULT '', score INTEGER NOT NULL DEFAULT 0)"); err != nil {
			t.Fatalf("node %d create records: %v", i, err)
		}
		if err := cluster.Node(i).SetTableReplicated("records", true); err != nil {
			t.Fatalf("node %d replicate records: %v", i, err)
		}
	}
	if _, err := cluster.Node(0).Simple("INSERT INTO records(name,score) VALUES('seed',1)"); err != nil {
		t.Fatalf("insert seed: %v", err)
	}
	if err := cluster.Node(0).Flush(); err != nil {
		t.Fatalf("flush seed: %v", err)
	}
	if err := goharness.AssertRows(cluster, []int{0, 1, 2},
		"SELECT name,score FROM records ORDER BY name",
		[][]string{{"seed", "1"}}); err != nil {
		t.Fatalf("converge seed: %v", err)
	}
	if err := cluster.Node(2).Flush(); err != nil {
		t.Fatalf("node 2 pre-stop flush: %v", err)
	}
	if err := cluster.StopNode(2); err != nil {
		t.Fatalf("stop node 2: %v", err)
	}
	// The altering node wraps the migration in the cr-sqlite
	// begin/commit-alter protocol so its own triggers are rebuilt.
	for _, sql := range []string{
		"SELECT crsql_begin_alter('records')",
		"ALTER TABLE records ADD COLUMN note TEXT",
		"SELECT crsql_commit_alter('records')",
	} {
		if _, err := cluster.Node(0).Simple(sql); err != nil {
			t.Fatalf("migrate %q: %v", sql, err)
		}
	}
	if _, err := cluster.Node(0).Simple("UPDATE records SET note='new-field' WHERE name='seed'"); err != nil {
		t.Fatalf("update after DDL: %v", err)
	}
	if _, err := cluster.Node(0).Simple("INSERT INTO records(name,score,note) VALUES('new',2,'written-after-ddl')"); err != nil {
		t.Fatalf("insert after DDL: %v", err)
	}
	if err := cluster.Node(0).Flush(); err != nil {
		t.Fatalf("flush after DDL: %v", err)
	}
	expected := [][]string{
		{"new", "2", "written-after-ddl"},
		{"seed", "1", "new-field"},
	}
	// The online peer adopts the column through schema replication.
	if err := goharness.AssertRows(cluster, []int{0, 1},
		"SELECT name,score,note FROM records ORDER BY name", expected); err != nil {
		t.Fatalf("converge migrated rows on adopter: %v", err)
	}
	// The adopter must be writable after adoption: its CRR triggers
	// must have been rebuilt for the new column.
	if _, err := cluster.Node(1).Simple("INSERT INTO records(name,score,note) VALUES('adopter-write',3,'from-node-1')"); err != nil {
		t.Fatalf("adopter write after DDL: %v", err)
	}
	if err := cluster.Node(1).Flush(); err != nil {
		t.Fatalf("flush adopter write: %v", err)
	}
	expected = [][]string{
		{"adopter-write", "3", "from-node-1"},
		{"new", "2", "written-after-ddl"},
		{"seed", "1", "new-field"},
	}
	if err := goharness.AssertRows(cluster, []int{0, 1},
		"SELECT name,score,note FROM records ORDER BY name", expected); err != nil {
		t.Fatalf("converge adopter write: %v", err)
	}
	// The offline peer must learn the new schema and values on reconnect.
	if err := cluster.StartNode(2); err != nil {
		t.Fatalf("restart node 2: %v", err)
	}
	if err := goharness.AssertRows(cluster, []int{0, 1, 2},
		"SELECT name,score,note FROM records ORDER BY name", expected); err != nil {
		t.Fatalf("converge migrated rows: %v", err)
	}
	// The rejoining peer must be writable too.
	if _, err := cluster.Node(2).Simple("INSERT INTO records(name,score,note) VALUES('rejoin-write',4,'from-node-2')"); err != nil {
		t.Fatalf("rejoin write after DDL: %v", err)
	}
	if err := cluster.Node(2).Flush(); err != nil {
		t.Fatalf("flush rejoin write: %v", err)
	}
	expected = [][]string{
		{"adopter-write", "3", "from-node-1"},
		{"new", "2", "written-after-ddl"},
		{"rejoin-write", "4", "from-node-2"},
		{"seed", "1", "new-field"},
	}
	if err := goharness.AssertRows(cluster, []int{0, 1, 2},
		"SELECT name,score,note FROM records ORDER BY name", expected); err != nil {
		t.Fatalf("converge rejoin write: %v", err)
	}
	for _, sql := range []string{
		"CREATE TABLE local_only(id INTEGER PRIMARY KEY NOT NULL, old TEXT NOT NULL DEFAULT '')",
		"ALTER TABLE local_only RENAME COLUMN old TO renamed",
		"ALTER TABLE local_only RENAME TO renamed_local",
		"DROP TABLE renamed_local",
	} {
		if _, err := cluster.Node(0).Simple(sql); err != nil {
			t.Fatalf("local DDL %q: %v", sql, err)
		}
	}
	if err := goharness.AssertRows(cluster, []int{0, 1, 2},
		"SELECT name,score,note FROM records ORDER BY name", expected); err != nil {
		t.Fatalf("converge after local DDL: %v", err)
	}
	failed = false
}

func TestLocalDestructiveDDLLeavesReplicatedRows(t *testing.T) {
	goharness.SkipUnlessLive(t)
	cluster, err := goharness.NewCluster(goharness.ClusterOptions{
		Name:     "schema-evolution-local",
		NumNodes: 3,
	})
	if err != nil {
		t.Fatalf("start cluster: %v", err)
	}
	failed := true
	defer func() { cluster.Finish(failed) }()

	for i := 0; i < 3; i++ {
		if _, err := cluster.Node(i).Simple(
			"CREATE TABLE IF NOT EXISTS records(name TEXT PRIMARY KEY NOT NULL DEFAULT '', score INTEGER NOT NULL DEFAULT 0)"); err != nil {
			t.Fatalf("node %d create records: %v", i, err)
		}
		if err := cluster.Node(i).SetTableReplicated("records", true); err != nil {
			t.Fatalf("node %d replicate records: %v", i, err)
		}
	}
	if _, err := cluster.Node(0).Simple("INSERT INTO records(name,score) VALUES('seed',1)"); err != nil {
		t.Fatalf("insert seed: %v", err)
	}
	if err := cluster.Node(0).Flush(); err != nil {
		t.Fatalf("flush seed: %v", err)
	}
	expected := [][]string{{"seed", "1"}}
	if err := goharness.AssertRows(cluster, []int{0, 1, 2},
		"SELECT name,score FROM records ORDER BY name", expected); err != nil {
		t.Fatalf("converge seed: %v", err)
	}
	for _, sql := range []string{
		"CREATE TABLE local_only(id INTEGER PRIMARY KEY NOT NULL, old TEXT NOT NULL DEFAULT '')",
		"ALTER TABLE local_only RENAME COLUMN old TO renamed",
		"ALTER TABLE local_only RENAME TO renamed_local",
		"DROP TABLE renamed_local",
	} {
		if _, err := cluster.Node(0).Simple(sql); err != nil {
			t.Fatalf("local DDL %q: %v", sql, err)
		}
	}
	if err := goharness.AssertRows(cluster, []int{0, 1, 2},
		"SELECT name,score FROM records ORDER BY name", expected); err != nil {
		t.Fatalf("converge after local DDL: %v", err)
	}
	failed = false
}

func TestReplicatedDestructiveDDLRejected(t *testing.T) {
	goharness.SkipUnlessLive(t)
	// Blocked: the native SQL surface has no replicated-DDL guard
	// (DROP/RENAME on a CRR would succeed) and no
	// MURMUR SHOW TABLES REPLICATION equivalent.
	t.Skip("harness: replicated-DDL guard and per-table replication flags")
}
