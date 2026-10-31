// Live scenario: bound values stay data and errors leave the store usable.
//
// Port of MURMUR-SQL sqli-api: two native nodes share a replicated
// records table, six injection payloads inserted as bound parameters
// land byte-exact on both nodes, a duplicate-key insert fails on the
// SQLite UNIQUE constraint (no pgwire 23505 exists here), a bad-column
// query errors, the same node still counts all six rows afterwards, and
// sqlite_master on both nodes shows no injected application tables
// (murmur/crsqlite internal tables are excluded from the listing).
package sqliapi

import (
	"strconv"
	"strings"
	"testing"

	goharness "github.com/marcgauthier/sqlite-murmur-go/clients/go/tests-live/goharness"
)

func TestSQLParametersDoNotExecuteInjectedStatements(t *testing.T) {
	goharness.SkipUnlessLive(t)
	cluster, err := goharness.NewCluster(goharness.ClusterOptions{
		Name:     "sqli-api",
		NumNodes: 2,
	})
	if err != nil {
		t.Fatalf("start cluster: %v", err)
	}
	failed := true
	defer func() { cluster.Finish(failed) }()

	for i := 0; i < 2; i++ {
		if _, err := cluster.Node(i).Simple(
			"CREATE TABLE IF NOT EXISTS records(id INTEGER PRIMARY KEY NOT NULL, body TEXT NOT NULL DEFAULT '')"); err != nil {
			t.Fatalf("node %d create records: %v", i, err)
		}
		if err := cluster.Node(i).SetTableReplicated("records", true); err != nil {
			t.Fatalf("node %d replicate records: %v", i, err)
		}
	}
	attacks := []string{
		"'; DROP TABLE records; --",
		"x' OR 1=1 --",
		"'); DELETE FROM records; --",
		"SELECT * FROM sqlite_master",
		"quote' slash\\ newline\n unicode 日本語",
		"/v1/query?sql=DROP%20TABLE%20records",
	}
	var expected [][]string
	for i, body := range attacks {
		n, err := cluster.Node(0).Execute(
			"INSERT INTO records(id,body) VALUES($1,$2)", int64(i), body)
		if err != nil {
			t.Fatalf("insert attack %d: %v", i, err)
		}
		if n != 1 {
			t.Fatalf("insert attack %d affected %d rows, want 1", i, n)
		}
		expected = append(expected, []string{body})
	}
	if err := cluster.Node(0).Flush(); err != nil {
		t.Fatalf("flush attacks: %v", err)
	}
	if err := goharness.AssertRows(cluster, []int{0, 1},
		"SELECT body FROM records ORDER BY id", expected); err != nil {
		t.Fatalf("converge attacks: %v", err)
	}
	_, err = cluster.Node(0).Execute(
		"INSERT INTO records(id,body) VALUES($1,$2)", int64(0), "duplicate")
	if err == nil {
		t.Fatal("duplicate insert accepted")
	}
	// No pgwire SQLSTATEs here: the native store reports the SQLite
	// UNIQUE violation directly.
	if !strings.Contains(strings.ToUpper(err.Error()), "UNIQUE") {
		t.Fatalf("duplicate error = %q, want a UNIQUE violation (%v)", err, err)
	}
	if _, err := cluster.Node(0).Simple("SELECT definitely_missing_column FROM records"); err == nil {
		t.Fatal("bad-column query accepted")
	}
	rows, err := cluster.Node(0).Simple("SELECT count(*) FROM records")
	if err != nil {
		t.Fatalf("count records: %v", err)
	}
	want := [][]string{{strconv.Itoa(len(attacks))}}
	if !equalRows(rows, want) {
		t.Fatalf("count = %v, want %v", rows, want)
	}
	for i := 0; i < 2; i++ {
		tables, err := cluster.Node(i).Simple(
			"SELECT name FROM sqlite_master WHERE type='table'" +
				" AND name NOT LIKE 'murmur\\_%' ESCAPE '\\'" +
				" AND name NOT LIKE '%crsql%'" +
				" AND name NOT LIKE 'sqlite\\_%' ESCAPE '\\'" +
				" ORDER BY name")
		if err != nil {
			t.Fatalf("node %d list tables: %v", i, err)
		}
		if !equalRows(tables, [][]string{{"records"}}) {
			t.Fatalf("node %d tables = %v, want [[records]]", i, tables)
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
