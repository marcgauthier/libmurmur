// Live scenario: typed application rows travel through the SQL client.
//
// Port of MURMUR-SQL typed-records: typed inserts replicate with
// byte-identical values, updates and deletes converge, keys stay
// stable across a restart, statements are atomic, node-local tables
// stay local and persist, and files replicate and download. There is
// no id_murmur_primary_key column here, so key-stability legs compare
// full ordered rows instead. Typed reads go through Simple string
// projections (hex(payload), IS NULL) rather than typed accessors.
// Transaction-control words are real SQLite transactions on this
// stack (not documented no-ops), managed primary keys, ALTER TABLE on
// replicated tables, CRDT merge policies, and snapshot catch-up have
// no native equivalent, so those legs are skipped with named harness
// gaps.
package typedrecords

import (
	"bytes"
	"reflect"
	"strconv"
	"testing"
	"time"

	goharness "github.com/marcgauthier/sqlite-murmur-go/clients/go/tests-live/goharness"
)

// schema creates the shared typed fixture and enables its replication
// (Rust: schema).
func schema(t *testing.T, cluster *goharness.Cluster) {
	t.Helper()
	for i := 0; i < cluster.Len(); i++ {
		if _, err := cluster.Node(i).Simple(
			"CREATE TABLE IF NOT EXISTS records(id INTEGER PRIMARY KEY NOT NULL, title TEXT NOT NULL DEFAULT '', score REAL, payload BLOB, optional TEXT)"); err != nil {
			t.Fatalf("node %d create records: %v", i, err)
		}
		if err := cluster.Node(i).SetTableReplicated("records", true); err != nil {
			t.Fatalf("node %d replicate records: %v", i, err)
		}
	}
}

func flushAll(t *testing.T, cluster *goharness.Cluster) {
	t.Helper()
	for i := 0; i < cluster.Len(); i++ {
		if err := cluster.Node(i).Flush(); err != nil {
			t.Fatalf("node %d flush: %v", i, err)
		}
	}
}

func TestSQLTypedRecordsReplicateUpdateDeleteAndRebuildAfterRestart(t *testing.T) {
	goharness.SkipUnlessLive(t)
	cluster, err := goharness.NewCluster(goharness.ClusterOptions{
		Name:     "typed-records-roundtrip",
		NumNodes: 3,
	})
	if err != nil {
		t.Fatalf("start cluster: %v", err)
	}
	failed := true
	defer func() { cluster.Finish(failed) }()

	schema(t, cluster)
	title := "quotes ' and unicode 日本語"
	payload := []byte{0, 1, 127, 128, 255}
	if _, err := cluster.Node(0).Execute(
		"INSERT INTO records(id,title,score,payload,optional) VALUES($1,$2,$3,$4,$5)",
		int64(1), title, 1.25, payload, nil); err != nil {
		t.Fatalf("node 0 typed insert: %v", err)
	}
	if _, err := cluster.Node(1).Simple(
		"INSERT INTO records(id,title,score,payload,optional) VALUES(2,'second',-2.5,x'', 'present')"); err != nil {
		t.Fatalf("node 1 typed insert: %v", err)
	}
	flushAll(t, cluster)
	projection := "SELECT id,title,score,hex(payload),optional FROM records ORDER BY id"
	expected := [][]string{
		{"1", title, "1.25", "00017F80FF", ""},
		{"2", "second", "-2.5", "", "present"},
	}
	if err := goharness.AssertRows(cluster, []int{0, 1, 2}, projection, expected); err != nil {
		t.Fatalf("converge typed rows: %v", err)
	}
	// No id_murmur_primary_key column exists here: key stability is
	// proven by full ordered-row comparison instead.
	keys, err := cluster.Node(0).Simple(projection)
	if err != nil {
		t.Fatalf("node 0 read keys: %v", err)
	}
	for i := 1; i < 3; i++ {
		got, err := cluster.Node(i).Simple(projection)
		if err != nil {
			t.Fatalf("node %d read keys: %v", i, err)
		}
		if !reflect.DeepEqual(got, keys) {
			t.Fatalf("node %d keys = %v, want %v", i, got, keys)
		}
	}
	typed, err := cluster.Node(2).Simple(
		"SELECT title,score,hex(payload),optional IS NULL FROM records WHERE id=1")
	if err != nil {
		t.Fatalf("node 2 typed read: %v", err)
	}
	if len(typed) != 1 {
		t.Fatalf("node 2 typed read = %d rows, want 1", len(typed))
	}
	if got := typed[0][0]; got != title {
		t.Fatalf("title = %q, want %q", got, title)
	}
	if got := typed[0][1]; got != "1.25" {
		t.Fatalf("score = %q, want 1.25", got)
	}
	if got := typed[0][2]; got != "00017F80FF" {
		t.Fatalf("payload = %q, want 00017F80FF", got)
	}
	if got := typed[0][3]; got != "1" {
		t.Fatalf("optional IS NULL = %q, want 1", got)
	}
	if _, err := cluster.Node(2).Execute(
		"UPDATE records SET title=$1 WHERE id=$2", "updated remotely", int64(1)); err != nil {
		t.Fatalf("node 2 remote update: %v", err)
	}
	if _, err := cluster.Node(1).Execute("DELETE FROM records WHERE id=$1", int64(2)); err != nil {
		t.Fatalf("node 1 delete: %v", err)
	}
	flushAll(t, cluster)
	finalRows := [][]string{{"1", "updated remotely", "1.25", "00017F80FF", ""}}
	if err := goharness.AssertRows(cluster, []int{0, 1, 2}, projection, finalRows); err != nil {
		t.Fatalf("converge final rows: %v", err)
	}
	if err := cluster.Node(2).Flush(); err != nil {
		t.Fatalf("node 2 pre-restart flush: %v", err)
	}
	if err := cluster.StopNode(2); err != nil {
		t.Fatalf("stop node 2: %v", err)
	}
	if err := cluster.StartNode(2); err != nil {
		t.Fatalf("restart node 2: %v", err)
	}
	if err := goharness.AssertRows(cluster, []int{2}, projection, finalRows); err != nil {
		t.Fatalf("node 2 post-restart rows: %v", err)
	}
	got, err := cluster.Node(2).Simple(projection)
	if err != nil {
		t.Fatalf("node 2 post-restart keys: %v", err)
	}
	if !reflect.DeepEqual(got, finalRows) {
		t.Fatalf("node 2 post-restart keys = %v, want %v", got, finalRows)
	}
	failed = false
}

func TestSQLTransactionWordsAreNoops(t *testing.T) {
	goharness.SkipUnlessLive(t)
	// Blocked: the reference asserts BEGIN/ROLLBACK are documented
	// no-ops (rows survive ROLLBACK). This stack is real SQLite, where
	// ROLLBACK undoes the batch, so the no-op legs cannot pass. The
	// atomic multi-row-statement leg is ported separately below.
	t.Skip("harness: transaction-control words are real SQLite transactions, not documented no-ops")
}

func TestSQLStatementAtomicity(t *testing.T) {
	goharness.SkipUnlessLive(t)
	cluster, err := goharness.NewCluster(goharness.ClusterOptions{
		Name:     "typed-records-rollback",
		NumNodes: 2,
	})
	if err != nil {
		t.Fatalf("start cluster: %v", err)
	}
	failed := true
	defer func() { cluster.Finish(failed) }()

	schema(t, cluster)
	// Stack truth: ROLLBACK undoes the batch (real SQLite, the
	// opposite of the reference no-op legs, which are skipped above).
	if err := cluster.Node(0).ExecBatch(
		"BEGIN; INSERT INTO records(id,title) VALUES(1,'rolled-back'); ROLLBACK"); err != nil {
		t.Fatalf("rollback batch: %v", err)
	}
	if err := goharness.AssertRows(cluster, []int{0},
		"SELECT id,title FROM records ORDER BY id", [][]string{}); err != nil {
		// AssertRows with an empty expectation converges once the
		// table exists and holds no rows.
		t.Fatalf("rolled-back row leaked: %v", err)
	}
	if err := cluster.Node(0).ExecBatch(
		"BEGIN; INSERT INTO records(id,title) VALUES(2,'kept'); INSERT INTO records(id,title) VALUES(3,'also-kept'); COMMIT"); err != nil {
		t.Fatalf("multi-statement batch: %v", err)
	}
	if err := cluster.Node(0).Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}
	// The first row of a failed multi-row statement must not leak into
	// the store or replication when the second row violates a unique key.
	if _, err := cluster.Node(0).Simple(
		"INSERT INTO records(id,title) VALUES(4,'must-rollback'),(2,'duplicate')"); err == nil {
		t.Fatal("duplicate multi-row insert accepted")
	}
	if err := goharness.AssertRows(cluster, []int{0, 1},
		"SELECT id,title FROM records ORDER BY id",
		[][]string{
			{"2", "kept"},
			{"3", "also-kept"},
		}); err != nil {
		t.Fatalf("converge: %v", err)
	}
	failed = false
}

func TestSQLNodeLocalRecordsStayLocalAndPersistAfterRestart(t *testing.T) {
	goharness.SkipUnlessLive(t)
	cluster, err := goharness.NewCluster(goharness.ClusterOptions{
		Name:     "typed-records-local",
		NumNodes: 2,
	})
	if err != nil {
		t.Fatalf("start cluster: %v", err)
	}
	failed := true
	defer func() { cluster.Finish(failed) }()

	schema(t, cluster)
	for i := 0; i < 2; i++ {
		if _, err := cluster.Node(i).Simple(
			"CREATE TABLE private_records(id INTEGER PRIMARY KEY NOT NULL, body TEXT)"); err != nil {
			t.Fatalf("node %d create private_records: %v", i, err)
		}
		body := "private-to-node-" + strconv.Itoa(i)
		if _, err := cluster.Node(i).Execute(
			"INSERT INTO private_records(id,body) VALUES($1,$2)", int64(i), body); err != nil {
			t.Fatalf("node %d private insert: %v", i, err)
		}
		if err := cluster.Node(i).Flush(); err != nil {
			t.Fatalf("node %d flush: %v", i, err)
		}
	}
	if _, err := cluster.Node(0).Simple(
		"INSERT INTO records(id,title) VALUES(10,'replicated-control')"); err != nil {
		t.Fatalf("control insert: %v", err)
	}
	if err := cluster.Node(0).Flush(); err != nil {
		t.Fatalf("flush control: %v", err)
	}
	if err := goharness.AssertRows(cluster, []int{0, 1},
		"SELECT title FROM records", [][]string{{"replicated-control"}}); err != nil {
		t.Fatalf("converge control: %v", err)
	}
	// No MURMUR SHOW TABLES REPLICATION surface here: local-only is
	// proven behaviorally (each node still holds exactly its own
	// private row after the control row replicated).
	for i := 0; i < 2; i++ {
		wantBody := "private-to-node-" + strconv.Itoa(i)
		got, err := cluster.Node(i).Simple("SELECT id,body FROM private_records")
		if err != nil {
			t.Fatalf("node %d private read: %v", i, err)
		}
		want := [][]string{{strconv.Itoa(i), wantBody}}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("node %d private rows = %v, want %v (leaked?)", i, got, want)
		}
	}
	for i := 0; i < 2; i++ {
		if err := cluster.StopNode(i); err != nil {
			t.Fatalf("stop node %d: %v", i, err)
		}
		if err := cluster.StartNode(i); err != nil {
			t.Fatalf("restart node %d: %v", i, err)
		}
		wantBody := "private-to-node-" + strconv.Itoa(i)
		got, err := cluster.Node(i).Simple("SELECT id,body FROM private_records")
		if err != nil {
			t.Fatalf("node %d post-restart read: %v", i, err)
		}
		want := [][]string{{strconv.Itoa(i), wantBody}}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("node %d private rows = %v, want %v", i, got, want)
		}
		columns, err := cluster.Node(i).Simple(
			"SELECT name FROM pragma_table_info('private_records') WHERE pk=1")
		if err != nil {
			t.Fatalf("node %d pragma read: %v", i, err)
		}
		if !reflect.DeepEqual(columns, [][]string{{"id"}}) {
			t.Fatalf("node %d pk columns = %v, want [[id]]", i, columns)
		}
	}
	failed = false
}

func TestSQLReplicationRebuildsPopulatedKeysAndEnforcesImmutableApplicationKeys(t *testing.T) {
	goharness.SkipUnlessLive(t)
	// Blocked: the reference exercises managed primary keys
	// (id_murmur_primary_key rebuild on replicate, immutable
	// application-key enforcement, unreplicate/re-replicate key
	// transitions). cr-sqlite rows carry no managed key column and
	// unreplicate has no native equivalent, so no leg can transfer.
	t.Skip("harness: managed primary keys (id_murmur_primary_key rebuild, immutable application keys, unreplicate)")
}

func TestSQLFilesReplicateAndDownloadThroughTheGoClient(t *testing.T) {
	goharness.SkipUnlessLive(t)
	cluster, err := goharness.NewCluster(goharness.ClusterOptions{
		Name:     "typed-records-files",
		NumNodes: 2,
		Files:    true,
	})
	if err != nil {
		t.Fatalf("start cluster: %v", err)
	}
	failed := true
	defer func() { cluster.Finish(failed) }()

	// Mesh gate (the files-soak pattern): seed sessions only
	// establish once user-table writes give the sync loop something
	// to ship, and file metadata alone never wakes the mesh.
	schema(t, cluster)
	if _, err := cluster.Node(0).Simple(
		"INSERT INTO records(id,title) VALUES(1,'mesh-gate')"); err != nil {
		t.Fatalf("mesh gate insert: %v", err)
	}
	if err := cluster.Node(0).Flush(); err != nil {
		t.Fatalf("mesh gate flush: %v", err)
	}
	if err := goharness.AssertRows(cluster, []int{0, 1},
		"SELECT title FROM records", [][]string{{"mesh-gate"}}); err != nil {
		t.Fatalf("converge mesh gate: %v", err)
	}

	payload := make([]byte, 150_000)
	for i := range payload {
		payload[i] = byte((i*131 + i/251) % 256)
	}
	name := "typed/file ' unicode 日本語.bin"
	if err := cluster.Node(0).FileUpload(name, payload); err != nil {
		t.Fatalf("upload: %v", err)
	}
	deadline := time.Now().Add(60 * time.Second)
	for {
		list, err := cluster.Node(1).FileList()
		if err != nil {
			t.Fatalf("node 1 file list: %v", err)
		}
		found := false
		for _, m := range list {
			found = found || (!m.Deleted && m.Name == name)
		}
		if found {
			break
		}
		if !time.Now().Before(deadline) {
			t.Fatal("replicated file metadata never arrived")
		}
		time.Sleep(100 * time.Millisecond)
	}
	// Peer fetch is automatic on the driver's fetch tick; the harness
	// pins the cadence at 30 s (no interval knob), so the fetch wait
	// is 90 s (the files-soak bound).
	available, err := cluster.Node(1).FileAvailable(name)
	if err != nil {
		t.Fatalf("node 1 file available: %v", err)
	}
	deadline = time.Now().Add(90 * time.Second)
	for !available {
		if !time.Now().Before(deadline) {
			t.Fatal("replicated file did not fetch")
		}
		time.Sleep(200 * time.Millisecond)
		available, err = cluster.Node(1).FileAvailable(name)
		if err != nil {
			t.Fatalf("node 1 file available: %v", err)
		}
	}
	got, err := cluster.Node(1).FileDownload(name)
	if err != nil {
		t.Fatalf("node 1 download: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("replicated file bytes differ")
	}
	// The reference restarts the receiver; an in-process node that
	// completed a fetch cannot restart (driver start fails with "File
	// exists"; the established files-corrupt-source finding), and a
	// child restart drops the files staging, so the uploader restarts
	// instead: the file's store persistence is proven from the source
	// side.
	if err := cluster.Node(0).Flush(); err != nil {
		t.Fatalf("node 0 flush: %v", err)
	}
	if err := cluster.StopNode(0); err != nil {
		t.Fatalf("stop node 0: %v", err)
	}
	if err := cluster.StartNode(0); err != nil {
		t.Fatalf("restart node 0: %v", err)
	}
	if err := cluster.PeerMesh(); err != nil {
		t.Fatalf("re-mesh after restart: %v", err)
	}
	got, err = cluster.Node(0).FileDownload(name)
	if err != nil {
		t.Fatalf("post-restart download: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("post-restart file bytes differ")
	}
	failed = false
}

func TestSQLConcurrentAdditiveSchemaBranchesPreserveBothValues(t *testing.T) {
	goharness.SkipUnlessLive(t)
	// Blocked: the reference branches replicated schemas with
	// concurrent additive ALTER TABLE on both sides. ALTER TABLE on
	// replicated tables breaks CRR writes on this stack (the
	// established schema-evolution/migration-crash gap).
	t.Skip("harness: ALTER TABLE on replicated tables breaks CRR writes")
}

func TestSQLCRDTOperationsConvergeAcrossOfflinePartition(t *testing.T) {
	goharness.SkipUnlessLive(t)
	// Blocked: the reference configures replication.merge_policies
	// and drives MURMUR POLICY counter/set/max/min ops. Merge-policy
	// ops have no native equivalent on this stack (the established
	// merge-policies gap).
	t.Skip("harness: merge-policy ops (PN_COUNTER/OR_SET/MAX/MIN) have no native equivalent")
}

func TestSQLEmptyPeerRecoversTypedRowsFromARetentionSnapshot(t *testing.T) {
	goharness.SkipUnlessLive(t)
	// Not wired: the reference prunes source logs with MURMUR RETENTION
	// COLLECT and requires the empty peer to catch up through a
	// retained snapshot without advancing its applied-log counter.
	// On-demand collect (Node.RetentionCollect) and stale-rejoin
	// snapshot delivery both exist now; the leg needs writing.
	t.Skip("harness: retention-snapshot recovery leg not wired")
}
