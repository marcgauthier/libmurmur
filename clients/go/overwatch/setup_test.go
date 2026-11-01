package overwatch

import (
	"errors"
	"testing"
	"time"

	"github.com/marcgauthier/sqlite-murmur-go/clients/go/murmurdb"
)

// Encrypted open and schema setup behave like OVERWATCH's embedded
// database: a key-sealed store, idempotent DDL that resumes after
// interruption, declared-column validation, and per-table
// replicated/node-local scope.

func TestOpenEncryptedStore(t *testing.T) {
	key := testKey(t)
	db, _ := openStore(t, key)
	if err := db.Ping(); err != nil {
		t.Fatalf("ping: %v", err)
	}
}

func TestOpenWrongKeyRejected(t *testing.T) {
	key := testKey(t)
	db, dir := openStore(t, key)
	setupSchema(t, db)
	if _, err := db.Exec(
		"INSERT INTO contacts(id,name) VALUES('c1','seed')"); err != nil {
		t.Fatalf("seed: %v", err)
	}
	db.Close()
	// Open is lazy; the unlock probe surfaces on first use.
	wrong := testKey(t)
	bad, err := murmurdb.Open(dir + "/store?key=" + hexKey(wrong))
	if err != nil {
		t.Fatalf("open with wrong key: %v", err)
	}
	defer bad.Close()
	if err := bad.Ping(); !errors.Is(err, murmurdb.ErrWrongKey) {
		t.Fatalf("wrong key err = %v, want ErrWrongKey", err)
	}
	// The sealed store still opens with the right key.
	good := openDir(t, dir, key)
	var name string
	if err := good.QueryRow(
		"SELECT name FROM contacts WHERE id='c1'").Scan(&name); err != nil {
		t.Fatalf("reopen read: %v", err)
	}
	if name != "seed" {
		t.Fatalf("reopen name = %q", name)
	}
}

func TestSchemaSetupIdempotentAndResumable(t *testing.T) {
	key := testKey(t)
	db, _ := openStore(t, key)
	// First setup creates everything.
	setupSchema(t, db)
	// Second setup is a no-op (restarted setup run).
	setupSchema(t, db)
	for _, table := range replicatedTables {
		if !replicated(t, db, table) {
			t.Fatalf("%s lost its replication flag", table)
		}
	}
	// Interrupted DDL: a fresh store with only contacts present must
	// converge on the full schema.
	db2, _ := openStore(t, testKey(t))
	if _, err := db2.Exec(appTables[0]); err != nil {
		t.Fatalf("partial setup: %v", err)
	}
	setupSchema(t, db2)
	for _, table := range append(append([]string{}, replicatedTables...), localTables...) {
		var name string
		if err := db2.QueryRow(
			"SELECT name FROM sqlite_master WHERE type='table' AND name=?",
			table).Scan(&name); err != nil {
			t.Fatalf("table %s missing after resume: %v", table, err)
		}
	}
	for _, table := range replicatedTables {
		if !replicated(t, db2, table) {
			t.Fatalf("%s not flagged after resume", table)
		}
	}
}

func TestDeclaredColumnsValidated(t *testing.T) {
	key := testKey(t)
	db, _ := openStore(t, key)
	setupSchema(t, db)
	// contacts must expose the declared record columns in order.
	rows, err := db.Query("SELECT name FROM pragma_table_info('contacts') ORDER BY cid")
	if err != nil {
		t.Fatalf("pragma: %v", err)
	}
	defer rows.Close()
	var got []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatalf("scan: %v", err)
		}
		got = append(got, name)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows: %v", err)
	}
	declared := []string{"id", "name", "email", "phone", "score", "created_time", "updated_time", "deleted_at"}
	if len(got) != len(declared) {
		t.Fatalf("contacts columns = %v", got)
	}
	for i := range declared {
		if got[i] != declared[i] {
			t.Fatalf("contacts columns = %v", got)
		}
	}
}

func TestReplicationScopeSplit(t *testing.T) {
	key := testKey(t)
	db, _ := openStore(t, key)
	setupSchema(t, db)
	// Domain collections replicate (OVERWATCH contacts), while
	// sessions and permissions stay node-local (OVERWATCH groups).
	for _, table := range replicatedTables {
		if !replicated(t, db, table) {
			t.Fatalf("expected %s to be replicated", table)
		}
	}
	for _, table := range localTables {
		if replicated(t, db, table) {
			t.Fatalf("expected %s to be node-local", table)
		}
	}
}

func TestTimestampsAreUnixSeconds(t *testing.T) {
	key := testKey(t)
	db, _ := openStore(t, key)
	setupSchema(t, db)
	now := time.Now().UTC().Unix()
	if _, err := db.Exec(
		"INSERT INTO contacts(id,name,created_time,updated_time) VALUES('c-ts','ts',$1,$1)",
		now); err != nil {
		t.Fatalf("insert: %v", err)
	}
	var created, updated int64
	if err := db.QueryRow(
		"SELECT created_time,updated_time FROM contacts WHERE id='c-ts'").Scan(&created, &updated); err != nil {
		t.Fatalf("read: %v", err)
	}
	if created != now || updated != now {
		t.Fatalf("timestamps = %d,%d want %d", created, updated, now)
	}
	if _, err := db.Exec(
		"UPDATE contacts SET name='ts2',updated_time=$1 WHERE id='c-ts'",
		now+60); err != nil {
		t.Fatalf("update: %v", err)
	}
	var name string
	if err := db.QueryRow(
		"SELECT name,updated_time FROM contacts WHERE id='c-ts'").Scan(&name, &updated); err != nil {
		t.Fatalf("reread: %v", err)
	}
	if name != "ts2" || updated != now+60 {
		t.Fatalf("updated row = %q,%d", name, updated)
	}
}
