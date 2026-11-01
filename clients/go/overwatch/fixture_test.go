// Package overwatch exercises libmurmur the way the OVERWATCH
// application uses its database: database/sql over an encrypted
// store, UUID-keyed collections with Unix-second timestamps and soft
// deletes, per-table replicated/node-local scope, $N and ?
// placeholders, multi-statement write transactions, junction-table
// reconciliation, LIKE search over typed tables, and concurrent CRUD.
package overwatch

import (
	"crypto/rand"
	"database/sql"
	"fmt"
	"testing"

	"github.com/marcgauthier/sqlite-murmur-go/clients/go/murmurdb"
)

// testKey returns a fresh random 32-byte store key.
func testKey(t *testing.T) [32]byte {
	t.Helper()
	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		t.Fatalf("rand key: %v", err)
	}
	return key
}

// openStore opens an encrypted murmurdb store in a fresh temp dir.
func openStore(t *testing.T, key [32]byte) (*sql.DB, string) {
	t.Helper()
	dir := t.TempDir()
	db, err := murmurdb.Open(fmt.Sprintf("%s/store?key=%s", dir, hexKey(key)))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db, dir
}

// openDir opens an encrypted murmurdb store at an explicit dir.
func openDir(t *testing.T, dir string, key [32]byte) *sql.DB {
	t.Helper()
	db, err := murmurdb.Open(fmt.Sprintf("%s/store?key=%s", dir, hexKey(key)))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// hexKey renders a store key as 64 lowercase hex digits.
func hexKey(key [32]byte) string {
	const digits = "0123456789abcdef"
	buf := make([]byte, 0, 64)
	for _, c := range key {
		buf = append(buf, digits[c>>4], digits[c&15])
	}
	return string(buf)
}

// appTables are the OVERWATCH-shaped collections. Every table carries
// a string UUID id, Unix-second created/updated times, and a nullable
// soft-delete stamp.
var appTables = []string{
	`CREATE TABLE IF NOT EXISTS contacts(id TEXT PRIMARY KEY NOT NULL DEFAULT '', name TEXT NOT NULL DEFAULT '', email TEXT, phone TEXT NOT NULL DEFAULT '', score INTEGER NOT NULL DEFAULT 0, created_time INTEGER NOT NULL DEFAULT 0, updated_time INTEGER NOT NULL DEFAULT 0, deleted_at INTEGER)`,
	`CREATE TABLE IF NOT EXISTS sites(id TEXT PRIMARY KEY NOT NULL DEFAULT '', name TEXT NOT NULL DEFAULT '', smc_id TEXT NOT NULL DEFAULT '', status TEXT NOT NULL DEFAULT 'active', created_time INTEGER NOT NULL DEFAULT 0, updated_time INTEGER NOT NULL DEFAULT 0, deleted_at INTEGER)`,
	`CREATE TABLE IF NOT EXISTS tasks(id TEXT PRIMARY KEY NOT NULL DEFAULT '', title TEXT NOT NULL DEFAULT '', state TEXT NOT NULL DEFAULT 'open', created_time INTEGER NOT NULL DEFAULT 0, updated_time INTEGER NOT NULL DEFAULT 0, deleted_at INTEGER)`,
	`CREATE TABLE IF NOT EXISTS task_site(task_id TEXT NOT NULL DEFAULT '', site_id TEXT NOT NULL DEFAULT '', PRIMARY KEY(task_id, site_id))`,
	`CREATE TABLE IF NOT EXISTS issues(id TEXT PRIMARY KEY NOT NULL DEFAULT '', title TEXT NOT NULL DEFAULT '', created_time INTEGER NOT NULL DEFAULT 0, updated_time INTEGER NOT NULL DEFAULT 0, deleted_at INTEGER)`,
	`CREATE TABLE IF NOT EXISTS issue_updates(id TEXT PRIMARY KEY NOT NULL DEFAULT '', issue_id TEXT NOT NULL DEFAULT '', body TEXT NOT NULL DEFAULT '', created_time INTEGER NOT NULL DEFAULT 0)`,
	`CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY NOT NULL DEFAULT '', name TEXT NOT NULL DEFAULT '', dashboard_config TEXT NOT NULL DEFAULT '{}', created_time INTEGER NOT NULL DEFAULT 0, updated_time INTEGER NOT NULL DEFAULT 0, deleted_at INTEGER)`,
	`CREATE TABLE IF NOT EXISTS documents(id TEXT PRIMARY KEY NOT NULL DEFAULT '', title TEXT NOT NULL DEFAULT '', body TEXT NOT NULL DEFAULT '', created_time INTEGER NOT NULL DEFAULT 0, updated_time INTEGER NOT NULL DEFAULT 0, deleted_at INTEGER)`,
	// Node-local tables: sessions, caches, permissions.
	`CREATE TABLE IF NOT EXISTS sessions(id TEXT PRIMARY KEY NOT NULL DEFAULT '', user_id TEXT NOT NULL DEFAULT '', expires INTEGER NOT NULL DEFAULT 0)`,
	`CREATE TABLE IF NOT EXISTS group_permissions(group_id TEXT NOT NULL DEFAULT '', permission TEXT NOT NULL DEFAULT '', PRIMARY KEY(group_id, permission))`,
}

// appIndexes covers the lookup paths list views use.
var appIndexes = []string{
	`CREATE INDEX IF NOT EXISTS idx_contacts_name ON contacts(name)`,
	`CREATE INDEX IF NOT EXISTS idx_sites_smc ON sites(smc_id)`,
	`CREATE INDEX IF NOT EXISTS idx_tasks_state ON tasks(state)`,
	`CREATE INDEX IF NOT EXISTS idx_issue_updates_issue ON issue_updates(issue_id)`,
	`CREATE INDEX IF NOT EXISTS idx_task_site_site ON task_site(site_id)`,
}

// replicatedTables are the collections that converge across nodes.
var replicatedTables = []string{
	"contacts", "sites", "tasks", "task_site", "issues",
	"issue_updates", "users", "documents",
}

// localTables stay on their node.
var localTables = []string{"sessions", "group_permissions"}

// setupSchema creates tables, indexes, and replication flags. It is
// idempotent: re-running after a partial setup (interrupted DDL)
// converges without errors.
func setupSchema(t *testing.T, db *sql.DB) {
	t.Helper()
	for _, ddl := range appTables {
		if _, err := db.Exec(ddl); err != nil {
			t.Fatalf("setup ddl: %v", err)
		}
	}
	for _, ddl := range appIndexes {
		if _, err := db.Exec(ddl); err != nil {
			t.Fatalf("setup index: %v", err)
		}
	}
	for _, table := range replicatedTables {
		if replicated(t, db, table) {
			continue
		}
		if _, err := db.Exec(fmt.Sprintf("SELECT crsql_as_crr('main','%s')", table)); err != nil {
			t.Fatalf("replicate %s: %v", table, err)
		}
	}
}

// replicated reports whether a table carries CRR tracking (the
// cr-sqlite clock side table exists).
func replicated(t *testing.T, db *sql.DB, table string) bool {
	t.Helper()
	var name string
	err := db.QueryRow(
		"SELECT name FROM sqlite_master WHERE type='table' AND name=?",
		table+"__crsql_clock").Scan(&name)
	if err == sql.ErrNoRows {
		return false
	}
	if err != nil {
		t.Fatalf("clock check %s: %v", table, err)
	}
	return true
}

// queryMaps runs a query and returns rows as maps (OVERWATCH
// QueryMaps shape), preserving NULLs as nil.
func queryMaps(t *testing.T, db *sql.DB, query string, args ...any) []map[string]any {
	t.Helper()
	rows, err := db.Query(query, args...)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	defer rows.Close()
	cols, err := rows.Columns()
	if err != nil {
		t.Fatalf("columns: %v", err)
	}
	var out []map[string]any
	for rows.Next() {
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			t.Fatalf("scan: %v", err)
		}
		m := make(map[string]any, len(cols))
		for i, c := range cols {
			m[c] = vals[i]
		}
		out = append(out, m)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows: %v", err)
	}
	return out
}
