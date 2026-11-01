package overwatch

import (
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Durability mirrors OVERWATCH's restart and backup story: rows and
// replication flags survive close/reopen, and a file-level copy of a
// closed store reopens with its data intact under the same key.

func TestReopenSurvivesRestart(t *testing.T) {
	key := testKey(t)
	db, dir := openStore(t, key)
	setupSchema(t, db)
	if _, err := db.Exec(
		"INSERT INTO contacts(id,name,email) VALUES('persist-1','Keep','keep@example.com')"); err != nil {
		t.Fatalf("insert: %v", err)
	}
	if _, err := db.Exec(
		"INSERT INTO sessions(id,user_id,expires) VALUES('sess-keep','u9',999)"); err != nil {
		t.Fatalf("session insert: %v", err)
	}
	db.Close()
	// Reopen the same store: rows, flags, and local tables intact.
	db2 := openDir(t, dir, key)
	var email string
	if err := db2.QueryRow(
		"SELECT email FROM contacts WHERE id='persist-1'").Scan(&email); err != nil || email != "keep@example.com" {
		t.Fatalf("contact = %q,%v", email, err)
	}
	var user string
	if err := db2.QueryRow(
		"SELECT user_id FROM sessions WHERE id='sess-keep'").Scan(&user); err != nil || user != "u9" {
		t.Fatalf("session = %q,%v", user, err)
	}
	for _, table := range replicatedTables {
		if !replicated(t, db2, table) {
			t.Fatalf("%s lost its flag across restart", table)
		}
	}
	// The reopened store accepts writes.
	if _, err := db2.Exec("INSERT INTO contacts(id,name) VALUES('persist-2','More')"); err != nil {
		t.Fatalf("post-reopen write: %v", err)
	}
}

func TestFileCopyBackupReopens(t *testing.T) {
	key := testKey(t)
	db, dir := openStore(t, key)
	setupSchema(t, db)
	for i := 0; i < 25; i++ {
		if _, err := db.Exec("INSERT INTO sites(id,name,smc_id) VALUES(?,?,?)",
			"bk-"+itoa(i), "Site", "smc-x"); err != nil {
			t.Fatalf("insert %d: %v", i, err)
		}
	}
	db.Close()
	// File-level backup of the closed store.
	backup := t.TempDir() + "/backup"
	if err := copyTree(dir, backup); err != nil {
		t.Fatalf("copy: %v", err)
	}
	// The backup reopens under the same key with all rows.
	restored := openDir(t, backup, key)
	var count int
	if err := restored.QueryRow("SELECT COUNT(*) FROM sites").Scan(&count); err != nil || count != 25 {
		t.Fatalf("restored sites = %d,%v", count, err)
	}
	// The live store is unaffected by the copy.
	live := openDir(t, dir, key)
	var liveCount int
	if err := live.QueryRow("SELECT COUNT(*) FROM sites").Scan(&liveCount); err != nil || liveCount != 25 {
		t.Fatalf("live sites = %d,%v", liveCount, err)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [8]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// copyTree copies a directory tree (file-level backup of a closed store).
func copyTree(src, dst string) error {
	return filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		in, err := os.Open(path)
		if err != nil {
			return err
		}
		defer in.Close()
		out, err := os.Create(target)
		if err != nil {
			return err
		}
		defer out.Close()
		_, err = io.Copy(out, in)
		return err
	})
}

func TestJSONDocumentRoundTrip(t *testing.T) {
	db, _ := openStore(t, testKey(t))
	setupSchema(t, db)
	// OVERWATCH dashboard_config stores a versioned JSON document.
	doc := `{"version":3,"policy":"fit","widgets":[{"id":"map","filter":{"smc":["a","b"]},"visible":true}],"layouts":{"lg":[1,2,3]}}`
	if _, err := db.Exec(
		"INSERT INTO users(id,name,dashboard_config) VALUES('u-dash','Dash',$1)", doc); err != nil {
		t.Fatalf("insert: %v", err)
	}
	var got string
	if err := db.QueryRow("SELECT dashboard_config FROM users WHERE id='u-dash'").Scan(&got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if got != doc {
		t.Fatalf("doc mismatch:\n got %q\nwant %q", got, doc)
	}
}

func TestLargeDocumentBody(t *testing.T) {
	db, _ := openStore(t, testKey(t))
	setupSchema(t, db)
	body := strings.Repeat("Lorem ipsum dolor sit amet. ", 40000) // ~1.1 MB
	if _, err := db.Exec(
		"INSERT INTO documents(id,title,body) VALUES('doc-big','Big',$1)", body); err != nil {
		t.Fatalf("insert: %v", err)
	}
	var got string
	if err := db.QueryRow("SELECT body FROM documents WHERE id='doc-big'").Scan(&got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if got != body {
		t.Fatalf("body mismatch: %d vs %d bytes", len(got), len(body))
	}
}
