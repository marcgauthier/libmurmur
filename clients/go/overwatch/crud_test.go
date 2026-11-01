package overwatch

import (
	"database/sql"
	"strings"
	"testing"
)

// Record CRUD mirrors OVERWATCH's InsertRecord/GetRecord/UpdateRecord
// flow: UUID ids, nullable fields, rows read back as maps, and both
// ? and $N placeholders at the execution boundary.

func TestContactCRUDRoundTrip(t *testing.T) {
	db, _ := openStore(t, testKey(t))
	setupSchema(t, db)

	res, err := db.Exec(
		"INSERT INTO contacts(id,name,email,phone,score,created_time,updated_time) VALUES(?,?,?,?,?,?,?)",
		"c-1", "Ada", "ada@example.com", "555-0100", 7, 1700000000, 1700000000)
	if err != nil {
		t.Fatalf("insert: %v", err)
	}
	if n, err := res.RowsAffected(); err != nil || n != 1 {
		t.Fatalf("rows affected = %d,%v", n, err)
	}
	got := queryMaps(t, db, "SELECT * FROM contacts WHERE id=?", "c-1")
	if len(got) != 1 {
		t.Fatalf("get returned %d rows", len(got))
	}
	if got[0]["name"] != "Ada" || got[0]["email"] != "ada@example.com" {
		t.Fatalf("get = %v", got[0])
	}
	if _, err := db.Exec(
		"UPDATE contacts SET name=?,score=?,updated_time=? WHERE id=?",
		"Ada L.", 8, 1700000060, "c-1"); err != nil {
		t.Fatalf("update: %v", err)
	}
	var name string
	var score int64
	if err := db.QueryRow(
		"SELECT name,score FROM contacts WHERE id='c-1'").Scan(&name, &score); err != nil {
		t.Fatalf("reread: %v", err)
	}
	if name != "Ada L." || score != 8 {
		t.Fatalf("updated = %q,%d", name, score)
	}
	// Soft delete hides the row from live views but keeps it stored.
	if _, err := db.Exec(
		"UPDATE contacts SET deleted_at=? WHERE id=?", 1700000100, "c-1"); err != nil {
		t.Fatalf("soft delete: %v", err)
	}
	var live int
	if err := db.QueryRow(
		"SELECT COUNT(*) FROM contacts WHERE deleted_at IS NULL").Scan(&live); err != nil {
		t.Fatalf("live count: %v", err)
	}
	if live != 0 {
		t.Fatalf("live rows = %d after soft delete", live)
	}
	var stored int
	if err := db.QueryRow("SELECT COUNT(*) FROM contacts").Scan(&stored); err != nil {
		t.Fatalf("stored count: %v", err)
	}
	if stored != 1 {
		t.Fatalf("stored rows = %d after soft delete", stored)
	}
	if _, err := db.Exec("DELETE FROM contacts WHERE id=?", "c-1"); err != nil {
		t.Fatalf("hard delete: %v", err)
	}
	if err := db.QueryRow("SELECT COUNT(*) FROM contacts").Scan(&stored); err != nil || stored != 0 {
		t.Fatalf("stored rows = %d,%v after hard delete", stored, err)
	}
}

func TestPlaceholdersQuestionAndNumbered(t *testing.T) {
	db, _ := openStore(t, testKey(t))
	setupSchema(t, db)
	// OVERWATCH binds $N at its execution boundary; anonymous ? must
	// work too.
	if _, err := db.Exec(
		"INSERT INTO contacts(id,name,score) VALUES($1,$2,$3)", "c-a", "Ann", 1); err != nil {
		t.Fatalf("numbered insert: %v", err)
	}
	if _, err := db.Exec(
		"INSERT INTO contacts(id,name,score) VALUES(?,?,?)", "c-b", "Bob", 2); err != nil {
		t.Fatalf("anonymous insert: %v", err)
	}
	var name string
	if err := db.QueryRow(
		"SELECT name FROM contacts WHERE id=$1", "c-a").Scan(&name); err != nil || name != "Ann" {
		t.Fatalf("numbered select = %q,%v", name, err)
	}
	if err := db.QueryRow(
		"SELECT name FROM contacts WHERE id=?", "c-b").Scan(&name); err != nil || name != "Bob" {
		t.Fatalf("anonymous select = %q,%v", name, err)
	}
	if _, err := db.Exec(
		"UPDATE contacts SET score=$1 WHERE id=$2", 9, "c-a"); err != nil {
		t.Fatalf("numbered update: %v", err)
	}
	var score int64
	if err := db.QueryRow("SELECT score FROM contacts WHERE id='c-a'").Scan(&score); err != nil || score != 9 {
		t.Fatalf("score = %d,%v", score, err)
	}
}

func TestNullsPreservedInMaps(t *testing.T) {
	db, _ := openStore(t, testKey(t))
	setupSchema(t, db)
	if _, err := db.Exec(
		"INSERT INTO contacts(id,name,email,deleted_at) VALUES('c-n','NoMail',NULL,NULL)"); err != nil {
		t.Fatalf("insert: %v", err)
	}
	got := queryMaps(t, db, "SELECT id,name,email,deleted_at FROM contacts WHERE id='c-n'")
	if len(got) != 1 {
		t.Fatalf("rows = %d", len(got))
	}
	if got[0]["email"] != nil {
		t.Fatalf("email = %#v, want nil", got[0]["email"])
	}
	if got[0]["deleted_at"] != nil {
		t.Fatalf("deleted_at = %#v, want nil", got[0]["deleted_at"])
	}
	if got[0]["name"] != "NoMail" {
		t.Fatalf("name = %#v", got[0]["name"])
	}
}

func TestUpsertOnConflict(t *testing.T) {
	db, _ := openStore(t, testKey(t))
	setupSchema(t, db)
	// OVERWATCH bootstrap rows use INSERT ... ON CONFLICT DO NOTHING.
	for i := 0; i < 2; i++ {
		if _, err := db.Exec(
			"INSERT INTO sessions(id,user_id,expires) VALUES('s1','u1',100) ON CONFLICT(id) DO NOTHING"); err != nil {
			t.Fatalf("upsert %d: %v", i, err)
		}
	}
	var count int
	if err := db.QueryRow("SELECT COUNT(*) FROM sessions").Scan(&count); err != nil || count != 1 {
		t.Fatalf("sessions = %d,%v", count, err)
	}
	// ... and DO UPDATE for reconciliation refreshes.
	if _, err := db.Exec(
		"INSERT INTO sessions(id,user_id,expires) VALUES('s1','u1',200) ON CONFLICT(id) DO UPDATE SET expires=excluded.expires"); err != nil {
		t.Fatalf("upsert update: %v", err)
	}
	var expires int64
	if err := db.QueryRow("SELECT expires FROM sessions WHERE id='s1'").Scan(&expires); err != nil || expires != 200 {
		t.Fatalf("expires = %d,%v", expires, err)
	}
}

func TestConstraintErrorsSurfaced(t *testing.T) {
	db, _ := openStore(t, testKey(t))
	setupSchema(t, db)
	if _, err := db.Exec("INSERT INTO contacts(id,name) VALUES('dup','one')"); err != nil {
		t.Fatalf("first insert: %v", err)
	}
	// Duplicate primary key must fail loudly for the validation layer.
	err := func() error {
		_, err := db.Exec("INSERT INTO contacts(id,name) VALUES('dup','two')")
		return err
	}()
	if err == nil {
		t.Fatal("duplicate primary key accepted")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "unique") &&
		!strings.Contains(strings.ToLower(err.Error()), "constraint") {
		t.Fatalf("duplicate error = %v", err)
	}
	// The failed statement left the original row untouched.
	var name string
	if err := db.QueryRow("SELECT name FROM contacts WHERE id='dup'").Scan(&name); err != nil || name != "one" {
		t.Fatalf("row = %q,%v", name, err)
	}
}

func TestGetMissingRecord(t *testing.T) {
	db, _ := openStore(t, testKey(t))
	setupSchema(t, db)
	var name string
	err := db.QueryRow("SELECT name FROM contacts WHERE id='nope'").Scan(&name)
	if err != sql.ErrNoRows {
		t.Fatalf("missing row err = %v, want sql.ErrNoRows", err)
	}
}
