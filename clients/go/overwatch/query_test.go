package overwatch

import (
	"database/sql"
	"fmt"
	"reflect"
	"testing"
)

// List-view query shapes mirror OVERWATCH's filter predicates:
// comparisons, IN lists, LIKE variants with case folding, NULL
// checks, boolean composition, sorting, pagination, counts,
// soft-delete filtering, junction joins, and aggregates.

func seedContactsX(t *testing.T, db *sql.DB) {
	t.Helper()
	rows := []struct {
		id, name, email, phone string
		score                  int64
		deleted                *int64
	}{
		{"c-1", "Alice Admin", "alice@example.com", "555-0001", 10, nil},
		{"c-2", "bob Builder", "bob@example.com", "555-0002", 20, nil},
		{"c-3", "Carol Clark", "", "555-0003", 30, nil},
		{"c-4", "alice cooper", "coop@example.com", "555-0004", 40, nil},
		{"c-5", "Dave", "dave@example.com", "555-0005", 50, int64p(1700000000)},
	}
	for _, r := range rows {
		var email any = r.email
		if r.email == "" {
			email = nil
		}
		var deleted any
		if r.deleted != nil {
			deleted = *r.deleted
		}
		if _, err := db.Exec(
			"INSERT INTO contacts(id,name,email,phone,score,deleted_at) VALUES(?,?,?,?,?,?)",
			r.id, r.name, email, r.phone, r.score, deleted); err != nil {
			t.Fatalf("seed %s: %v", r.id, err)
		}
	}
}

func int64p(v int64) *int64 { return &v }

func TestFilterComparisons(t *testing.T) {
	db, _ := openStore(t, testKey(t))
	setupSchema(t, db)
	seedContactsX(t, db)
	cases := []struct {
		name  string
		query string
		args  []any
		want  []string
	}{
		{"eq", "SELECT id FROM contacts WHERE name=? ORDER BY id", []any{"Dave"}, []string{"c-5"}},
		{"ne", "SELECT id FROM contacts WHERE score!=? ORDER BY id", []any{10}, []string{"c-2", "c-3", "c-4", "c-5"}},
		{"gt", "SELECT id FROM contacts WHERE score>? ORDER BY id", []any{25}, []string{"c-3", "c-4", "c-5"}},
		{"gte", "SELECT id FROM contacts WHERE score>=? ORDER BY id", []any{40}, []string{"c-4", "c-5"}},
		{"lt", "SELECT id FROM contacts WHERE score<? ORDER BY id", []any{20}, []string{"c-1"}},
		{"lte", "SELECT id FROM contacts WHERE score<=? ORDER BY id", []any{20}, []string{"c-1", "c-2"}},
		{"in", "SELECT id FROM contacts WHERE id IN (?,?,?) ORDER BY id", []any{"c-5", "c-1", "c-3"}, []string{"c-1", "c-3", "c-5"}},
		{"inSingle", "SELECT id FROM contacts WHERE id IN (?)", []any{"c-2"}, []string{"c-2"}},
		{"inEmpty", "SELECT id FROM contacts WHERE 0 = 1", nil, nil},
		{"startsWith", "SELECT id FROM contacts WHERE name LIKE ? || '%' ORDER BY id", []any{"Alice"}, []string{"c-1", "c-4"}},
		{"endsWith", "SELECT id FROM contacts WHERE name LIKE '%' || ? ORDER BY id", []any{"Clark"}, []string{"c-3"}},
		{"contains", "SELECT id FROM contacts WHERE name LIKE '%' || ? || '%' ORDER BY id", []any{"ob"} /* Bob */, []string{"c-2"}},
		{"containsFold", "SELECT id FROM contacts WHERE LOWER(name) LIKE '%' || LOWER(?) || '%' ORDER BY id", []any{"alice"}, []string{"c-1", "c-4"}},
		{"eqFold", "SELECT id FROM contacts WHERE LOWER(name)=LOWER(?)", []any{"BOB BUILDER"}, []string{"c-2"}},
		{"isNull", "SELECT id FROM contacts WHERE email IS NULL", nil, []string{"c-3"}},
		{"isNotNull", "SELECT id FROM contacts WHERE email IS NOT NULL ORDER BY id", nil, []string{"c-1", "c-2", "c-4", "c-5"}},
		{"and", "SELECT id FROM contacts WHERE score>? AND score<? ORDER BY id", []any{10, 40}, []string{"c-2", "c-3"}},
		{"or", "SELECT id FROM contacts WHERE score<? OR score>? ORDER BY id", []any{15, 45}, []string{"c-1", "c-5"}},
		{"not", "SELECT id FROM contacts WHERE NOT (score>? ) ORDER BY id", []any{30}, []string{"c-1", "c-2", "c-3"}},
		{"liveOnly", "SELECT id FROM contacts WHERE deleted_at IS NULL ORDER BY id", nil, []string{"c-1", "c-2", "c-3", "c-4"}},
	}
	for _, c := range cases {
		rows := queryMaps(t, db, c.query, c.args...)
		var got []string
		for _, r := range rows {
			got = append(got, r["id"].(string))
		}
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestSortingPaginationCounts(t *testing.T) {
	db, _ := openStore(t, testKey(t))
	setupSchema(t, db)
	seedContactsX(t, db)
	// ORDER BY score DESC with LIMIT/OFFSET pages.
	page := func(limit, offset int) []string {
		rows := queryMaps(t, db,
			"SELECT id FROM contacts WHERE deleted_at IS NULL ORDER BY score DESC LIMIT ? OFFSET ?",
			limit, offset)
		var ids []string
		for _, r := range rows {
			ids = append(ids, r["id"].(string))
		}
		return ids
	}
	if got, want := page(2, 0), []string{"c-4", "c-3"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("page0 = %v, want %v", got, want)
	}
	if got, want := page(2, 2), []string{"c-2", "c-1"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("page1 = %v, want %v", got, want)
	}
	var total int64
	if err := db.QueryRow("SELECT COUNT(*) FROM contacts WHERE deleted_at IS NULL").Scan(&total); err != nil || total != 4 {
		t.Fatalf("count = %d,%v", total, err)
	}
	// Aggregate over a group (stats-style).
	rows := queryMaps(t, db, "SELECT COUNT(*) AS n, SUM(score) AS s FROM contacts WHERE deleted_at IS NULL")
	if len(rows) != 1 {
		t.Fatalf("aggregate rows = %d", len(rows))
	}
	if fmt.Sprint(rows[0]["n"]) != "4" || fmt.Sprint(rows[0]["s"]) != "100" {
		t.Fatalf("aggregate = %v", rows[0])
	}
}

func TestJunctionJoin(t *testing.T) {
	db, _ := openStore(t, testKey(t))
	setupSchema(t, db)
	for _, s := range []struct{ id, name, smc string }{
		{"s-1", "HQ", "smc-a"}, {"s-2", "Branch", "smc-b"},
	} {
		if _, err := db.Exec("INSERT INTO sites(id,name,smc_id) VALUES(?,?,?)", s.id, s.name, s.smc); err != nil {
			t.Fatalf("site %s: %v", s.id, err)
		}
	}
	if _, err := db.Exec("INSERT INTO tasks(id,title) VALUES('t-1','Audit')"); err != nil {
		t.Fatalf("task: %v", err)
	}
	// Relationship reconciliation saves replacement rows before
	// pruning stale links.
	for _, link := range [][2]string{{"t-1", "s-1"}, {"t-1", "s-2"}} {
		if _, err := db.Exec("INSERT INTO task_site(task_id,site_id) VALUES(?,?)", link[0], link[1]); err != nil {
			t.Fatalf("link %v: %v", link, err)
		}
	}
	rows := queryMaps(t, db,
		`SELECT t.id AS task, s.name AS site FROM tasks t
		 JOIN task_site ts ON ts.task_id=t.id
		 JOIN sites s ON s.id=ts.site_id
		 WHERE t.id=? ORDER BY s.name`, "t-1")
	if len(rows) != 2 || rows[0]["site"] != "Branch" || rows[1]["site"] != "HQ" {
		t.Fatalf("join = %v", rows)
	}
	// Prune one stale link; the other survives.
	if _, err := db.Exec("DELETE FROM task_site WHERE task_id=? AND site_id=?", "t-1", "s-2"); err != nil {
		t.Fatalf("prune: %v", err)
	}
	rows = queryMaps(t, db, "SELECT site_id FROM task_site WHERE task_id='t-1'")
	if len(rows) != 1 || rows[0]["site_id"] != "s-1" {
		t.Fatalf("links = %v", rows)
	}
}

func TestSearchOverTypedTables(t *testing.T) {
	db, _ := openStore(t, testKey(t))
	setupSchema(t, db)
	// OVERWATCH knowledge search runs LIKE over typed tables (no
	// legacy FTS table).
	docs := []struct{ id, title, body string }{
		{"d-1", "Router Manual", "configure the uplink port speed"},
		{"d-2", "Switch Guide", "vlan trunk and uplink capacity"},
		{"d-3", "Holiday Policy", "office closure dates"},
	}
	for _, d := range docs {
		if _, err := db.Exec("INSERT INTO documents(id,title,body) VALUES(?,?,?)", d.id, d.title, d.body); err != nil {
			t.Fatalf("doc %s: %v", d.id, err)
		}
	}
	rows := queryMaps(t, db,
		"SELECT id FROM documents WHERE LOWER(title) LIKE LOWER(?) OR LOWER(body) LIKE LOWER(?) ORDER BY id",
		"%uplink%", "%uplink%")
	if len(rows) != 2 || rows[0]["id"] != "d-1" || rows[1]["id"] != "d-2" {
		t.Fatalf("search = %v", rows)
	}
}
