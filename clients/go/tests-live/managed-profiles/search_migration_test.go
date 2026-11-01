package managedprofiles

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"math"
	"reflect"
	"strconv"
	"testing"
	"time"

	mh "github.com/marcgauthier/sqlite-murmur-go/clients/go/tests-live/managedharness"
)

func searchNames(t *testing.T, c *mh.Cluster, node int) (string, string) {
	t.Helper()
	var fts, vec string
	for _, row := range c.Must(node, mh.Request{Op: "search-status"}).Rows {
		name := row[0].Text()
		if len(name) > 11 && name[:11] == "murmur_fts_" {
			fts = name
		} else {
			vec = name
		}
	}
	if fts == "" {
		t.Fatal("missing managed FTS index")
	}
	return fts, vec
}

func TestManagedMigrationCrashAndSchemaSearchAdoption(t *testing.T) {
	for _, phase := range []int{1, 2} {
		t.Run(strconv.Itoa(phase), func(t *testing.T) {
			c := mh.NewCluster(t, 3)
			c.Must(0, mh.Request{Op: "migrate", SQL: []string{"CREATE TABLE docs(id INTEGER NOT NULL PRIMARY KEY,body TEXT)"}})
			c.Must(0, mh.Request{Op: "replication", Table: "docs", Enabled: true})
			c.Must(0, mh.Request{Op: "search", Table: "docs", Column: "body", FTS: true})
			before := c.Publish()
			c.Exec(0, "INSERT INTO docs VALUES(1,'hello')")
			c.CatchUp()
			c.Must(0, mh.Request{Op: "refresh"})
			oldFTS, _ := searchNames(t, c, 0)
			migration := mh.Request{Op: "migrate", SQL: []string{"ALTER TABLE docs ADD COLUMN extra TEXT DEFAULT 'ready'; ALTER TABLE docs RENAME COLUMN body TO content; ALTER TABLE docs RENAME TO papers; CREATE INDEX papers_content ON papers(content)"}, Renames: []mh.Rename{{Table: "docs", Column: "body", NewColumn: "content"}, {Table: "docs", NewTable: "papers"}}, Crash: phase}
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			response, err := c.Nodes[0].Call(ctx, migration)
			cancel()
			if err == nil {
				t.Fatalf("migration crash hook did not terminate child: %+v", response)
			}
			ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
			code, err := c.Nodes[0].WaitExitCode(ctx)
			cancel()
			if err != nil || code != 82+phase {
				t.Fatalf("wrong crash boundary: code=%d err=%v", code, err)
			}
			c.Restart(0)
			if phase == 1 {
				if c.Query(0, "SELECT body FROM docs WHERE id=1")[0][0].Text() != "hello" {
					t.Fatal("precommit crash lost old schema/data")
				}
				if recovered := c.Must(0, mh.Request{Op: "export-schema"}).Data; !bytes.Equal(before, recovered) {
					t.Fatal("precommit migration published schema artifact")
				}
				migration.Crash = 0
				c.Must(0, migration)
			} else {
				if c.Query(0, "SELECT content FROM papers WHERE id=1")[0][0].Text() != "hello" {
					t.Fatal("post-store crash lost migrated schema/data")
				}
			}
			for node := 1; node < 3; node++ {
				if c.Query(node, "SELECT body FROM docs WHERE id=1")[0][0].Text() != "hello" {
					t.Fatal("isolated peer changed schema before adoption")
				}
			}
			after := c.Publish()
			if binary.LittleEndian.Uint64(after[52:60]) != binary.LittleEndian.Uint64(before[52:60])+1 {
				t.Fatal("migration artifact sequence was lost or minted twice")
			}
			c.Exec(0, "UPDATE papers SET content='done' WHERE id=1")
			c.CatchUp()
			for node := range c.Nodes {
				rows := c.Query(node, "SELECT content,extra FROM papers INDEXED BY papers_content WHERE id=1")
				if len(rows) != 1 || rows[0][0].Text() != "done" || rows[0][1].Text() != "ready" {
					t.Fatalf("migrated data/index/default: %+v", rows)
				}
				c.Must(node, mh.Request{Op: "refresh"})
				fts, _ := searchNames(t, c, node)
				if fts != oldFTS {
					t.Fatal("rename changed FTS identity")
				}
				if len(c.Query(node, fmt.Sprintf("SELECT rowid FROM temp.\"%s\" WHERE \"%s\" MATCH 'done'", fts, fts))) != 1 {
					t.Fatal("adopted search metadata did not follow migrated writes")
				}
			}
		})
	}
}

func point(x, y float32) string {
	var data [8]byte
	binary.LittleEndian.PutUint32(data[:4], math.Float32bits(x))
	binary.LittleEndian.PutUint32(data[4:], math.Float32bits(y))
	return fmt.Sprintf("x'%x'", data)
}

func TestManagedSearchAcrossProcessesMutationRenameRepairAndRestart(t *testing.T) {
	c := mh.NewCluster(t, 3)
	c.Must(0, mh.Request{Op: "migrate", SQL: []string{"CREATE TABLE docs(id INTEGER NOT NULL PRIMARY KEY,body TEXT,embedding BLOB)"}})
	c.Must(0, mh.Request{Op: "replication", Table: "docs", Enabled: true})
	c.Must(0, mh.Request{Op: "search", Table: "docs", Column: "body", FTS: true})
	c.Must(0, mh.Request{Op: "search", Table: "docs", Column: "embedding", Dims: 2})
	c.Publish()
	c.Exec(0, "INSERT INTO docs VALUES(1,'alpha',"+point(1, 0)+")", "INSERT INTO docs VALUES(2,'beta',"+point(0, 3)+")", "INSERT INTO docs VALUES(3,'alpha beta',"+point(5, 5)+")")
	c.CatchUp()
	checkSearch := func(table, column, term string, wantFTS []int64, wantVector int64) {
		t.Helper()
		for node := range c.Nodes {
			c.Must(node, mh.Request{Op: "refresh"})
			fts, vec := searchNames(t, c, node)
			if vec == "" {
				t.Fatal("missing managed vector index")
			}
			var got []int64
			for _, row := range c.Query(node, fmt.Sprintf("SELECT rowid FROM temp.\"%s\" WHERE \"%s\" MATCH '%s' ORDER BY rowid", fts, fts, term)) {
				got = append(got, row[0].Integer)
			}
			if !reflect.DeepEqual(got, wantFTS) {
				t.Fatalf("FTS node=%d got=%v want=%v", node, got, wantFTS)
			}
			rows := c.Query(node, fmt.Sprintf("SELECT rowid FROM temp.\"%s\" WHERE %s MATCH '[1,0]' AND k=1", vec, column))
			if len(rows) != 1 || rows[0][0].Integer != wantVector {
				t.Fatalf("vector node=%d rows=%+v", node, rows)
			}
		}
	}
	checkSearch("docs", "embedding", "alpha", []int64{1, 3}, 1)
	c.Exec(1, "UPDATE docs SET body='changed',embedding="+point(9, 9)+" WHERE id=1")
	c.Exec(2, "DELETE FROM docs WHERE id=3")
	c.CatchUp()
	checkSearch("docs", "embedding", "changed", []int64{1}, 2)
	beforeFTS, beforeVec := searchNames(t, c, 0)
	c.Must(0, mh.Request{Op: "migrate", SQL: []string{"ALTER TABLE docs RENAME COLUMN body TO content; ALTER TABLE docs RENAME COLUMN embedding TO point; ALTER TABLE docs RENAME TO papers"}, Renames: []mh.Rename{{Table: "docs", Column: "body", NewColumn: "content"}, {Table: "docs", Column: "embedding", NewColumn: "point"}, {Table: "docs", NewTable: "papers"}}})
	c.Publish()
	checkSearch("papers", "point", "changed", []int64{1}, 2)
	for node := range c.Nodes {
		fts, vec := searchNames(t, c, node)
		if fts != beforeFTS || vec != beforeVec {
			t.Fatal("search identities changed after rename")
		}
	}
	c.Exec(1, "UPDATE papers SET point=x'00' WHERE id=2")
	c.CatchUp()
	for node := range c.Nodes {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		response, err := c.Nodes[node].Call(ctx, mh.Request{Op: "refresh"})
		cancel()
		if err != nil || response.RC == 0 {
			t.Fatalf("invalid vector not reported: %+v %v", response, err)
		}
	}
	c.Exec(2, "UPDATE papers SET point="+point(0, 3)+" WHERE id=2")
	c.CatchUp()
	c.Restart(1)
	checkSearch("papers", "point", "changed", []int64{1}, 2)
}
