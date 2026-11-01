package managedharness

import (
	"path/filepath"
	"testing"
)

func TestNativeRoundtripAndOwnedResults(t *testing.T) {
	var key, seed [32]byte
	var database, origin [16]byte
	key[0], seed[0], database[0], origin[0] = 41, 11, 73, 1
	db, err := OpenNative(filepath.Join(t.TempDir(), "store"), key, database, origin, seed)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, request := range []Request{{Op: "migrate", SQL: []string{"CREATE TABLE t(id INTEGER NOT NULL PRIMARY KEY,n INTEGER,v TEXT)"}}, {Op: "policy", Table: "t", Column: "n", Policy: 1}, {Op: "replication", Table: "t", Enabled: true}, {Op: "exec", SQL: []string{"INSERT INTO t VALUES(1,10,'hello')", "SELECT murmur_counter_add('t','[1]','n',3)"}}} {
		if result := db.Do(request); result.RC != 0 {
			t.Fatalf("%s: %+v", request.Op, result)
		}
	}
	result := db.Do(Request{Op: "query", SQL: []string{"SELECT n,v FROM t"}})
	if result.RC != 0 || len(result.Rows) != 1 || result.Rows[0][0].Integer != 13 || result.Rows[0][1].Text() != "hello" {
		t.Fatalf("query: %+v", result)
	}
	next := db.Do(Request{Op: "next", Origin: origin})
	if next.RC != 0 || len(next.Data) < 200 {
		t.Fatalf("signed export: %+v", next)
	}
	if result := db.Do(Request{Op: "apply", Data: next.Data}); result.RC != 0 || result.Changed {
		t.Fatalf("duplicate apply: %+v", result)
	}
}
