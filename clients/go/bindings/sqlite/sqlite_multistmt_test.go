package sqlite

import (
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// Regression: Prepare compiled only the first statement, so multi-statement
// scripts silently dropped their tail. PrepareTail exposes the remainder.
func TestPrepareTailRunsEveryStatement(t *testing.T) {
	conn, err := Open(filepath.Join(t.TempDir(), "multi.db"), OpenReadWrite|OpenCreate)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer conn.Close()

	script := `CREATE TABLE t(a INTEGER PRIMARY KEY NOT NULL);
INSERT INTO t VALUES (1);
INSERT INTO t VALUES (2);
SELECT a FROM t ORDER BY a`
	var last [][]string
	stmts := 0
	for rest := script; strings.TrimSpace(rest) != ""; {
		st, tail, err := conn.PrepareTail(rest)
		if err != nil {
			t.Fatalf("PrepareTail: %v", err)
		}
		rest = tail
		if st == nil {
			continue
		}
		stmts++
		var rows [][]string
		for {
			done, err := st.Step()
			if err != nil {
				st.Close()
				t.Fatalf("Step: %v", err)
			}
			if done {
				break
			}
			row := make([]string, st.ColumnCount())
			for i := range row {
				row[i] = st.ColumnText(i)
			}
			rows = append(rows, row)
		}
		st.Close()
		last = rows
	}
	if stmts != 4 {
		t.Fatalf("ran %d statements, want 4", stmts)
	}
	if want := [][]string{{"1"}, {"2"}}; !reflect.DeepEqual(last, want) {
		t.Fatalf("last rows = %v, want %v", last, want)
	}
}

func TestPrepareTailEmpty(t *testing.T) {
	conn, err := Open(filepath.Join(t.TempDir(), "empty.db"), OpenReadWrite|OpenCreate)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer conn.Close()
	st, rest, err := conn.PrepareTail("  ; -- nothing here\n; ")
	if err != nil {
		t.Fatalf("PrepareTail: %v", err)
	}
	if st != nil {
		st.Close()
		t.Fatal("want nil stmt for empty script")
	}
	if strings.TrimSpace(rest) != "" {
		t.Fatalf("remainder = %q, want blank", rest)
	}
}
