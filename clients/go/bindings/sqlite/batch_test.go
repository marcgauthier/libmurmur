package sqlite

import (
	"strings"
	"testing"
)

func openBatch(t *testing.T) *Conn {
	t.Helper()
	db, err := Open(":memory:", OpenReadWrite|OpenCreate)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := db.Exec(`CREATE TABLE t(id INTEGER PRIMARY KEY, name TEXT, val REAL, blob BLOB)`); err != nil {
		t.Fatal(err)
	}
	return db
}

func TestExecBatchEquivalence(t *testing.T) {
	db := openBatch(t)
	st, err := db.Prepare(`INSERT INTO t(id,name,val,blob) VALUES(?1,?2,?3,?4)`)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	var args []Arg
	var arena []byte
	rows := []struct {
		id   int64
		name string
		val  float64
		blob []byte
		null bool
	}{
		{1, "one", 1.5, []byte{1, 2, 3}, false},
		{2, "", 0, nil, true}, // empty text + NULL blob
		{3, "three-three-three", -2.25, []byte{}, false},
	}
	for _, r := range rows {
		args = append(args, IntArg(r.id))
		var a Arg
		a, arena = TextArg(arena, r.name)
		args = append(args, a)
		args = append(args, FloatArg(r.val))
		if r.null {
			args = append(args, NullArg())
		} else {
			a, arena = BlobArg(arena, r.blob)
			args = append(args, a)
		}
	}
	if err := st.ExecBatch(args, arena, 4); err != nil {
		t.Fatalf("ExecBatch: %v", err)
	}

	// Verify with the classic per-column API.
	rd, err := db.Prepare(`SELECT id,name,val,blob FROM t ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rd.Close()
	for i, want := range rows {
		done, err := rd.Step()
		if err != nil || done {
			t.Fatalf("row %d: done=%v err=%v", i, done, err)
		}
		if got := rd.ColumnInt64(0); got != want.id {
			t.Fatalf("row %d id = %d", i, got)
		}
		if got := rd.ColumnText(1); got != want.name {
			t.Fatalf("row %d name = %q", i, got)
		}
		if got := rd.ColumnFloat(2); got != want.val {
			t.Fatalf("row %d val = %v", i, got)
		}
		if want.null {
			if rd.ColumnType(3) != TypeNull {
				t.Fatalf("row %d blob should be NULL", i)
			}
		} else if got := rd.ColumnBlob(3); string(got) != string(want.blob) {
			t.Fatalf("row %d blob = %x", i, got)
		}
	}
	if done, err := rd.Step(); err != nil || !done {
		t.Fatalf("trailing: done=%v err=%v", done, err)
	}
}

func TestExecBatchRowError(t *testing.T) {
	db := openBatch(t)
	st, err := db.Prepare(`INSERT INTO t(id,name,val,blob) VALUES(?1,?2,?3,?4)`)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	var args []Arg
	var arena []byte
	for _, id := range []int64{1, 2, 1} { // duplicate key on row 2
		args = append(args, IntArg(id))
		var a Arg
		a, arena = TextArg(arena, "x")
		args = append(args, a, FloatArg(0), NullArg())
	}
	err = st.ExecBatch(args, arena, 4)
	if err == nil || !strings.Contains(err.Error(), "row 2") {
		t.Fatalf("expected failing row 2, got %v", err)
	}
}

func TestStepRowsScan(t *testing.T) {
	db := openBatch(t)
	if err := db.Exec(`INSERT INTO t(id,name,val) VALUES(1,'a',1),(2,'bb',2),(3,'ccc',3)`); err != nil {
		t.Fatal(err)
	}
	st, err := db.Prepare(`SELECT id,name,val FROM t ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	types := []ColType{ColInt, ColText, ColFloat}
	cols := make([]Cell, 2*3)
	arena := make([]byte, 64)
	var got []string
	for {
		n, more, err := st.StepRows(types, cols, arena, 2)
		if err != nil {
			t.Fatal(err)
		}
		for r := 0; r < n; r++ {
			row := cols[r*3 : (r+1)*3]
			got = append(got, row[1].Text(arena))
			if row[0].Int64() != int64(len(got)) || row[2].Float() != float64(len(got)) {
				t.Fatalf("row %d cells = %+v", len(got), row)
			}
		}
		if !more {
			break
		}
	}
	if len(got) != 3 || got[0] != "a" || got[2] != "ccc" {
		t.Fatalf("scan = %q", got)
	}
}

func TestStepRowsTruncation(t *testing.T) {
	db := openBatch(t)
	big := strings.Repeat("z", 200)
	if err := db.Exec(`INSERT INTO t(id,name) VALUES(1,'` + big + `'),(2,'s')`); err != nil {
		t.Fatal(err)
	}
	st, err := db.Prepare(`SELECT id,name FROM t ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	types := []ColType{ColInt, ColText}
	cols := make([]Cell, 2*2)
	// Tiny arena: first call delivers nothing but reports more.
	n, more, err := st.StepRows(types, cols, make([]byte, 8), 2)
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 || !more {
		t.Fatalf("tiny arena: n=%d more=%v", n, more)
	}
	// Retry with room: the pending row plus the second row arrive.
	// A full batch still reports more until a call observes DONE.
	n, more, err = st.StepRows(types, cols, make([]byte, 512), 2)
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 || !more {
		t.Fatalf("retry: n=%d more=%v", n, more)
	}
	n, more, err = st.StepRows(types, cols, make([]byte, 512), 2)
	if err != nil || n != 0 || more {
		t.Fatalf("exhaust: n=%d more=%v err=%v", n, more, err)
	}
	arena := make([]byte, 512)
	// Re-run to check payload views against a fresh arena.
	if err := st.Reset(); err != nil {
		t.Fatal(err)
	}
	// Reset clears pending; both rows arrive in one call (a full
	// batch reports more until exhaustion is observed).
	n, more, err = st.StepRows(types, cols, arena, 2)
	if err != nil || n != 2 || !more {
		t.Fatalf("rescan: n=%d more=%v err=%v", n, more, err)
	}
	if got := cols[1].Text(arena); got != big {
		t.Fatal("big payload mismatch")
	}
	if got := cols[3].Text(arena); got != "s" {
		t.Fatalf("second payload = %q", got)
	}
}

func TestFetchPointLookups(t *testing.T) {
	db := openBatch(t)
	if err := db.Exec(`INSERT INTO t(id,name,val) VALUES(7,'seven',7.5)`); err != nil {
		t.Fatal(err)
	}
	byID, err := db.Prepare(`SELECT name,val FROM t WHERE id=?1`)
	if err != nil {
		t.Fatal(err)
	}
	defer byID.Close()
	byName, err := db.Prepare(`SELECT id,val FROM t WHERE name=?1`)
	if err != nil {
		t.Fatal(err)
	}
	defer byName.Close()

	types := []ColType{ColText, ColFloat}
	cells := make([]Cell, 2)
	arena := make([]byte, 64)
	ok, err := byID.FetchInt64(7, types, cells, arena)
	if err != nil || !ok {
		t.Fatalf("fetch id hit: ok=%v err=%v", ok, err)
	}
	if cells[0].Text(arena) != "seven" || cells[1].Float() != 7.5 {
		t.Fatalf("cells = %+v", cells)
	}
	ok, err = byID.FetchInt64(8, types, cells, arena)
	if err != nil || ok {
		t.Fatalf("fetch id miss: ok=%v err=%v", ok, err)
	}

	types2 := []ColType{ColInt, ColFloat}
	ok, err = byName.FetchText("seven", types2, cells, arena)
	if err != nil || !ok || cells[0].Int64() != 7 {
		t.Fatalf("fetch text hit: ok=%v err=%v cells=%+v", ok, err, cells)
	}
	ok, err = byName.FetchText("missing", types2, cells, arena)
	if err != nil || ok {
		t.Fatalf("fetch text miss: ok=%v err=%v", ok, err)
	}
	// Empty key binds empty (never NULL): no match, no error.
	ok, err = byName.FetchText("", types2, cells, arena)
	if err != nil || ok {
		t.Fatalf("fetch empty key: ok=%v err=%v", ok, err)
	}
}

func TestFetchManyInt64(t *testing.T) {
	db := openBatch(t)
	for _, row := range [][2]string{{"7", "seven"}, {"8", "eight"}, {"9", "nine"}} {
		if err := db.Exec(`INSERT INTO t(id,name,val) VALUES(` + row[0] + `,'` + row[1] + `',1.5)`); err != nil {
			t.Fatal(err)
		}
	}
	byID, err := db.Prepare(`SELECT name,val FROM t WHERE id=?1`)
	if err != nil {
		t.Fatal(err)
	}
	defer byID.Close()
	types := []ColType{ColText, ColFloat}
	keys := []int64{7, 42, 9, 8, 43}
	cells := make([]Cell, len(keys)*len(types))
	arena := make([]byte, 256)
	hits := make([]bool, len(keys))
	if err := byID.FetchManyInt64(keys, types, cells, arena, hits); err != nil {
		t.Fatal(err)
	}
	wantHits := []bool{true, false, true, true, false}
	for i, w := range wantHits {
		if hits[i] != w {
			t.Fatalf("hits = %v, want %v", hits, wantHits)
		}
	}
	want := map[int]string{7: "seven", 9: "nine", 8: "eight"}
	for i, k := range keys {
		if !hits[i] {
			continue
		}
		base := i * len(types)
		if cells[base].Text(arena) != want[int(k)] || cells[base+1].Float() != 1.5 {
			t.Fatalf("key %d cells = %+v", k, cells[base:base+2])
		}
	}
	// Truncation: the first key fits, the second does not.
	tiny := make([]byte, 5)
	cells2 := make([]Cell, 2*len(types))
	hits2 := make([]bool, 2)
	if err := byID.FetchManyInt64([]int64{7, 8}, types, cells2, tiny, hits2); err == nil {
		t.Fatal("expected truncation error")
	}
	if !hits2[0] || cells2[0].Text(tiny) != "seven" {
		t.Fatalf("truncated prefix invalid: hits=%v cells=%+v", hits2, cells2)
	}
}

func TestStepOnceAndBindTextEmpty(t *testing.T) {
	db := openBatch(t)
	st, err := db.Prepare(`INSERT INTO t(id,name) VALUES(?1,?2)`)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.BindInt64(1, 1); err != nil {
		t.Fatal(err)
	}
	if err := st.BindText(2, ""); err != nil {
		t.Fatal(err)
	}
	if err := st.StepOnce(); err != nil {
		t.Fatal(err)
	}
	// Statement was reset: reuse it directly.
	if err := st.BindInt64(1, 2); err != nil {
		t.Fatal(err)
	}
	if err := st.BindText(2, "x"); err != nil {
		t.Fatal(err)
	}
	if err := st.StepOnce(); err != nil {
		t.Fatal(err)
	}
	rd, err := db.Prepare(`SELECT name FROM t WHERE id=1`)
	if err != nil {
		t.Fatal(err)
	}
	defer rd.Close()
	if done, err := rd.Step(); err != nil || done {
		t.Fatalf("step: %v %v", done, err)
	}
	if rd.ColumnType(0) != TypeText || rd.ColumnText(0) != "" {
		t.Fatal("empty text must bind empty, not NULL")
	}
}
