package replication

import (
	"crypto/sha256"
	"strings"
	"testing"

	"github.com/marcgauthier/sqlite-murmur-go/clients/go/bindings/sqlite"
)

func mustNode(t *testing.T, hex string) NodeID {
	t.Helper()
	id, err := ParseID(hex)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func makeSyncTable(t *testing.T, db *sqlite.Conn, name string) {
	t.Helper()
	if err := db.Exec("CREATE TABLE " + name + "(a INTEGER PRIMARY KEY NOT NULL, b TEXT);"); err != nil {
		t.Fatal(err)
	}
	if err := MakeCRR(db, name); err != nil {
		t.Fatalf("makecrr: %v", err)
	}
}

func errKind(err error) string {
	if e, ok := err.(*Error); ok {
		return e.Kind
	}
	return ""
}

func TestExportRoundTrip(t *testing.T) {
	db := openCRR(t)
	makeSyncTable(t, db, "t")
	if err := db.Exec("INSERT INTO t VALUES(1,'x'),(2,'y');"); err != nil {
		t.Fatal(err)
	}
	current, err := DbVersion(db)
	if err != nil || current <= 0 {
		t.Fatalf("dbversion = %d,%v", current, err)
	}
	out, err := Export(db, Cursor{}, 1<<20, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if out.Next.From != current || out.Next.Through != nil || out.Next.After != nil {
		t.Fatalf("done cursor = %+v, want from=%d", out.Next, current)
	}
	cells, err := DecodeCells(out.Blob)
	if err != nil {
		t.Fatal(err)
	}
	// Two rows x one data column (b; the PK is the identity) = 2 cells.
	if len(cells) != 2 {
		t.Fatalf("cells = %d, want 2", len(cells))
	}
	for _, c := range cells {
		if c.Table != "t" || c.DBVersion <= 0 || len(c.SiteID) != 16 {
			t.Fatalf("bad cell: %+v", c)
		}
	}
	// Export again from the done cursor: empty batch, advanced from.
	out2, err := Export(db, out.Next, 1<<20, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if len(out2.Blob) != emptyCRSBLen {
		t.Fatalf("empty blob len = %d", len(out2.Blob))
	}
	if out2.Next.From != current {
		t.Fatalf("from = %d, want %d", out2.Next.From, current)
	}
}

func TestExportPaginates(t *testing.T) {
	db := openCRR(t)
	makeSyncTable(t, db, "t")
	// One transaction versions all rows together; twelve narrow
	// cells overflow the 300-byte page budget within the version.
	if err := db.Exec("INSERT INTO t VALUES(1,'x'),(2,'y'),(3,'z'),(4,'a'),(5,'b'),(6,'c'),(7,'d'),(8,'e'),(9,'f'),(10,'g'),(11,'h'),(12,'i');"); err != nil {
		t.Fatal(err)
	}
	full, err := Export(db, Cursor{}, 1<<20, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	fullCells, err := DecodeCells(full.Blob)
	if err != nil {
		t.Fatal(err)
	}
	var got []Cell
	cursor := Cursor{}
	rounds := 0
	for {
		rounds++
		if rounds > 20 {
			t.Fatal("no convergence")
		}
		part, err := Export(db, cursor, 300, 1<<20)
		if err != nil {
			t.Fatal(err)
		}
		cells, err := DecodeCells(part.Blob)
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, cells...)
		if part.Next.Through == nil {
			if part.Next.From == cursor.From && len(cells) == 0 && rounds == 1 {
				t.Fatal("first page empty")
			}
			break
		}
		if part.Next.After == nil {
			t.Fatal("partial page without after key")
		}
		cursor = part.Next
	}
	if rounds < 2 {
		t.Fatalf("rounds = %d, want pagination", rounds)
	}
	if len(got) != len(fullCells) {
		t.Fatalf("paged %d cells, full %d", len(got), len(fullCells))
	}
	for i := range got {
		a, b := got[i], fullCells[i]
		if a.Table != b.Table || string(a.PK) != string(b.PK) || a.CID != b.CID ||
			a.ColVersion != b.ColVersion || a.DBVersion != b.DBVersion || a.Seq != b.Seq {
			t.Fatalf("cell %d differs: %+v vs %+v", i, a, b)
		}
	}
}

func TestExportValidation(t *testing.T) {
	db := openCRR(t)
	makeSyncTable(t, db, "t")
	if err := db.Exec("INSERT INTO t VALUES(1,'x');"); err != nil {
		t.Fatal(err)
	}
	current, _ := DbVersion(db)
	neg := Cursor{From: -1}
	if _, err := Export(db, neg, 1<<20, 1<<20); errKind(err) != "Protocol" {
		t.Fatalf("negative from err = %v", err)
	}
	through := current - 1
	if through < 0 {
		through = 0
	}
	below := Cursor{From: current, Through: &through}
	if _, err := Export(db, below, 1<<20, 1<<20); errKind(err) != "Protocol" {
		t.Fatalf("through<from err = %v", err)
	}
	after := &Key{Version: current, Seq: 1, Table: "t", PK: []byte{1}, CID: "b"}
	orphan := Cursor{From: 0, After: after}
	if _, err := Export(db, orphan, 1<<20, 1<<20); errKind(err) != "Protocol" {
		t.Fatalf("after-without-through err = %v", err)
	}
	future := Cursor{From: current + 1}
	if _, err := Export(db, future, 1<<20, 1<<20); err == nil || !strings.Contains(err.Error(), "regressed") {
		t.Fatalf("from>current err = %v", err)
	}
	tt := current + 1
	futureThrough := Cursor{From: 0, Through: &tt}
	if _, err := Export(db, futureThrough, 1<<20, 1<<20); err == nil || !strings.Contains(err.Error(), "regressed") {
		t.Fatalf("through>current err = %v", err)
	}
}

func TestExportOptOut(t *testing.T) {
	db := openCRR(t)
	makeSyncTable(t, db, "t")
	makeSyncTable(t, db, "u")
	if err := db.Exec("INSERT INTO t VALUES(1,'x'); INSERT INTO u VALUES(1,'y');"); err != nil {
		t.Fatal(err)
	}
	if err := SetSetting(db, "table_replication", `{"t":false}`); err != nil {
		t.Fatal(err)
	}
	out, err := Export(db, Cursor{}, 1<<20, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	cells, err := DecodeCells(out.Blob)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cells {
		if c.Table == "t" {
			t.Fatalf("opted-out cell exported: %+v", c)
		}
	}
	if len(cells) == 0 {
		t.Fatal("all cells skipped")
	}
}

func TestExportOverloaded(t *testing.T) {
	db := openCRR(t)
	makeSyncTable(t, db, "t")
	big := strings.Repeat("v", 70000)
	if err := db.Exec("INSERT INTO t VALUES(1,'" + big + "');"); err != nil {
		t.Fatal(err)
	}
	if _, err := Export(db, Cursor{}, 1<<20, 65536); errKind(err) != "Overloaded" {
		t.Fatalf("oversize err = %v", err)
	}
}

func splitBlob(blob []byte) [][]byte {
	mid := len(blob) / 2
	return [][]byte{blob[:mid], blob[mid:]}
}

func TestStageApplyRoundTrip(t *testing.T) {
	donor := openCRR(t)
	makeSyncTable(t, donor, "t")
	if err := donor.Exec("INSERT INTO t VALUES(1,'x'),(2,'y');"); err != nil {
		t.Fatal(err)
	}
	donorNode := mustNode(t, strings.Repeat("11", 16))
	donorSite, err := SiteID(donor)
	if err != nil {
		t.Fatal(err)
	}
	batch, err := Export(donor, Cursor{}, 1<<20, 1<<20)
	if err != nil {
		t.Fatal(err)
	}

	db := openCRR(t)
	makeSyncTable(t, db, "t")
	if err := Reset(db, donorNode, donorSite); err != nil {
		t.Fatal(err)
	}
	site, previous, err := Progress(db, donorNode)
	if err != nil || site == nil || *site != donorSite {
		t.Fatalf("progress = %v,%+v,%v", site, previous, err)
	}
	if err := StageBegin(db, donorNode, 300000); err != nil {
		t.Fatal(err)
	}
	chunks := splitBlob(batch.Blob)
	for i, c := range chunks {
		if err := Stage(db, donorNode, uint32(i), c, 1<<20); err != nil {
			t.Fatal(err)
		}
	}
	digest := sha256.Sum256(batch.Blob)
	if err := Apply(db, donorNode, donorSite, previous, batch.Next, uint64(len(batch.Blob)), digest); err != nil {
		t.Fatal(err)
	}
	st, err := db.Prepare("SELECT b FROM t WHERE a=1")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if done, err := st.Step(); err != nil || done {
		t.Fatalf("row missing: %v %v", done, err)
	}
	if st.ColumnText(0) != "x" {
		t.Fatalf("b = %q", st.ColumnText(0))
	}
	st.Close()
	_, stored, err := Progress(db, donorNode)
	if err != nil || !cursorsEqual(stored, batch.Next) {
		t.Fatalf("stored = %+v, want %+v (%v)", stored, batch.Next, err)
	}
	raw, ok, err := kvGet(db, ProgressKey(donorNode))
	if err != nil || !ok {
		t.Fatalf("applied head missing: %v %v", ok, err)
	}
	applied, err := DecodeU64(raw)
	if err != nil || applied != uint64(batch.Next.From) {
		t.Fatalf("applied = %d,%v want %d", applied, err, batch.Next.From)
	}
	if n, err := countRows(db, "SELECT COUNT(*) FROM murmur_stage"); err != nil || n != 0 {
		t.Fatalf("stage rows = %d,%v", n, err)
	}
}

func countRows(db *sqlite.Conn, query string) (int64, error) {
	st, err := db.Prepare(query)
	if err != nil {
		return 0, err
	}
	defer st.Close()
	if done, err := st.Step(); err != nil || done {
		return 0, err
	}
	return st.ColumnInt64(0), nil
}

func TestApplyGuards(t *testing.T) {
	setup := func(t *testing.T) (*sqlite.Conn, NodeID, NodeID, BatchExport) {
		t.Helper()
		donor := openCRR(t)
		makeSyncTable(t, donor, "t")
		if err := donor.Exec("INSERT INTO t VALUES(1,'x');"); err != nil {
			t.Fatal(err)
		}
		node := mustNode(t, strings.Repeat("11", 16))
		site, err := SiteID(donor)
		if err != nil {
			t.Fatal(err)
		}
		batch, err := Export(donor, Cursor{}, 1<<20, 1<<20)
		if err != nil {
			t.Fatal(err)
		}
		db := openCRR(t)
		makeSyncTable(t, db, "t")
		if err := Reset(db, node, site); err != nil {
			t.Fatal(err)
		}
		return db, node, site, batch
	}
	stageAll := func(t *testing.T, db *sqlite.Conn, node NodeID, blob []byte) {
		t.Helper()
		if err := StageBegin(db, node, 300000); err != nil {
			t.Fatal(err)
		}
		for i, c := range splitBlob(blob) {
			if err := Stage(db, node, uint32(i), c, 1<<20); err != nil {
				t.Fatal(err)
			}
		}
	}

	t.Run("moved progress", func(t *testing.T) {
		db, node, site, batch := setup(t)
		stageAll(t, db, node, batch.Blob)
		wrong := Cursor{From: 999}
		digest := sha256.Sum256(batch.Blob)
		err := Apply(db, node, site, wrong, batch.Next, uint64(len(batch.Blob)), digest)
		if err == nil || !strings.Contains(err.Error(), "progress changed") {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("wrong site", func(t *testing.T) {
		db, node, _, batch := setup(t)
		stageAll(t, db, node, batch.Blob)
		other := mustNode(t, strings.Repeat("33", 16))
		digest := sha256.Sum256(batch.Blob)
		err := Apply(db, node, other, Cursor{}, batch.Next, uint64(len(batch.Blob)), digest)
		if err == nil || !strings.Contains(err.Error(), "progress changed") {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("missing chunk", func(t *testing.T) {
		db, node, site, batch := setup(t)
		if err := StageBegin(db, node, 300000); err != nil {
			t.Fatal(err)
		}
		chunks := splitBlob(batch.Blob)
		if err := Stage(db, node, 0, chunks[0], 1<<20); err != nil {
			t.Fatal(err)
		}
		if err := Stage(db, node, 2, chunks[1], 1<<20); err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(batch.Blob)
		err := Apply(db, node, site, Cursor{}, batch.Next, uint64(len(batch.Blob)), digest)
		if err == nil || !strings.Contains(err.Error(), "missing chunk") {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("bad digest", func(t *testing.T) {
		db, node, site, batch := setup(t)
		stageAll(t, db, node, batch.Blob)
		var bad [32]byte
		err := Apply(db, node, site, Cursor{}, batch.Next, uint64(len(batch.Blob)), bad)
		if err == nil || !strings.Contains(err.Error(), "digest or length") {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("bad length", func(t *testing.T) {
		db, node, site, batch := setup(t)
		stageAll(t, db, node, batch.Blob)
		digest := sha256.Sum256(batch.Blob)
		err := Apply(db, node, site, Cursor{}, batch.Next, uint64(len(batch.Blob)+1), digest)
		if errKind(err) != "Protocol" {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("all filtered skips ingest", func(t *testing.T) {
		db, node, site, batch := setup(t)
		if err := SetSetting(db, "table_replication", `{"t":false}`); err != nil {
			t.Fatal(err)
		}
		stageAll(t, db, node, batch.Blob)
		digest := sha256.Sum256(batch.Blob)
		if err := Apply(db, node, site, Cursor{}, batch.Next, uint64(len(batch.Blob)), digest); err != nil {
			t.Fatal(err)
		}
		if n, err := countRows(db, "SELECT COUNT(*) FROM t"); err != nil || n != 0 {
			t.Fatalf("rows = %d,%v", n, err)
		}
		_, stored, err := Progress(db, node)
		if err != nil || !cursorsEqual(stored, batch.Next) {
			t.Fatalf("stored = %+v, want %+v (%v)", stored, batch.Next, err)
		}
	})
}

func TestProgressReset(t *testing.T) {
	db := openCRR(t)
	node := mustNode(t, strings.Repeat("11", 16))
	site := mustNode(t, strings.Repeat("22", 16))
	gotSite, cur, err := Progress(db, node)
	if err != nil || gotSite != nil || !cursorsEqual(cur, Cursor{}) {
		t.Fatalf("missing = %v,%+v,%v", gotSite, cur, err)
	}
	if err := Reset(db, node, site); err != nil {
		t.Fatal(err)
	}
	gotSite, cur, err = Progress(db, node)
	if err != nil || gotSite == nil || *gotSite != site || !cursorsEqual(cur, Cursor{}) {
		t.Fatalf("after reset = %v,%+v,%v", gotSite, cur, err)
	}
	other := mustNode(t, strings.Repeat("33", 16))
	if err := Reset(db, node, other); err != nil {
		t.Fatal(err)
	}
	gotSite, _, err = Progress(db, node)
	if err != nil || gotSite == nil || *gotSite != other {
		t.Fatalf("after re-reset = %v,%v", gotSite, err)
	}
}

func TestStageBudget(t *testing.T) {
	db := openCRR(t)
	node := mustNode(t, strings.Repeat("11", 16))
	if err := StageBegin(db, node, 300000); err != nil {
		t.Fatal(err)
	}
	if err := Stage(db, node, 0, make([]byte, 100), 200); err != nil {
		t.Fatal(err)
	}
	if err := Stage(db, node, 1, make([]byte, 101), 200); errKind(err) != "Overloaded" {
		t.Fatalf("over budget err = %v", err)
	}
	if err := Stage(db, node, 1, make([]byte, 100), 200); err != nil {
		t.Fatal(err)
	}
}

func TestObservedMax(t *testing.T) {
	db := openCRR(t)
	origin := mustNode(t, strings.Repeat("11", 16))
	if err := ObservedMax(db, origin, 5); err != nil {
		t.Fatal(err)
	}
	if err := ObservedMax(db, origin, 3); err != nil {
		t.Fatal(err)
	}
	raw, ok, err := kvGet(db, ObservedKey(origin))
	if err != nil || !ok {
		t.Fatalf("head missing: %v %v", ok, err)
	}
	v, err := DecodeU64(raw)
	if err != nil || v != 5 {
		t.Fatalf("head = %d,%v", v, err)
	}
	if err := ObservedMax(db, origin, 7); err != nil {
		t.Fatal(err)
	}
	raw, _, _ = kvGet(db, ObservedKey(origin))
	v, _ = DecodeU64(raw)
	if v != 7 {
		t.Fatalf("head = %d, want 7", v)
	}
}

func TestSchemaDigest(t *testing.T) {
	db := openCRR(t)
	makeSyncTable(t, db, "t")
	pairs, err := SchemaPairs(db)
	if err != nil || len(pairs) != 1 || pairs[0].Table != "t" {
		t.Fatalf("pairs = %+v,%v", pairs, err)
	}
	d1, err := Schema(db)
	if err != nil {
		t.Fatal(err)
	}
	d2, err := Schema(db)
	if err != nil || d1 != d2 {
		t.Fatal("digest unstable")
	}
	raw, err := SchemaBytes(db)
	if err != nil {
		t.Fatal(err)
	}
	back, err := DecodeSchemaPairs(raw)
	if err != nil || len(back) != 1 || back[0] != pairs[0] {
		t.Fatalf("round trip = %+v,%v", back, err)
	}
	if sha256.Sum256(raw) != d1 {
		t.Fatal("digest mismatch")
	}
	if err := SetSetting(db, "table_replication", `{"t":false}`); err != nil {
		t.Fatal(err)
	}
	manifest, err := ManifestSchemaBytes(db)
	if err != nil {
		t.Fatal(err)
	}
	kept, err := DecodeSchemaPairs(manifest)
	if err != nil || len(kept) != 0 {
		t.Fatalf("manifest = %+v,%v", kept, err)
	}
}

func TestSchemaGuards(t *testing.T) {
	db := openCRR(t)
	if _, err := SchemaPairs(db); err == nil {
		t.Fatal("empty schema accepted")
	}
	evil := openCRR(t)
	if err := evil.Exec("CREATE TABLE murmur_evil(a); CREATE TABLE murmur_evil__crsql_clock(x);"); err != nil {
		t.Fatal(err)
	}
	if _, err := SchemaPairs(evil); err == nil || !strings.Contains(err.Error(), "murmur tables") {
		t.Fatalf("murmur crr err = %v", err)
	}
}

func TestEncodeSchemaPairsBytes(t *testing.T) {
	got := EncodeSchemaPairs([]SchemaPair{{Table: "a", DDL: "b"}})
	want := []byte{0x01, 0x01, 'a', 0x01, 'b'}
	if string(got) != string(want) {
		t.Fatalf("bytes = %x, want %x", got, want)
	}
	if _, err := DecodeSchemaPairs(append(got, 0x00)); err == nil {
		t.Fatal("trailing byte accepted")
	}
	if _, err := DecodeSchemaPairs(got[:3]); err == nil {
		t.Fatal("truncated accepted")
	}
}

func TestCursorCompare(t *testing.T) {
	a := &Key{Version: 1, Seq: 2, Table: "t", PK: []byte{1}, CID: "b"}
	b := &Key{Version: 1, Seq: 2, Table: "t", PK: []byte{1}, CID: "b"}
	if compareKey(a, b) != 0 {
		t.Fatal("equal keys compare nonzero")
	}
	c := &Key{Version: 1, Seq: 3, Table: "t", PK: []byte{1}, CID: "b"}
	if compareKey(a, c) >= 0 || compareKey(c, a) <= 0 {
		t.Fatal("seq order wrong")
	}
	if !cursorsEqual(Cursor{}, Cursor{}) {
		t.Fatal("zero cursors differ")
	}
	one := int64(1)
	if cursorsEqual(Cursor{From: 1}, Cursor{From: 1, Through: &one}) {
		t.Fatal("through mismatch ignored")
	}
	if _, err := NodeIDFromBytes(make([]byte, 31)); err == nil {
		t.Fatal("short id accepted")
	}
	var zero NodeID
	if !zero.IsZero() {
		t.Fatal("zero id not zero")
	}
}
