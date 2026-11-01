package replication

import (
	"io"
	"net"
	"strings"
	"sync"
	"testing"

	"github.com/marcgauthier/sqlite-murmur-go/clients/go/pkgs/tx"
)

const docsDDL = "CREATE TABLE docs(id INTEGER PRIMARY KEY, v TEXT)"

func schemaPairs(t *testing.T, tables ...[2]string) []byte {
	t.Helper()
	var pairs []SchemaPair
	for _, td := range tables {
		pairs = append(pairs, SchemaPair{Table: td[0], DDL: td[1]})
	}
	return EncodeSchemaPairs(pairs)
}

func TestPullerCompatibleCases(t *testing.T) {
	donor := schemaPairs(t, [2]string{"docs", docsDDL})
	ok, err := PullerCompatible(donor, donor)
	if err != nil || !ok {
		t.Fatal("identical rejected")
	}
	legacy := schemaPairs(t, [2]string{"docs", docsDDL}, [2]string{"adopted1", "CREATE TABLE adopted1(id INTEGER PRIMARY KEY)"})
	ok, err = PullerCompatible(donor, legacy)
	if err != nil || !ok {
		t.Fatal("puller-extra rejected")
	}
	ok, err = PullerCompatible(legacy, donor)
	if err != nil || ok {
		t.Fatal("puller-missing accepted")
	}
	// Puller-extra columns are harmless (donor changes address
	// columns by name) and required for branch merge.
	drifted := schemaPairs(t, [2]string{"docs", "CREATE TABLE docs(id INTEGER PRIMARY KEY, v TEXT, w TEXT)"})
	ok, err = PullerCompatible(donor, drifted)
	if err != nil || !ok {
		t.Fatal("puller-extra column rejected")
	}
	// Same shape in a different column order still vets: merged
	// branches append the adopted column last on each side.
	reordered := schemaPairs(t, [2]string{"docs", "CREATE TABLE docs(v TEXT, id INTEGER PRIMARY KEY)"})
	ok, err = PullerCompatible(donor, reordered)
	if err != nil || !ok {
		t.Fatal("reordered shape rejected")
	}
	// Same shape modulo formatting vets: only the digest fast-path
	// distinguishes bytes.
	pretty := schemaPairs(t, [2]string{"docs", "create table docs( id integer primary key,v text )"})
	ok, err = PullerCompatible(donor, pretty)
	if err != nil || !ok {
		t.Fatal("formatting drift rejected")
	}
	// Puller-missing columns and redefined columns still fail: the
	// donor's changes would be un-ingestable.
	subset := schemaPairs(t, [2]string{"docs", "CREATE TABLE docs(id INTEGER PRIMARY KEY)"})
	ok, err = PullerCompatible(donor, subset)
	if err != nil || ok {
		t.Fatal("puller-missing column accepted")
	}
	redef := schemaPairs(t, [2]string{"docs", "CREATE TABLE docs(id INTEGER PRIMARY KEY, v INTEGER)"})
	ok, err = PullerCompatible(donor, redef)
	if err != nil || ok {
		t.Fatal("redefined column accepted")
	}
	if _, err := PullerCompatible(donor, []byte{0x01, 0x02}); err == nil {
		t.Fatal("garbage accepted")
	}
}

func TestSchemaDiffCases(t *testing.T) {
	local := schemaPairs(t, [2]string{"docs", docsDDL})
	remote := schemaPairs(t,
		[2]string{"docs", "CREATE TABLE docs(id INTEGER PRIMARY KEY, v TEXT, n INTEGER)"},
		[2]string{"newt", "CREATE TABLE newt(id INTEGER PRIMARY KEY)"},
	)
	d, err := SchemaDiff(local, remote)
	if err != nil || !d.Additive {
		t.Fatalf("diff = %+v,%v", d, err)
	}
	if len(d.Delta.NewTables) != 1 || d.Delta.NewTables[0][0] != "newt" {
		t.Fatalf("tables = %+v", d.Delta.NewTables)
	}
	if len(d.Delta.AddColumns) != 1 || d.Delta.AddColumns[0][0] != "docs" {
		t.Fatalf("columns = %+v", d.Delta.AddColumns)
	}
	// Formatting drift is a no-op.
	pretty := schemaPairs(t, [2]string{"docs", "create table docs( id  integer primary key,v text )"})
	d, err = SchemaDiff(local, pretty)
	if err != nil || !d.Additive || len(d.Delta.NewTables) != 0 || len(d.Delta.AddColumns) != 0 {
		t.Fatalf("formatting diff = %+v,%v", d, err)
	}
	// Literal defaults really differ.
	litLocal := schemaPairs(t, [2]string{"docs", "CREATE TABLE docs(id INTEGER PRIMARY KEY, v TEXT DEFAULT 'a')"})
	litRemote := schemaPairs(t, [2]string{"docs", "CREATE TABLE docs(id INTEGER PRIMARY KEY, v TEXT DEFAULT 'A')"})
	d, err = SchemaDiff(litLocal, litRemote)
	if err != nil || d.Additive {
		t.Fatalf("default diff = %+v,%v", d, err)
	}
	// Local extras are kept, not conflicts: a subset remote adopts
	// as a no-op, and divergent branches merge through mutual
	// adoption.
	withGone := schemaPairs(t, [2]string{"docs", docsDDL}, [2]string{"gone", "CREATE TABLE gone(id INTEGER)"})
	d, _ = SchemaDiff(withGone, local)
	if !d.Additive || len(d.Delta.NewTables) != 0 || len(d.Delta.AddColumns) != 0 {
		t.Fatalf("retired = %+v", d)
	}
	dropped := schemaPairs(t, [2]string{"docs", "CREATE TABLE docs(id INTEGER PRIMARY KEY)"})
	d, _ = SchemaDiff(local, dropped)
	if !d.Additive || len(d.Delta.NewTables) != 0 || len(d.Delta.AddColumns) != 0 {
		t.Fatalf("dropped = %+v", d)
	}
	leftBranch := schemaPairs(t, [2]string{"docs", "CREATE TABLE docs(id INTEGER PRIMARY KEY, v TEXT, note TEXT)"})
	rightBranch := schemaPairs(t, [2]string{"docs", "CREATE TABLE docs(id INTEGER PRIMARY KEY, v TEXT, region TEXT)"})
	d, err = SchemaDiff(leftBranch, rightBranch)
	if err != nil || !d.Additive || len(d.Delta.AddColumns) != 1 {
		t.Fatalf("branch diff = %+v,%v", d, err)
	}
	if d.Delta.AddColumns[0][0] != "docs" || !strings.Contains(d.Delta.AddColumns[0][1], "region") {
		t.Fatalf("branch delta = %+v", d.Delta.AddColumns)
	}
	redefined := schemaPairs(t, [2]string{"docs", "CREATE TABLE docs(id TEXT PRIMARY KEY, v TEXT)"})
	d, _ = SchemaDiff(local, redefined)
	if d.Additive || !strings.Contains(d.Incompatible, "redefined") {
		t.Fatalf("redefined = %+v", d)
	}
	constrained := schemaPairs(t, [2]string{"docs", "CREATE TABLE docs(id INTEGER PRIMARY KEY, v TEXT, UNIQUE(v))"})
	d, _ = SchemaDiff(local, constrained)
	if d.Additive || !strings.Contains(d.Incompatible, "constraint") {
		t.Fatalf("constraint = %+v", d)
	}
	broken := schemaPairs(t, [2]string{"docs", "CREATE TABLE docs(id INTEGER PRIMARY KEY, v TEXT"})
	d, _ = SchemaDiff(local, broken)
	if d.Additive {
		t.Fatalf("unparseable = %+v", d)
	}
}

func TestSchemaParamsLoad(t *testing.T) {
	db := openCRR(t)
	p, err := SchemaParamsFrom(db)
	if err != nil {
		t.Fatal(err)
	}
	if !p.AcceptRemoteSchema || p.SchemaMaster != nil || p.Master {
		t.Fatalf("defaults = %+v", p)
	}
	if err := SetSetting(db, "schema_master", "00000000000000000000000000000001"); err != nil {
		t.Fatal(err)
	}
	if err := SetSetting(db, "schema_master_enabled", "1"); err != nil {
		t.Fatal(err)
	}
	if err := SetSetting(db, "accept_remote_schema", "0"); err != nil {
		t.Fatal(err)
	}
	p, err = SchemaParamsFrom(db)
	if err != nil {
		t.Fatal(err)
	}
	if p.AcceptRemoteSchema || p.SchemaMaster == nil || !p.Master {
		t.Fatalf("set = %+v", p)
	}
	st, err := db.Prepare("UPDATE murmur_config SET value='zz' WHERE name='schema_master'")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, err := st.Step(); err != nil {
		t.Fatal(err)
	}
	st.Close()
	if _, err := SchemaParamsFrom(db); err == nil {
		t.Fatal("bad master accepted")
	}
}

func TestSchemaValidators(t *testing.T) {
	for _, ddl := range []string{
		docsDDL, docsDDL + ";",
		"CREATE TABLE IF NOT EXISTS docs(id INTEGER)",
		"CREATE TABLE main.docs(id INTEGER)",
	} {
		if err := CheckCreateTable("docs", ddl); err != nil {
			t.Fatalf("accept %q: %v", ddl, err)
		}
	}
	for _, ddl := range []string{
		"CREATE TABLE other(id INTEGER)",
		"CREATE TEMP TABLE docs(id INTEGER)",
		"CREATE VIRTUAL TABLE docs USING fts5(x)",
		"DROP TABLE docs",
		"CREATE TABLE docs(id INTEGER); DROP TABLE docs;",
		"CREATE TABLE aux.docs(id INTEGER)",
		"CREATE TABLE docs AS SELECT 1",
	} {
		if err := CheckCreateTable("docs", ddl); err == nil {
			t.Fatalf("reject %q accepted", ddl)
		}
	}
	if n, err := CheckAddColumn("n INTEGER DEFAULT 0"); err != nil || n != "n" {
		t.Fatalf("column = %q,%v", n, err)
	}
	if n, err := CheckAddColumn("v TEXT DEFAULT 'a;b'"); err != nil || n != "v" {
		t.Fatalf("quoted semi = %q,%v", n, err)
	}
	for _, c := range []string{"n INTEGER; DROP TABLE docs", "n INTEGER, m INTEGER", "PRIMARY KEY (id)", ""} {
		if _, err := CheckAddColumn(c); err == nil {
			t.Fatalf("column %q accepted", c)
		}
	}
}

func testSchemaParams() *SchemaParams {
	return &SchemaParams{AcceptRemoteSchema: true, MaxSchemaBytes: 1 << 20}
}

func testSigned(sequence uint64, schema []byte) tx.SignedSchema {
	return tx.SignedSchema{
		Database: fillNode(1), Signer: NodeID{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9},
		Sequence: sequence, Schema: schema,
	}
}

func fillNode(b byte) NodeID {
	var id NodeID
	for i := range id {
		id[i] = b
	}
	return id
}

func TestManifestSequence(t *testing.T) {
	group := fillNode(1)
	be, _, e := openBackend(t, group, "07070707070707070707070707070707")
	params := testSchemaParams()
	one := schemaPairs(t, [2]string{"docs", docsDDL})
	m1, err := BuildSchemaManifest(be, params, e.node, group, one)
	if err != nil || m1.Sequence != 1 {
		t.Fatalf("m1 = %+v,%v", m1, err)
	}
	m1b, err := BuildSchemaManifest(be, params, e.node, group, one)
	if err != nil || m1b.Sequence != 1 {
		t.Fatalf("retransmit = %+v,%v", m1b, err)
	}
	two := schemaPairs(t, [2]string{"docs", docsDDL}, [2]string{"more", "CREATE TABLE more(id INTEGER)"})
	m2, err := BuildSchemaManifest(be, params, e.node, group, two)
	if err != nil || m2.Sequence != 2 {
		t.Fatalf("m2 = %+v,%v", m2, err)
	}
	master := *params
	master.Master = true
	other := fillNode(9)
	master.SchemaMaster = &other
	if _, err := BuildSchemaManifest(be, &master, e.node, group, []byte{}); err == nil {
		t.Fatal("foreign master accepted")
	}
	master.SchemaMaster = &e.node
	if _, err := BuildSchemaManifest(be, &master, e.node, group, []byte{}); err != nil {
		t.Fatalf("self master: %v", err)
	}
}

func TestCheckManifestDecisions(t *testing.T) {
	group := fillNode(1)
	be, _, e := openBackend(t, group, "08080808080808080808080808080808")
	params := testSchemaParams()
	source := NodeID{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9}
	local := schemaPairs(t, [2]string{"docs", docsDDL})
	if _, err := CheckSchemaManifest(be, params, e.node, local, ptrSigned(testSigned(1, local)), fillNode(7)); err == nil {
		t.Fatal("wrong source accepted")
	}
	remote := schemaPairs(t, [2]string{"docs", docsDDL}, [2]string{"more", "CREATE TABLE more(id INTEGER)"})
	d, err := CheckSchemaManifest(be, params, e.node, local, ptrSigned(testSigned(1, remote)), source)
	if err != nil || d != SchemaAdopt {
		t.Fatalf("adopt = %v,%v", d, err)
	}
	first := testSigned(1, local)
	d, err = CheckSchemaManifest(be, params, e.node, local, ptrSigned(first), source)
	if err != nil || d != SchemaCurrent {
		t.Fatalf("current = %v,%v", d, err)
	}
	d, err = CheckSchemaManifest(be, params, e.node, local, ptrSigned(testSigned(1, local)), source)
	if err != nil || d != SchemaStale {
		t.Fatalf("stale = %v,%v", d, err)
	}
	// A subset remote is not destructive: it adopts as a no-op
	// (local extras are kept) instead of recording without adopt.
	dropped := schemaPairs(t, [2]string{"docs", "CREATE TABLE docs(id INTEGER PRIMARY KEY)"})
	d, err = CheckSchemaManifest(be, params, e.node, local, ptrSigned(testSigned(2, dropped)), source)
	if err != nil || d != SchemaAdopt {
		t.Fatalf("subset = %v,%v", d, err)
	}
	gated := *params
	five := fillNode(5)
	gated.SchemaMaster = &five
	d, err = CheckSchemaManifest(be, &gated, e.node, local, ptrSigned(testSigned(3, remote)), source)
	if err != nil || d != SchemaRecord {
		t.Fatalf("gated = %v,%v", d, err)
	}
	closed := *params
	closed.AcceptRemoteSchema = false
	d, err = CheckSchemaManifest(be, &closed, e.node, local, ptrSigned(testSigned(4, remote)), source)
	if err != nil || d != SchemaRecord {
		t.Fatalf("closed = %v,%v", d, err)
	}
}

func ptrSigned(s tx.SignedSchema) *tx.SignedSchema { return &s }

// servePipe opens fresh donor-served pipes per call, collecting serve errors.
type servePipe struct {
	t     *testing.T
	donor *Engine
	peer  NodeID
	mu    sync.Mutex
	wg    sync.WaitGroup
	errs  []error
}

func (s *servePipe) open() (io.Writer, io.Reader, error) {
	return s.openWith(false)
}

// openDrain serves one stream, then discards one trailing frame. It
// models QUIC buffering for the adopt ack, which no server verb
// reads (fire-and-forget tail): a synchronous pipe would rendezvous
// forever without the drain.
func (s *servePipe) openDrain() (io.Writer, io.Reader, error) {
	return s.openWith(true)
}

func (s *servePipe) openWith(drain bool) (io.Writer, io.Reader, error) {
	c1, c2 := net.Pipe()
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		if err := s.donor.ServeStream(s.peer, c1, c1); err != nil {
			s.mu.Lock()
			s.errs = append(s.errs, err)
			s.mu.Unlock()
		}
		if drain {
			_, _ = ReadFrame(c1)
		}
	}()
	return c2, c2, nil
}

func (s *servePipe) check() {
	s.t.Helper()
	s.wg.Wait()
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, err := range s.errs {
		s.t.Errorf("serve: %v", err)
	}
}

// drainMismatch removes the single expected schema-mismatch serve
// error produced by the adopt-retry flow.
func (s *servePipe) drainMismatch() {
	s.t.Helper()
	s.wg.Wait()
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.errs) != 1 || !strings.Contains(s.errs[0].Error(), "schema mismatch") {
		s.t.Fatalf("serve errs = %v", s.errs)
	}
	s.errs = nil
}

func TestAdoptLoopback(t *testing.T) {
	group := mustNode(t, strings.Repeat("aa", 16))
	donor, donorDB := openEngine(t, group, strings.Repeat("11", 16))
	makeSyncTable(t, donorDB, "t")
	if err := donorDB.Exec("CREATE TABLE u(a INTEGER PRIMARY KEY NOT NULL, b TEXT);"); err != nil {
		t.Fatal(err)
	}
	if err := MakeCRR(donorDB, "u"); err != nil {
		t.Fatal(err)
	}
	if err := donorDB.Exec("INSERT INTO t VALUES(1,'x'); INSERT INTO u VALUES(1,'z');"); err != nil {
		t.Fatal(err)
	}
	receiver, receiverDB := openEngine(t, group, strings.Repeat("22", 16))
	makeSyncTable(t, receiverDB, "t")
	pipes := &servePipe{t: t, donor: donor, peer: receiver.node}
	// Pull 1: mismatch (served as Error) then adopt over a draining
	// stream, then reset.
	w, r, err := pipes.open()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := receiver.PullOnce(donor.node, w, r); !isSchemaMismatch(err) {
		t.Fatalf("pull 1 err = %v", err)
	}
	w, r, err = pipes.openDrain()
	if err != nil {
		t.Fatal(err)
	}
	if err := receiver.AdoptFromPeer(donor.node, func() (io.Writer, io.Reader, error) { return w, r, nil }); err != nil {
		t.Fatal(err)
	}
	// Pulls 2-3: reset then batch.
	more := true
	for i := 0; i < 3 && more; i++ {
		w, r, err := pipes.open()
		if err != nil {
			t.Fatal(err)
		}
		more, err = receiver.PullOnce(donor.node, w, r)
		if err != nil {
			t.Fatal(err)
		}
	}
	if more {
		t.Fatal("no convergence")
	}
	pipes.drainMismatch()
	pipes.check()
	yes, err := IsCRR(receiverDB, "u")
	if err != nil || !yes {
		t.Fatalf("u adopted CRR = %v,%v", yes, err)
	}
	st, err := receiverDB.Prepare("SELECT b FROM u WHERE a=1")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if done, err := st.Step(); err != nil || done {
		t.Fatalf("adopted row missing: %v %v", done, err)
	}
	if st.ColumnText(0) != "z" {
		t.Fatalf("b = %q", st.ColumnText(0))
	}
	st.Close()
	receiver.mu.Lock()
	adoptions := receiver.schemaAdoptions
	receiver.mu.Unlock()
	if adoptions != 1 {
		t.Fatalf("adoptions = %d", adoptions)
	}
}

func TestVetFetchLoopback(t *testing.T) {
	group := mustNode(t, strings.Repeat("aa", 16))
	donor, donorDB := openEngine(t, group, strings.Repeat("11", 16))
	makeSyncTable(t, donorDB, "t")
	puller, pullerDB := openEngine(t, group, strings.Repeat("22", 16))
	makeSyncTable(t, pullerDB, "t")
	if err := pullerDB.Exec("CREATE TABLE legacy(a INTEGER PRIMARY KEY NOT NULL);"); err != nil {
		t.Fatal(err)
	}
	if err := MakeCRR(pullerDB, "legacy"); err != nil {
		t.Fatal(err)
	}
	pipes := &servePipe{t: t, donor: puller, peer: donor.node}
	verdict, ok := donor.VetFetch(puller.node, pipes.open)
	if !ok || !verdict {
		t.Fatalf("legacy vet = %v,%v", verdict, ok)
	}
	pipes.check()
	// Puller missing a donor table fails the vet.
	bare, bareDB := openEngine(t, group, strings.Repeat("33", 16))
	if err := bareDB.Exec("CREATE TABLE other(a INTEGER PRIMARY KEY NOT NULL);"); err != nil {
		t.Fatal(err)
	}
	if err := MakeCRR(bareDB, "other"); err != nil {
		t.Fatal(err)
	}
	pipes2 := &servePipe{t: t, donor: bare, peer: donor.node}
	verdict, ok = donor.VetFetch(bare.node, pipes2.open)
	if !ok || verdict {
		t.Fatalf("missing vet = %v,%v", verdict, ok)
	}
	pipes2.check()
}

func TestPushSchemaLoopback(t *testing.T) {
	group := mustNode(t, strings.Repeat("aa", 16))
	master, masterDB := openEngine(t, group, strings.Repeat("11", 16))
	makeSyncTable(t, masterDB, "t")
	if err := SetSetting(masterDB, "schema_master_enabled", "1"); err != nil {
		t.Fatal(err)
	}
	if err := SetSetting(masterDB, "schema_master", master.node.String()); err != nil {
		t.Fatal(err)
	}
	peer, peerDB := openEngine(t, group, strings.Repeat("22", 16))
	makeSyncTable(t, peerDB, "t")
	pipes := &servePipe{t: t, donor: peer, peer: master.node}
	master.PushSchema(peer.node, pipes.open)
	pipes.check()
	master.mu.Lock()
	sent := master.sent
	_, recorded := master.schemaSent[peer.node]
	master.mu.Unlock()
	if sent != 1 || !recorded {
		t.Fatalf("sent=%d recorded=%v", sent, recorded)
	}
	// Second push is skipped (no new stream).
	master.PushSchema(peer.node, func() (io.Writer, io.Reader, error) {
		t.Fatal("redundant push opened a stream")
		return nil, nil, nil
	})
	be := NewBackend(peerDB, group, peer.node)
	keys, err := be.Keys(tx.SchemaAcceptedKey(master.node))
	if err != nil || len(keys) != 1 {
		t.Fatalf("accepted keys = %d,%v", len(keys), err)
	}
}
