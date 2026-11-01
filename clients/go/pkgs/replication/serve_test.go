package replication

import (
	"bytes"
	"net"
	"strings"
	"testing"

	"github.com/marcgauthier/libmurmur/clients/go/bindings/sqlite"
)

type stubTransport struct{}

func (stubTransport) LocalAddr() string            { return "" }
func (stubTransport) Dial(string) (Session, error) { return nil, errClosed("stub") }
func (stubTransport) Accept() (Session, error)     { return nil, errClosed("stub") }
func (stubTransport) Close() error                 { return nil }

// openEngine builds a running-shaped engine without a transport:
// identity fields are wired directly for loopback tests.
func openEngine(t *testing.T, group NodeID, nodeHex string) (*Engine, *sqlite.Conn) {
	t.Helper()
	db := openCRR(t)
	site, err := SiteID(db)
	if err != nil {
		t.Fatal(err)
	}
	e := New(db, nil)
	e.group = group
	e.node = mustNode(t, nodeHex)
	e.site = site
	e.incarnation = 7
	params, err := loadServeParams(db)
	if err != nil {
		t.Fatal(err)
	}
	e.serveSem = make(chan struct{}, params.sessions)
	e.serving = newByteSem(params.queueBytes)
	e.receiving = newByteSem(params.queueBytes)
	e.gossipFanout = params.gossipFanout
	e.view = NewView(Member{Node: e.node, Addr: e.advertise, Incarnation: e.incarnation, State: StateAlive})
	e.persistedIncarnation = e.incarnation
	e.running = true
	return e, db
}

func TestServeLoopbackPull(t *testing.T) {
	group := mustNode(t, strings.Repeat("aa", 16))
	donor, donorDB := openEngine(t, group, strings.Repeat("11", 16))
	makeSyncTable(t, donorDB, "t")
	if err := donorDB.Exec("INSERT INTO t VALUES(1,'x'),(2,'y');"); err != nil {
		t.Fatal(err)
	}
	receiver, receiverDB := openEngine(t, group, strings.Repeat("22", 16))
	makeSyncTable(t, receiverDB, "t")

	// Handshake both directions over a synchronous pipe.
	h1, h2 := net.Pipe()
	defer h1.Close()
	defer h2.Close()
	donorHS := make(chan error, 1)
	go func() {
		inc, _, err := donor.Handshake(h1, h1, false, receiver.node)
		if err == nil && inc != 7 {
			t.Errorf("donor saw incarnation %d", inc)
		}
		donorHS <- err
	}()
	inc, _, err := receiver.Handshake(h2, h2, true, donor.node)
	if err != nil {
		t.Fatal(err)
	}
	if inc != 7 {
		t.Fatalf("receiver saw incarnation %d", inc)
	}
	if err := <-donorHS; err != nil {
		t.Fatal(err)
	}

	// First pull: reset handshake (receiver has no progress row).
	p1, p2 := net.Pipe()
	defer p1.Close()
	defer p2.Close()
	serveErr := make(chan error, 1)
	go func() { serveErr <- donor.ServeStream(receiver.node, p1, p1) }()
	more, err := receiver.PullOnce(donor.node, p2, p2)
	if err != nil {
		t.Fatal(err)
	}
	if !more {
		t.Fatal("reset pull should report more")
	}
	if err := <-serveErr; err != nil {
		t.Fatal(err)
	}
	storedSite, stored, err := Progress(receiverDB, donor.node)
	if err != nil || storedSite == nil || *storedSite != donor.site {
		t.Fatalf("progress = %v,%+v,%v", storedSite, stored, err)
	}

	// Second pull: the batch flows and applies.
	q1, q2 := net.Pipe()
	defer q1.Close()
	defer q2.Close()
	go func() { serveErr <- donor.ServeStream(receiver.node, q1, q1) }()
	more, err = receiver.PullOnce(donor.node, q2, q2)
	if err != nil {
		t.Fatal(err)
	}
	if more {
		t.Fatal("done batch should report no more")
	}
	if err := <-serveErr; err != nil {
		t.Fatal(err)
	}
	st, err := receiverDB.Prepare("SELECT b FROM t WHERE a=2")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if done, err := st.Step(); err != nil || done {
		t.Fatalf("row missing: %v %v", done, err)
	}
	if st.ColumnText(0) != "y" {
		t.Fatalf("b = %q", st.ColumnText(0))
	}
	st.Close()
	receiver.mu.Lock()
	applied := receiver.applied
	receiver.mu.Unlock()
	donor.mu.Lock()
	sent := donor.sent
	donor.mu.Unlock()
	if applied != 1 || sent != 1 {
		t.Fatalf("applied=%d sent=%d, want 1/1", applied, sent)
	}

	// Third pull: idle, counters frozen.
	r1, r2 := net.Pipe()
	defer r1.Close()
	defer r2.Close()
	go func() { serveErr <- donor.ServeStream(receiver.node, r1, r1) }()
	more, err = receiver.PullOnce(donor.node, r2, r2)
	if err != nil {
		t.Fatal(err)
	}
	if more {
		t.Fatal("idle pull should report no more")
	}
	if err := <-serveErr; err != nil {
		t.Fatal(err)
	}
	receiver.mu.Lock()
	appliedAfter := receiver.applied
	receiver.mu.Unlock()
	if appliedAfter != 1 {
		t.Fatalf("applied=%d after idle", appliedAfter)
	}
}

func TestServeAuth(t *testing.T) {
	group := mustNode(t, strings.Repeat("aa", 16))
	donor, donorDB := openEngine(t, group, strings.Repeat("11", 16))
	makeSyncTable(t, donorDB, "t")
	peer := mustNode(t, strings.Repeat("22", 16))
	schema, err := Schema(donorDB)
	if err != nil {
		t.Fatal(err)
	}
	other := mustNode(t, strings.Repeat("bb", 16))
	cases := []struct {
		name string
		req  MsgPull
		kind string
	}{
		{"group", MsgPull{Group: other, Node: peer, Site: peer, Schema: schema}, "Auth"},
		{"node", MsgPull{Group: group, Node: other, Site: peer, Schema: schema}, "Auth"},
		{"cloned site", MsgPull{Group: group, Node: peer, Site: donor.site, Schema: schema}, "Auth"},
	}
	for _, c := range cases {
		var buf bytes.Buffer
		err := donor.ServePull(peer, &buf, bytes.NewReader(nil), c.req)
		if errKind(err) != c.kind {
			t.Fatalf("%s: err = %v", c.name, err)
		}
	}
	// Unknown expected site reaches the Reset reply, not an error.
	var buf bytes.Buffer
	req := MsgPull{Group: group, Node: peer, Site: peer, Schema: schema, ExpectedSite: &other}
	if err := donor.ServePull(peer, &buf, bytes.NewReader(nil), req); err != nil {
		t.Fatal(err)
	}
	reply, err := DecodeMessage(mustUnframe(t, &buf))
	if err != nil {
		t.Fatal(err)
	}
	reset, ok := reply.(MsgReset)
	if !ok || reset.Site != donor.site {
		t.Fatalf("reply = %T %+v", reply, reply)
	}
}

func mustUnframe(t *testing.T, buf *bytes.Buffer) []byte {
	t.Helper()
	msg, err := ReadFrame(buf)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := EncodeMessage(msg)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestStartClaimsIdentity(t *testing.T) {
	db := openCRR(t)
	e := New(db, stubTransport{})
	if err := e.Start(); err == nil {
		t.Fatal("start without group accepted")
	}
	if err := SetSetting(db, "group_id", strings.Repeat("aa", 16)); err != nil {
		t.Fatal(err)
	}
	if err := e.Start(); err != nil {
		t.Fatal(err)
	}
	node1, site1, inc1 := e.node, e.site, e.incarnation
	if node1.IsZero() || site1.IsZero() || inc1 == 0 {
		t.Fatalf("identity = %v %v %d", node1, site1, inc1)
	}
	if e.serveSem == nil || e.serving == nil || e.receiving == nil {
		t.Fatal("serve state not initialised")
	}
	if err := e.Stop(); err != nil {
		t.Fatal(err)
	}
	e2 := New(db, stubTransport{})
	if err := e2.Start(); err != nil {
		t.Fatal(err)
	}
	if e2.node != node1 || e2.site != site1 || e2.incarnation != inc1+1 {
		t.Fatalf("restart identity changed: %+v", e2)
	}
	if err := e2.Stop(); err != nil {
		t.Fatal(err)
	}
	// A pinned site that no longer matches the CRR site refuses boot.
	if err := execArgs(db, "UPDATE murmur_identity SET site=?1 WHERE id=1", bytes.Repeat([]byte{9}, 16)); err != nil {
		t.Fatal(err)
	}
	e3 := New(db, stubTransport{})
	if err := e3.Start(); errKind(err) != "Auth" {
		t.Fatalf("cloned site err = %v", err)
	}
}
