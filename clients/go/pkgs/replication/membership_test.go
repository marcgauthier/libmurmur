package replication

import (
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"
)

type stubSession struct {
	id     NodeID
	sent   [][]byte
	closed bool
}

func (s *stubSession) PeerID() NodeID              { return s.id }
func (s *stubSession) OpenStream() (Stream, error) { return nil, errClosed("stub") }
func (s *stubSession) AcceptStream() (Stream, error) {
	return nil, errClosed("stub")
}
func (s *stubSession) SendDatagram(b []byte) error {
	s.sent = append(s.sent, append([]byte(nil), b...))
	return nil
}
func (s *stubSession) RecvDatagram() ([]byte, error) { return nil, errClosed("stub") }
func (s *stubSession) Close() error                  { s.closed = true; return nil }

func testMember(node byte, incarnation uint64, state State) Member {
	var id NodeID
	for i := range id {
		id[i] = node
	}
	return Member{Node: id, Addr: netip.MustParseAddrPort("127.0.0.1:7443"), Incarnation: incarnation, State: state}
}

func TestViewMergeRules(t *testing.T) {
	v := NewView(testMember(1, 1, StateAlive))
	v.Merge(testMember(2, 3, StateDead))
	v.Merge(testMember(2, 2, StateAlive))
	var n2 NodeID
	for i := range n2 {
		n2[i] = 2
	}
	if v.Members[n2].State != StateDead {
		t.Fatal("stale gossip revived")
	}
	v.Merge(testMember(2, 4, StateAlive))
	if v.Members[n2].State != StateAlive {
		t.Fatal("newer incarnation ignored")
	}
	var n3 NodeID
	for i := range n3 {
		n3[i] = 3
	}
	v.Excluded[n3] = true
	v.Merge(testMember(3, 9, StateAlive))
	if _, ok := v.Members[n3]; ok {
		t.Fatal("excluded node merged")
	}
	v.Merge(testMember(1, 10, StateSuspect))
	if v.Local.Incarnation != 11 {
		t.Fatalf("local incarnation = %d", v.Local.Incarnation)
	}
	if v.Local.State != StateAlive {
		t.Fatal("local state changed")
	}
	// Same-incarnation rank ties never regress.
	v.Merge(testMember(2, 4, StateAlive))
	v.Merge(testMember(2, 4, StateAlive))
	if v.Members[n2].State != StateAlive {
		t.Fatal("tie regressed")
	}
	// Higher rank at same incarnation wins.
	v.Merge(testMember(2, 4, StateSuspect))
	if v.Members[n2].State != StateSuspect {
		t.Fatal("rank tie-break ignored")
	}
}

func TestViewAckNonce(t *testing.T) {
	v := NewView(testMember(1, 1, StateAlive))
	var n2 NodeID
	for i := range n2 {
		n2[i] = 2
	}
	v.Pending[n2] = pendingProbe{at: time.Now(), nonce: 4}
	v.Acknowledged(n2, 3)
	if len(v.Pending) != 1 {
		t.Fatal("wrong nonce cleared")
	}
	v.Acknowledged(n2, 4)
	if len(v.Pending) != 0 {
		t.Fatal("ack not cleared")
	}
}

func TestViewExpireLifecycle(t *testing.T) {
	v := NewView(Member{Node: testMember(1, 1, StateAlive).Node, Addr: netip.MustParseAddrPort("127.0.0.1:1"), Incarnation: 1, State: StateAlive})
	v.Merge(Member{Node: testMember(2, 1, StateAlive).Node, Addr: netip.MustParseAddrPort("127.0.0.1:2"), Incarnation: 1, State: StateAlive})
	var n2 NodeID
	for i := range n2 {
		n2[i] = 2
	}
	past := time.Now().Add(-10 * time.Second)
	v.Pending[n2] = pendingProbe{at: past, nonce: 7}
	reqs := v.Expire()
	if len(reqs) != 1 || reqs[0].target != n2 || reqs[0].nonce != 7 {
		t.Fatalf("indirect reqs = %+v", reqs)
	}
	if v.Members[n2].State != StateAlive {
		t.Fatal("premature suspicion")
	}
	p := v.Pending[n2]
	p.at = past
	v.Pending[n2] = p
	v.Expire()
	if v.Members[n2].State != StateSuspect {
		t.Fatal("no suspicion after indirect timeout")
	}
	v.Suspect[n2] = time.Now().Add(-30 * time.Second)
	v.Expire()
	if v.Members[n2].State != StateDead {
		t.Fatal("no death after suspect expiry")
	}
	if _, ok := v.Suspect[n2]; ok {
		t.Fatal("suspect entry not reaped")
	}
}

func TestBelowWithBoundaries(t *testing.T) {
	words := func(v ...uint64) func() (uint64, error) {
		i := 0
		return func() (uint64, error) {
			if i >= len(v) {
				return 0, errClosed("empty")
			}
			w := v[i]
			i++
			return w, nil
		}
	}
	// 0 is rejected for bound 3 (threshold 2^64 mod 3 = 1... word 0
	// < 1 is rejected), then 4 % 3 = 1.
	n, err := belowWith(words(0, 4), 3)
	if err != nil || n != 1 {
		t.Fatalf("below = %d,%v", n, err)
	}
	if n, _ := belowWith(words(), 1); n != 0 {
		t.Fatal("bound 1 must yield 0 without drawing")
	}
	if n, _ := belowWith(words(^uint64(0)), 2); n != 1 {
		t.Fatal("max word mod 2")
	}
	if _, err := belowWith(words(), 2); err == nil {
		t.Fatal("empty source accepted")
	}
	s, err := sampleWith(words(3, 3), []int{0, 1, 2, 3}, 2)
	if err != nil || len(s) != 2 || s[0] != 2 || s[1] != 1 {
		t.Fatalf("sample = %+v,%v", s, err)
	}
	s, err = sampleWith(words(0), []int{0, 1}, 1)
	if err != nil || len(s) != 1 || s[0] != 1 {
		t.Fatalf("choose = %+v,%v", s, err)
	}
	if _, err := sampleWith(words(), []int{0, 1}, 1); err == nil {
		t.Fatal("sample without entropy accepted")
	}
	if _, ok := randChoose([]int{}); ok {
		t.Fatal("choose from empty")
	}
}

func TestPacketRoundTrip(t *testing.T) {
	g := mustNode(t, strings.Repeat("aa", 16))
	n1 := mustNode(t, strings.Repeat("11", 16))
	n2 := mustNode(t, strings.Repeat("22", 16))
	members := []Member{testMember(3, 5, StateSuspect)}
	packets := []Packet{
		PktGossip{Database: g, Sender: n1, Members: members},
		PktIndirectAck{Database: g, Sender: n1, Target: n2, Nonce: 9},
		PktPing{Database: g, Sender: n1, Nonce: 7, Members: members},
		PktAck{Database: g, Sender: n1, Nonce: 8, Members: nil},
		PktPingRequest{Database: g, Sender: n1, Target: n2, Nonce: 10},
	}
	for i, p := range packets {
		raw := EncodePacket(p)
		if len(raw) > maxDatagramBytes {
			t.Fatalf("packet %d too large: %d", i, len(raw))
		}
		back, err := DecodePacket(raw)
		if err != nil {
			t.Fatalf("packet %d: %v", i, err)
		}
		if string(EncodePacket(back)) != string(raw) {
			t.Fatalf("packet %d unstable", i)
		}
	}
	if _, err := DecodePacket(append(EncodePacket(packets[0]), 0)); err == nil {
		t.Fatal("trailing byte accepted")
	}
	if _, err := DecodePacket([]byte{9}); err == nil {
		t.Fatal("unknown tag accepted")
	}
	if _, err := DecodePacket(EncodePacket(packets[2])[:5]); err == nil {
		t.Fatal("truncated accepted")
	}
}

func TestGoldenPackets(t *testing.T) {
	g := mustNode(t, strings.Repeat("aa", 16))
	n1 := mustNode(t, strings.Repeat("11", 16))
	n2 := mustNode(t, strings.Repeat("22", 16))
	var n3, n4 NodeID
	for i := range n3 {
		n3[i] = 0x33
		n4[i] = 0x44
	}
	m := Member{Node: n3, Addr: netip.MustParseAddrPort("127.0.0.1:7443"), Incarnation: 5, State: StateSuspect}
	v6m := Member{Node: n4, Addr: netip.MustParseAddrPort("[::1]:7443"), Incarnation: 300, State: StateAlive}
	cases := []struct {
		name string
		pkt  Packet
	}{
		{"vec_pkt_gossip.bin", PktGossip{Database: g, Sender: n1, Members: []Member{m, v6m}}},
		{"vec_pkt_indirectack.bin", PktIndirectAck{Database: g, Sender: n1, Target: n2, Nonce: 9}},
		{"vec_pkt_ping.bin", PktPing{Database: g, Sender: n1, Nonce: 7, Members: []Member{m}}},
		{"vec_pkt_ack.bin", PktAck{Database: g, Sender: n1, Nonce: 8}},
		{"vec_pkt_pingreq.bin", PktPingRequest{Database: g, Sender: n1, Target: n2, Nonce: 10}},
	}
	for _, c := range cases {
		raw, err := os.ReadFile("testdata/" + c.name)
		if err != nil {
			t.Fatal(err)
		}
		if string(EncodePacket(c.pkt)) != string(raw) {
			t.Fatalf("%s: encode mismatch:\n got %x\nwant %x", c.name, EncodePacket(c.pkt), raw)
		}
		back, err := DecodePacket(raw)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if string(EncodePacket(back)) != string(raw) {
			t.Fatalf("%s: decode unstable", c.name)
		}
	}
}

func TestGoldenSchemaPairs(t *testing.T) {
	raw, err := os.ReadFile("testdata/vec_schema_pairs.bin")
	if err != nil {
		t.Fatal(err)
	}
	pairs := []SchemaPair{{Table: "a", DDL: "b"}, {Table: "Sticky Notes!", DDL: "CREATE TABLE t(x)"}}
	if string(EncodeSchemaPairs(pairs)) != string(raw) {
		t.Fatalf("encode mismatch:\n got %x\nwant %x", EncodeSchemaPairs(pairs), raw)
	}
	back, err := DecodeSchemaPairs(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(back) != 2 || back[0] != pairs[0] || back[1] != pairs[1] {
		t.Fatalf("decode = %+v", back)
	}
}

func TestHandleGossip(t *testing.T) {
	group := mustNode(t, strings.Repeat("aa", 16))
	e, _ := openEngine(t, group, strings.Repeat("11", 16))
	peer := mustNode(t, strings.Repeat("22", 16))
	m := testMember(3, 2, StateAlive)
	if err := e.handlePacket(peer, EncodePacket(PktGossip{Database: group, Sender: peer, Members: []Member{m}})); err != nil {
		t.Fatal(err)
	}
	if _, ok := e.view.Members[m.Node]; !ok {
		t.Fatal("member not merged")
	}
	other := mustNode(t, strings.Repeat("bb", 16))
	err := e.handlePacket(peer, EncodePacket(PktGossip{Database: other, Sender: peer}))
	if errKind(err) != "Auth" {
		t.Fatalf("wrong db err = %v", err)
	}
	err = e.handlePacket(peer, EncodePacket(PktGossip{Database: group, Sender: other}))
	if errKind(err) != "Auth" {
		t.Fatalf("wrong sender err = %v", err)
	}
	big := []Member{m, m, m, m, m}
	err = e.handlePacket(peer, EncodePacket(PktGossip{Database: group, Sender: peer, Members: big}))
	if errKind(err) != "Auth" {
		t.Fatalf("oversize members err = %v", err)
	}
	if err := e.handlePacket(peer, make([]byte, maxDatagramBytes+1)); errKind(err) != "Protocol" {
		t.Fatalf("oversize datagram err = %v", err)
	}
}

func TestHandlePingAck(t *testing.T) {
	group := mustNode(t, strings.Repeat("aa", 16))
	e, _ := openEngine(t, group, strings.Repeat("11", 16))
	peer := mustNode(t, strings.Repeat("22", 16))
	sess := &stubSession{id: peer}
	e.conns[peer] = sess
	e.view.Pending[peer] = pendingProbe{at: time.Now(), nonce: 7}
	m := testMember(3, 2, StateAlive)
	err := e.handlePacket(peer, EncodePacket(PktPing{Database: group, Sender: peer, Nonce: 7, Members: []Member{m}}))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := e.view.Members[m.Node]; !ok {
		t.Fatal("ping members not merged")
	}
	if len(e.view.Pending) != 0 {
		t.Fatal("pending not acked")
	}
	if len(sess.sent) != 1 {
		t.Fatalf("replies = %d", len(sess.sent))
	}
	back, err := DecodePacket(sess.sent[0])
	if err != nil {
		t.Fatal(err)
	}
	ack, ok := back.(PktAck)
	if !ok || ack.Nonce != 7 || ack.Sender != e.node {
		t.Fatalf("reply = %T %+v", back, back)
	}
	// Zero-nonce pings merge without replying.
	sess.sent = nil
	err = e.handlePacket(peer, EncodePacket(PktPing{Database: group, Sender: peer, Members: []Member{m}}))
	if err != nil {
		t.Fatal(err)
	}
	if len(sess.sent) != 0 {
		t.Fatal("zero-nonce ping got a reply")
	}
}

func TestHandlePingRequestRelay(t *testing.T) {
	group := mustNode(t, strings.Repeat("aa", 16))
	e, _ := openEngine(t, group, strings.Repeat("11", 16))
	peer := mustNode(t, strings.Repeat("22", 16))
	target := mustNode(t, strings.Repeat("33", 16))
	peerSess := &stubSession{id: peer}
	targetSess := &stubSession{id: target}
	e.conns[peer] = peerSess
	e.conns[target] = targetSess
	err := e.handlePacket(peer, EncodePacket(PktPingRequest{Database: group, Sender: peer, Target: target, Nonce: 5}))
	if err != nil {
		t.Fatal(err)
	}
	if len(targetSess.sent) != 1 {
		t.Fatalf("forwards = %d", len(targetSess.sent))
	}
	fwd, err := DecodePacket(targetSess.sent[0])
	if err != nil {
		t.Fatal(err)
	}
	ping, ok := fwd.(PktPing)
	if !ok || ping.Nonce != 5 || ping.Sender != e.node {
		t.Fatalf("forward = %T %+v", fwd, fwd)
	}
	// The relayed ack routes back to the requester as IndirectAck.
	err = e.handlePacket(target, EncodePacket(PktAck{Database: group, Sender: target, Nonce: 5}))
	if err != nil {
		t.Fatal(err)
	}
	if len(peerSess.sent) != 1 {
		t.Fatalf("indirect acks = %d", len(peerSess.sent))
	}
	ia, err := DecodePacket(peerSess.sent[0])
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := ia.(PktIndirectAck); !ok {
		t.Fatalf("relay reply = %T", ia)
	}
}

func TestHandleIncarnationRefute(t *testing.T) {
	group := mustNode(t, strings.Repeat("aa", 16))
	e, db := openEngine(t, group, strings.Repeat("11", 16))
	peer := mustNode(t, strings.Repeat("22", 16))
	self := Member{Node: e.node, Addr: e.advertise, Incarnation: e.incarnation, State: StateSuspect}
	if err := e.handlePacket(peer, EncodePacket(PktGossip{Database: group, Sender: peer, Members: []Member{self}})); err != nil {
		t.Fatal(err)
	}
	if e.view.Local.Incarnation != 8 {
		t.Fatalf("incarnation = %d", e.view.Local.Incarnation)
	}
	st, err := db.Prepare("SELECT incarnation FROM murmur_identity WHERE id=1")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if done, err := st.Step(); err != nil || done {
		t.Fatalf("identity row: %v %v", done, err)
	}
	if st.ColumnInt64(0) != 8 {
		t.Fatalf("persisted = %d", st.ColumnInt64(0))
	}
}

func TestProbePingsConnected(t *testing.T) {
	group := mustNode(t, strings.Repeat("aa", 16))
	e, _ := openEngine(t, group, strings.Repeat("11", 16))
	peer := mustNode(t, strings.Repeat("22", 16))
	sess := &stubSession{id: peer}
	e.conns[peer] = sess
	e.probe()
	if len(sess.sent) != 1 {
		t.Fatalf("pings = %d", len(sess.sent))
	}
	back, err := DecodePacket(sess.sent[0])
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := back.(PktPing); !ok {
		t.Fatalf("probe = %T", back)
	}
	if _, ok := e.view.Pending[peer]; !ok {
		t.Fatal("no pending probe")
	}
}

func TestAddRemoveNode(t *testing.T) {
	group := mustNode(t, strings.Repeat("aa", 16))
	e, _ := openEngine(t, group, strings.Repeat("11", 16))
	if err := e.AddSeed("not-an-address"); errKind(err) != "Invalid" {
		t.Fatalf("bad addr err = %v", err)
	}
	if err := e.AddSeed("127.0.0.1:7443"); err != nil {
		t.Fatal(err)
	}
	if !e.seeds["127.0.0.1:7443"] {
		t.Fatal("seed not stored")
	}
	select {
	case <-e.syncCh:
	default:
		t.Fatal("no sync notify")
	}
	peer := mustNode(t, strings.Repeat("22", 16))
	sess := &stubSession{id: peer}
	e.conns[peer] = sess
	m := testMember(0x22, 1, StateAlive)
	m.Node = peer
	m.Addr = netip.MustParseAddrPort("127.0.0.1:7443")
	e.view.Members[peer] = m
	e.RemoveNode(peer)
	if !sess.closed {
		t.Fatal("session not closed")
	}
	if _, ok := e.conns[peer]; ok {
		t.Fatal("conn not dropped")
	}
	if !e.view.Excluded[peer] || e.view.Members[peer].State != StateLeft {
		t.Fatal("view not marked left")
	}
	if e.seeds["127.0.0.1:7443"] {
		t.Fatal("seed not forgotten")
	}
}

func TestFetchSources(t *testing.T) {
	group := mustNode(t, strings.Repeat("aa", 16))
	e, _ := openEngine(t, group, strings.Repeat("11", 16))
	alive := testMember(2, 1, StateAlive)
	suspect := testMember(3, 1, StateSuspect)
	dead := testMember(4, 1, StateDead)
	e.view.Merge(alive)
	e.view.Merge(suspect)
	e.view.Merge(dead)
	srcs := e.FetchSources(7555)
	if len(srcs) != 2 {
		t.Fatalf("sources = %d", len(srcs))
	}
	for _, s := range srcs {
		if s.Addr.Port() != 7555 || s.Addr.Addr() != netip.MustParseAddr("127.0.0.1") {
			t.Fatalf("source = %+v", s)
		}
	}
}
