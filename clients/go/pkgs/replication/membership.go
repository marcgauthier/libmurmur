// Membership: bounded SWIM state, gossip datagrams, and probing.
//
// Go port of membership.rs plus the Engine packet/gossip/probe path
// (engine.rs). Relayed identities are discovery hints, never
// credentials: every datagram envelope is authenticated against the
// transport session peer. Random selection mirrors
// crates/common/random.rs (reservoir sampling over rejection-sampled
// words) with crypto/rand as the word source.
package replication

import (
	"crypto/rand"
	"encoding/binary"
	"net/netip"
	"time"
)

// ---------------------------------------------------------------------------
// Random selection
// ---------------------------------------------------------------------------

// randWord draws one crypto-random word.
func randWord() (uint64, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint64(b[:]), nil
}

// belowWith draws uniformly from [0, upper) via rejection sampling.
func belowWith(word func() (uint64, error), upper int) (int, error) {
	if upper <= 0 {
		return 0, errInvalid("random upper bound must be nonzero")
	}
	if upper == 1 {
		return 0, nil
	}
	bound := uint64(upper)
	// Reject the short remainder of the 2^64 domain before reducing
	// modulo bound; each remaining result has the same number of
	// representatives.
	threshold := (0 - bound) % bound
	for {
		w, err := word()
		if err != nil {
			return 0, err
		}
		if w >= threshold {
			return int(w % bound), nil
		}
	}
}

// randBelow draws uniformly from [0, upper).
func randBelow(upper int) int {
	n, err := belowWith(randWord, upper)
	if err != nil {
		panic("crypto randomness failed: " + err.Error())
	}
	return n
}

// sampleWith reservoir-samples up to amount items.
func sampleWith[T any](word func() (uint64, error), values []T, amount int) ([]T, error) {
	var out []T
	if amount <= 0 {
		return out, nil
	}
	for i, v := range values {
		if len(out) < amount {
			out = append(out, v)
			continue
		}
		slot, err := belowWith(word, i+1)
		if err != nil {
			return nil, err
		}
		if slot < amount {
			out[slot] = v
		}
	}
	return out, nil
}

// randSample reservoir-samples up to amount items.
func randSample[T any](values []T, amount int) []T {
	out, err := sampleWith(randWord, values, amount)
	if err != nil {
		panic("crypto randomness failed: " + err.Error())
	}
	return out
}

// randChoose picks one item uniformly, or false when empty.
func randChoose[T any](values []T) (T, bool) {
	var zero T
	if len(values) == 0 {
		return zero, false
	}
	return values[randBelow(len(values))], true
}

// ---------------------------------------------------------------------------
// Packets
// ---------------------------------------------------------------------------

// State is the SWIM member state.
type State int

const (
	StateAlive State = iota
	StateSuspect
	StateDead
	StateLeft
)

func (s State) rank() int { return int(s) }

func (s State) String() string {
	switch s {
	case StateAlive:
		return "alive"
	case StateSuspect:
		return "suspect"
	case StateDead:
		return "dead"
	case StateLeft:
		return "left"
	default:
		return "unknown"
	}
}

// Member is one gossiped group member.
type Member struct {
	Node        NodeID
	Addr        netip.AddrPort
	Incarnation uint64
	State       State
}

// Packet is one membership datagram body. Tags match the Rust
// declaration order (postcard discriminant).
type Packet interface{ packetTag() }

type (
	PktGossip struct {
		Database NodeID
		Sender   NodeID
		Members  []Member
	}
	PktIndirectAck struct {
		Database NodeID
		Sender   NodeID
		Target   NodeID
		Nonce    uint64
	}
	PktPing struct {
		Database NodeID
		Sender   NodeID
		Nonce    uint64
		Members  []Member
	}
	PktAck struct {
		Database NodeID
		Sender   NodeID
		Nonce    uint64
		Members  []Member
	}
	PktPingRequest struct {
		Database NodeID
		Sender   NodeID
		Target   NodeID
		Nonce    uint64
	}
)

func (PktGossip) packetTag()      {}
func (PktIndirectAck) packetTag() {}
func (PktPing) packetTag()        {}
func (PktAck) packetTag()         {}
func (PktPingRequest) packetTag() {}

// maxDatagramBytes caps membership datagrams on the wire.
const maxDatagramBytes = 1000

// maxPacketMembers caps decoded member lists (decode guard; the
// datagram limit bounds real packets far below this).
const maxPacketMembers = 4096

func appendMember(out []byte, m Member) []byte {
	out = append(out, m.Node[:]...)
	out = appendAddr(out, m.Addr)
	out = appendVarint(out, m.Incarnation)
	return appendVarint(out, uint64(m.State))
}

func readMember(buf []byte) (Member, []byte, error) {
	var m Member
	raw, rest, err := readFixed(buf, 16)
	if err != nil {
		return m, nil, err
	}
	copy(m.Node[:], raw)
	if m.Addr, rest, err = readAddr(rest); err != nil {
		return m, nil, err
	}
	if m.Incarnation, rest, err = readVarint(rest); err != nil {
		return m, nil, err
	}
	var st uint64
	if st, rest, err = readVarint(rest); err != nil {
		return m, nil, err
	}
	if st > 3 {
		return m, nil, errProtocol("invalid member state")
	}
	m.State = State(st)
	return m, rest, nil
}

func appendMembers(out []byte, members []Member) []byte {
	out = appendVarint(out, uint64(len(members)))
	for _, m := range members {
		out = appendMember(out, m)
	}
	return out
}

func readMembers(buf []byte) ([]Member, []byte, error) {
	n, rest, err := readVarint(buf)
	if err != nil {
		return nil, nil, err
	}
	if n > maxPacketMembers {
		return nil, nil, errProtocol("member list too large")
	}
	out := make([]Member, 0, n)
	for i := uint64(0); i < n; i++ {
		var m Member
		if m, rest, err = readMember(rest); err != nil {
			return nil, nil, err
		}
		out = append(out, m)
	}
	return out, rest, nil
}

// EncodePacket serializes a datagram body (postcard layout).
func EncodePacket(p Packet) []byte {
	var out []byte
	switch v := p.(type) {
	case PktGossip:
		out = appendVarint(out, 0)
		out = append(out, v.Database[:]...)
		out = append(out, v.Sender[:]...)
		out = appendMembers(out, v.Members)
	case PktIndirectAck:
		out = appendVarint(out, 1)
		out = append(out, v.Database[:]...)
		out = append(out, v.Sender[:]...)
		out = append(out, v.Target[:]...)
		out = appendVarint(out, v.Nonce)
	case PktPing:
		out = appendVarint(out, 2)
		out = append(out, v.Database[:]...)
		out = append(out, v.Sender[:]...)
		out = appendVarint(out, v.Nonce)
		out = appendMembers(out, v.Members)
	case PktAck:
		out = appendVarint(out, 3)
		out = append(out, v.Database[:]...)
		out = append(out, v.Sender[:]...)
		out = appendVarint(out, v.Nonce)
		out = appendMembers(out, v.Members)
	case PktPingRequest:
		out = appendVarint(out, 4)
		out = append(out, v.Database[:]...)
		out = append(out, v.Sender[:]...)
		out = append(out, v.Target[:]...)
		out = appendVarint(out, v.Nonce)
	}
	return out
}

// DecodePacket parses a datagram body; trailing bytes fail closed.
func DecodePacket(b []byte) (Packet, error) {
	tag, rest, err := readVarint(b)
	if err != nil {
		return nil, err
	}
	readNode := func(buf []byte) (NodeID, []byte, error) {
		var id NodeID
		raw, rest, err := readFixed(buf, 16)
		if err != nil {
			return id, nil, err
		}
		copy(id[:], raw)
		return id, rest, nil
	}
	var p Packet
	switch tag {
	case 0:
		var v PktGossip
		if v.Database, rest, err = readNode(rest); err != nil {
			return nil, err
		}
		if v.Sender, rest, err = readNode(rest); err != nil {
			return nil, err
		}
		if v.Members, rest, err = readMembers(rest); err != nil {
			return nil, err
		}
		p = v
	case 1:
		var v PktIndirectAck
		if v.Database, rest, err = readNode(rest); err != nil {
			return nil, err
		}
		if v.Sender, rest, err = readNode(rest); err != nil {
			return nil, err
		}
		if v.Target, rest, err = readNode(rest); err != nil {
			return nil, err
		}
		if v.Nonce, rest, err = readVarint(rest); err != nil {
			return nil, err
		}
		p = v
	case 2:
		var v PktPing
		if v.Database, rest, err = readNode(rest); err != nil {
			return nil, err
		}
		if v.Sender, rest, err = readNode(rest); err != nil {
			return nil, err
		}
		if v.Nonce, rest, err = readVarint(rest); err != nil {
			return nil, err
		}
		if v.Members, rest, err = readMembers(rest); err != nil {
			return nil, err
		}
		p = v
	case 3:
		var v PktAck
		if v.Database, rest, err = readNode(rest); err != nil {
			return nil, err
		}
		if v.Sender, rest, err = readNode(rest); err != nil {
			return nil, err
		}
		if v.Nonce, rest, err = readVarint(rest); err != nil {
			return nil, err
		}
		if v.Members, rest, err = readMembers(rest); err != nil {
			return nil, err
		}
		p = v
	case 4:
		var v PktPingRequest
		if v.Database, rest, err = readNode(rest); err != nil {
			return nil, err
		}
		if v.Sender, rest, err = readNode(rest); err != nil {
			return nil, err
		}
		if v.Target, rest, err = readNode(rest); err != nil {
			return nil, err
		}
		if v.Nonce, rest, err = readVarint(rest); err != nil {
			return nil, err
		}
		p = v
	default:
		return nil, errProtocol("unknown packet tag")
	}
	if len(rest) != 0 {
		return nil, errProtocol("trailing packet bytes")
	}
	return p, nil
}

// ---------------------------------------------------------------------------
// View
// ---------------------------------------------------------------------------

// maxViewMembers caps the membership table.
const maxViewMembers = 4096

type pendingProbe struct {
	at       time.Time
	nonce    uint64
	indirect bool
}

// probeReq is one indirect-repair request from View.Expire.
type probeReq struct {
	target NodeID
	nonce  uint64
}

// View is the bounded SWIM state. The Engine guards it with its mutex.
type View struct {
	Members   map[NodeID]Member
	Local     Member
	Excluded  map[NodeID]bool
	Pending   map[NodeID]pendingProbe
	Suspect   map[NodeID]time.Time
	Awareness uint32
}

// NewView creates the membership state for the local member.
func NewView(local Member) *View {
	return &View{
		Members:  map[NodeID]Member{},
		Local:    local,
		Excluded: map[NodeID]bool{},
		Pending:  map[NodeID]pendingProbe{},
		Suspect:  map[NodeID]time.Time{},
	}
}

// Merge folds a gossiped member in. Newer incarnations win; ties go
// to the higher state rank. Stale gossip can never revive.
// Refutes about self bump the local incarnation.
func (v *View) Merge(m Member) {
	if m.Node == v.Local.Node {
		if m.Incarnation >= v.Local.Incarnation && m.State != StateAlive {
			v.Local.Incarnation = m.Incarnation + 1
		}
		return
	}
	if v.Excluded[m.Node] {
		return
	}
	if len(v.Members) >= maxViewMembers {
		if _, ok := v.Members[m.Node]; !ok {
			return
		}
	}
	old, ok := v.Members[m.Node]
	if !ok || m.Incarnation > old.Incarnation ||
		(m.Incarnation == old.Incarnation && m.State.rank() > old.State.rank()) {
		if m.State == StateAlive {
			delete(v.Suspect, m.Node)
		}
		v.Members[m.Node] = m
	}
}

// Gossip returns the local member plus up to three random members.
func (v *View) Gossip() []Member {
	out := []Member{v.Local}
	rest := make([]Member, 0, len(v.Members))
	for _, m := range v.Members {
		rest = append(rest, m)
	}
	return append(out, randSample(rest, 3)...)
}

// Acknowledged clears a pending probe on nonce match.
func (v *View) Acknowledged(node NodeID, nonce uint64) {
	if p, ok := v.Pending[node]; ok && p.nonce == nonce {
		delete(v.Pending, node)
		if v.Awareness > 0 {
			v.Awareness--
		}
	}
}

// Expire advances probe timers: timed-out direct probes request one
// indirect repair round; timed-out indirect probes mark Suspect;
// long-suspect members go Dead. Awareness scales both timeouts.
func (v *View) Expire() []probeReq {
	now := time.Now()
	timeout := time.Duration(500*(uint64(v.Awareness)+1)) * time.Millisecond
	var lost []NodeID
	for id, p := range v.Pending {
		if now.Sub(p.at) >= timeout {
			lost = append(lost, id)
		}
	}
	var indirect []probeReq
	for _, id := range lost {
		p := v.Pending[id]
		if !p.indirect {
			p.at = now
			p.indirect = true
			v.Pending[id] = p
			indirect = append(indirect, probeReq{target: id, nonce: p.nonce})
		} else {
			delete(v.Pending, id)
			if m, ok := v.Members[id]; ok {
				m.State = StateSuspect
				v.Members[id] = m
				if _, ok := v.Suspect[id]; !ok {
					v.Suspect[id] = now
				}
			}
			if v.Awareness < 8 {
				v.Awareness++
			}
		}
	}
	expiry := time.Duration(5*(uint64(v.Awareness)+1)) * time.Second
	var dead []NodeID
	for id, at := range v.Suspect {
		if now.Sub(at) >= expiry {
			dead = append(dead, id)
		}
	}
	for _, id := range dead {
		if m, ok := v.Members[id]; ok {
			m.State = StateDead
			v.Members[id] = m
		}
		delete(v.Suspect, id)
	}
	return indirect
}

// ---------------------------------------------------------------------------
// Engine membership
// ---------------------------------------------------------------------------

type relayKey struct {
	target NodeID
	nonce  uint64
}

type relayEntry struct {
	requester NodeID
	at        time.Time
}

// sendPacket delivers one datagram to a connected peer.
func (e *Engine) sendPacket(id NodeID, p Packet) {
	data := EncodePacket(p)
	if len(data) > maxDatagramBytes {
		return
	}
	e.mu.Lock()
	sess, ok := e.conns[id]
	e.mu.Unlock()
	if !ok {
		return
	}
	_ = sess.SendDatagram(data)
}

// broadcast fans one datagram out to gossip_fanout random sessions.
func (e *Engine) broadcast(p Packet) {
	data := EncodePacket(p)
	if len(data) > maxDatagramBytes {
		return
	}
	e.mu.Lock()
	peers := make([]Session, 0, len(e.conns))
	for _, s := range e.conns {
		peers = append(peers, s)
	}
	fanout := e.gossipFanout
	e.mu.Unlock()
	for _, s := range randSample(peers, fanout) {
		_ = s.SendDatagram(data)
	}
}

// gossip broadcasts the local gossip slice.
func (e *Engine) gossip() {
	e.mu.Lock()
	members := e.view.Gossip()
	group, node := e.group, e.node
	e.mu.Unlock()
	e.broadcast(PktGossip{Database: group, Sender: node, Members: members})
}

// probe expires timers, pings one random connected peer, and relays
// indirect repairs for lost probes.
func (e *Engine) probe() {
	e.mu.Lock()
	lost := e.view.Expire()
	var targets []NodeID
	for id := range e.conns {
		targets = append(targets, id)
	}
	group, node := e.group, e.node
	e.mu.Unlock()
	if target, ok := randChoose(targets); ok {
		var nb [8]byte
		_, _ = rand.Read(nb[:])
		nonce := binary.LittleEndian.Uint64(nb[:])
		e.mu.Lock()
		if _, dup := e.view.Pending[target]; !dup {
			e.view.Pending[target] = pendingProbe{at: time.Now(), nonce: nonce}
		} else {
			nonce = e.view.Pending[target].nonce
		}
		members := e.view.Gossip()
		e.mu.Unlock()
		e.sendPacket(target, PktPing{Database: group, Sender: node, Nonce: nonce, Members: members})
	}
	for _, req := range lost {
		e.mu.Lock()
		var relays []NodeID
		for id := range e.conns {
			if id != req.target {
				relays = append(relays, id)
			}
		}
		e.mu.Unlock()
		for _, id := range randSample(relays, 3) {
			e.sendPacket(id, PktPingRequest{Database: group, Sender: node, Target: req.target, Nonce: req.nonce})
		}
	}
}

// handlePacket processes one datagram from the session peer.
func (e *Engine) handlePacket(peer NodeID, datagram []byte) error {
	if len(datagram) > maxDatagramBytes {
		return errProtocol("membership datagram length")
	}
	packet, err := DecodePacket(datagram)
	if err != nil {
		return err
	}
	e.mu.Lock()
	group, local := e.group, e.node
	e.mu.Unlock()
	envelope := func(database, sender NodeID, members []Member) error {
		if database != group || sender != peer || len(members) > 4 {
			return errAuth("membership envelope")
		}
		return nil
	}
	switch p := packet.(type) {
	case PktGossip:
		if err := envelope(p.Database, p.Sender, p.Members); err != nil {
			return err
		}
		e.mu.Lock()
		for _, m := range p.Members {
			e.view.Merge(m)
		}
		e.mu.Unlock()
	case PktPing:
		if p.Nonce == 0 {
			if err := envelope(p.Database, p.Sender, p.Members); err != nil {
				return err
			}
			e.mu.Lock()
			for _, m := range p.Members {
				e.view.Merge(m)
			}
			e.mu.Unlock()
			break
		}
		if err := envelope(p.Database, p.Sender, p.Members); err != nil {
			return err
		}
		e.mu.Lock()
		for _, m := range p.Members {
			e.view.Merge(m)
		}
		e.view.Acknowledged(peer, p.Nonce)
		e.mu.Unlock()
		e.mu.Lock()
		req, ok := e.relays[relayKey{target: peer, nonce: p.Nonce}]
		if ok {
			delete(e.relays, relayKey{target: peer, nonce: p.Nonce})
		}
		e.mu.Unlock()
		if ok {
			e.sendPacket(req.requester, PktIndirectAck{Database: group, Sender: local, Target: peer, Nonce: p.Nonce})
		}
		e.mu.Lock()
		reply := e.view.Gossip()
		e.mu.Unlock()
		e.sendPacket(peer, PktAck{Database: group, Sender: local, Nonce: p.Nonce, Members: reply})
	case PktAck:
		if err := envelope(p.Database, p.Sender, p.Members); err != nil {
			return err
		}
		e.mu.Lock()
		for _, m := range p.Members {
			e.view.Merge(m)
		}
		e.view.Acknowledged(peer, p.Nonce)
		e.mu.Unlock()
		e.mu.Lock()
		req, ok := e.relays[relayKey{target: peer, nonce: p.Nonce}]
		if ok {
			delete(e.relays, relayKey{target: peer, nonce: p.Nonce})
		}
		e.mu.Unlock()
		if ok {
			e.sendPacket(req.requester, PktIndirectAck{Database: group, Sender: local, Target: peer, Nonce: p.Nonce})
		}
	case PktIndirectAck:
		if p.Database != group || p.Sender != peer {
			return errAuth("indirect ACK envelope")
		}
		e.mu.Lock()
		e.view.Acknowledged(p.Target, p.Nonce)
		e.mu.Unlock()
	case PktPingRequest:
		if p.Database != group || p.Sender != peer {
			return errAuth("probe envelope")
		}
		e.mu.Lock()
		for k, re := range e.relays {
			if time.Since(re.at) >= 5*time.Second {
				delete(e.relays, k)
			}
		}
		if len(e.relays) >= maxViewMembers {
			e.mu.Unlock()
			return errOverloaded("relay capacity")
		}
		e.relays[relayKey{target: p.Target, nonce: p.Nonce}] = relayEntry{requester: peer, at: time.Now()}
		members := e.view.Gossip()
		e.mu.Unlock()
		e.sendPacket(p.Target, PktPing{Database: group, Sender: local, Nonce: p.Nonce, Members: members})
	default:
		return errProtocol("unknown packet")
	}
	// A refuted incarnation persists so the next boot starts ahead.
	e.mu.Lock()
	incarnation := e.view.Local.Incarnation
	persisted := e.persistedIncarnation
	e.mu.Unlock()
	if incarnation > persisted {
		if err := execArgs(e.db, "UPDATE murmur_identity SET incarnation=max(incarnation,?1) WHERE id=1", int64(incarnation)); err != nil {
			return err
		}
		e.mu.Lock()
		if incarnation > e.persistedIncarnation {
			e.persistedIncarnation = incarnation
			e.incarnation = incarnation
		}
		e.mu.Unlock()
	}
	return nil
}

// AddSeed registers a bootstrap address (operator driven).
func (e *Engine) AddSeed(addr string) error {
	ap, err := netip.ParseAddrPort(addr)
	if err != nil {
		return errInvalid("expected IP:port")
	}
	key := ap.String()
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.seeds) >= maxViewMembers && !e.seeds[key] {
		return errOverloaded("seed capacity")
	}
	e.seeds[key] = true
	select {
	case e.syncCh <- struct{}{}:
	default:
	}
	return nil
}

// RemoveNode excludes a node: view drops it, seeds forget it, and the
// live session closes.
func (e *Engine) RemoveNode(node NodeID) {
	e.mu.Lock()
	if e.view != nil {
		e.view.Excluded[node] = true
		delete(e.view.Pending, node)
		delete(e.view.Suspect, node)
		if m, ok := e.view.Members[node]; ok {
			m.State = StateLeft
			e.view.Members[node] = m
			delete(e.seeds, m.Addr.String())
		}
	}
	sess, ok := e.conns[node]
	if ok {
		delete(e.conns, node)
	}
	e.mu.Unlock()
	if ok {
		_ = sess.Close()
	}
}

// FetchSource is one uniform-port fetch dial target.
type FetchSource struct {
	Node NodeID
	Addr netip.AddrPort
}

// FetchSources lists dial targets: uniform-port derivation (peer IP,
// our fetch port). Skips self, excluded, and Dead/Left members;
// Suspect stays included.
func (e *Engine) FetchSources(fetchPort uint16) []FetchSource {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.view == nil {
		return nil
	}
	var out []FetchSource
	for _, m := range e.view.Members {
		if m.Node == e.view.Local.Node || e.view.Excluded[m.Node] {
			continue
		}
		if m.State != StateAlive && m.State != StateSuspect {
			continue
		}
		out = append(out, FetchSource{Node: m.Node, Addr: netip.AddrPortFrom(m.Addr.Addr(), fetchPort)})
	}
	return out
}
