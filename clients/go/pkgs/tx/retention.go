package tx

import (
	"time"
)

// Retention liveness subset: peer records, merge/touch, and key
// helpers. Ported from murmur-tx/src/retention.rs. The collection and
// pruning passes land with the retention step; snapshots only need
// liveness (touch/peer) plus maintain/prune support.

var peersPrefix = []byte("07/replication/retention/peers/")

// PeerRetention is the per-peer liveness record.
type PeerRetention struct {
	Node           NodeID
	LastSeenMillis uint64
	Retired        bool
	Acknowledged   map[NodeID]uint64
}

// EncodePeerRetention serializes a liveness record.
func EncodePeerRetention(p PeerRetention) []byte {
	out := append([]byte(nil), p.Node[:]...)
	out = appendVarint(out, p.LastSeenMillis)
	if p.Retired {
		out = append(out, 1)
	} else {
		out = append(out, 0)
	}
	return appendBoundary(out, p.Acknowledged)
}

// DecodePeerRetention parses a liveness record.
func DecodePeerRetention(b []byte) (PeerRetention, error) {
	var p PeerRetention
	raw, rest, err := readFixed(b, 16)
	if err != nil {
		return p, err
	}
	copy(p.Node[:], raw)
	if p.LastSeenMillis, rest, err = readVarint(rest); err != nil {
		return p, err
	}
	if len(rest) < 1 {
		return p, errProtocol("truncated peer record")
	}
	switch rest[0] {
	case 0:
	case 1:
		p.Retired = true
	default:
		return p, errProtocol("invalid peer retired flag")
	}
	rest = rest[1:]
	if p.Acknowledged, rest, err = readBoundary(rest); err != nil {
		return p, err
	}
	if len(rest) != 0 {
		return p, errProtocol("trailing peer bytes")
	}
	return p, nil
}

// FloorKey addresses a retention floor.
func FloorKey(origin NodeID) []byte {
	return []byte("07/replication/retention/floor/" + hexID(origin))
}

// PeerKey addresses a peer liveness record.
func PeerKey(node NodeID) []byte {
	return []byte(string(peersPrefix) + hexID(node))
}

// ExcludedKey addresses a retired-peer tombstone.
func ExcludedKey(node NodeID) []byte {
	return []byte("07/replication/excluded/" + hexID(node))
}

// NowMillis is the unix millisecond clock.
func NowMillis() uint64 {
	return uint64(time.Now().UnixMilli())
}

// RetentionStatus is the collector status surface.
type RetentionStatus struct {
	Peers                 []PeerRetention
	CollectedTransactions uint64
	LastCollectionMillis  uint64
}

// Status collects peer liveness plus collector counters.
func Status(backend Backend) (RetentionStatus, error) {
	var st RetentionStatus
	keys, err := backend.Keys(peersPrefix)
	if err != nil {
		return st, err
	}
	for _, k := range keys {
		raw, ok, err := backend.Get(k)
		if err != nil {
			return st, err
		}
		if ok {
			p, err := DecodePeerRetention(raw)
			if err != nil {
				return st, err
			}
			st.Peers = append(st.Peers, p)
		}
	}
	if raw, ok, err := backend.Get([]byte("07/replication/retention/collected")); err != nil {
		return st, err
	} else if ok {
		st.CollectedTransactions, err = DecodeU64(raw)
		if err != nil {
			return st, err
		}
	}
	if raw, ok, err := backend.Get([]byte("07/replication/retention/last")); err != nil {
		return st, err
	} else if ok {
		st.LastCollectionMillis, err = DecodeU64(raw)
		if err != nil {
			return st, err
		}
	}
	return st, nil
}

// Peer loads a liveness record.
func Peer(backend Backend, node NodeID) (*PeerRetention, error) {
	raw, ok, err := backend.Get(PeerKey(node))
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, nil
	}
	p, err := DecodePeerRetention(raw)
	if err != nil {
		return nil, err
	}
	return &p, nil
}

// Touch records peer contact and max-merges acknowledged progress.
// Writes are skipped when nothing changed within 10s of the last
// touch; retired peers fail Auth.
func Touch(backend Backend, node NodeID, progress []Progress) error {
	state, err := Peer(backend, node)
	if err != nil {
		return err
	}
	if state == nil {
		state = &PeerRetention{Node: node, Acknowledged: map[NodeID]uint64{}}
	}
	if state.Retired {
		return errAuth("retired peer")
	}
	now := NowMillis()
	changed := state.LastSeenMillis == 0
	for _, entry := range progress {
		v := state.Acknowledged[entry.Origin]
		changed = changed || entry.Applied > v
		if entry.Applied > v {
			state.Acknowledged[entry.Origin] = entry.Applied
		}
	}
	if len(state.Acknowledged) > 4096 {
		return errOverloaded("peer record too large")
	}
	var since uint64
	if now >= state.LastSeenMillis {
		since = now - state.LastSeenMillis
	}
	if !changed && since < 10000 {
		return nil
	}
	if now > state.LastSeenMillis {
		state.LastSeenMillis = now
	}
	return backend.Commit([]Record{Put(PeerKey(node), EncodePeerRetention(*state))})
}

// Retire marks a peer retired and records the exclusion tombstone.
func Retire(backend Backend, node NodeID) error {
	state, err := Peer(backend, node)
	if err != nil {
		return err
	}
	if state == nil {
		state = &PeerRetention{Node: node, LastSeenMillis: NowMillis(), Acknowledged: map[NodeID]uint64{}}
	}
	state.Retired = true
	return backend.Commit([]Record{
		Put(PeerKey(node), EncodePeerRetention(*state)),
		Put(ExcludedKey(node), append([]byte(nil), node[:]...)),
	})
}
