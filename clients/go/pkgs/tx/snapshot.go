package tx

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Durable peer snapshot transfers. Kv records are the only
// authoritative state.
//
// Ported from murmur-tx/src/snapshot.rs: the key scheme, the
// Manifest/Incoming/Pin codecs, and the config-free state machine
// (receive, missing, incoming, outgoing, cancel, maintain,
// prune_limit, reap_forgotten_pins, stream_read, validate_chunk).
// The signed build/verify/accept/finish entry points belong to the
// archived transport; the embedded engine uses the transport-verified
// forks in the replication package instead.

var (
	// OUT stages donor-side chunks.
	OUT = []byte("07/replication/snapshot-v1/out/")
	// IN stages recipient-side chunks.
	IN = []byte("07/replication/snapshot-v1/in/")
	// RECEIPTS holds completion receipts.
	RECEIPTS = []byte("07/replication/snapshot-v1/receipts/")
	// PINS holds retention pins.
	PINS = []byte("07/replication/snapshot-v1/pins/")
)

// STREAM_MAGIC prefixes streamed snapshot payloads.
var STREAM_MAGIC = []byte("MURMUR-SNAPSHOT\x00\x02")

const (
	// BUILD_GRACE_MILLIS marks a streaming build live for an hour.
	BUILD_GRACE_MILLIS = 3600000
	// BUILD_STALE_MILLIS bounds a dead build's leftovers.
	BUILD_STALE_MILLIS = 300000
	// BUILD_FRESH_MARGIN_MILLIS is the active-build reuse margin.
	BUILD_FRESH_MARGIN_MILLIS = BUILD_GRACE_MILLIS - BUILD_STALE_MILLIS
)

// Manifest describes one snapshot transfer.
type Manifest struct {
	Database  NodeID
	Donor     NodeID
	Recipient NodeID
	Transfer  NodeID
	Expires   uint64
	Bytes     uint64
	Digest    [32]byte
	Schema    [32]byte
	Progress  []Progress
	Chunks    [][32]byte
	Signature []byte
}

// Incoming is a staged recipient-side transfer.
type Incoming struct {
	Manifest Manifest
	Deadline uint64
}

// Pin protects the log range a snapshot covers.
type Pin struct {
	Recipient NodeID
	Boundary  map[NodeID]uint64
	Target    map[NodeID]uint64 // nil = untargeted
	HasTarget bool
	Expires   uint64
	Digest    [32]byte
}

// HeaderKey addresses a transfer header.
func HeaderKey(prefix []byte, transfer NodeID) []byte {
	return []byte(string(prefix) + hexID(transfer) + "/header")
}

// ChunkKey addresses one transfer chunk.
func ChunkKey(prefix []byte, transfer NodeID, index uint32) []byte {
	return []byte(fmt.Sprintf("%s%s/chunk/%08d", string(prefix), hexID(transfer), index))
}

// PinKey addresses a retention pin.
func PinKey(transfer NodeID) []byte {
	return []byte(string(PINS) + hexID(transfer))
}

// ReceiptKey addresses a completion receipt.
func ReceiptKey(transfer NodeID) []byte {
	return []byte(string(RECEIPTS) + hexID(transfer))
}

// InstallKey addresses the streaming install cursor.
func InstallKey(transfer NodeID) []byte {
	return []byte(string(IN) + hexID(transfer) + "/install")
}

func appendProgressVec(out []byte, v []Progress) []byte {
	out = appendVarint(out, uint64(len(v)))
	for _, p := range v {
		out = append(out, EncodeProgress(p)...)
	}
	return out
}

func readProgressVec(buf []byte) ([]Progress, []byte, error) {
	n, rest, err := readVarint(buf)
	if err != nil {
		return nil, nil, err
	}
	if n > 4096 {
		return nil, nil, errProtocol("progress list too large")
	}
	out := make([]Progress, 0, n)
	for i := uint64(0); i < n; i++ {
		var p Progress
		raw, tail, err := readProgressRest(rest)
		if err != nil {
			return nil, nil, err
		}
		p = raw
		rest = tail
		out = append(out, p)
	}
	return out, rest, nil
}

// readProgressRest decodes one Progress, returning the remainder.
func readProgressRest(buf []byte) (Progress, []byte, error) {
	var p Progress
	raw, rest, err := readFixed(buf, 16)
	if err != nil {
		return p, nil, err
	}
	copy(p.Origin[:], raw)
	if p.Applied, rest, err = readVarint(rest); err != nil {
		return p, nil, err
	}
	if p.Observed, rest, err = readVarint(rest); err != nil {
		return p, nil, err
	}
	if p.RetainedFrom, rest, err = readVarint(rest); err != nil {
		return p, nil, err
	}
	if p.RetainedThrough, rest, err = readVarint(rest); err != nil {
		return p, nil, err
	}
	return p, rest, nil
}

func appendBoundary(out []byte, m map[NodeID]uint64) []byte {
	keys := make([]NodeID, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		return bytes.Compare(keys[i][:], keys[j][:]) < 0
	})
	out = appendVarint(out, uint64(len(keys)))
	for _, k := range keys {
		out = append(out, k[:]...)
		out = appendVarint(out, m[k])
	}
	return out
}

func readBoundary(buf []byte) (map[NodeID]uint64, []byte, error) {
	n, rest, err := readVarint(buf)
	if err != nil {
		return nil, nil, err
	}
	if n > 4096 {
		return nil, nil, errProtocol("boundary too large")
	}
	out := make(map[NodeID]uint64, n)
	for i := uint64(0); i < n; i++ {
		raw, tail, err := readFixed(rest, 16)
		if err != nil {
			return nil, nil, err
		}
		var k NodeID
		copy(k[:], raw)
		var v uint64
		if v, tail, err = readVarint(tail); err != nil {
			return nil, nil, err
		}
		out[k] = v
		rest = tail
	}
	return out, rest, nil
}

// EncodeManifest serializes a transfer manifest.
func EncodeManifest(m Manifest) []byte {
	out := append([]byte(nil), m.Database[:]...)
	out = append(out, m.Donor[:]...)
	out = append(out, m.Recipient[:]...)
	out = append(out, m.Transfer[:]...)
	out = appendVarint(out, m.Expires)
	out = appendVarint(out, m.Bytes)
	out = append(out, m.Digest[:]...)
	out = append(out, m.Schema[:]...)
	out = appendProgressVec(out, m.Progress)
	out = appendVarint(out, uint64(len(m.Chunks)))
	for _, c := range m.Chunks {
		out = append(out, c[:]...)
	}
	return appendBytes(out, m.Signature)
}

// DecodeManifest parses a transfer manifest; trailing bytes fail closed.
func DecodeManifest(b []byte) (Manifest, error) {
	m, rest, err := decodeManifestRest(b)
	if err != nil {
		return m, err
	}
	if len(rest) != 0 {
		return m, errProtocol("trailing manifest bytes")
	}
	return m, nil
}

// EncodeIncoming serializes a staged transfer.
func EncodeIncoming(r Incoming) []byte {
	out := EncodeManifest(r.Manifest)
	return appendVarint(out, r.Deadline)
}

// DecodeIncoming parses a staged transfer.
func DecodeIncoming(b []byte) (Incoming, error) {
	var r Incoming
	m, rest, err := decodeManifestRest(b)
	if err != nil {
		return r, err
	}
	r.Manifest = m
	if r.Deadline, rest, err = readVarint(rest); err != nil {
		return r, err
	}
	if len(rest) != 0 {
		return r, errProtocol("trailing incoming bytes")
	}
	return r, nil
}

func decodeManifestRest(b []byte) (Manifest, []byte, error) {
	var m Manifest
	rest := b
	var err error
	for _, dst := range []*NodeID{&m.Database, &m.Donor, &m.Recipient, &m.Transfer} {
		var raw []byte
		if raw, rest, err = readFixed(rest, 16); err != nil {
			return m, nil, err
		}
		copy(dst[:], raw)
	}
	if m.Expires, rest, err = readVarint(rest); err != nil {
		return m, nil, err
	}
	if m.Bytes, rest, err = readVarint(rest); err != nil {
		return m, nil, err
	}
	var raw []byte
	if raw, rest, err = readFixed(rest, 32); err != nil {
		return m, nil, err
	}
	copy(m.Digest[:], raw)
	if raw, rest, err = readFixed(rest, 32); err != nil {
		return m, nil, err
	}
	copy(m.Schema[:], raw)
	if m.Progress, rest, err = readProgressVec(rest); err != nil {
		return m, nil, err
	}
	var n uint64
	if n, rest, err = readVarint(rest); err != nil {
		return m, nil, err
	}
	if n > 1<<24 {
		return m, nil, errProtocol("chunk list too large")
	}
	m.Chunks = make([][32]byte, 0, n)
	for i := uint64(0); i < n; i++ {
		if raw, rest, err = readFixed(rest, 32); err != nil {
			return m, nil, err
		}
		var c [32]byte
		copy(c[:], raw)
		m.Chunks = append(m.Chunks, c)
	}
	var sig []byte
	if sig, rest, err = readBytes(rest); err != nil {
		return m, nil, err
	}
	m.Signature = append([]byte(nil), sig...)
	return m, rest, nil
}

// EncodePin serializes a retention pin.
func EncodePin(p Pin) []byte {
	out := append([]byte(nil), p.Recipient[:]...)
	out = appendBoundary(out, p.Boundary)
	if !p.HasTarget {
		out = append(out, 0)
	} else {
		out = append(out, 1)
		out = appendBoundary(out, p.Target)
	}
	out = appendVarint(out, p.Expires)
	return append(out, p.Digest[:]...)
}

// DecodePin parses a retention pin.
func DecodePin(b []byte) (Pin, error) {
	var p Pin
	raw, rest, err := readFixed(b, 16)
	if err != nil {
		return p, err
	}
	copy(p.Recipient[:], raw)
	if p.Boundary, rest, err = readBoundary(rest); err != nil {
		return p, err
	}
	if len(rest) < 1 {
		return p, errProtocol("truncated pin target")
	}
	switch rest[0] {
	case 0:
		rest = rest[1:]
	case 1:
		rest = rest[1:]
		p.HasTarget = true
		if p.Target, rest, err = readBoundary(rest); err != nil {
			return p, err
		}
	default:
		return p, errProtocol("invalid pin target")
	}
	if p.Expires, rest, err = readVarint(rest); err != nil {
		return p, err
	}
	if raw, rest, err = readFixed(rest, 32); err != nil {
		return p, err
	}
	copy(p.Digest[:], raw)
	if len(rest) != 0 {
		return p, errProtocol("trailing pin bytes")
	}
	return p, nil
}

// StreamRead reassembles a validated byte range of the staged payload.
func StreamRead(backend Backend, m *Manifest, offset uint64, length int) ([]byte, error) {
	if length < 0 {
		return nil, errProtocol("snapshot stream bounds")
	}
	end := offset + uint64(length)
	if end < offset || end > m.Bytes {
		return nil, errProtocol("snapshot stream bounds")
	}
	out := make([]byte, 0, length)
	at := int(offset)
	for len(out) < length {
		index := at / ChunkBytes
		raw, ok, err := backend.Get(ChunkKey(IN, m.Transfer, uint32(index)))
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, errUnavailable("snapshot stream chunk missing")
		}
		if err := ValidateChunk(m, m.Donor, uint32(index), raw); err != nil {
			return nil, err
		}
		off := at % ChunkBytes
		n := length - len(out)
		if n > len(raw)-off {
			n = len(raw) - off
		}
		out = append(out, raw[off:off+n]...)
		at += n
	}
	return out, nil
}

// LoadIncoming loads the staged recipient-side transfer, if any.
func LoadIncoming(backend Backend) (*Incoming, error) {
	keys, err := backend.Keys(IN)
	if err != nil {
		return nil, err
	}
	for _, k := range keys {
		if !strings.HasSuffix(string(k), "/header") {
			continue
		}
		raw, ok, err := backend.Get(k)
		if err != nil {
			return nil, err
		}
		if ok {
			r, err := DecodeIncoming(raw)
			if err != nil {
				return nil, err
			}
			return &r, nil
		}
	}
	return nil, nil
}

// Receive stages one validated chunk.
func Receive(backend Backend, source, transfer NodeID, index uint32, data []byte, now uint64) error {
	if raw, ok, err := backend.Get(ReceiptKey(transfer)); err != nil {
		return err
	} else if ok {
		receipt, err := DecodeIncoming(raw)
		if err != nil {
			return err
		}
		return ValidateChunk(&receipt.Manifest, source, index, data)
	}
	raw, ok, err := backend.Get(HeaderKey(IN, transfer))
	if err != nil {
		return err
	}
	if !ok {
		return errUnavailable("snapshot manifest missing")
	}
	state, err := DecodeIncoming(raw)
	if err != nil {
		return err
	}
	if state.Deadline <= now {
		return errUnavailable("snapshot expired")
	}
	if err := ValidateChunk(&state.Manifest, source, index, data); err != nil {
		return err
	}
	key := ChunkKey(IN, transfer, index)
	if old, ok, err := backend.Get(key); err != nil {
		return err
	} else if ok {
		if !bytes.Equal(old, data) {
			return errAuth("conflicting snapshot chunk")
		}
		return nil
	}
	return backend.Commit([]Record{Put(key, data)})
}

// ValidateChunk checks chunk identity, length, and hash.
func ValidateChunk(m *Manifest, source NodeID, index uint32, data []byte) error {
	i := int(index)
	if source != m.Donor || i >= len(m.Chunks) {
		return errAuth("snapshot chunk identity")
	}
	rest := int(m.Bytes) - i*ChunkBytes
	expected := rest
	if expected > ChunkBytes {
		expected = ChunkBytes
	}
	if len(data) != expected || sha256.Sum256(data) != m.Chunks[i] {
		return errAuth("snapshot chunk length or hash")
	}
	return nil
}

// Missing lists up to 128 absent chunk indexes via the key index.
func Missing(backend Backend, state *Incoming) ([]uint32, error) {
	prefix := string(IN) + hexID(state.Manifest.Transfer) + "/chunk/"
	keys, err := backend.Keys([]byte(prefix))
	if err != nil {
		return nil, err
	}
	saved := make(map[string]bool, len(keys))
	for _, k := range keys {
		saved[string(k)] = true
	}
	var out []uint32
	for i := 0; i < len(state.Manifest.Chunks); i++ {
		if !saved[string(ChunkKey(IN, state.Manifest.Transfer, uint32(i)))] {
			out = append(out, uint32(i))
			if len(out) == 128 {
				break
			}
		}
	}
	return out, nil
}

// PruneLimit is the minimum allowed pruning boundary across live pins.
func PruneLimit(backend Backend, origin NodeID, now uint64) (uint64, error) {
	limit := ^uint64(0)
	keys, err := backend.Keys(PINS)
	if err != nil {
		return 0, err
	}
	for _, k := range keys {
		raw, ok, err := backend.Get(k)
		if err != nil {
			return 0, err
		}
		if !ok {
			continue
		}
		pin, err := DecodePin(raw)
		if err != nil {
			return 0, err
		}
		if pin.Expires > now {
			if b, ok := pin.Boundary[origin]; ok {
				if b < limit {
					limit = b
				}
			} else if limit > 0 {
				limit = 0
			}
		}
	}
	return limit, nil
}

// Maintain sweeps expired pins, headers, orphan chunks, and receipts.
func Maintain(backend Backend, now uint64) error {
	var records []Record
	keys, err := backend.Keys(PINS)
	if err != nil {
		return err
	}
	for _, k := range keys {
		raw, ok, err := backend.Get(k)
		if err != nil {
			return err
		}
		if !ok {
			continue
		}
		pin, err := DecodePin(raw)
		if err != nil {
			return err
		}
		caughtUp := false
		if pin.HasTarget {
			peer, err := Peer(backend, pin.Recipient)
			if err != nil {
				return err
			}
			if peer != nil {
				caughtUp = true
				for o, s := range pin.Target {
					if peer.Acknowledged[o] < s {
						caughtUp = false
						break
					}
				}
			}
		}
		if pin.Expires <= now || caughtUp {
			records = append(records, Delete(k))
		}
		if len(records) == 256 {
			break
		}
	}
	if len(records) > 0 {
		if err := backend.Commit(records); err != nil {
			return err
		}
	}
	for _, prefix := range [][]byte{IN, OUT} {
		keys, err := backend.Keys(prefix)
		if err != nil {
			return err
		}
		live := map[string]bool{}
		records = nil
		for _, k := range keys {
			if !strings.HasSuffix(string(k), "/header") {
				continue
			}
			raw, ok, err := backend.Get(k)
			if err != nil {
				return err
			}
			if !ok {
				continue
			}
			var transfer NodeID
			var expired bool
			if bytes.Equal(prefix, IN) {
				r, err := DecodeIncoming(raw)
				if err != nil {
					return err
				}
				transfer = r.Manifest.Transfer
				expired = r.Deadline <= now
			} else {
				m, err := DecodeManifest(raw)
				if err != nil {
					return err
				}
				transfer = m.Transfer
				praw, ok, err := backend.Get(PinKey(m.Transfer))
				if err != nil {
					return err
				}
				targeted := false
				if ok {
					pin, err := DecodePin(praw)
					if err != nil {
						return err
					}
					targeted = pin.HasTarget
				} else {
					targeted = true
				}
				expired = m.Expires <= now || targeted
			}
			if expired && len(records) < 256 {
				records = append(records, Delete(k))
			} else {
				live[hexID(transfer)] = true
			}
		}
		for _, k := range keys {
			if len(records) >= 256 {
				break
			}
			if strings.HasSuffix(string(k), "/header") {
				continue
			}
			text := string(k)
			id := ""
			if rest, ok := strings.CutPrefix(text, string(prefix)); ok {
				if i := strings.IndexByte(rest, '/'); i >= 0 {
					id = rest[:i]
				} else {
					id = rest
				}
			}
			if !live[id] {
				records = append(records, Delete(k))
			}
		}
		if len(records) > 0 {
			if err := backend.Commit(records); err != nil {
				return err
			}
		}
	}
	records = nil
	keys, err = backend.Keys(RECEIPTS)
	if err != nil {
		return err
	}
	for _, k := range keys {
		raw, ok, err := backend.Get(k)
		if err != nil {
			return err
		}
		if !ok {
			continue
		}
		r, err := DecodeIncoming(raw)
		if err != nil {
			return err
		}
		if r.Deadline <= now {
			records = append(records, Delete(k))
		}
		if len(records) == 256 {
			break
		}
	}
	if len(records) > 0 {
		if err := backend.Commit(records); err != nil {
			return err
		}
	}
	// Version 8 partial transfers have no durable sender identity.
	old, err := backend.Keys([]byte("07/replication/snapshot/"))
	if err != nil {
		return err
	}
	if len(old) > 256 {
		old = old[:256]
	}
	if len(old) > 0 {
		records = records[:0]
		for _, k := range old {
			records = append(records, Delete(k))
		}
		return backend.Commit(records)
	}
	return nil
}

// ReapForgottenPins drops pins whose recipients retired, aged out
// offline with no live session, or already acknowledge the boundary.
func ReapForgottenPins(backend Backend, now uint64, maximumOffline time.Duration, online map[NodeID]bool) error {
	var records []Record
	keys, err := backend.Keys(PINS)
	if err != nil {
		return err
	}
	maxOff := uint64(maximumOffline.Milliseconds())
	for _, k := range keys {
		raw, ok, err := backend.Get(k)
		if err != nil {
			return err
		}
		if !ok {
			continue
		}
		pin, err := DecodePin(raw)
		if err != nil {
			return err
		}
		peer, err := Peer(backend, pin.Recipient)
		if err != nil {
			return err
		}
		forgotten := false
		if peer != nil {
			unseen := now - peer.LastSeenMillis
			if now < peer.LastSeenMillis {
				unseen = 0
			}
			forgotten = peer.Retired || (!online[pin.Recipient] && unseen > maxOff)
		}
		fulfilled := !pin.HasTarget && len(pin.Boundary) > 0 && peer != nil &&
			!peer.Retired && (online[pin.Recipient] || now-peer.LastSeenMillis <= maxOff)
		if fulfilled {
			unseen := now - peer.LastSeenMillis
			if now < peer.LastSeenMillis {
				unseen = 0
			}
			fulfilled = online[pin.Recipient] || unseen <= maxOff
			for o, s := range pin.Boundary {
				if peer.Acknowledged[o] < s {
					fulfilled = false
					break
				}
			}
		}
		if (forgotten || fulfilled) && len(records) < 256 {
			records = append(records, Delete(k))
		}
		if len(records) >= 256 {
			break
		}
	}
	if len(records) > 0 {
		return backend.Commit(records)
	}
	return nil
}
