// Package tx mirrors murmur-tx: the transaction-protocol replication
// core (keys, snapshots, retention) reused over a Backend the engine
// implements. Only the subset reachable from the embedded CRR engine
// is ported: the archived transport engine, file transfer, bridge,
// queue, and policy modules stay Rust-only. Codecs are hand-written
// postcard (varint integers, raw arrays, varint-length vecs/strings,
// varint enum tags), matching the golden-tested conventions of the
// replication package.
package tx

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"unicode/utf8"
)

// NodeID is a 128-bit group/node/site/transfer identity.
type NodeID [16]byte

// String renders the id as 32 hex digits.
func (id NodeID) String() string { return hex.EncodeToString(id[:]) }

// Zero reports the unset id.
func (id NodeID) Zero() bool { return id == NodeID{} }

// IsZero reports the unset id.
func (id NodeID) IsZero() bool { return id == NodeID{} }

// ParseID parses a 128-bit hex identity (dashes ignored, nonzero).
func ParseID(v string) (NodeID, error) {
	var out NodeID
	raw, err := hex.DecodeString(strings.ReplaceAll(v, "-", ""))
	if err != nil || len(raw) != 16 {
		return out, errInvalidf("invalid node id %q", v)
	}
	copy(out[:], raw)
	if out == (NodeID{}) {
		return out, errInvalidf("zero node id %q", v)
	}
	return out, nil
}

func hexID(id NodeID) string { return hex.EncodeToString(id[:]) }

// Error categories mirror the tx crate errors.
type Error struct {
	Kind string
	Msg  string
}

func (e *Error) Error() string {
	if e.Msg == "" {
		return e.Kind
	}
	return e.Kind + ": " + e.Msg
}

func errInvalid(msg string) *Error     { return &Error{Kind: "Invalid", Msg: msg} }
func errProtocol(msg string) *Error    { return &Error{Kind: "Protocol", Msg: msg} }
func errAuth(msg string) *Error        { return &Error{Kind: "Auth", Msg: msg} }
func errOverloaded(msg string) *Error  { return &Error{Kind: "Overloaded", Msg: msg} }
func errUnavailable(msg string) *Error { return &Error{Kind: "Unavailable", Msg: msg} }

func errInvalidf(format string, args ...any) *Error {
	return &Error{Kind: "Invalid", Msg: fmt.Sprintf(format, args...)}
}

// ---------------------------------------------------------------------------
// postcard primitives
// ---------------------------------------------------------------------------

func appendVarint(out []byte, v uint64) []byte {
	var b [binary.MaxVarintLen64]byte
	n := binary.PutUvarint(b[:], v)
	return append(out, b[:n]...)
}

func readVarint(buf []byte) (uint64, []byte, error) {
	v, n := binary.Uvarint(buf)
	if n <= 0 {
		return 0, nil, errProtocol("truncated varint")
	}
	return v, buf[n:], nil
}

func appendBytes(out, b []byte) []byte {
	out = appendVarint(out, uint64(len(b)))
	return append(out, b...)
}

func readBytes(buf []byte) ([]byte, []byte, error) {
	n, rest, err := readVarint(buf)
	if err != nil {
		return nil, nil, err
	}
	if n > uint64(len(rest)) {
		return nil, nil, errProtocol("truncated bytes")
	}
	return rest[:n], rest[n:], nil
}

func readFixed(buf []byte, n int) ([]byte, []byte, error) {
	if len(buf) < n {
		return nil, nil, errProtocol("truncated fixed")
	}
	return buf[:n], buf[n:], nil
}

func readString(buf []byte) (string, []byte, error) {
	b, rest, err := readBytes(buf)
	if err != nil {
		return "", nil, err
	}
	if !utf8.Valid(b) {
		return "", nil, errProtocol("invalid string")
	}
	return string(b), rest, nil
}

// EncodeU64 encodes a head counter.
func EncodeU64(v uint64) []byte { return appendVarint(nil, v) }

// DecodeU64 decodes a head counter; trailing bytes fail closed.
func DecodeU64(b []byte) (uint64, error) {
	v, rest, err := readVarint(b)
	if err != nil {
		return 0, err
	}
	if len(rest) != 0 {
		return 0, errProtocol("trailing u64 bytes")
	}
	return v, nil
}

// ---------------------------------------------------------------------------
// Records and backend
// ---------------------------------------------------------------------------

// Record is one kv put (Value != nil) or delete (Value == nil).
type Record struct {
	Key   []byte
	Value []byte
}

// Put builds a put record (empty values stay puts, never deletes).
func Put(key, value []byte) Record {
	if value == nil {
		value = []byte{}
	}
	return Record{Key: key, Value: value}
}

// Delete builds a delete record.
func Delete(key []byte) Record { return Record{Key: key} }

// IsDelete reports a delete record.
func (r Record) IsDelete() bool { return r.Value == nil }

// BridgeHeader supplies trusted import policy for a sealed native MHB1 bundle.
// These keys come from operator configuration, never from the wire payload.
// The snapshot path does not construct bridge headers.
type BridgeHeader struct {
	Database         NodeID
	Stream           string
	Signer, Receiver [32]byte
	StagingBytes     uint64
}

// Backend is the kv + snapshot surface the engine implements. All
// calls must serialize on the store; commits are durable.
type Backend interface {
	// CancelPending interrupts pending waits; never an active commit.
	CancelPending()
	Identity() (NodeID, NodeID)
	Get(key []byte) ([]byte, bool, error)
	GetMany(keys [][]byte) ([][]byte, []bool, error)
	GetManyBounded(keys [][]byte, maxBytes int) ([][]byte, []bool, error)
	Keys(prefix []byte) ([][]byte, error)
	KeysPage(prefix, after []byte, limit int) ([][]byte, error)
	Progress() ([]Progress, error)
	Commit(records []Record) error
	ImportBridge(header BridgeHeader, payload []byte) (bool, error)
	ReleaseOwnership(table string, key []byte, column *string) (bool, error)
	Publish(records []Record) error
	Snapshot() ([]byte, error)
	SnapshotWithProgress() ([]byte, []Progress, error)
	CreateSnapshot(recipient NodeID) (Manifest, error)
	AcknowledgeSnapshot(recipient, transfer NodeID, digest [32]byte) error
	RetentionCheckpoint() error
	PruneHistory(origin NodeID, through uint64) (uint64, error)
	ReclaimRetention() error
	Schema() ([]byte, error)
	Apply(payloads [][]byte, records []Record) (bool, error)
	Observe(millis uint64, logical uint32) error
	AcceptSchema(schema []byte) (bool, error)
}
