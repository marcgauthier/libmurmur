package tx

import (
	"crypto/sha256"
	"fmt"
)

const (
	// Version is the tx wire version.
	Version uint16 = 13
	// FrameBytes caps one tx frame.
	FrameBytes = 8 << 20
	// ChunkBytes caps one snapshot chunk payload.
	ChunkBytes = 64 << 10
)

// Progress is the durable per-origin watermark set.
type Progress struct {
	Origin          NodeID
	Applied         uint64
	Observed        uint64
	RetainedFrom    uint64
	RetainedThrough uint64
}

// EncodeProgress serializes one watermark set.
func EncodeProgress(p Progress) []byte {
	out := append([]byte(nil), p.Origin[:]...)
	out = appendVarint(out, p.Applied)
	out = appendVarint(out, p.Observed)
	out = appendVarint(out, p.RetainedFrom)
	return appendVarint(out, p.RetainedThrough)
}

// DecodeProgress parses one watermark set; trailing bytes fail closed.
func DecodeProgress(b []byte) (Progress, error) {
	var p Progress
	raw, rest, err := readFixed(b, 16)
	if err != nil {
		return p, err
	}
	copy(p.Origin[:], raw)
	if p.Applied, rest, err = readVarint(rest); err != nil {
		return p, err
	}
	if p.Observed, rest, err = readVarint(rest); err != nil {
		return p, err
	}
	if p.RetainedFrom, rest, err = readVarint(rest); err != nil {
		return p, err
	}
	if p.RetainedThrough, rest, err = readVarint(rest); err != nil {
		return p, err
	}
	if len(rest) != 0 {
		return p, errProtocol("trailing progress bytes")
	}
	return p, nil
}

// ProgressKey is the applied-head key for an origin.
func ProgressKey(origin NodeID) []byte {
	return []byte("07/replication/applied/" + hexID(origin))
}

// SchemaManifestKey is the node-local outbound manifest cursor key.
func SchemaManifestKey() []byte { return []byte("07/replication/schema/manifest") }

// SchemaAcceptedKey is the highest-accepted-schema-sequence key per signer.
func SchemaAcceptedKey(signer NodeID) []byte {
	return []byte("07/replication/schema/accepted/" + hexID(signer))
}

// ObservedKey is the observed-head key for an origin.
func ObservedKey(origin NodeID) []byte {
	return []byte("07/replication/observed/" + hexID(origin))
}

// RetainedKey is the retained-head key for an origin.
func RetainedKey(origin NodeID) []byte {
	return []byte("07/replication/retained/" + hexID(origin))
}

// ChunkPrefix groups one origin sequence's chunks.
func TxChunkPrefix(origin NodeID, seq uint64) string {
	return fmt.Sprintf("07/replication/chunks/%s/%020d/", hexID(origin), seq)
}

// SchemaDigest digests canonical schema bytes.
func SchemaDigest(b []byte) [32]byte { return sha256.Sum256(b) }

// SchemaSignDomain prefixes schema signature bytes.
var SchemaSignDomain = []byte("murmur/sqlite-schema/v1")

// SignedSchema is a master-signed schema promise. Schema carries
// canonical replicated-subset bytes; local-only tables are excluded
// by the sender before signing. The embedded engine leaves Signature
// empty (transport authentication replaces it).
type SignedSchema struct {
	Database  NodeID
	Signer    NodeID
	Sequence  uint64
	Schema    []byte
	Signature []byte
}

// EncodeSignedSchema serializes the promise.
func EncodeSignedSchema(s SignedSchema) []byte {
	out := append([]byte(nil), s.Database[:]...)
	out = append(out, s.Signer[:]...)
	out = appendVarint(out, s.Sequence)
	out = appendBytes(out, s.Schema)
	return appendBytes(out, s.Signature)
}

// DecodeSignedSchema parses the promise; trailing bytes fail closed.
func DecodeSignedSchema(b []byte) (SignedSchema, error) {
	var s SignedSchema
	raw, rest, err := readFixed(b, 16)
	if err != nil {
		return s, err
	}
	copy(s.Database[:], raw)
	if raw, rest, err = readFixed(rest, 16); err != nil {
		return s, err
	}
	copy(s.Signer[:], raw)
	if s.Sequence, rest, err = readVarint(rest); err != nil {
		return s, err
	}
	var sc []byte
	if sc, rest, err = readBytes(rest); err != nil {
		return s, err
	}
	s.Schema = append([]byte(nil), sc...)
	var sig []byte
	if sig, rest, err = readBytes(rest); err != nil {
		return s, err
	}
	s.Signature = append([]byte(nil), sig...)
	if len(rest) != 0 {
		return s, errProtocol("trailing schema bytes")
	}
	return s, nil
}

// SignedBytes returns the domain-separated signature preimage:
// domain + (database, signer, sequence, sha256(schema) as bytes).
func (s SignedSchema) SignedBytes() []byte {
	out := append([]byte(nil), SchemaSignDomain...)
	out = append(out, s.Database[:]...)
	out = append(out, s.Signer[:]...)
	out = appendVarint(out, s.Sequence)
	sum := sha256.Sum256(s.Schema)
	return appendBytes(out, sum[:])
}

// Digest returns the schema digest.
func (s SignedSchema) Digest() [32]byte { return sha256.Sum256(s.Schema) }
