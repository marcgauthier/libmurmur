package replication

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"net/netip"
	"unicode/utf8"

	"github.com/marcgauthier/libmurmur/clients/go/pkgs/tx"
)

// Wire protocol: postcard-compatible framing mirroring
// murmur-replication/src/protocol.rs. Integers are unsigned varints
// (signed via zigzag), byte strings carry a varint length, Options
// are 0x00/0x01, enums a varint variant index, structs fields in
// declaration order. testdata/*.bin are golden vectors generated
// from the Rust implementation; the codec test asserts byte equality.

const (
	// ALPN identifies the replication protocol on TLS.
	ALPN = "murmur-crsqlite/1"
	// FrameBytes caps one length-prefixed message frame.
	FrameBytes = 128 << 10
	// ChunkBytes caps one batch chunk payload.
	ChunkBytes = 64 << 10
)

// Digest is the SHA-256 batch digest.
func Digest(b []byte) [32]byte { return sha256.Sum256(b) }

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

func zigEncode(v int64) uint64 { return uint64((v << 1) ^ (v >> 63)) }

func zigDecode(v uint64) int64 { return int64(v>>1) ^ -int64(v&1) }

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

func readFixed(buf []byte, n int) ([]byte, []byte, error) {
	if len(buf) < n {
		return nil, nil, errProtocol("truncated fixed")
	}
	return buf[:n], buf[n:], nil
}

// Key is a change-cell stream position.
type Key struct {
	Version int64
	Seq     int64
	Table   string
	PK      []byte
	CID     string
}

func cmpInt(a, b int64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

func cmpStr(a, b string) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

func cmpBytes(a, b []byte) int {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] != b[i] {
			if a[i] < b[i] {
				return -1
			}
			return 1
		}
	}
	return cmpLen(len(a), len(b))
}

func cmpLen(a, b int) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

func appendKey(out []byte, k Key) []byte {
	out = appendVarint(out, zigEncode(k.Version))
	out = appendVarint(out, zigEncode(k.Seq))
	out = appendBytes(out, []byte(k.Table))
	out = appendBytes(out, k.PK)
	return appendBytes(out, []byte(k.CID))
}

func readKey(buf []byte) (Key, []byte, error) {
	var k Key
	v, rest, err := readVarint(buf)
	if err != nil {
		return k, nil, err
	}
	k.Version = zigDecode(v)
	v, rest, err = readVarint(rest)
	if err != nil {
		return k, nil, err
	}
	k.Seq = zigDecode(v)
	if k.Table, rest, err = readString(rest); err != nil {
		return k, nil, err
	}
	var pk []byte
	if pk, rest, err = readBytes(rest); err != nil {
		return k, nil, err
	}
	k.PK = append([]byte(nil), pk...)
	if k.CID, rest, err = readString(rest); err != nil {
		return k, nil, err
	}
	return k, rest, nil
}

// Cursor is a receive/export stream position.
type Cursor struct {
	From    int64
	Through *int64
	After   *Key
}

func appendCursor(out []byte, c Cursor) []byte {
	out = appendVarint(out, zigEncode(c.From))
	if c.Through == nil {
		out = append(out, 0)
	} else {
		out = append(out, 1)
		out = appendVarint(out, zigEncode(*c.Through))
	}
	if c.After == nil {
		return append(out, 0)
	}
	out = append(out, 1)
	return appendKey(out, *c.After)
}

func readCursor(buf []byte) (Cursor, []byte, error) {
	var c Cursor
	v, rest, err := readVarint(buf)
	if err != nil {
		return c, nil, err
	}
	c.From = zigDecode(v)
	var b byte
	if len(rest) < 1 {
		return c, nil, errProtocol("truncated option")
	}
	b, rest = rest[0], rest[1:]
	switch b {
	case 0:
	case 1:
		var t uint64
		if t, rest, err = readVarint(rest); err != nil {
			return c, nil, err
		}
		tv := zigDecode(t)
		c.Through = &tv
	default:
		return c, nil, errProtocol("invalid option")
	}
	if len(rest) < 1 {
		return c, nil, errProtocol("truncated option")
	}
	b, rest = rest[0], rest[1:]
	switch b {
	case 0:
	case 1:
		var k Key
		if k, rest, err = readKey(rest); err != nil {
			return c, nil, err
		}
		c.After = &k
	default:
		return c, nil, errProtocol("invalid option")
	}
	return c, rest, nil
}

// EncodeCursor serializes a progress cursor for murmur_progress.
func EncodeCursor(c Cursor) []byte { return appendCursor(nil, c) }

// DecodeCursor parses a stored progress cursor.
func DecodeCursor(b []byte) (Cursor, error) {
	c, rest, err := readCursor(b)
	if err != nil {
		return c, err
	}
	if len(rest) != 0 {
		return c, errProtocol("trailing cursor bytes")
	}
	return c, nil
}

// Message is one wire frame payload. Variant indices match the Rust
// declaration order.
type Message interface{ messageTag() }

type (
	MsgHello struct {
		Group, Node, Site NodeID
		Schema            [32]byte
		Incarnation       uint64
		Addr              netip.AddrPort
	}
	MsgPull struct {
		Group, Node, Site NodeID
		Schema            [32]byte
		ExpectedSite      *NodeID
		Cursor            Cursor
	}
	MsgReset struct {
		Site NodeID
	}
	MsgIdle  struct{}
	MsgBatch struct {
		Site   NodeID
		Cursor Cursor
		Bytes  uint64
		Digest [32]byte
	}
	MsgChunk struct {
		Index uint32
		Data  []byte
	}
	MsgSnapshotRequest struct {
		Group, Node, Site NodeID
		Schema            [32]byte
	}
	MsgSnapshotManifest struct {
		Manifest []byte
	}
	MsgSchemaRequest  struct{}
	MsgSchemaManifest struct {
		Manifest []byte
	}
	MsgSchemaAck struct {
		Digest   [32]byte
		Sequence uint64
	}
	MsgEnd struct{}
	MsgAck struct {
		Digest [32]byte
	}
	MsgError struct {
		Text string
	}
)

func (MsgHello) messageTag()            {}
func (MsgPull) messageTag()             {}
func (MsgReset) messageTag()            {}
func (MsgIdle) messageTag()             {}
func (MsgBatch) messageTag()            {}
func (MsgChunk) messageTag()            {}
func (MsgSnapshotRequest) messageTag()  {}
func (MsgSnapshotManifest) messageTag() {}
func (MsgSchemaRequest) messageTag()    {}
func (MsgSchemaManifest) messageTag()   {}
func (MsgSchemaAck) messageTag()        {}
func (MsgEnd) messageTag()              {}
func (MsgAck) messageTag()              {}
func (MsgError) messageTag()            {}

func appendAddr(out []byte, ap netip.AddrPort) []byte {
	addr := ap.Addr()
	switch {
	case addr.Is4():
		out = appendVarint(out, 0)
		b := addr.As4()
		out = append(out, b[:]...)
	case addr.Is6():
		out = appendVarint(out, 1)
		b := addr.As16()
		out = append(out, b[:]...)
	default:
		// Invalid addresses encode as unspecified V4; decoding
		// validates before use.
		out = appendVarint(out, 0)
		out = append(out, 0, 0, 0, 0)
	}
	return appendVarint(out, uint64(ap.Port()))
}

func readAddr(buf []byte) (netip.AddrPort, []byte, error) {
	var zero netip.AddrPort
	v, rest, err := readVarint(buf)
	if err != nil {
		return zero, nil, err
	}
	var addr netip.Addr
	switch v {
	case 0:
		var b []byte
		if b, rest, err = readFixed(rest, 4); err != nil {
			return zero, nil, err
		}
		addr = netip.AddrFrom4([4]byte{b[0], b[1], b[2], b[3]})
	case 1:
		var b []byte
		if b, rest, err = readFixed(rest, 16); err != nil {
			return zero, nil, err
		}
		var ab [16]byte
		copy(ab[:], b)
		addr = netip.AddrFrom16(ab)
	default:
		return zero, nil, errProtocol("invalid address family")
	}
	p, rest, err := readVarint(rest)
	if err != nil {
		return zero, nil, err
	}
	if p > math.MaxUint16 {
		return zero, nil, errProtocol("invalid port")
	}
	return netip.AddrPortFrom(addr, uint16(p)), rest, nil
}

// EncodeMessage serializes one frame payload.
func EncodeMessage(m Message) ([]byte, error) {
	var out []byte
	var err error
	out, err = appendMessage(out, m)
	return out, err
}

func appendMessage(out []byte, m Message) ([]byte, error) {
	switch v := m.(type) {
	case MsgHello:
		out = appendVarint(out, 0)
		out = append(out, v.Group[:]...)
		out = append(out, v.Node[:]...)
		out = append(out, v.Site[:]...)
		out = append(out, v.Schema[:]...)
		out = appendVarint(out, v.Incarnation)
		return appendAddr(out, v.Addr), nil
	case MsgPull:
		out = appendVarint(out, 1)
		out = append(out, v.Group[:]...)
		out = append(out, v.Node[:]...)
		out = append(out, v.Site[:]...)
		out = append(out, v.Schema[:]...)
		if v.ExpectedSite == nil {
			out = append(out, 0)
		} else {
			out = append(out, 1)
			out = append(out, v.ExpectedSite[:]...)
		}
		return appendCursor(out, v.Cursor), nil
	case MsgReset:
		out = appendVarint(out, 2)
		return append(out, v.Site[:]...), nil
	case MsgIdle:
		return appendVarint(out, 3), nil
	case MsgBatch:
		out = appendVarint(out, 4)
		out = append(out, v.Site[:]...)
		out = appendCursor(out, v.Cursor)
		out = appendVarint(out, v.Bytes)
		return append(out, v.Digest[:]...), nil
	case MsgChunk:
		out = appendVarint(out, 5)
		out = appendVarint(out, uint64(v.Index))
		return appendBytes(out, v.Data), nil
	case MsgSnapshotRequest:
		out = appendVarint(out, 6)
		out = append(out, v.Group[:]...)
		out = append(out, v.Node[:]...)
		out = append(out, v.Site[:]...)
		return append(out, v.Schema[:]...), nil
	case MsgSnapshotManifest:
		out = appendVarint(out, 7)
		return appendBytes(out, v.Manifest), nil
	case MsgSchemaRequest:
		return appendVarint(out, 8), nil
	case MsgSchemaManifest:
		out = appendVarint(out, 9)
		return appendBytes(out, v.Manifest), nil
	case MsgSchemaAck:
		out = appendVarint(out, 10)
		out = append(out, v.Digest[:]...)
		return appendVarint(out, v.Sequence), nil
	case MsgEnd:
		return appendVarint(out, 11), nil
	case MsgAck:
		out = appendVarint(out, 12)
		return append(out, v.Digest[:]...), nil
	case MsgError:
		out = appendVarint(out, 13)
		return appendBytes(out, []byte(v.Text)), nil
	}
	return nil, errProtocol("unknown message")
}

// DecodeMessage parses one frame payload, rejecting trailing bytes.
func DecodeMessage(b []byte) (Message, error) {
	v, rest, err := readVarint(b)
	if err != nil {
		return nil, err
	}
	m, rest, err := readMessageBody(v, rest)
	if err != nil {
		return nil, err
	}
	if len(rest) != 0 {
		return nil, errProtocol("trailing message bytes")
	}
	return m, nil
}

func readNode(buf []byte) (NodeID, []byte, error) {
	var id NodeID
	b, rest, err := readFixed(buf, 16)
	if err != nil {
		return id, nil, err
	}
	copy(id[:], b)
	return id, rest, nil
}

func readDigest(buf []byte) ([32]byte, []byte, error) {
	var d [32]byte
	b, rest, err := readFixed(buf, 32)
	if err != nil {
		return d, nil, err
	}
	copy(d[:], b)
	return d, rest, nil
}

func readMessageBody(tag uint64, buf []byte) (Message, []byte, error) {
	var err error
	switch tag {
	case 0:
		var m MsgHello
		if m.Group, buf, err = readNode(buf); err != nil {
			return nil, nil, err
		}
		if m.Node, buf, err = readNode(buf); err != nil {
			return nil, nil, err
		}
		if m.Site, buf, err = readNode(buf); err != nil {
			return nil, nil, err
		}
		if m.Schema, buf, err = readDigest(buf); err != nil {
			return nil, nil, err
		}
		if m.Incarnation, buf, err = readVarint(buf); err != nil {
			return nil, nil, err
		}
		if m.Addr, buf, err = readAddr(buf); err != nil {
			return nil, nil, err
		}
		return m, buf, nil
	case 1:
		var m MsgPull
		if m.Group, buf, err = readNode(buf); err != nil {
			return nil, nil, err
		}
		if m.Node, buf, err = readNode(buf); err != nil {
			return nil, nil, err
		}
		if m.Site, buf, err = readNode(buf); err != nil {
			return nil, nil, err
		}
		if m.Schema, buf, err = readDigest(buf); err != nil {
			return nil, nil, err
		}
		if len(buf) < 1 {
			return nil, nil, errProtocol("truncated option")
		}
		b := buf[0]
		buf = buf[1:]
		switch b {
		case 0:
		case 1:
			var id NodeID
			if id, buf, err = readNode(buf); err != nil {
				return nil, nil, err
			}
			m.ExpectedSite = &id
		default:
			return nil, nil, errProtocol("invalid option")
		}
		if m.Cursor, buf, err = readCursor(buf); err != nil {
			return nil, nil, err
		}
		return m, buf, nil
	case 2:
		var m MsgReset
		if m.Site, buf, err = readNode(buf); err != nil {
			return nil, nil, err
		}
		return m, buf, nil
	case 3:
		return MsgIdle{}, buf, nil
	case 4:
		var m MsgBatch
		if m.Site, buf, err = readNode(buf); err != nil {
			return nil, nil, err
		}
		if m.Cursor, buf, err = readCursor(buf); err != nil {
			return nil, nil, err
		}
		if m.Bytes, buf, err = readVarint(buf); err != nil {
			return nil, nil, err
		}
		if m.Digest, buf, err = readDigest(buf); err != nil {
			return nil, nil, err
		}
		return m, buf, nil
	case 5:
		var m MsgChunk
		var idx uint64
		if idx, buf, err = readVarint(buf); err != nil {
			return nil, nil, err
		}
		if idx > math.MaxUint32 {
			return nil, nil, errProtocol("chunk index overflow")
		}
		m.Index = uint32(idx)
		var data []byte
		if data, buf, err = readBytes(buf); err != nil {
			return nil, nil, err
		}
		m.Data = append([]byte(nil), data...)
		return m, buf, nil
	case 6:
		var m MsgSnapshotRequest
		if m.Group, buf, err = readNode(buf); err != nil {
			return nil, nil, err
		}
		if m.Node, buf, err = readNode(buf); err != nil {
			return nil, nil, err
		}
		if m.Site, buf, err = readNode(buf); err != nil {
			return nil, nil, err
		}
		if m.Schema, buf, err = readDigest(buf); err != nil {
			return nil, nil, err
		}
		return m, buf, nil
	case 7:
		var m MsgSnapshotManifest
		var data []byte
		if data, buf, err = readBytes(buf); err != nil {
			return nil, nil, err
		}
		m.Manifest = append([]byte(nil), data...)
		return m, buf, nil
	case 8:
		return MsgSchemaRequest{}, buf, nil
	case 9:
		var m MsgSchemaManifest
		var data []byte
		if data, buf, err = readBytes(buf); err != nil {
			return nil, nil, err
		}
		m.Manifest = append([]byte(nil), data...)
		return m, buf, nil
	case 10:
		var m MsgSchemaAck
		if m.Digest, buf, err = readDigest(buf); err != nil {
			return nil, nil, err
		}
		if m.Sequence, buf, err = readVarint(buf); err != nil {
			return nil, nil, err
		}
		return m, buf, nil
	case 11:
		return MsgEnd{}, buf, nil
	case 12:
		var m MsgAck
		if m.Digest, buf, err = readDigest(buf); err != nil {
			return nil, nil, err
		}
		return m, buf, nil
	case 13:
		var m MsgError
		if m.Text, buf, err = readString(buf); err != nil {
			return nil, nil, err
		}
		return m, buf, nil
	}
	return nil, nil, errProtocol(fmt.Sprintf("unknown message tag %d", tag))
}

// WriteFrame writes one length-prefixed frame. Payloads past
// FrameBytes fail with Overloaded before touching the stream.
func WriteFrame(w io.Writer, m Message) error {
	data, err := EncodeMessage(m)
	if err != nil {
		return err
	}
	if len(data) > FrameBytes {
		return errOverloaded("frame too large")
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(data)))
	if _, err := w.Write(hdr[:]); err != nil {
		return errProtocol(err.Error())
	}
	if _, err := w.Write(data); err != nil {
		return errProtocol(err.Error())
	}
	return nil
}

// ReadFrame reads one length-prefixed frame. Empty and oversized
// lengths fail closed.
func ReadFrame(r io.Reader) (Message, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, errProtocol("truncated frame header")
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n == 0 || n > FrameBytes {
		return nil, errProtocol("invalid frame length")
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, errProtocol("truncated frame")
	}
	return DecodeMessage(buf)
}

// Cell is one decoded CRSB change cell. Sig carries the v2
// 64-byte origin signature (nil for v1 cells).
type Cell struct {
	Table      string
	PK         []byte
	CID        string
	Val        CellVal
	ColVersion int64
	DBVersion  int64
	SiteID     []byte
	CL         int64
	Seq        int64
	Sig        []byte
}

// CellVal tags: 0 null, 1 integer, 2 real, 3 text, 4 blob.
type CellVal struct {
	Tag  byte
	Int  int64
	Real float64
	Blob []byte
}

func NullVal() CellVal          { return CellVal{} }
func IntVal(v int64) CellVal    { return CellVal{Tag: 1, Int: v} }
func RealVal(v float64) CellVal { return CellVal{Tag: 2, Real: v} }
func TextVal(v []byte) CellVal  { return CellVal{Tag: 3, Blob: v} }
func BlobVal(v []byte) CellVal  { return CellVal{Tag: 4, Blob: v} }

func appendField(out, v []byte) []byte {
	var l [4]byte
	binary.LittleEndian.PutUint32(l[:], uint32(len(v)))
	out = append(out, l[:]...)
	return append(out, v...)
}

// EncodeCells serializes cells to CRSB wire bytes: `CRSB` + version
// 1 + count + cells. Decoding an export and re-encoding reproduces
// the input byte-for-byte.
func EncodeCells(cells []Cell) []byte {
	blob := []byte{'C', 'R', 'S', 'B', 1, 0, 0, 0, 0, 0, 0, 0}
	binary.LittleEndian.PutUint32(blob[8:12], uint32(len(cells)))
	for _, c := range cells {
		blob = EncodeCell(blob, c)
	}
	return blob
}

// EncodeCellsV2 serializes cells to CRSB wire bytes with version 2
// (every cell carries its 64-byte origin signature). All cells must
// have a 64-byte Sig; otherwise EncodeCellsV2 returns nil.
func EncodeCellsV2(cells []Cell) []byte {
	blob := []byte{'C', 'R', 'S', 'B', 2, 0, 0, 0, 0, 0, 0, 0}
	binary.LittleEndian.PutUint32(blob[8:12], uint32(len(cells)))
	for _, c := range cells {
		nb := EncodeCellV2(blob, c)
		if nb == nil {
			return nil
		}
		blob = nb
	}
	return blob
}

// EncodeCellV2 appends one v2 cell record (EncodeCell plus the sig
// field). It returns nil unless the cell has a 64-byte Sig.
func EncodeCellV2(blob []byte, c Cell) []byte {
	if len(c.Sig) != 64 {
		return nil
	}
	blob = EncodeCell(blob, c)
	return appendField(blob, c.Sig)
}

// CellCanonical returns the signed bytes for one cell, byte-identical
// to murmur_cell_canonical: domain separator plus the hop-stable
// merge content (table, pk, cid, value, col_version, site).
// db_version is reassigned at every ingest hop, so it stays out;
// cl/seq ride opaquely (stored, echoed, never compared).
func CellCanonical(c Cell) []byte {
	out := []byte("MURMUR-CELL-SIGv1")
	out = append(out, 0)
	out = appendField(out, []byte(c.Table))
	out = appendField(out, c.PK)
	out = appendField(out, []byte(c.CID))
	var v [8]byte
	switch c.Val.Tag {
	case 0:
		out = append(out, 0)
	case 1:
		out = append(out, 1)
		binary.LittleEndian.PutUint64(v[:], uint64(c.Val.Int))
		out = append(out, v[:]...)
	case 2:
		out = append(out, 2)
		binary.LittleEndian.PutUint64(v[:], math.Float64bits(c.Val.Real))
		out = append(out, v[:]...)
	case 3:
		out = append(out, 3)
		out = appendField(out, c.Val.Blob)
	default:
		out = append(out, 4)
		out = appendField(out, c.Val.Blob)
	}
	binary.LittleEndian.PutUint64(v[:], uint64(c.ColVersion))
	out = append(out, v[:]...)
	return appendField(out, c.SiteID)
}

// EncodeCell appends one cell record. Export uses it to account the
// exact encoded length against max_batch_bytes before admitting a row.
func EncodeCell(blob []byte, c Cell) []byte {
	blob = appendField(blob, []byte(c.Table))
	blob = appendField(blob, c.PK)
	blob = appendField(blob, []byte(c.CID))
	var v [8]byte
	switch c.Val.Tag {
	case 0:
		blob = append(blob, 0)
	case 1:
		blob = append(blob, 1)
		binary.LittleEndian.PutUint64(v[:], uint64(c.Val.Int))
		blob = append(blob, v[:]...)
	case 2:
		blob = append(blob, 2)
		binary.LittleEndian.PutUint64(v[:], math.Float64bits(c.Val.Real))
		blob = append(blob, v[:]...)
	case 3:
		blob = append(blob, 3)
		blob = appendField(blob, c.Val.Blob)
	default:
		blob = append(blob, 4)
		blob = appendField(blob, c.Val.Blob)
	}
	binary.LittleEndian.PutUint64(v[:], uint64(c.ColVersion))
	blob = append(blob, v[:]...)
	binary.LittleEndian.PutUint64(v[:], uint64(c.DBVersion))
	blob = append(blob, v[:]...)
	blob = appendField(blob, c.SiteID)
	binary.LittleEndian.PutUint64(v[:], uint64(c.CL))
	blob = append(blob, v[:]...)
	binary.LittleEndian.PutUint64(v[:], uint64(c.Seq))
	blob = append(blob, v[:]...)
	return blob
}

// DecodeCells strictly decodes CRSB bytes: magic, version, and count
// are verified and no trailing bytes are allowed.
func DecodeCells(blob []byte) ([]Cell, error) {
	rest := blob
	take := func(n int) ([]byte, error) {
		if len(rest) < n {
			return nil, errProtocol("CRSB truncated")
		}
		out := rest[:n]
		rest = rest[n:]
		return out, nil
	}
	takeField := func() ([]byte, error) {
		lb, err := take(4)
		if err != nil {
			return nil, err
		}
		n := binary.LittleEndian.Uint32(lb)
		if uint64(n) > uint64(len(rest)) {
			return nil, errProtocol("CRSB truncated")
		}
		return take(int(n))
	}
	takeI64 := func() (int64, error) {
		b, err := take(8)
		if err != nil {
			return 0, err
		}
		return int64(binary.LittleEndian.Uint64(b)), nil
	}
	magic, err := take(4)
	if err != nil {
		return nil, err
	}
	if string(magic) != "CRSB" {
		return nil, errProtocol("CRSB magic")
	}
	ver, err := take(4)
	if err != nil {
		return nil, err
	}
	v2 := ver[0] == 2 && ver[1] == 0 && ver[2] == 0 && ver[3] == 0
	if !v2 && (ver[0] != 1 || ver[1] != 0 || ver[2] != 0 || ver[3] != 0) {
		return nil, errProtocol("CRSB version")
	}
	cl, err := take(4)
	if err != nil {
		return nil, err
	}
	count := binary.LittleEndian.Uint32(cl)
	if uint64(count) > uint64(len(rest))+1 {
		// Each cell needs at least one byte; absurd counts fail fast.
		return nil, errProtocol("CRSB truncated")
	}
	cells := make([]Cell, 0, min(count, 1<<20))
	for i := uint32(0); i < count; i++ {
		var c Cell
		tb, err := takeField()
		if err != nil {
			return nil, err
		}
		if !utf8.Valid(tb) {
			return nil, errProtocol("CRSB table")
		}
		c.Table = string(append([]byte(nil), tb...))
		pk, err := takeField()
		if err != nil {
			return nil, err
		}
		c.PK = append([]byte(nil), pk...)
		cb, err := takeField()
		if err != nil {
			return nil, err
		}
		if !utf8.Valid(cb) {
			return nil, errProtocol("CRSB cid")
		}
		c.CID = string(append([]byte(nil), cb...))
		tag, err := take(1)
		if err != nil {
			return nil, err
		}
		switch tag[0] {
		case 0:
		case 1:
			v, err := takeI64()
			if err != nil {
				return nil, err
			}
			c.Val = IntVal(v)
		case 2:
			b, err := take(8)
			if err != nil {
				return nil, err
			}
			c.Val = RealVal(math.Float64frombits(binary.LittleEndian.Uint64(b)))
		case 3:
			b, err := takeField()
			if err != nil {
				return nil, err
			}
			c.Val = TextVal(append([]byte(nil), b...))
		case 4:
			b, err := takeField()
			if err != nil {
				return nil, err
			}
			c.Val = BlobVal(append([]byte(nil), b...))
		default:
			return nil, errProtocol("CRSB value tag")
		}
		if c.ColVersion, err = takeI64(); err != nil {
			return nil, err
		}
		if c.DBVersion, err = takeI64(); err != nil {
			return nil, err
		}
		site, err := takeField()
		if err != nil {
			return nil, err
		}
		c.SiteID = append([]byte(nil), site...)
		if c.CL, err = takeI64(); err != nil {
			return nil, err
		}
		if c.Seq, err = takeI64(); err != nil {
			return nil, err
		}
		if v2 {
			sig, err := takeField()
			if err != nil {
				return nil, err
			}
			if len(sig) != 64 {
				return nil, errProtocol("CRSB sig")
			}
			c.Sig = append([]byte(nil), sig...)
		}
		cells = append(cells, c)
	}
	if len(rest) != 0 {
		return nil, errProtocol("CRSB trailing bytes")
	}
	return cells, nil
}

func min(a uint32, b uint32) uint32 {
	if a < b {
		return a
	}
	return b
}

// EncodeU64 serializes kv head values (postcard u64).
func EncodeU64(v uint64) []byte { return tx.EncodeU64(v) }

// DecodeU64 parses kv head values, rejecting trailing bytes.
func DecodeU64(b []byte) (uint64, error) {
	v, err := tx.DecodeU64(b)
	if err != nil {
		return 0, errProtocol(err.Error())
	}
	return v, nil
}

// ProgressKey is the applied-head kv key for an origin.
func ProgressKey(origin NodeID) []byte {
	return tx.ProgressKey(origin)
}

// ObservedKey is the observed-head kv key for an origin.
func ObservedKey(origin NodeID) []byte {
	return tx.ObservedKey(origin)
}
