package replication

import (
	"bytes"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func loadVector(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return b
}

func vecNode(b byte) NodeID {
	var id NodeID
	for i := range id {
		id[i] = b + byte(i)
	}
	return id
}

func vecSchema() [32]byte {
	var s [32]byte
	for i := range s {
		s[i] = 0xAA
	}
	return s
}

func vecDigest() [32]byte {
	var d [32]byte
	for i := range d {
		d[i] = 0xBB
	}
	return d
}

func vecKey() Key {
	return Key{Version: 42, Seq: 7, Table: "t", PK: []byte{1, 2, 3}, CID: "b"}
}

func TestGoldenKey(t *testing.T) {
	want := loadVector(t, "key.bin")
	enc := appendKey(nil, vecKey())
	if !bytes.Equal(enc, want) {
		t.Fatalf("key bytes:\n%x\nwant:\n%x", enc, want)
	}
	k, rest, err := readKey(want)
	if err != nil || len(rest) != 0 {
		t.Fatalf("decode: %v rest=%d", err, len(rest))
	}
	if !reflect.DeepEqual(k, vecKey()) {
		t.Fatalf("key = %+v", k)
	}
	neg, _, err := readKey(loadVector(t, "key_neg.bin"))
	if err != nil {
		t.Fatalf("neg decode: %v", err)
	}
	if neg.Version != -7 || neg.Seq != -1 || neg.Table != "" || len(neg.PK) != 0 || neg.CID != "" {
		t.Fatalf("neg = %+v", neg)
	}
	if enc := appendKey(nil, neg); !bytes.Equal(enc, loadVector(t, "key_neg.bin")) {
		t.Fatalf("neg re-encode mismatch: %x", enc)
	}
}

func TestGoldenCursors(t *testing.T) {
	if enc := EncodeCursor(Cursor{}); !bytes.Equal(enc, loadVector(t, "cursor_default.bin")) {
		t.Fatalf("default cursor: %x", enc)
	}
	through := int64(100)
	after := vecKey()
	full := Cursor{From: 42, Through: &through, After: &after}
	if enc := EncodeCursor(full); !bytes.Equal(enc, loadVector(t, "cursor_full.bin")) {
		t.Fatalf("full cursor:\n%x\nwant:\n%x", enc, loadVector(t, "cursor_full.bin"))
	}
	back, err := DecodeCursor(loadVector(t, "cursor_full.bin"))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if back.From != 42 || back.Through == nil || *back.Through != 100 || back.After == nil || !reflect.DeepEqual(*back.After, vecKey()) {
		t.Fatalf("cursor = %+v", back)
	}
	if _, err := DecodeCursor(append(loadVector(t, "cursor_full.bin"), 0)); err == nil {
		t.Fatal("trailing cursor byte accepted")
	}
}

func TestGoldenMessages(t *testing.T) {
	v4 := netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), 4401)
	v6 := netip.AddrPortFrom(netip.AddrFrom16([16]byte{15: 1}), 4401)
	after := vecKey()
	site := vecNode(3)
	data := make([]byte, 100)
	for i := range data {
		data[i] = byte(i)
	}
	cases := []struct {
		name string
		msg  Message
	}{
		{"msg_hello.bin", MsgHello{Group: vecNode(1), Node: vecNode(2), Site: vecNode(3), Schema: vecSchema(), Incarnation: 9, Addr: v4}},
		{"msg_hello_v6.bin", MsgHello{Group: vecNode(1), Node: vecNode(2), Site: vecNode(3), Schema: vecSchema(), Incarnation: 9, Addr: v6}},
		{"msg_pull.bin", MsgPull{Group: vecNode(1), Node: vecNode(2), Site: vecNode(3), Schema: vecSchema(), ExpectedSite: &site, Cursor: Cursor{From: 42, After: &after}}},
		{"msg_batch.bin", MsgBatch{Site: vecNode(3), Cursor: Cursor{From: 100}, Bytes: 12345, Digest: vecDigest()}},
		{"msg_chunk.bin", MsgChunk{Index: 3, Data: data}},
		{"msg_ack.bin", MsgAck{Digest: vecDigest()}},
		{"msg_idle.bin", MsgIdle{}},
		{"msg_end.bin", MsgEnd{}},
		{"msg_reset.bin", MsgReset{Site: vecNode(3)}},
		{"msg_error.bin", MsgError{Text: "boom"}},
		{"msg_snapshot_request.bin", MsgSnapshotRequest{Group: vecNode(1), Node: vecNode(2), Site: vecNode(3), Schema: vecSchema()}},
	}
	for _, c := range cases {
		want := loadVector(t, c.name)
		got, err := EncodeMessage(c.msg)
		if err != nil {
			t.Fatalf("%s encode: %v", c.name, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("%s:\n%x\nwant:\n%x", c.name, got, want)
		}
		back, err := DecodeMessage(want)
		if err != nil {
			t.Fatalf("%s decode: %v", c.name, err)
		}
		rt, err := EncodeMessage(back)
		if err != nil || !bytes.Equal(rt, want) {
			t.Fatalf("%s round-trip mismatch: %v", c.name, err)
		}
	}
	// Unit and manifest-only shapes round-trip without vectors.
	for _, m := range []Message{
		MsgSchemaRequest{},
		MsgSchemaManifest{Manifest: []byte{1, 2}},
		MsgSnapshotManifest{Manifest: []byte{3}},
		MsgSchemaAck{Digest: vecDigest(), Sequence: 9},
		MsgPull{Group: vecNode(1), Cursor: Cursor{}},
	} {
		enc, err := EncodeMessage(m)
		if err != nil {
			t.Fatalf("encode %T: %v", m, err)
		}
		back, err := DecodeMessage(enc)
		if err != nil {
			t.Fatalf("decode %T: %v", m, err)
		}
		rt, _ := EncodeMessage(back)
		if !bytes.Equal(rt, enc) {
			t.Fatalf("%T round-trip mismatch", m)
		}
	}
	if _, err := DecodeMessage([]byte{99}); err == nil {
		t.Fatal("unknown tag accepted")
	}
	if _, err := DecodeMessage(append(loadVector(t, "msg_idle.bin"), 0)); err == nil {
		t.Fatal("trailing message byte accepted")
	}
}

func TestGoldenCells(t *testing.T) {
	want := loadVector(t, "crsb_cells.bin")
	cells, err := DecodeCells(want)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(cells) != 5 {
		t.Fatalf("count = %d", len(cells))
	}
	if cells[0].Val.Tag != 0 || !reflect.DeepEqual(cells[1].Val, IntVal(-7)) || cells[2].Val.Real != 1.5 ||
		!bytes.Equal(cells[3].Val.Blob, []byte("hi")) || cells[3].Val.Tag != 3 ||
		!bytes.Equal(cells[4].Val.Blob, []byte{0, 1, 2}) || cells[4].Val.Tag != 4 {
		t.Fatalf("vals = %+v", cells)
	}
	if cells[1].Table != "t" || cells[1].CID != "b" || cells[1].ColVersion != 5 ||
		cells[1].DBVersion != 6 || cells[1].CL != 7 || cells[1].Seq != 8 {
		t.Fatalf("cell1 = %+v", cells[1])
	}
	if enc := EncodeCells(cells); !bytes.Equal(enc, want) {
		t.Fatalf("re-encode mismatch:\n%x\nwant:\n%x", enc, want)
	}
	// Strictness: bad magic, bad version, truncation, trailing bytes.
	bad := append([]byte(nil), want...)
	bad[0] = 'X'
	if _, err := DecodeCells(bad); err == nil {
		t.Fatal("bad magic accepted")
	}
	bad = append([]byte(nil), want...)
	bad[4] = 2
	if _, err := DecodeCells(bad); err == nil {
		t.Fatal("bad version accepted")
	}
	if _, err := DecodeCells(want[:len(want)-1]); err == nil {
		t.Fatal("truncation accepted")
	}
	if _, err := DecodeCells(append(append([]byte(nil), want...), 0)); err == nil {
		t.Fatal("trailing byte accepted")
	}
	bad = append([]byte(nil), want...)
	bad[len(bad)-1] ^= 0xFF
	if _, err := DecodeCells(bad); err == nil {
		// A flipped last byte still decodes (seq value changes);
		// integrity is the digest's job, checked by apply.
		t.Logf("note: last-byte flip changes seq, still well-formed")
	}
}

func TestGoldenKV(t *testing.T) {
	if enc := EncodeU64(300); !bytes.Equal(enc, loadVector(t, "u64_300.bin")) {
		t.Fatalf("u64 300: %x", enc)
	}
	if enc := EncodeU64(^uint64(0)); !bytes.Equal(enc, loadVector(t, "u64_max.bin")) {
		t.Fatalf("u64 max: %x", enc)
	}
	if v, err := DecodeU64(loadVector(t, "u64_300.bin")); err != nil || v != 300 {
		t.Fatalf("decode 300 = %d,%v", v, err)
	}
	if string(ProgressKey(vecNode(4))) != string(loadVector(t, "progress_key.txt")) {
		t.Fatalf("progress key = %q", ProgressKey(vecNode(4)))
	}
	if string(ObservedKey(vecNode(4))) != string(loadVector(t, "observed_key.txt")) {
		t.Fatalf("observed key = %q", ObservedKey(vecNode(4)))
	}
}

func TestFrameIO(t *testing.T) {
	var buf bytes.Buffer
	msgs := []Message{MsgIdle{}, MsgChunk{Index: 1, Data: []byte("payload")}, MsgError{Text: "x"}}
	for _, m := range msgs {
		if err := WriteFrame(&buf, m); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	for _, want := range msgs {
		got, err := ReadFrame(&buf)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		a, _ := EncodeMessage(got)
		b, _ := EncodeMessage(want)
		if !bytes.Equal(a, b) {
			t.Fatalf("frame mismatch: %T", want)
		}
	}
	if err := WriteFrame(&buf, MsgChunk{Index: 0, Data: make([]byte, FrameBytes)}); err == nil {
		t.Fatal("oversized frame accepted")
	}
	if _, err := ReadFrame(bytes.NewReader([]byte{0, 0, 0, 0})); err == nil {
		t.Fatal("empty frame accepted")
	}
	if _, err := ReadFrame(bytes.NewReader([]byte{0, 0, 0, 3, 0xff})); err == nil {
		t.Fatal("invalid frame accepted")
	}
}
