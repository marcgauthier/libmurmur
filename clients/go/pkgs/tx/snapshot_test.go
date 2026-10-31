package tx

import (
	"bytes"
	"crypto/sha256"
	"os"
	"sort"
	"strings"
	"sync"
	"testing"
)

// Memory is a map-backed Backend for state-machine tests.
type Memory struct {
	mu      sync.Mutex
	data    map[string][]byte
	applied int
}

func NewMemory() *Memory { return &Memory{data: map[string][]byte{}} }

func (m *Memory) CancelPending()                    {}
func (m *Memory) Identity() (NodeID, NodeID)        { return NodeID{1}, NodeID{2} }
func (m *Memory) Schema() ([]byte, error)           { return []byte("schema"), nil }
func (m *Memory) RetentionCheckpoint() error        { return nil }
func (m *Memory) ReclaimRetention() error           { return nil }
func (m *Memory) Observe(uint64, uint32) error      { return nil }
func (m *Memory) AcceptSchema([]byte) (bool, error) { return false, nil }
func (m *Memory) CreateSnapshot(NodeID) (Manifest, error) {
	return Manifest{}, errUnavailable("no")
}
func (m *Memory) AcknowledgeSnapshot(NodeID, NodeID, [32]byte) error {
	return errUnavailable("no")
}
func (m *Memory) PruneHistory(NodeID, uint64) (uint64, error) { return 0, nil }
func (m *Memory) ImportBridge(BridgeHeader, []byte) (bool, error) {
	return false, nil
}
func (m *Memory) ReleaseOwnership(string, []byte, *string) (bool, error) {
	return false, nil
}
func (m *Memory) Snapshot() ([]byte, error) { return []byte("snap"), nil }
func (m *Memory) SnapshotWithProgress() ([]byte, []Progress, error) {
	return []byte("snap"), nil, nil
}
func (m *Memory) Progress() ([]Progress, error) { return nil, nil }

func (m *Memory) Get(key []byte) ([]byte, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.data[string(key)]
	return append([]byte(nil), v...), ok, nil
}

func (m *Memory) GetMany(keys [][]byte) ([][]byte, []bool, error) {
	vals := make([][]byte, len(keys))
	flags := make([]bool, len(keys))
	for i, k := range keys {
		v, ok, _ := m.Get(k)
		vals[i], flags[i] = v, ok
	}
	return vals, flags, nil
}

func (m *Memory) GetManyBounded(keys [][]byte, maxBytes int) ([][]byte, []bool, error) {
	all, flags, err := m.GetMany(keys)
	if err != nil {
		return nil, nil, err
	}
	var vals [][]byte
	var out []bool
	used := 0
	for i, v := range all {
		if len(vals) > 0 && used+len(v) > maxBytes {
			break
		}
		used += len(v)
		vals, out = append(vals, v), append(out, flags[i])
		if used >= maxBytes {
			break
		}
	}
	return vals, out, nil
}

func (m *Memory) Keys(prefix []byte) ([][]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out [][]byte
	for k := range m.data {
		if strings.HasPrefix(k, string(prefix)) {
			out = append(out, []byte(k))
		}
	}
	sort.Slice(out, func(i, j int) bool { return bytes.Compare(out[i], out[j]) < 0 })
	return out, nil
}

func (m *Memory) KeysPage(prefix, after []byte, limit int) ([][]byte, error) {
	all, err := m.Keys(prefix)
	if err != nil {
		return nil, err
	}
	var out [][]byte
	for _, k := range all {
		if after != nil && bytes.Compare(k, after) <= 0 {
			continue
		}
		out = append(out, k)
		if len(out) == limit {
			break
		}
	}
	return out, nil
}

func (m *Memory) Commit(records []Record) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, r := range records {
		if r.IsDelete() {
			delete(m.data, string(r.Key))
		} else {
			m.data[string(r.Key)] = append([]byte(nil), r.Value...)
		}
	}
	return nil
}

func (m *Memory) Publish(records []Record) error { return m.Commit(records) }

func (m *Memory) Apply(payloads [][]byte, records []Record) (bool, error) {
	m.mu.Lock()
	m.applied++
	m.mu.Unlock()
	return true, m.Commit(records)
}

func fillID(b byte) NodeID {
	var id NodeID
	for i := range id {
		id[i] = b
	}
	return id
}

func TestGoldenTxCodecs(t *testing.T) {
	progress := Progress{Origin: fillID(0xcc), Applied: 300, Observed: 301, RetainedFrom: 7, RetainedThrough: 299}
	raw, err := os.ReadFile("testdata/vec_progress.bin")
	if err != nil {
		t.Fatal(err)
	}
	if string(EncodeProgress(progress)) != string(raw) {
		t.Fatalf("progress:\n got %x\nwant %x", EncodeProgress(progress), raw)
	}
	if back, err := DecodeProgress(raw); err != nil || back != progress {
		t.Fatalf("progress decode = %+v,%v", back, err)
	}
	manifest := Manifest{
		Database: fillID(0xaa), Donor: fillID(0x11), Recipient: fillID(0x22), Transfer: fillID(0xbb),
		Expires: 999999, Bytes: 70000, Digest: [32]byte{}, Schema: [32]byte{},
		Progress: []Progress{progress}, Chunks: [][32]byte{{1}, {2}},
	}
	for i := range manifest.Digest {
		manifest.Digest[i] = 0xdd
		manifest.Schema[i] = 0xee
	}
	for i := 1; i < 32; i++ {
		manifest.Chunks[0][i] = 0x01
		manifest.Chunks[1][i] = 0x02
	}
	raw, err = os.ReadFile("testdata/vec_manifest.bin")
	if err != nil {
		t.Fatal(err)
	}
	if string(EncodeManifest(manifest)) != string(raw) {
		t.Fatalf("manifest:\n got %x\nwant %x", EncodeManifest(manifest), raw)
	}
	back, err := DecodeManifest(raw)
	if err != nil {
		t.Fatal(err)
	}
	if string(EncodeManifest(back)) != string(raw) {
		t.Fatal("manifest decode unstable")
	}
	pin := Pin{
		Recipient: fillID(0x22),
		Boundary:  map[NodeID]uint64{fillID(0xcc): 300, fillID(0x01): 5},
		Target:    map[NodeID]uint64{fillID(0xcc): 400},
		HasTarget: true, Expires: 888,
	}
	for i := range pin.Digest {
		pin.Digest[i] = 0xf1
	}
	raw, err = os.ReadFile("testdata/vec_pin_some.bin")
	if err != nil {
		t.Fatal(err)
	}
	if string(EncodePin(pin)) != string(raw) {
		t.Fatalf("pin some:\n got %x\nwant %x", EncodePin(pin), raw)
	}
	pin2 := Pin{Recipient: fillID(0x22), Expires: 1}
	for i := range pin2.Digest {
		pin2.Digest[i] = 0xf2
	}
	raw, err = os.ReadFile("testdata/vec_pin_none.bin")
	if err != nil {
		t.Fatal(err)
	}
	if string(EncodePin(pin2)) != string(raw) {
		t.Fatalf("pin none:\n got %x\nwant %x", EncodePin(pin2), raw)
	}
	incoming := Incoming{Manifest: manifest, Deadline: 777}
	raw, err = os.ReadFile("testdata/vec_incoming.bin")
	if err != nil {
		t.Fatal(err)
	}
	if string(EncodeIncoming(incoming)) != string(raw) {
		t.Fatalf("incoming:\n got %x\nwant %x", EncodeIncoming(incoming), raw)
	}
	if _, err := DecodeIncoming(append(raw, 0)); err == nil {
		t.Fatal("trailing incoming byte accepted")
	}
}

func TestGoldenSignedSchema(t *testing.T) {
	s := SignedSchema{
		Database: fillID(0xaa), Signer: fillID(0x11), Sequence: 300,
		Schema: []byte{1, 2, 3, 4, 5}, Signature: []byte{9, 9},
	}
	raw, err := os.ReadFile("testdata/vec_signed_schema.bin")
	if err != nil {
		t.Fatal(err)
	}
	if string(EncodeSignedSchema(s)) != string(raw) {
		t.Fatalf("signed schema:\n got %x\nwant %x", EncodeSignedSchema(s), raw)
	}
	back, err := DecodeSignedSchema(raw)
	if err != nil {
		t.Fatal(err)
	}
	if string(EncodeSignedSchema(back)) != string(raw) {
		t.Fatal("decode unstable")
	}
	pre := s.SignedBytes()
	if string(pre[:len(SchemaSignDomain)]) != string(SchemaSignDomain) {
		t.Fatal("domain prefix")
	}
}

func TestKeys(t *testing.T) {
	id := fillID(0xab)
	if string(HeaderKey(OUT, id)) != "07/replication/snapshot-v1/out/"+id.String()+"/header" {
		t.Fatal("header key")
	}
	if string(ChunkKey(IN, id, 7)) != "07/replication/snapshot-v1/in/"+id.String()+"/chunk/00000007" {
		t.Fatal("chunk key")
	}
	if string(ProgressKey(id)) != "07/replication/applied/"+id.String() {
		t.Fatal("progress key")
	}
	if string(ObservedKey(id)) != "07/replication/observed/"+id.String() {
		t.Fatal("observed key")
	}
	if string(PeerKey(id)) != "07/replication/retention/peers/"+id.String() {
		t.Fatal("peer key")
	}
}

func TestReceiveMissingMaintain(t *testing.T) {
	be := NewMemory()
	donor := NodeID{2}
	transfer := fillID(0xbb)
	data := bytes.Repeat([]byte{7}, 100)
	m := Manifest{
		Database: NodeID{1}, Donor: donor, Recipient: NodeID{2}, Transfer: transfer,
		Expires: 999999, Bytes: uint64(len(data)), Progress: nil,
		Chunks: [][32]byte{sha256Sum(data)},
	}
	staged := Incoming{Manifest: m, Deadline: 999999}
	if err := be.Commit([]Record{Put(HeaderKey(IN, transfer), EncodeIncoming(staged))}); err != nil {
		t.Fatal(err)
	}
	missing, err := Missing(be, &staged)
	if err != nil || len(missing) != 1 || missing[0] != 0 {
		t.Fatalf("missing = %+v,%v", missing, err)
	}
	if err := Receive(be, donor, transfer, 0, data, 100); err != nil {
		t.Fatal(err)
	}
	if err := Receive(be, donor, transfer, 0, data, 100); err != nil {
		t.Fatal("idempotent receive failed")
	}
	if err := Receive(be, donor, transfer, 0, []byte{1}, 100); err == nil {
		t.Fatal("conflicting chunk accepted")
	}
	missing, err = Missing(be, &staged)
	if err != nil || len(missing) != 0 {
		t.Fatalf("missing = %+v,%v", missing, err)
	}
	got, err := StreamRead(be, &m, 10, 20)
	if err != nil || !bytes.Equal(got, data[10:30]) {
		t.Fatalf("stream = %x,%v", got, err)
	}
	if _, err := StreamRead(be, &m, 90, 20); err == nil {
		t.Fatal("overrun accepted")
	}
}

func sha256Sum(b []byte) [32]byte { return sha256.Sum256(b) }

func TestTouchPeer(t *testing.T) {
	be := NewMemory()
	node := fillID(0x22)
	if err := Touch(be, node, []Progress{{Origin: fillID(0x11), Applied: 5}}); err != nil {
		t.Fatal(err)
	}
	p, err := Peer(be, node)
	if err != nil || p == nil || p.Acknowledged[fillID(0x11)] != 5 || p.LastSeenMillis == 0 {
		t.Fatalf("peer = %+v,%v", p, err)
	}
	before := p.LastSeenMillis
	if err := Touch(be, node, []Progress{{Origin: fillID(0x11), Applied: 3}}); err != nil {
		t.Fatal(err)
	}
	p, _ = Peer(be, node)
	if p.Acknowledged[fillID(0x11)] != 5 || p.LastSeenMillis != before {
		t.Fatal("regressed or rewrote within window")
	}
	if err := Retire(be, node); err != nil {
		t.Fatal(err)
	}
	if err := Touch(be, node, nil); err == nil {
		t.Fatal("retired peer touched")
	}
}

func TestParseIDTx(t *testing.T) {
	id, err := ParseID("aa-bb-cc-ddeeff00112233445566778899")
	if err != nil {
		t.Fatal(err)
	}
	if id.String() != "aabbccddeeff00112233445566778899" {
		t.Fatal("dash strip")
	}
	if _, err := ParseID("00"); err == nil {
		t.Fatal("short accepted")
	}
	if _, err := ParseID("00000000000000000000000000000000"); err == nil {
		t.Fatal("zero accepted")
	}
}
