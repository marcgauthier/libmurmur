package replication

import (
	"io"
	"net"
	"strings"
	"testing"

	"github.com/marcgauthier/libmurmur/clients/go/bindings/sqlite"
	"github.com/marcgauthier/libmurmur/clients/go/pkgs/tx"
)

func openBackend(t *testing.T, group NodeID, nodeHex string) (*CrrBackend, *sqlite.Conn, *Engine) {
	t.Helper()
	e, db := openEngine(t, group, nodeHex)
	return NewBackend(db, group, e.node), db, e
}

func TestBackendKV(t *testing.T) {
	group := mustNode(t, strings.Repeat("aa", 16))
	be, _, e := openBackend(t, group, strings.Repeat("11", 16))
	if g, n := be.Identity(); g != group || n != e.node {
		t.Fatal("identity")
	}
	if err := be.Commit([]tx.Record{tx.Put([]byte("k/1"), []byte("v1")), tx.Put([]byte("k/2"), []byte("v22"))}); err != nil {
		t.Fatal(err)
	}
	v, ok, err := be.Get([]byte("k/1"))
	if err != nil || !ok || string(v) != "v1" {
		t.Fatalf("get = %q,%v,%v", v, ok, err)
	}
	if _, ok, _ := be.Get([]byte("k/9")); ok {
		t.Fatal("phantom hit")
	}
	vals, flags, err := be.GetMany([][]byte{[]byte("k/2"), []byte("k/9"), []byte("k/1")})
	if err != nil || len(vals) != 3 || !flags[0] || flags[1] || !flags[2] {
		t.Fatalf("getmany = %+v,%v,%v", vals, flags, err)
	}
	if string(vals[0]) != "v22" || string(vals[2]) != "v1" {
		t.Fatal("order")
	}
	vals, _, err = be.GetManyBounded([][]byte{[]byte("k/1"), []byte("k/2")}, 2)
	if err != nil || len(vals) != 1 {
		t.Fatalf("bounded = %d,%v", len(vals), err)
	}
	keys, err := be.Keys([]byte("k/"))
	if err != nil || len(keys) != 2 || string(keys[0]) != "k/1" {
		t.Fatalf("keys = %+v,%v", keys, err)
	}
	page, err := be.KeysPage([]byte("k/"), []byte("k/1"), 10)
	if err != nil || len(page) != 1 || string(page[0]) != "k/2" {
		t.Fatalf("page = %+v,%v", page, err)
	}
	if err := be.Commit([]tx.Record{tx.Delete([]byte("k/1"))}); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := be.Get([]byte("k/1")); ok {
		t.Fatal("delete missed")
	}
	if err := be.Publish([]tx.Record{tx.Put([]byte("k/3"), []byte("v"))}); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := be.Get([]byte("k/3")); !ok {
		t.Fatal("publish missed")
	}
}

func TestBackendProgressObserve(t *testing.T) {
	group := mustNode(t, strings.Repeat("aa", 16))
	be, db, e := openBackend(t, group, strings.Repeat("11", 16))
	makeSyncTable(t, db, "t")
	if err := db.Exec("INSERT INTO t VALUES(1,'x');"); err != nil {
		t.Fatal(err)
	}
	peer := mustNode(t, strings.Repeat("22", 16))
	if err := be.Commit([]tx.Record{
		tx.Put(tx.ProgressKey(peer), tx.EncodeU64(9)),
		tx.Put(tx.ObservedKey(peer), tx.EncodeU64(12)),
	}); err != nil {
		t.Fatal(err)
	}
	heads, err := be.Progress()
	if err != nil {
		t.Fatal(err)
	}
	byOrigin := map[NodeID]tx.Progress{}
	for _, h := range heads {
		byOrigin[h.Origin] = h
	}
	if byOrigin[peer].Applied != 9 || byOrigin[peer].Observed != 12 {
		t.Fatalf("peer heads = %+v", byOrigin[peer])
	}
	current, _ := DbVersion(db)
	if byOrigin[e.node].Applied != uint64(current) {
		t.Fatalf("live head = %+v, current %d", byOrigin[e.node], current)
	}
	m1, l1, err := clockObserve(db, 100, 2)
	if err != nil || m1 != 100 || l1 != 2 {
		t.Fatalf("clock = %d,%d,%v", m1, l1, err)
	}
	m2, l2, err := clockObserve(db, 90, 9)
	if err != nil || m2 != 100 || l2 != 2 {
		t.Fatalf("clock regressed = %d,%d", m2, l2)
	}
	if err := be.Observe(110, 1); err != nil {
		t.Fatal(err)
	}
	if _, _, err := clockObserve(db, 0, 0); err != nil {
		t.Fatal(err)
	}
	if err := be.RetentionCheckpoint(); err != nil {
		t.Fatal(err)
	}
	if n, err := be.PruneHistory(peer, 5); err != nil || n != 0 {
		t.Fatalf("prune = %d,%v", n, err)
	}
	if err := be.ReclaimRetention(); err != nil {
		t.Fatal(err)
	}
	if ok, err := be.ImportBridge(tx.BridgeHeader{}, nil); err == nil || ok {
		t.Fatal("invalid bridge policy accepted")
	}
	if ok, err := be.ReleaseOwnership("t", nil, nil); err == nil || ok {
		t.Fatal("invalid ownership key accepted")
	}
}

func TestBackendSnapshotOffline(t *testing.T) {
	group := mustNode(t, strings.Repeat("aa", 16))
	be, db, _ := openBackend(t, group, strings.Repeat("11", 16))
	makeSyncTable(t, db, "t")
	if err := db.Exec("INSERT INTO t VALUES(1,'x');"); err != nil {
		t.Fatal(err)
	}
	raw, err := be.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	snap, err := DecodeCrrSnapshot(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Segments) == 0 || snap.Version <= 0 {
		t.Fatalf("snapshot = %+v", snap)
	}
	raw2, heads, err := be.SnapshotWithProgress()
	if err != nil || string(raw) != string(raw2) {
		t.Fatalf("snapshot+progress = %d,%d,%v", len(raw2), len(heads), err)
	}
	// No stored heads on a fresh database (live merge is Progress-only).
	if len(heads) != 0 {
		t.Fatalf("heads = %d, want 0", len(heads))
	}
	off := NewOfflineBackend(db, group, mustNode(t, strings.Repeat("11", 16)))
	if _, err := off.Snapshot(); err == nil {
		t.Fatal("offline snapshot served")
	}
	if _, ok, _ := off.Get([]byte("k/3")); ok {
		t.Fatal("offline phantom")
	}
	if _, err := be.CreateSnapshot(group); err == nil {
		t.Fatal("create snapshot served")
	}
}

func TestSnapshotServeFetchLoopback(t *testing.T) {
	group := mustNode(t, strings.Repeat("aa", 16))
	donor, donorDB := openEngine(t, group, strings.Repeat("11", 16))
	makeSyncTable(t, donorDB, "t")
	if err := donorDB.Exec("INSERT INTO t VALUES(1,'x'),(2,'y');"); err != nil {
		t.Fatal(err)
	}
	// Stored donor head: the manifest boundary carries it to the peer.
	donorVer, err := DbVersion(donorDB)
	if err != nil {
		t.Fatal(err)
	}
	donorBe0 := NewBackend(donorDB, group, donor.node)
	if err := donorBe0.Commit([]tx.Record{
		tx.Put(tx.ProgressKey(donor.node), tx.EncodeU64(uint64(donorVer))),
		tx.Put(tx.ObservedKey(donor.node), tx.EncodeU64(uint64(donorVer))),
	}); err != nil {
		t.Fatal(err)
	}
	receiver, receiverDB := openEngine(t, group, strings.Repeat("22", 16))
	makeSyncTable(t, receiverDB, "t")
	if err := SetSetting(receiverDB, "snapshot_trusted_sources", `["`+donor.node.String()+`"]`); err != nil {
		t.Fatal(err)
	}
	receiver.conns[donor.node] = &stubSession{id: donor.node}

	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	serveErr := make(chan error, 1)
	go func() { serveErr <- donor.ServeStream(receiver.node, c1, c1) }()
	transfer, err := receiver.FetchSnapshot(donor.node, func() (io.Writer, io.Reader, error) {
		return c2, c2, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if transfer.IsZero() {
		t.Fatal("zero transfer")
	}
	if err := <-serveErr; err != nil {
		t.Fatal(err)
	}
	st, err := receiverDB.Prepare("SELECT b FROM t WHERE a=1")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if done, err := st.Step(); err != nil || done {
		t.Fatalf("row missing: %v %v", done, err)
	}
	if st.ColumnText(0) != "x" {
		t.Fatalf("b = %q", st.ColumnText(0))
	}
	st.Close()
	// Progress heads advanced past the snapshot boundary.
	raw, ok, err := kvGet(receiverDB, ProgressKey(donor.node))
	if err != nil || !ok {
		t.Fatalf("applied head missing: %v %v", ok, err)
	}
	applied, err := DecodeU64(raw)
	if err != nil || applied != uint64(donorVer) {
		t.Fatalf("applied = %d,%v want %d", applied, err, donorVer)
	}
	receiver.mu.Lock()
	gotApplied := receiver.applied
	receiver.mu.Unlock()
	donor.mu.Lock()
	gotSent := donor.sent
	donor.mu.Unlock()
	if gotApplied != 1 || gotSent != 1 {
		t.Fatalf("applied=%d sent=%d, want 1/1", gotApplied, gotSent)
	}
	// Receipt is durable; IN staging is reaped.
	be := NewBackend(receiverDB, group, receiver.node)
	keys, err := be.Keys(tx.IN)
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range keys {
		if strings.HasSuffix(string(k), "/header") {
			t.Fatalf("staged header survived: %s", k)
		}
	}
	rkeys, err := be.Keys(tx.RECEIPTS)
	if err != nil || len(rkeys) != 1 {
		t.Fatalf("receipts = %d,%v", len(rkeys), err)
	}
}

func TestSnapshotTrust(t *testing.T) {
	group := mustNode(t, strings.Repeat("aa", 16))
	donor, donorDB := openEngine(t, group, strings.Repeat("11", 16))
	makeSyncTable(t, donorDB, "t")
	if err := donorDB.Exec("INSERT INTO t VALUES(1,'x');"); err != nil {
		t.Fatal(err)
	}
	receiver, receiverDB := openEngine(t, group, strings.Repeat("22", 16))
	makeSyncTable(t, receiverDB, "t")
	// No trust configured: the donor is unlisted.
	receiver.conns[donor.node] = &stubSession{id: donor.node}
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	serveErr := make(chan error, 1)
	go func() { serveErr <- donor.ServeStream(receiver.node, c1, c1) }()
	_, err := receiver.FetchSnapshot(donor.node, func() (io.Writer, io.Reader, error) {
		return c2, c2, nil
	})
	if err == nil || !strings.Contains(err.Error(), "trust") {
		t.Fatalf("untrusted err = %v", err)
	}
	// The receiver stopped reading after the manifest; close the pipe
	// so the donor's chunk writes fail instead of blocking forever.
	c1.Close()
	c2.Close()
	<-serveErr
	// Trust the donor but expire the manifest: build directly with a
	// zero lifetime and confirm accept refuses.
	if err := SetSetting(receiverDB, "snapshot_trusted_sources", `["`+donor.node.String()+`"]`); err != nil {
		t.Fatal(err)
	}
	params, err := SnapshotParamsFrom(receiverDB)
	if err != nil {
		t.Fatal(err)
	}
	donorBe := NewBackend(donorDB, group, donor.node)
	manifest, err := BuildSnapshotFor(donorDB, donorBe, params, 1<<20, 1<<20, receiver.node, 1000, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(manifest.Chunks) == 0 || manifest.Bytes == 0 {
		t.Fatal("empty build")
	}
	receiverBe := NewBackend(receiverDB, group, receiver.node)
	expired := manifest
	expired.Expires = 500
	if err := AcceptSnapshot(receiverBe, params, donor.node, expired, 1000); errKind(err) != "Auth" {
		t.Fatalf("expired err = %v", err)
	}
	// Chunkless manifests are in-progress builds, never servable.
	chunkless := manifest
	chunkless.Chunks = nil
	if err := AcceptSnapshot(receiverBe, params, donor.node, chunkless, 1000); err == nil {
		t.Fatal("chunkless accepted")
	}
}
