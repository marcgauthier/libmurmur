package replication

import (
	"strings"
	"testing"

	"github.com/marcgauthier/sqlite-murmur-go/clients/go/pkgs/tx"
)

func retentionParams() *RetentionParams {
	return &RetentionParams{MinimumRetained: 1000, MaximumOfflineMs: 604800000}
}

func putApplied(t *testing.T, be *CrrBackend, origin NodeID, seq uint64) {
	t.Helper()
	if err := be.Commit([]tx.Record{tx.Put(tx.ProgressKey(origin), tx.EncodeU64(seq))}); err != nil {
		t.Fatal(err)
	}
}

func ackPeer(t *testing.T, be *CrrBackend, peer, origin NodeID, seq uint64) {
	t.Helper()
	if err := tx.Touch(be, peer, []tx.Progress{{Origin: origin, Applied: seq, Observed: seq}}); err != nil {
		t.Fatal(err)
	}
}

func floorOf(t *testing.T, be *CrrBackend, origin NodeID) uint64 {
	t.Helper()
	raw, ok, err := be.Get(tx.FloorKey(origin))
	if err != nil || !ok {
		t.Fatalf("floor missing: %v %v", ok, err)
	}
	v, err := tx.DecodeU64(raw)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestMyStreamFloorMinLiveAck(t *testing.T) {
	group := fillNode(1)
	be, _, e := openBackend(t, group, "02020202020202020202020202020202")
	own := e.node
	fast := fillNode(9)
	slow := fillNode(8)
	ackPeer(t, be, fast, own, 5000)
	ackPeer(t, be, slow, own, 3000)
	online := map[NodeID]bool{fast: true, slow: true}
	floor, err := MyStreamFloor(be, retentionParams(), online, own, 9000, 1000000, 0)
	if err != nil || floor != 2000 {
		t.Fatalf("floor = %d,%v", floor, err)
	}
	floor, err = MyStreamFloor(be, retentionParams(), online, own, 2500, 1000000, 0)
	if err != nil || floor != 1500 {
		t.Fatalf("capped = %d,%v", floor, err)
	}
	if err := tx.Retire(be, slow); err != nil {
		t.Fatal(err)
	}
	floor, err = MyStreamFloor(be, retentionParams(), online, own, 9000, 1000000, 0)
	if err != nil || floor != 4000 {
		t.Fatalf("survivor = %d,%v", floor, err)
	}
	online[fillNode(7)] = true
	floor, err = MyStreamFloor(be, retentionParams(), online, own, 9000, 1000000, 0)
	if err != nil || floor != 0 {
		t.Fatalf("unrecorded = %d,%v", floor, err)
	}
}

func TestMyStreamFloorSingleNode(t *testing.T) {
	group := fillNode(1)
	be, _, e := openBackend(t, group, "02020202020202020202020202020202")
	floor, err := MyStreamFloor(be, retentionParams(), map[NodeID]bool{}, e.node, 5000, 1000000, 0)
	if err != nil || floor != 4000 {
		t.Fatalf("floor = %d,%v", floor, err)
	}
	seeded := retentionParams()
	seeded.BootstrapNonempty = true
	floor, err = MyStreamFloor(be, seeded, map[NodeID]bool{}, e.node, 5000, 30000, 0)
	if err != nil || floor != 0 {
		t.Fatalf("young = %d,%v", floor, err)
	}
}

func TestFloorsAdvanceToTailCap(t *testing.T) {
	group := fillNode(1)
	be, _, _ := openBackend(t, group, "02020202020202020202020202020202")
	origin := fillNode(7)
	putApplied(t, be, origin, 5000)
	moved, err := CollectFloors(be, retentionParams(), map[NodeID]bool{}, 1000000, 0)
	if err != nil || moved != 1 {
		t.Fatalf("moved = %d,%v", moved, err)
	}
	if f := floorOf(t, be, origin); f != 4000 {
		t.Fatalf("floor = %d", f)
	}
	heads, err := be.Progress()
	if err != nil {
		t.Fatal(err)
	}
	var found *tx.Progress
	for i := range heads {
		if heads[i].Origin == origin {
			found = &heads[i]
		}
	}
	if found == nil || found.RetainedFrom != 4001 || found.RetainedThrough != 5000 {
		t.Fatalf("window = %+v", found)
	}
	moved, err = CollectFloors(be, retentionParams(), map[NodeID]bool{}, 2000000, 0)
	if err != nil || moved != 0 {
		t.Fatalf("second moved = %d,%v", moved, err)
	}
}

func TestUnrecordedOnlinePinsFloor(t *testing.T) {
	group := fillNode(1)
	be, _, _ := openBackend(t, group, "02020202020202020202020202020202")
	origin := fillNode(7)
	putApplied(t, be, origin, 5000)
	moved, err := CollectFloors(be, retentionParams(), map[NodeID]bool{fillNode(9): true}, 1000000, 0)
	if err != nil || moved != 0 {
		t.Fatalf("moved = %d,%v", moved, err)
	}
	if _, ok, _ := be.Get(tx.FloorKey(origin)); ok {
		t.Fatal("floor written")
	}
}

func TestRetiredPeerIgnored(t *testing.T) {
	group := fillNode(1)
	be, _, _ := openBackend(t, group, "02020202020202020202020202020202")
	origin := fillNode(7)
	peer := fillNode(9)
	putApplied(t, be, origin, 5000)
	ackPeer(t, be, peer, origin, 100)
	moved, err := CollectFloors(be, retentionParams(), map[NodeID]bool{peer: true}, 1000000, 0)
	if err != nil || moved != 1 {
		t.Fatalf("moved = %d,%v", moved, err)
	}
	if f := floorOf(t, be, origin); f != 100 {
		t.Fatalf("floor = %d", f)
	}
	if err := tx.Retire(be, peer); err != nil {
		t.Fatal(err)
	}
	moved, err = CollectFloors(be, retentionParams(), map[NodeID]bool{}, 2000000, 0)
	if err != nil || moved != 1 {
		t.Fatalf("second moved = %d,%v", moved, err)
	}
	if f := floorOf(t, be, origin); f != 4000 {
		t.Fatalf("floor = %d", f)
	}
}

func TestTouchRetireStatusRoundTrip(t *testing.T) {
	group := fillNode(1)
	be, _, _ := openBackend(t, group, "02020202020202020202020202020202")
	peer := fillNode(9)
	origin := fillNode(7)
	ackPeer(t, be, peer, origin, 42)
	status, err := tx.Status(be)
	if err != nil || len(status.Peers) != 1 {
		t.Fatalf("status = %+v,%v", status, err)
	}
	if status.Peers[0].Acknowledged[origin] != 42 || status.Peers[0].Retired {
		t.Fatalf("peer = %+v", status.Peers[0])
	}
	if err := tx.Retire(be, peer); err != nil {
		t.Fatal(err)
	}
	status, err = tx.Status(be)
	if err != nil || !status.Peers[0].Retired {
		t.Fatalf("retired = %+v,%v", status, err)
	}
	if err := tx.Touch(be, peer, nil); err == nil {
		t.Fatal("retired touch accepted")
	}
}

func TestRetentionPassPrunesTombstones(t *testing.T) {
	group := mustNode(t, strings.Repeat("aa", 16))
	e, db := openEngine(t, group, strings.Repeat("11", 16))
	makeSyncTable(t, db, "t")
	// Tombstones land at db_version 2; a third transaction moves the
	// acked floor (current - min_kept) onto them.
	if err := db.Exec("INSERT INTO t VALUES(1,'x'),(2,'y'); DELETE FROM t; INSERT INTO t VALUES(3,'z');"); err != nil {
		t.Fatal(err)
	}
	if err := SetSetting(db, "retention_min_kept", "1"); err != nil {
		t.Fatal(err)
	}
	peer := mustNode(t, strings.Repeat("22", 16))
	e.conns[peer] = &stubSession{id: peer}
	be := NewBackend(db, group, e.node)
	current, err := DbVersion(db)
	if err != nil {
		t.Fatal(err)
	}
	ackPeer(t, be, peer, e.node, uint64(current))
	before, err := countRows(db, "SELECT COUNT(*) FROM t__crsql_clock WHERE col_name='-1'")
	if err != nil || before == 0 {
		t.Fatalf("tombstones = %d,%v", before, err)
	}
	floors, pruned := e.RetentionPass()
	if floors != 1 {
		t.Fatalf("floors = %d", floors)
	}
	after, err := countRows(db, "SELECT COUNT(*) FROM t__crsql_clock WHERE col_name='-1'")
	if err != nil {
		t.Fatal(err)
	}
	if pruned == 0 || after >= before {
		t.Fatalf("pruned=%d before=%d after=%d", pruned, before, after)
	}
	mark, err := GCWatermark(db)
	if err != nil || mark == 0 {
		t.Fatalf("watermark = %d,%v", mark, err)
	}
}

func TestTransferTouchWiring(t *testing.T) {
	group := mustNode(t, strings.Repeat("aa", 16))
	donor, donorDB := openEngine(t, group, strings.Repeat("11", 16))
	makeSyncTable(t, donorDB, "t")
	if err := donorDB.Exec("INSERT INTO t VALUES(1,'x');"); err != nil {
		t.Fatal(err)
	}
	receiver, receiverDB := openEngine(t, group, strings.Repeat("22", 16))
	makeSyncTable(t, receiverDB, "t")
	pipes := &servePipe{t: t, donor: donor, peer: receiver.node}
	more := true
	for i := 0; i < 3 && more; i++ {
		w, r, err := pipes.open()
		if err != nil {
			t.Fatal(err)
		}
		more, err = receiver.PullOnce(donor.node, w, r)
		if err != nil {
			t.Fatal(err)
		}
	}
	pipes.check()
	donorBe := NewBackend(donorDB, group, donor.node)
	st, err := tx.Status(donorBe)
	if err != nil || len(st.Peers) != 1 || st.Peers[0].Node != receiver.node {
		t.Fatalf("donor status = %+v,%v", st, err)
	}
	if st.Peers[0].Acknowledged[donor.node] == 0 {
		t.Fatal("donor has no ack of receiver")
	}
	receiverBe := NewBackend(receiverDB, group, receiver.node)
	st, err = tx.Status(receiverBe)
	if err != nil || len(st.Peers) != 1 || st.Peers[0].Node != donor.node {
		t.Fatalf("receiver status = %+v,%v", st, err)
	}
}
