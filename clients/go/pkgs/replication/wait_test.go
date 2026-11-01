package replication

import (
	"testing"
	"time"

	"github.com/marcgauthier/libmurmur/clients/go/pkgs/tx"
)

func TestObservedDeficit(t *testing.T) {
	heads := []tx.Progress{
		{Origin: fillNode(1), Applied: 10, Observed: 12},
		{Origin: fillNode(2), Applied: 5, Observed: 5},
	}
	if d := ObservedDeficit(heads); d != 2 {
		t.Fatalf("deficit = %d", d)
	}
	if d := ObservedDeficit(nil); d != 0 {
		t.Fatalf("empty = %d", d)
	}
}

func TestWaitApplied(t *testing.T) {
	group := fillNode(1)
	be, _, _ := openBackend(t, group, "02020202020202020202020202020202")
	if ok, err := WaitForApplied(be, fillNode(9), 0, 0); err != nil || !ok {
		t.Fatalf("zero = %v,%v", ok, err)
	}
	putApplied(t, be, fillNode(7), 10)
	if ok, err := WaitForApplied(be, fillNode(7), 10, 50*time.Millisecond); err != nil || !ok {
		t.Fatalf("reached = %v,%v", ok, err)
	}
	if ok, err := WaitForApplied(be, fillNode(7), 9, 0); err != nil || !ok {
		t.Fatalf("covered = %v,%v", ok, err)
	}
	if ok, err := WaitForApplied(be, fillNode(7), 11, 0); err != nil || ok {
		t.Fatalf("unreached zero-timeout = %v,%v", ok, err)
	}
	start := time.Now()
	if ok, err := WaitForApplied(be, fillNode(7), 11, 150*time.Millisecond); err != nil || ok {
		t.Fatalf("timeout = %v,%v", ok, err)
	}
	if time.Since(start) < 100*time.Millisecond {
		t.Fatal("returned before polling")
	}
}

func TestWaitLag(t *testing.T) {
	group := fillNode(1)
	be, _, _ := openBackend(t, group, "02020202020202020202020202020202")
	if ok, err := WaitForLag(be, 0, 0); err != nil || !ok {
		t.Fatalf("empty = %v,%v", ok, err)
	}
	if err := be.Commit([]tx.Record{tx.Put(tx.ObservedKey(fillNode(7)), tx.EncodeU64(10))}); err != nil {
		t.Fatal(err)
	}
	if ok, err := WaitForLag(be, 10, 0); err != nil || !ok {
		t.Fatalf("bound met = %v,%v", ok, err)
	}
	if ok, err := WaitForLag(be, 9, 150*time.Millisecond); err != nil || ok {
		t.Fatalf("unmet = %v,%v", ok, err)
	}
	putApplied(t, be, fillNode(7), 10)
	if ok, err := WaitForLag(be, 9, 0); err != nil || !ok {
		t.Fatalf("caught up = %v,%v", ok, err)
	}
}
