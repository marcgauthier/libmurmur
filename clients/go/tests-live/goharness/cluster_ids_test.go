package goharness

import "testing"

// Regression: ids were index+1 in the last byte only, so two clusters
// in one test minted identical ids and the engine accept path dropped
// the duplicate-id dials (dbid-isolation went vacuous).
func TestNewNodeIDsDistinctAcrossClusters(t *testing.T) {
	seen := map[[16]byte]bool{}
	for c := 0; c < 4; c++ {
		ids, err := newNodeIDs(16)
		if err != nil {
			t.Fatalf("newNodeIDs: %v", err)
		}
		for i, id := range ids {
			if id[15] != byte(i+1) {
				t.Fatalf("cluster %d id %d last byte = %d", c, i, id[15])
			}
			if seen[id] {
				t.Fatalf("duplicate id %x across clusters", id)
			}
			seen[id] = true
		}
	}
}

func TestNewNodeIDsRange(t *testing.T) {
	if _, err := newNodeIDs(0); err == nil {
		t.Error("newNodeIDs(0) succeeded, want error")
	}
	if _, err := newNodeIDs(256); err == nil {
		t.Error("newNodeIDs(256) succeeded, want error")
	}
}
