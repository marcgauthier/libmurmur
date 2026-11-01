package driver

import (
	"encoding/json"
	"path/filepath"
	"testing"

	sqlite "github.com/marcgauthier/libmurmur/clients/go/bindings/sqlite"
)

// Regression: health_triple inverted the murmur_cfg_atoi return code, so
// budgets.stage_bytes and scheduler.pending_config were always null.
func TestHealthExposesStageAndPending(t *testing.T) {
	if err := Init(-1048576, 100); err != nil {
		t.Fatalf("Init: %v", err)
	}
	conn, err := sqlite.Open(filepath.Join(t.TempDir(), "health.db"),
		sqlite.OpenReadWrite|sqlite.OpenCreate)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer conn.Close()
	if err := EnsureSchema(conn.NativeDB()); err != nil {
		t.Fatalf("EnsureSchema: %v", err)
	}
	n := New(conn.NativeDB())
	defer n.Close()

	var h struct {
		Budgets struct {
			StageBytes *int64 `json:"stage_bytes"`
		} `json:"budgets"`
		Scheduler struct {
			PendingConfig *struct {
				LocalShare uint64 `json:"local_share"`
			} `json:"pending_config"`
		} `json:"scheduler"`
	}
	if err := json.Unmarshal([]byte(n.Health()), &h); err != nil {
		t.Fatalf("unmarshal health: %v", err)
	}
	if h.Budgets.StageBytes == nil {
		t.Error("budgets.stage_bytes is null, want a number")
	}
	if h.Scheduler.PendingConfig == nil {
		t.Fatal("scheduler.pending_config is null, want an object")
	}
	if h.Scheduler.PendingConfig.LocalShare < 1 || h.Scheduler.PendingConfig.LocalShare > 99 {
		t.Errorf("local_share = %d, want 1..99", h.Scheduler.PendingConfig.LocalShare)
	}
}
