package replication

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/marcgauthier/libmurmur/clients/go/bindings/sqlite"
)

// openSQL binds a fresh offline engine to a memory database and
// installs the SQL surface.
func openSQL(t *testing.T) (*sqlite.Conn, *Engine) {
	t.Helper()
	db, err := sqlite.Open(":memory:", sqlite.OpenReadWrite|sqlite.OpenCreate)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	eng := New(db, nil)
	if err := RegisterSQL(db, eng); err != nil {
		t.Fatal(err)
	}
	return db, eng
}

func queryOneText(t *testing.T, db *sqlite.Conn, q string) (string, error) {
	t.Helper()
	st, err := db.Prepare(q)
	if err != nil {
		return "", err
	}
	defer st.Close()
	done, err := st.Step()
	if err != nil {
		return "", err
	}
	if done {
		return "", nil
	}
	return st.ColumnText(0), nil
}

// requireEngineErr runs q, expects a murmur extended code plus a
// message fragment.
func requireEngineErr(t *testing.T, db *sqlite.Conn, q string, code int32, frag string) {
	t.Helper()
	_, err := queryOneText(t, db, "SELECT "+q)
	if err == nil {
		t.Fatalf("%s: expected error", q)
	}
	var se *sqlite.Error
	if !errors.As(err, &se) {
		t.Fatalf("%s: not a sqlite error: %v", q, err)
	}
	if int32(se.ExtCode) != code {
		t.Fatalf("%s: ext code %d, want %d (%v)", q, se.ExtCode, code, err)
	}
	if !strings.Contains(se.Msg, frag) {
		t.Fatalf("%s: message %q misses %q", q, se.Msg, frag)
	}
}

// requireAutocommitErr runs q inside a transaction and expects the
// engine Invalid code.
func requireAutocommitErr(t *testing.T, db *sqlite.Conn, q string, frag string) {
	t.Helper()
	if err := db.Exec("BEGIN"); err != nil {
		t.Fatal(err)
	}
	_, err := queryOneText(t, db, "SELECT "+q)
	rbErr := db.Exec("ROLLBACK")
	if err == nil {
		t.Fatalf("%s: expected autocommit error", q)
	}
	var se *sqlite.Error
	if !errors.As(err, &se) || int32(se.ExtCode) != codeInvalid {
		t.Fatalf("%s: want Invalid code, got %v", q, err)
	}
	if !strings.Contains(se.Msg, frag) {
		t.Fatalf("%s: message %q misses %q", q, se.Msg, frag)
	}
	if rbErr != nil {
		t.Fatal(rbErr)
	}
}

func TestSQLStoppedShapes(t *testing.T) {
	db, _ := openSQL(t)

	status, err := queryOneText(t, db, "SELECT murmur_status()")
	if err != nil {
		t.Fatal(err)
	}
	if status != `{"running":false}` {
		t.Fatalf("stopped status = %s", status)
	}

	progress, err := queryOneText(t, db, "SELECT murmur_progress()")
	if err != nil {
		t.Fatal(err)
	}
	if progress != `[]` {
		t.Fatalf("stopped progress = %s", progress)
	}

	health, err := queryOneText(t, db, "SELECT murmur_health()")
	if err != nil {
		t.Fatal(err)
	}
	var hh map[string]any
	if err := json.Unmarshal([]byte(health), &hh); err != nil {
		t.Fatalf("health json: %v (%s)", err, health)
	}
	for _, key := range []string{"version", "replication", "scheduler", "storage", "budgets", "retention"} {
		if _, ok := hh[key]; !ok {
			t.Fatalf("health missing %s: %s", key, health)
		}
	}
	rep, _ := hh["replication"].(map[string]any)
	if rep == nil || rep["running"] != false {
		t.Fatalf("health replication block = %v", hh["replication"])
	}

	gc, err := queryOneText(t, db, "SELECT murmur_gc()")
	if err != nil {
		t.Fatal(err)
	}
	if gc != "0" {
		t.Fatalf("fresh gc = %s", gc)
	}
}

func TestSQLStartStopSync(t *testing.T) {
	db, err := sqlite.Open(":memory:", sqlite.OpenReadWrite|sqlite.OpenCreate)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	eng := New(db, stubTransport{})
	if err := RegisterSQL(db, eng); err != nil {
		t.Fatal(err)
	}

	// No group configured: start fails Invalid.
	requireEngineErr(t, db, "murmur_start()", codeInvalid, "murmur_group_id")
	// Sync while stopped: Unavailable.
	requireEngineErr(t, db, "murmur_sync()", codeUnavailable, "replication is stopped")
	// Stop while stopped: 0, never an error.
	stopped, err := queryOneText(t, db, "SELECT murmur_stop()")
	if err != nil {
		t.Fatal(err)
	}
	if stopped != "0" {
		t.Fatalf("stop-while-stopped = %s", stopped)
	}

	group := strings.Repeat("ab", 16)
	if err := SetSetting(db, "group_id", group); err != nil {
		t.Fatal(err)
	}
	started, err := queryOneText(t, db, "SELECT murmur_start()")
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	if started != "1" {
		t.Fatalf("start = %s", started)
	}
	again, err := queryOneText(t, db, "SELECT murmur_start()")
	if err != nil {
		t.Fatal(err)
	}
	if again != "0" {
		t.Fatalf("second start = %s", again)
	}

	status, err := queryOneText(t, db, "SELECT murmur_status()")
	if err != nil {
		t.Fatal(err)
	}
	var st map[string]any
	if err := json.Unmarshal([]byte(status), &st); err != nil {
		t.Fatalf("status json: %v (%s)", err, status)
	}
	for _, key := range []string{"running", "node_id", "site_id", "group_id", "connected_peers", "applied_batches", "sent_batches", "vet_ok", "serve_ok"} {
		if _, ok := st[key]; !ok {
			t.Fatalf("running status missing %s: %s", key, status)
		}
	}
	if st["running"] != true || st["group_id"] != group {
		t.Fatalf("running status identity: %s", status)
	}

	synced, err := queryOneText(t, db, "SELECT murmur_sync()")
	if err != nil {
		t.Fatal(err)
	}
	if synced != "1" {
		t.Fatalf("sync = %s", synced)
	}

	// A recorded verb failure surfaces in status.
	requireEngineErr(t, db, "murmur_remove_peer('bogus')", codeInvalid, "node id")
	status, err = queryOneText(t, db, "SELECT murmur_status()")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(status, "last_error_code") {
		t.Fatalf("status misses recorded failure: %s", status)
	}

	stopped, err = queryOneText(t, db, "SELECT murmur_stop()")
	if err != nil {
		t.Fatal(err)
	}
	if stopped != "1" {
		t.Fatalf("stop = %s", stopped)
	}
	status, err = queryOneText(t, db, "SELECT murmur_status()")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(status, `"running":false`) {
		t.Fatalf("post-stop status = %s", status)
	}
}

func TestSQLPeerControls(t *testing.T) {
	db, eng := openSQL(t)

	added, err := queryOneText(t, db, "SELECT murmur_add_peer('127.0.0.1:18080')")
	if err != nil {
		t.Fatal(err)
	}
	if added != "1" {
		t.Fatalf("add = %s", added)
	}
	raw, err := Setting(db, "bootstrap")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(raw, "127.0.0.1:18080") {
		t.Fatalf("bootstrap = %s", raw)
	}
	if !eng.seeds["127.0.0.1:18080"] {
		t.Fatal("seed not registered on engine")
	}
	// Hostnames are not IP:port.
	requireEngineErr(t, db, "murmur_add_peer('peer.example:18080')", codeInvalid, "expected IP:port")
	requireEngineErr(t, db, "murmur_add_peer('bogus')", codeInvalid, "expected IP:port")

	id := "00000000-0000-0000-0000-000000000007"
	removed, err := queryOneText(t, db, "SELECT murmur_remove_peer('"+id+"')")
	if err != nil {
		t.Fatal(err)
	}
	if removed != "1" {
		t.Fatalf("remove = %s", removed)
	}
	requireEngineErr(t, db, "murmur_remove_peer('bogus')", codeInvalid, "node id")

	// Retire works offline: exclusion persists, no backend needed.
	retired, err := queryOneText(t, db, "SELECT murmur_retire_peer('"+id+"')")
	if err != nil {
		t.Fatal(err)
	}
	if retired != "1" {
		t.Fatalf("retire = %s", retired)
	}
	requireEngineErr(t, db, "murmur_retire_peer('bogus')", codeInvalid, "node id")

	// Snapshot requests need a running engine.
	requireEngineErr(t, db, "murmur_snapshot_request('"+id+"')", codeUnavailable, "replication is not running")
	requireEngineErr(t, db, "murmur_snapshot_request('bogus')", codeInvalid, "node id")
}

func TestSQLAutocommitGates(t *testing.T) {
	db, _ := openSQL(t)
	controls := []string{"murmur_start()", "murmur_stop()", "murmur_sync()"}
	for _, q := range controls {
		requireAutocommitErr(t, db, q, "replication controls require autocommit")
	}
	peers := []string{
		"murmur_add_peer('127.0.0.1:1')",
		"murmur_remove_peer('00000000-0000-0000-0000-000000000001')",
		"murmur_retire_peer('00000000-0000-0000-0000-000000000001')",
		"murmur_snapshot_request('00000000-0000-0000-0000-000000000001')",
	}
	for _, q := range peers {
		requireAutocommitErr(t, db, q, "peer controls require autocommit")
	}
	waits := []string{
		"murmur_wait_applied('00000000-0000-0000-0000-000000000001',0,0)",
		"murmur_wait_lag(0,0)",
	}
	for _, q := range waits {
		requireAutocommitErr(t, db, q, "waits require autocommit")
	}
}

func TestSQLWaits(t *testing.T) {
	db, _ := openSQL(t)
	id := "'00000000-0000-0000-0000-000000000001'"

	// Stopped engines answer 0 without touching the backend.
	zero, err := queryOneText(t, db, "SELECT murmur_wait_applied("+id+",1,5)")
	if err != nil {
		t.Fatal(err)
	}
	if zero != "0" {
		t.Fatalf("stopped wait_applied = %s", zero)
	}
	zero, err = queryOneText(t, db, "SELECT murmur_wait_lag(0,5)")
	if err != nil {
		t.Fatal(err)
	}
	if zero != "0" {
		t.Fatalf("stopped wait_lag = %s", zero)
	}

	// Argument validation still applies while stopped.
	requireEngineErr(t, db, "murmur_wait_applied('bogus',1,5)", codeInvalid, "node id")
	requireEngineErr(t, db, "murmur_wait_applied("+id+",-1,5)", codeInvalid, "sequence must be >= 0")
	requireEngineErr(t, db, "murmur_wait_applied("+id+",1,-5)", codeInvalid, "timeout")
	requireEngineErr(t, db, "murmur_wait_lag(-1,5)", codeInvalid, "bound must be >= 0")
	requireEngineErr(t, db, "murmur_wait_lag(0,-5)", codeInvalid, "timeout")

	// Running engine: seq 0 is immediate, unmet targets time out
	// to 0, and a satisfied lag bound answers 1.
	group := mustNode(t, strings.Repeat("cc", 16))
	eng, rdb := openEngine(t, group, strings.Repeat("dd", 16))
	if err := RegisterSQL(rdb, eng); err != nil {
		t.Fatal(err)
	}
	one, err := queryOneText(t, rdb, "SELECT murmur_wait_applied("+id+",0,5)")
	if err != nil {
		t.Fatal(err)
	}
	if one != "1" {
		t.Fatalf("zero-seq wait = %s", one)
	}
	zero, err = queryOneText(t, rdb, "SELECT murmur_wait_applied("+id+",1,5)")
	if err != nil {
		t.Fatal(err)
	}
	if zero != "0" {
		t.Fatalf("unmet wait = %s", zero)
	}
	one, err = queryOneText(t, rdb, "SELECT murmur_wait_lag(1000000,50)")
	if err != nil {
		t.Fatal(err)
	}
	if one != "1" {
		t.Fatalf("satisfied lag = %s", one)
	}

	// Running but unconnected snapshot peer.
	requireEngineErr(t, rdb, "murmur_snapshot_request("+id+")", codeUnavailable, "not connected")
}

func TestSQLUnknownVerbsStayUnregistered(t *testing.T) {
	db, _ := openSQL(t)
	for _, q := range []string{
		"SELECT murmur_config('group_id')",
		"SELECT murmur_peers()",
		"SELECT * FROM murmur_peers",
		"SELECT murmur_active()",
	} {
		if _, err := queryOneText(t, db, q); err == nil {
			t.Fatalf("%s: expected no-such-function", q)
		} else if !strings.Contains(err.Error(), "no such") {
			t.Fatalf("%s: want no-such-function, got %v", q, err)
		}
	}
}
