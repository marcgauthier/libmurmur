package replication

import (
	"encoding/json"
	"net/netip"
	"sync"
	"time"

	"github.com/marcgauthier/libmurmur/clients/go/bindings/sqlite"
	"github.com/marcgauthier/libmurmur/clients/go/pkgs/tx"
)

// Transport moves frames between nodes. Implementations own dialing,
// listening, identity (TLS), streams, and datagrams; the engine only
// sees framed bytes plus peer identities.
type Transport interface {
	// LocalAddr reports the bound address once listening.
	LocalAddr() string
	// Dial opens a session to addr.
	Dial(addr string) (Session, error)
	// Accept returns the next inbound session, blocking.
	Accept() (Session, error)
	// Close stops listening and all sessions.
	Close() error
}

// Session is one authenticated peer connection.
type Session interface {
	// PeerID is the verified remote node id.
	PeerID() NodeID
	// OpenStream opens a bidirectional frame stream.
	OpenStream() (Stream, error)
	// AcceptStream takes the next inbound stream, blocking.
	AcceptStream() (Stream, error)
	// SendDatagram queues an unreliable membership datagram.
	SendDatagram([]byte) error
	// RecvDatagram takes the next datagram, blocking.
	RecvDatagram() ([]byte, error)
	// Close ends the session.
	Close() error
}

// Stream is a reliable bidirectional byte stream.
type Stream interface {
	Write([]byte) error
	Read([]byte) (int, error)
	Close() error
}

// Engine runs group replication on one database. Start loads config,
// installs the schema, and serves peers until Stop. The zero value is
// unusable; construct with New.
type Engine struct {
	db *sqlite.Conn
	mu sync.Mutex

	running   bool
	startedAt time.Time
	node      NodeID
	site      NodeID
	group     NodeID
	signer    *CellSigner
	transport Transport

	incarnation uint64
	advertise   netip.AddrPort
	serveSem    chan struct{}
	serving     *byteSem
	receiving   *byteSem

	applied uint64
	sent    uint64

	view                 *View
	seeds                map[string]bool
	conns                map[NodeID]Session
	relays               map[relayKey]relayEntry
	persistedIncarnation uint64
	syncCh               chan struct{}
	gossipFanout         int

	serveOK        uint64
	serveReject    uint64
	serveError     uint64
	lastErr        *recordedError
	lastErrorText  string
	snapshotStatus string

	vetted          map[vettedKey]bool
	vetOK           uint64
	vetNo           uint64
	vetFail         uint64
	schemaAdoptions uint64
	schemaSent      map[NodeID]schemaSentKey
}

// New binds an engine to db. Transport may be nil for offline use;
// Start fails without one.
func New(db *sqlite.Conn, transport Transport) *Engine {
	return &Engine{
		db:         db,
		transport:  transport,
		seeds:      map[string]bool{},
		conns:      map[NodeID]Session{},
		relays:     map[relayKey]relayEntry{},
		syncCh:     make(chan struct{}, 1),
		vetted:     map[vettedKey]bool{},
		schemaSent: map[NodeID]schemaSentKey{},
	}
}

// Start loads configuration, installs the schema, and begins serving.
func (e *Engine) Start() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.running {
		return errBusy("replication already running")
	}
	if e.transport == nil {
		return errInvalid("no transport configured")
	}
	if err := EnsureSchema(e.db); err != nil {
		return err
	}
	if err := sqlite.CrsqliteInit(e.db); err != nil {
		return err
	}
	group, err := Setting(e.db, "group_id")
	if err != nil {
		return err
	}
	if group == "" {
		return errInvalid("murmur_group_id is not set")
	}
	gid, err := ParseID(group)
	if err != nil {
		return err
	}
	site, err := claimSite(e.db)
	if err != nil {
		return err
	}
	node, err := claimNode(e.db)
	if err != nil {
		return err
	}
	incarnation, err := bumpIncarnation(e.db)
	if err != nil {
		return err
	}
	params, err := loadServeParams(e.db)
	if err != nil {
		return err
	}
	advertise, err := parseAdvertise(e.db)
	if err != nil {
		return err
	}
	// Origin signing key: a configured origin_key_file must load
	// exactly 32 raw seed bytes; unloadable fails Start loud.
	// Empty means no local signing (verify/forward only).
	if keyPath, err := Setting(e.db, "origin_key_file"); err != nil {
		return err
	} else if keyPath != "" {
		signer, err := LoadCellSigner(keyPath)
		if err != nil {
			return errAuth("origin_key_file must hold exactly 32 seed bytes")
		}
		e.signer = signer
	}
	e.group = gid
	e.node = node
	e.site = site
	e.incarnation = incarnation
	e.advertise = advertise
	if params.sessions < 1 {
		params.sessions = 1
	}
	e.serveSem = make(chan struct{}, params.sessions)
	e.serving = newByteSem(params.queueBytes)
	e.receiving = newByteSem(params.queueBytes)
	e.gossipFanout = params.gossipFanout
	e.view = NewView(Member{Node: node, Addr: advertise, Incarnation: incarnation, State: StateAlive})
	// Reload persisted exclusions: removal must survive restart.
	excluded, err := loadExcluded(e.db)
	if err != nil {
		return err
	}
	for _, id := range excluded {
		e.view.Excluded[id] = true
	}
	e.persistedIncarnation = incarnation
	// Seed the bootstrap dial set from the persisted setting.
	if raw, err := Setting(e.db, "bootstrap"); err == nil && raw != "" {
		for _, s := range decodeBootstrap(raw) {
			e.seeds[s] = true
		}
	}
	e.running = true
	e.startedAt = time.Now()
	return nil
}

// decodeBootstrap parses the persisted bootstrap address list,
// skipping malformed entries.
func decodeBootstrap(raw string) []string {
	var v []string
	if err := json.Unmarshal([]byte(raw), &v); err != nil {
		return nil
	}
	return v
}

// parseAdvertise resolves the advertised address (zero when unset).
func parseAdvertise(db *sqlite.Conn) (netip.AddrPort, error) {
	raw, err := Setting(db, "advertise")
	if err != nil {
		return netip.AddrPort{}, err
	}
	if raw == "" {
		return netip.AddrPort{}, nil
	}
	addr, err := netip.ParseAddrPort(raw)
	if err != nil {
		return netip.AddrPort{}, errInvalid("invalid advertise")
	}
	return addr, nil
}

// Stop ends serving. Peers disconnect; local state stays.
func (e *Engine) Stop() error {
	e.mu.Lock()
	if !e.running {
		e.mu.Unlock()
		return errClosed("replication is not running")
	}
	e.running = false
	conns := e.conns
	e.conns = map[NodeID]Session{}
	if e.signer != nil {
		e.signer.seed = [32]byte{}
		e.signer = nil
	}
	e.mu.Unlock()
	for _, s := range conns {
		_ = s.Close()
	}
	if e.transport != nil {
		e.transport.Close()
	}
	return nil
}

// Running reports the engine state.
func (e *Engine) Running() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.running
}

// Status renders the murmur_status JSON: live counters plus the
// recorded verb failure, if any. Stopped engines report running:false.
func (e *Engine) Status() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := map[string]any{"running": e.running}
	if e.running {
		var bind any
		if e.transport != nil {
			bind = e.transport.LocalAddr()
		}
		var snapshot any
		if e.snapshotStatus != "" {
			snapshot = e.snapshotStatus
		}
		var lastErr any
		if e.lastErrorText != "" {
			lastErr = e.lastErrorText
		}
		out["node_id"] = e.node.String()
		out["site_id"] = e.site.String()
		out["group_id"] = e.group.String()
		out["bind"] = bind
		out["connected_peers"] = len(e.conns)
		out["applied_batches"] = e.applied
		out["sent_batches"] = e.sent
		out["snapshot"] = snapshot
		out["schema_adoptions"] = e.schemaAdoptions
		out["vet_ok"] = e.vetOK
		out["vet_no"] = e.vetNo
		out["vet_fail"] = e.vetFail
		out["serve_ok"] = e.serveOK
		out["serve_reject"] = e.serveReject
		out["serve_error"] = e.serveError
		out["last_error"] = lastErr
	}
	if e.lastErr != nil {
		out["last_error_code"] = e.lastErr.code
		out["last_error_kind"] = e.lastErr.kind
		out["last_error_message"] = e.lastErr.message
	}
	raw, err := json.Marshal(out)
	if err != nil {
		return `{"running":false}`
	}
	return string(raw)
}

// Health renders the murmur_health JSON (versioned, additive).
// Unmeasurable metrics stay null. Short reads only: no flush, no
// network activity, no CRR initialization.
func (e *Engine) Health() string {
	e.mu.Lock()
	running := e.running
	var applied, sent, peers, engineErr any
	if running {
		applied = e.applied
		sent = e.sent
		peers = len(e.conns)
		if e.lastErrorText != "" {
			engineErr = e.lastErrorText
		}
	}
	serving, receiving := 0, 0
	if e.serving != nil {
		serving = e.serving.inUse()
	}
	if e.receiving != nil {
		receiving = e.receiving.inUse()
	}
	lastErr := e.lastErr
	e.mu.Unlock()
	var pending, stageBytes, cursor any
	if local, debt, reserve, stage, cur, ok := healthStore(e.db); ok {
		pending = map[string]any{
			"local_share": local, "remote_share": 100 - local,
			"max_debt_ms": debt, "maintenance_reserve_every": reserve,
		}
		stageBytes = stage
		cursor = cur
	}
	var effective any
	if local, debt, reserve, ok := schedulerSettings(e.db); ok {
		effective = map[string]any{
			"local_share": local, "remote_share": 100 - local,
			"max_debt_ms": debt, "maintenance_reserve_every": reserve,
		}
	} else {
		effective = map[string]any{
			"local_share": uint64(90), "remote_share": uint64(10),
			"max_debt_ms": uint64(1000), "maintenance_reserve_every": uint64(100),
		}
	}
	retention := retentionHealth(e)
	replication := map[string]any{
		"running": running, "applied_batches": applied, "sent_batches": sent,
		"connected_peers": peers, "last_error": engineErr,
	}
	if lastErr != nil {
		replication["last_error_code"] = lastErr.code
		replication["last_error_kind"] = lastErr.kind
		replication["last_error_message"] = lastErr.message
	}
	out := map[string]any{
		"version":     1,
		"replication": replication,
		"scheduler": map[string]any{
			"local_admission_enforced": false,
			"scope":                    "remote_and_maintenance",
			"effective_config":         effective,
			"pending_config":           pending,
			"stats":                    nil,
		},
		"storage": map[string]any{
			"committed_cursor": cursor,
			"durable_cursor":   nil,
			"counters":         nil,
		},
		"budgets": map[string]any{
			"serving_in_use_bytes":   serving,
			"receiving_in_use_bytes": receiving,
			"stage_bytes":            stageBytes,
			"worker_payload_bytes":   nil,
		},
		"retention": retention,
	}
	raw, err := json.Marshal(out)
	if err != nil {
		return `{"version":1}`
	}
	return string(raw)
}

// healthStore reads pending scheduler config, staged bytes, and the
// local logical cursor in one short pass. Any failure nulls the
// whole block rather than reporting partial reads.
func healthStore(db *sqlite.Conn) (local, debt, reserve uint64, stage int64, cursor any, ok bool) {
	num := func(name string) (uint64, error) {
		raw, err := Setting(db, name)
		if err != nil {
			return 0, err
		}
		return atoi(raw)
	}
	var err error
	if local, err = num("writer_local_share"); err != nil {
		return 0, 0, 0, 0, nil, false
	}
	if local < 1 || local > 99 {
		return 0, 0, 0, 0, nil, false
	}
	if debt, err = num("writer_max_debt_ms"); err != nil {
		return 0, 0, 0, 0, nil, false
	}
	if reserve, err = num("writer_maintenance_reserve_every"); err != nil {
		return 0, 0, 0, 0, nil, false
	}
	st, err := db.Prepare("SELECT SUM(LENGTH(data)) FROM murmur_stage")
	if err != nil {
		return 0, 0, 0, 0, nil, false
	}
	defer st.Close()
	done, err := st.Step()
	if err != nil || done {
		return 0, 0, 0, 0, nil, false
	}
	if st.ColumnType(0) != sqlite.TypeNull {
		stage = st.ColumnInt64(0)
	}
	st.Close()
	if v, err := DbVersion(db); err == nil {
		cursor = v
	}
	return local, debt, reserve, stage, cursor, true
}

func schedulerSettings(db *sqlite.Conn) (local, debt, reserve uint64, ok bool) {
	num := func(name string) (uint64, error) {
		raw, err := Setting(db, name)
		if err != nil {
			return 0, err
		}
		return atoi(raw)
	}
	var err error
	if local, err = num("writer_local_share"); err != nil || local < 1 || local > 99 {
		return 0, 0, 0, false
	}
	if debt, err = num("writer_max_debt_ms"); err != nil {
		return 0, 0, 0, false
	}
	if reserve, err = num("writer_maintenance_reserve_every"); err != nil {
		return 0, 0, 0, false
	}
	return local, debt, reserve, true
}

func retentionHealth(e *Engine) any {
	e.mu.Lock()
	running := e.running
	group, node := e.group, e.node
	e.mu.Unlock()
	if !running {
		return nil
	}
	backend := NewBackend(e.db, group, node)
	status, err := tx.Status(backend)
	if err != nil {
		return nil
	}
	retired := 0
	for _, p := range status.Peers {
		if p.Retired {
			retired++
		}
	}
	return map[string]any{
		"peers":                  len(status.Peers),
		"retired":                retired,
		"collected_transactions": status.CollectedTransactions,
		"last_collection_millis": status.LastCollectionMillis,
	}
}

// Progress renders the murmur_progress JSON array of per-origin
// heads, or [] while stopped.
func (e *Engine) Progress() string {
	e.mu.Lock()
	running := e.running
	group, node := e.group, e.node
	e.mu.Unlock()
	if !running {
		return "[]"
	}
	backend := NewBackend(e.db, group, node)
	heads, err := backend.Progress()
	if err != nil {
		return "[]"
	}
	rows := make([]map[string]any, 0, len(heads))
	for _, p := range heads {
		rows = append(rows, map[string]any{
			"origin": p.Origin.String(), "applied": p.Applied, "observed": p.Observed,
			"retained_from": p.RetainedFrom, "retained_through": p.RetainedThrough,
		})
	}
	raw, err := json.Marshal(rows)
	if err != nil {
		return "[]"
	}
	return string(raw)
}

// Peers renders the murmur_peers JSON array from the membership view.
func (e *Engine) Peers() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := "["
	first := true
	emit := func(m Member) {
		if !first {
			out += ","
		}
		first = false
		connected := "false"
		if _, ok := e.conns[m.Node]; ok {
			connected = "true"
		}
		out += `{"node_id":"` + m.Node.String() + `","address":"` + m.Addr.String() +
			`","state":"` + m.State.String() + `","connected":` + connected +
			`,"incarnation":` + itoa(m.Incarnation) + `}`
	}
	if e.view != nil {
		emit(e.view.Local)
		for _, m := range e.view.Members {
			emit(m)
		}
	}
	return out + "]"
}
