// In-process node: a native replication driver over a VFS-backed
// store, all inside the test process.
package goharness

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/marcgauthier/sqlite-murmur-go/clients/go/bindings/driver"
	"github.com/marcgauthier/sqlite-murmur-go/clients/go/bindings/files"
	"github.com/marcgauthier/sqlite-murmur-go/clients/go/bindings/sqlite"
)

var initOnce sync.Once
var initErr error

func ensureInit() error {
	initOnce.Do(func() {
		initErr = driver.Init(0, 0)
	})
	return initErr
}

// Node is one live cluster member. The zero mode is in-process;
// child-process nodes embed the same SQL/admin surface over stdio
// (see child.go).
type Node struct {
	Dir     string // node dir (tls/, data/)
	DataDir string // murmur store dir
	ID      [16]byte
	Addr    string // QUIC bind/advertise host:port
	TLS     *TlsPaths

	mu      sync.Mutex
	conn    *sqlite.Conn
	native  *driver.Node
	running bool
	files   bool
	fcfg    *FilesConfig
	child   *childNode // non-nil for child-process mode
}

// FilesConfig stages the file-object store on a node.
type FilesConfig struct {
	Dir  string // object dir (created)
	Key  [32]byte
	IP   string // fetch bind IP (distinct 127.0.0.x per node)
	Port uint16 // uniform cluster fetch port
}

// NodeConfig carries the boot parameters for one node.
type NodeConfig struct {
	Dir     string
	ID      [16]byte
	Group   [16]byte
	Addr    string
	TLS     *TlsPaths
	Key     [32]byte
	Seeds   []string // bootstrap addrs
	Trust   [][16]byte
	Child   bool // run as a child process instead of in-process
	NoStart bool // boot the store but leave replication stopped
	Files   *FilesConfig
}

// BootNode creates the store, keys it, writes identity/settings, and
// starts replication (unless NoStart).
func BootNode(cfg NodeConfig) (*Node, error) {
	if err := ensureInit(); err != nil {
		return nil, err
	}
	if cfg.Child {
		return bootChild(cfg)
	}
	n := &Node{Dir: cfg.Dir, ID: cfg.ID, Addr: cfg.Addr, TLS: cfg.TLS}
	dataDir := filepath.Join(cfg.Dir, "data")
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return nil, err
	}
	n.DataDir = dataDir
	conn, err := sqlite.OpenVFS(dataDir, sqlite.OpenReadWrite|sqlite.OpenCreate, "sqlite-murmur")
	if err != nil {
		return nil, fmtErr("open store", err)
	}
	n.conn = conn
	if rc := conn.SetKey(cfg.Key); rc != 0 {
		conn.Close()
		return nil, fmt.Errorf("key store: rc=%d", rc)
	}
	if err := sqlite.CrsqliteInit(conn); err != nil {
		conn.Close()
		return nil, fmtErr("crsqlite init", err)
	}
	db := conn.NativeDB()
	if err := driver.EnsureSchema(db); err != nil {
		conn.Close()
		return nil, err
	}
	if err := conn.Exec(fmt.Sprintf("UPDATE murmur_identity SET node=x'%s' WHERE id=1", Hex(cfg.ID[:]))); err != nil {
		conn.Close()
		return nil, fmtErr("set node id", err)
	}
	settings := map[string]string{
		"group_id":    Hex(cfg.Group[:]),
		"bind":        cfg.Addr,
		"advertise":   cfg.Addr,
		"certificate": cfg.TLS.Chain,
		"private_key": cfg.TLS.Key,
		"ca":          cfg.TLS.Ca,
	}
	if len(cfg.Seeds) > 0 {
		raw, _ := json.Marshal(cfg.Seeds)
		settings["bootstrap"] = string(raw)
	}
	if len(cfg.Trust) > 0 {
		var hexes []string
		for _, t := range cfg.Trust {
			hexes = append(hexes, Hex(t[:]))
		}
		raw, _ := json.Marshal(hexes)
		settings["snapshot_trusted_sources"] = string(raw)
	}
	for k, v := range settings {
		if err := driver.SetSetting(db, k, v); err != nil {
			conn.Close()
			return nil, err
		}
	}
	n.native = driver.New(db)
	n.files = cfg.Files != nil
	n.fcfg = cfg.Files
	if cfg.Files != nil {
		if err := os.MkdirAll(cfg.Files.Dir, 0o755); err != nil {
			n.native.Close()
			conn.Close()
			return nil, err
		}
		if err := files.Stage(n.native.NativeDriver(), cfg.Files.Dir,
			cfg.Files.Key, cfg.Files.IP, cfg.Files.Port); err != nil {
			n.native.Close()
			conn.Close()
			return nil, err
		}
	}
	if !cfg.NoStart {
		if err := n.native.Start(); err != nil {
			n.native.Close()
			conn.Close()
			return nil, err
		}
		n.running = true
	}
	return n, nil
}

// IDHex renders the node id.
func (n *Node) IDHex() string { return Hex(n.ID[:]) }

// IsRunning reports whether replication is up.
func (n *Node) IsRunning() bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.child != nil {
		return n.child.running()
	}
	return n.running
}

// Start starts replication on a stopped node (reuses the open store).
func (n *Node) Start() error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.child != nil {
		return n.child.start()
	}
	if n.running {
		return nil
	}
	if err := n.native.Start(); err != nil {
		return err
	}
	n.running = true
	return nil
}

// Stop stops replication, keeping the store open.
func (n *Node) Stop() error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.child != nil {
		return n.child.stop()
	}
	if !n.running {
		return nil
	}
	if err := n.native.Stop(); err != nil {
		return err
	}
	n.running = false
	return nil
}

// Close stops replication and closes the store.
func (n *Node) Close() error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.child != nil {
		return n.child.close()
	}
	if n.native != nil {
		if n.running {
			n.native.Stop()
			n.running = false
		}
		n.native.Close()
		n.native = nil
	}
	if n.conn != nil {
		err := n.conn.Close()
		n.conn = nil
		return err
	}
	return nil
}

// Simple runs a query and returns all rows as strings (NULL -> "").
// $N placeholders are translated to ? for SQLite. Multi-statement
// scripts run every statement in order; rows of the last statement
// win (pgwire simple-protocol parity).
func (n *Node) Simple(query string) ([][]string, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.child != nil {
		return n.child.simple(query)
	}
	// Whole-op guard: multi-statement scripts (including explicit
	// BEGIN..COMMIT) must not interleave with engine transactions.
	sqlite.LockWriter()
	defer sqlite.UnlockWriter()
	var rows [][]string
	rest := TranslateParams(query)
	for {
		if strings.TrimSpace(rest) == "" {
			return rows, nil
		}
		st, tail, err := n.conn.PrepareTail(rest)
		if err != nil {
			return nil, err
		}
		if st == nil {
			if len(tail) >= len(rest) {
				return rows, nil
			}
			rest = tail
			continue
		}
		rest = tail
		rows = nil
		for {
			done, err := st.Step()
			if err != nil {
				st.Close()
				return nil, err
			}
			if done {
				break
			}
			nc := st.ColumnCount()
			row := make([]string, nc)
			for i := 0; i < nc; i++ {
				row[i] = columnString(st, i)
			}
			rows = append(rows, row)
		}
		st.Close()
	}
}

// Execute runs a statement with bound args and returns rows affected.
func (n *Node) Execute(query string, args ...any) (int64, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.child != nil {
		return n.child.execute(query, args...)
	}
	sqlite.LockWriter()
	defer sqlite.UnlockWriter()
	st, err := n.conn.Prepare(TranslateParams(query))
	if err != nil {
		return 0, err
	}
	defer st.Close()
	for i, a := range args {
		if err := bindAny(st, i+1, a); err != nil {
			return 0, err
		}
	}
	done, err := st.Step()
	if err != nil {
		return 0, err
	}
	if !done {
		return 0, fmt.Errorf("execute returned rows")
	}
	return n.conn.Changes(), nil
}

// ExecBatch runs multi-statement SQL.
func (n *Node) ExecBatch(sql string) error {
	if n.child != nil {
		_, err := n.child.simple(sql)
		return err
	}
	sqlite.LockWriter()
	defer sqlite.UnlockWriter()
	return n.conn.Exec(sql)
}

func columnString(st interface {
	ColumnType(i int) int
	ColumnInt64(i int) int64
	ColumnFloat(i int) float64
	ColumnText(i int) string
	ColumnBlob(i int) []byte
}, i int) string {
	switch st.ColumnType(i) {
	case 1: // INTEGER
		return strconv.FormatInt(st.ColumnInt64(i), 10)
	case 2: // FLOAT
		return strconv.FormatFloat(st.ColumnFloat(i), 'g', -1, 64)
	case 3: // TEXT
		return st.ColumnText(i)
	case 4: // BLOB
		return Hex(st.ColumnBlob(i))
	default: // NULL
		return ""
	}
}

func bindAny(st interface {
	BindInt64(i int, v int64) error
	BindFloat(i int, v float64) error
	BindText(i int, v string) error
	BindBlob(i int, v []byte) error
	BindNull(i int) error
}, i int, v any) error {
	switch t := v.(type) {
	case nil:
		return st.BindNull(i)
	case int:
		return st.BindInt64(i, int64(t))
	case int32:
		return st.BindInt64(i, int64(t))
	case int64:
		return st.BindInt64(i, t)
	case uint:
		return st.BindInt64(i, int64(t))
	case uint32:
		return st.BindInt64(i, int64(t))
	case uint64:
		return st.BindInt64(i, int64(t))
	case float32:
		return st.BindFloat(i, float64(t))
	case float64:
		return st.BindFloat(i, t)
	case string:
		return st.BindText(i, t)
	case []byte:
		return st.BindBlob(i, t)
	case bool:
		if t {
			return st.BindInt64(i, 1)
		}
		return st.BindInt64(i, 0)
	default:
		return fmt.Errorf("unsupported bind type %T", v)
	}
}

// Flush forces durability (MURMUR FLUSH).
func (n *Node) Flush() error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.child != nil {
		return n.child.flush()
	}
	return driver.Commit(n.DataDir)
}

// RetentionCollect runs one retention collection pass now
// (reference RETENTION COLLECT parity).
func (n *Node) RetentionCollect() (uint64, uint64, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.child != nil {
		return n.child.collect()
	}
	return n.native.RetentionCollect()
}

// SetTableReplicated marks a table CRR (MURMUR SET TABLE ... REPLICATED).
func (n *Node) SetTableReplicated(table string, replicated bool) error {
	if !replicated {
		return fmt.Errorf("unreplicate not supported natively")
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.child != nil {
		return n.child.setTable(table, replicated)
	}
	st, err := n.conn.Prepare(fmt.Sprintf("SELECT crsql_as_crr('main',%s)", quoteIdent(table)))
	if err != nil {
		return err
	}
	defer st.Close()
	_, err = st.Step()
	return err
}

func quoteIdent(s string) string {
	return "\"" + s + "\""
}

// PeerAdd adds a dial target at runtime (MURMUR PEER ADD).
func (n *Node) PeerAdd(addr string) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.child != nil {
		return n.child.peerAdd(addr)
	}
	return n.native.AddSeed(addr)
}

// PeerRow is one decoded SHOW PEERS row.
type PeerRow struct {
	NodeID    string `json:"node_id"`
	Address   string `json:"address"`
	State     string `json:"state"`
	Connected bool   `json:"connected"`
}

// ShowPeers decodes the membership view (MURMUR SHOW PEERS).
func (n *Node) ShowPeers() ([]PeerRow, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	var raw string
	if n.child != nil {
		var err error
		raw, err = n.child.peers()
		if err != nil {
			return nil, err
		}
	} else {
		raw = n.native.Peers()
	}
	var rows []PeerRow
	if err := json.Unmarshal([]byte(raw), &rows); err != nil {
		return nil, fmt.Errorf("decode peers: %w", err)
	}
	return rows, nil
}

// ShowStatus returns the engine status snapshot (MURMUR SHOW STATUS).
func (n *Node) ShowStatus() (any, error) {
	return n.snapJSON(func() string { return n.native.Status() },
		func() (string, error) { return n.child.status() })
}

// ShowReplication returns the progress snapshot (MURMUR SHOW REPLICATION).
func (n *Node) ShowReplication() (any, error) {
	return n.snapJSON(func() string { return n.native.Progress() },
		func() (string, error) { return n.child.progress() })
}

// ShowHealth returns the health snapshot.
func (n *Node) ShowHealth() (any, error) {
	return n.snapJSON(func() string { return n.native.Health() },
		func() (string, error) { return n.child.health() })
}

// HasFiles reports whether the file store is staged.
func (n *Node) HasFiles() bool { return n.files }

// FileUpload stores one object.
func (n *Node) FileUpload(name string, data []byte) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.child != nil {
		return n.child.fileUpload(name, data)
	}
	h := files.Handle(n.native.NativeDriver())
	if h == nil {
		return fmt.Errorf("files not staged")
	}
	return files.UploadOne(h, name, data)
}

// FileDownload fetches one object's full plaintext.
func (n *Node) FileDownload(name string) ([]byte, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.child != nil {
		return n.child.fileDownload(name)
	}
	h := files.Handle(n.native.NativeDriver())
	if h == nil {
		return nil, fmt.Errorf("files not staged")
	}
	return files.Download(h, name)
}

// FileAvailable reports local object availability.
func (n *Node) FileAvailable(name string) (bool, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.child != nil {
		return n.child.fileAvailable(name)
	}
	h := files.Handle(n.native.NativeDriver())
	if h == nil {
		return false, fmt.Errorf("files not staged")
	}
	return files.Available(h, name)
}

// FileList lists file metadata.
func (n *Node) FileList() ([]files.Meta, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.child != nil {
		return n.child.fileList()
	}
	h := files.Handle(n.native.NativeDriver())
	if h == nil {
		return nil, fmt.Errorf("files not staged")
	}
	return files.List(h)
}

func (n *Node) snapJSON(local func() string, remote func() (string, error)) (any, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	var raw string
	if n.child != nil {
		var err error
		raw, err = remote()
		if err != nil {
			return nil, err
		}
	} else {
		raw = local()
	}
	var v any
	if err := json.Unmarshal([]byte(raw), &v); err != nil {
		return nil, fmt.Errorf("decode snapshot: %w", err)
	}
	return v, nil
}
