// murmur-test-node: single store + replication node behind a JSON
// stdio protocol. Spawned by the live harness for child-process legs
// (kill/crash/partition); in-process legs skip this binary.
package main

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/marcgauthier/sqlite-murmur-go/clients/go/bindings/driver"
	"github.com/marcgauthier/sqlite-murmur-go/clients/go/bindings/files"
	"github.com/marcgauthier/sqlite-murmur-go/clients/go/bindings/sqlite"
)

type strList []string

func (s *strList) String() string     { return fmt.Sprint(*s) }
func (s *strList) Set(v string) error { *s = append(*s, v); return nil }

type req struct {
	ID         uint64 `json:"id"`
	Op         string `json:"op"`
	SQL        string `json:"sql,omitempty"`
	Args       []any  `json:"args,omitempty"`
	Addr       string `json:"addr,omitempty"`
	Table      string `json:"table,omitempty"`
	Replicated bool   `json:"replicated,omitempty"`
	Name       string `json:"name,omitempty"`
	Data       []byte `json:"data,omitempty"`
}

type resp struct {
	ID      uint64       `json:"id"`
	OK      bool         `json:"ok"`
	Error   string       `json:"error,omitempty"`
	Rows    [][]string   `json:"rows,omitempty"`
	Changes int64        `json:"changes,omitempty"`
	Raw     string       `json:"raw,omitempty"`
	Data    []byte       `json:"data,omitempty"`
	Metas   []files.Meta `json:"metas,omitempty"`
	Moved   uint64       `json:"moved,omitempty"`
	Pruned  uint64       `json:"pruned,omitempty"`
}

func fail(id uint64, err error) resp {
	return resp{ID: id, Error: err.Error()}
}

func decodeHex(s string, n int) ([]byte, error) {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != n {
		return nil, fmt.Errorf("want %d hex bytes", n)
	}
	return b, nil
}

func main() {
	var dir, idHex, groupHex, addr, ca, cert, keyPEM, unlockHex string
	var seeds, trust strList
	var noStart, schemaMaster bool
	var filesDir, filesKeyHex, filesIP string
	var filesPort int
	flag.StringVar(&dir, "dir", "", "node dir")
	flag.StringVar(&idHex, "id", "", "node id hex")
	flag.StringVar(&groupHex, "group", "", "group id hex")
	flag.StringVar(&addr, "addr", "", "bind/advertise host:port")
	flag.StringVar(&ca, "ca", "", "ca pem")
	flag.StringVar(&cert, "cert", "", "chain pem")
	flag.StringVar(&keyPEM, "key", "", "key pem")
	flag.StringVar(&unlockHex, "unlock", "", "unlock key hex")
	flag.Var(&seeds, "seed", "bootstrap addr (repeatable)")
	flag.Var(&trust, "trust", "trusted node hex (repeatable)")
	flag.BoolVar(&noStart, "no-start", false, "boot without starting")
	flag.BoolVar(&schemaMaster, "schema-master", false, "act as schema master")
	flag.StringVar(&filesDir, "files-dir", "", "file object dir (enables files)")
	flag.StringVar(&filesKeyHex, "files-key", "", "file store key hex")
	flag.StringVar(&filesIP, "files-ip", "127.0.0.1", "fetch bind IP")
	flag.IntVar(&filesPort, "files-port", 0, "fetch port")
	flag.Parse()

	out := bufio.NewWriter(os.Stdout)
	ready := func(ok bool, errMsg string) {
		raw, _ := json.Marshal(map[string]any{"ready": ok, "error": errMsg})
		out.Write(raw)
		out.WriteByte('\n')
		out.Flush()
	}

	id, err := decodeHex(idHex, 16)
	if err != nil {
		ready(false, err.Error())
		return
	}
	group, err := decodeHex(groupHex, 16)
	if err != nil {
		ready(false, err.Error())
		return
	}
	unlock, err := decodeHex(unlockHex, 32)
	if err != nil {
		ready(false, err.Error())
		return
	}
	if err := driver.Init(0, 0); err != nil {
		ready(false, err.Error())
		return
	}
	dataDir := filepath.Join(dir, "data")
	os.MkdirAll(dataDir, 0o755)
	conn, err := sqlite.OpenVFS(dataDir, sqlite.OpenReadWrite|sqlite.OpenCreate, "sqlite-murmur")
	if err != nil {
		ready(false, err.Error())
		return
	}
	var key [32]byte
	copy(key[:], unlock)
	if rc := conn.SetKey(key); rc != 0 {
		ready(false, fmt.Sprintf("key rc=%d", rc))
		return
	}
	if err := sqlite.CrsqliteInit(conn); err != nil {
		ready(false, err.Error())
		return
	}
	db := conn.NativeDB()
	if err := driver.EnsureSchema(db); err != nil {
		ready(false, err.Error())
		return
	}
	if err := conn.Exec(fmt.Sprintf("UPDATE murmur_identity SET node=x'%s' WHERE id=1", idHex)); err != nil {
		ready(false, err.Error())
		return
	}
	settings := map[string]string{
		"group_id": Hex(group), "bind": addr, "advertise": addr,
		"certificate": cert, "private_key": keyPEM, "ca": ca,
	}
	if len(seeds) > 0 {
		raw, _ := json.Marshal([]string(seeds))
		settings["bootstrap"] = string(raw)
	}
	if len(trust) > 0 {
		raw, _ := json.Marshal([]string(trust))
		settings["snapshot_trusted_sources"] = string(raw)
	}
	if schemaMaster {
		settings["schema_master_enabled"] = "1"
		settings["schema_master"] = idHex
	}
	_ = id
	for k, v := range settings {
		if err := driver.SetSetting(db, k, v); err != nil {
			ready(false, err.Error())
			return
		}
	}
	node := driver.New(db)
	filesOn := filesDir != ""
	if filesOn {
		fkey, err := decodeHex(filesKeyHex, 32)
		if err != nil {
			ready(false, err.Error())
			return
		}
		var fk [32]byte
		copy(fk[:], fkey)
		os.MkdirAll(filesDir, 0o755)
		if err := files.Stage(node.NativeDriver(), filesDir, fk, filesIP, uint16(filesPort)); err != nil {
			ready(false, err.Error())
			return
		}
	}
	if !noStart {
		if err := node.Start(); err != nil {
			ready(false, err.Error())
			return
		}
	}
	ready(true, "")

	in := bufio.NewReader(os.Stdin)
	enc := json.NewEncoder(out)
	run := true
	for run {
		line, err := in.ReadBytes('\n')
		if err != nil {
			break
		}
		var r req
		if err := json.Unmarshal(line, &r); err != nil {
			enc.Encode(resp{Error: "bad request: " + err.Error()})
			out.Flush()
			continue
		}
		var rp resp
		rp.ID = r.ID
		rp.OK = true
		switch r.Op {
		case "simple":
			rows, err := doSimple(conn, r.SQL)
			if err != nil {
				rp = fail(r.ID, err)
			} else {
				rp.Rows = rows
			}
		case "execute":
			n, err := doExecute(conn, r.SQL, r.Args)
			if err != nil {
				rp = fail(r.ID, err)
			} else {
				rp.Changes = n
			}
		case "flush":
			if err := driver.Commit(dataDir); err != nil {
				rp = fail(r.ID, err)
			}
		case "collect":
			moved, pruned, err := node.RetentionCollect()
			if err != nil {
				rp = fail(r.ID, err)
			} else {
				rp.Moved = moved
				rp.Pruned = pruned
			}
		case "set_table":
			if !r.Replicated {
				rp = fail(r.ID, fmt.Errorf("unreplicate unsupported"))
				break
			}
			if _, err := doSimple(conn, fmt.Sprintf("SELECT crsql_as_crr('main',\"%s\")", r.Table)); err != nil {
				rp = fail(r.ID, err)
			}
		case "peer_add":
			if err := node.AddSeed(r.Addr); err != nil {
				rp = fail(r.ID, err)
			}
		case "file_upload":
			h := files.Handle(node.NativeDriver())
			if h == nil {
				rp = fail(r.ID, fmt.Errorf("files not staged"))
			} else if err := files.UploadOne(h, r.Name, r.Data); err != nil {
				rp = fail(r.ID, err)
			}
		case "file_download":
			h := files.Handle(node.NativeDriver())
			if h == nil {
				rp = fail(r.ID, fmt.Errorf("files not staged"))
			} else if data, err := files.Download(h, r.Name); err != nil {
				rp = fail(r.ID, err)
			} else {
				rp.Data = data
			}
		case "file_available":
			h := files.Handle(node.NativeDriver())
			if h == nil {
				rp = fail(r.ID, fmt.Errorf("files not staged"))
			} else if avail, err := files.Available(h, r.Name); err != nil {
				rp = fail(r.ID, err)
			} else if avail {
				rp.Changes = 1
			}
		case "file_list":
			h := files.Handle(node.NativeDriver())
			if h == nil {
				rp = fail(r.ID, fmt.Errorf("files not staged"))
			} else if metas, err := files.List(h); err != nil {
				rp = fail(r.ID, err)
			} else {
				rp.Metas = metas
			}
		case "peers":
			rp.Raw = node.Peers()
		case "status":
			rp.Raw = node.Status()
		case "progress":
			rp.Raw = node.Progress()
		case "health":
			rp.Raw = node.Health()
		case "start":
			if err := node.Start(); err != nil {
				rp = fail(r.ID, err)
			}
		case "stop":
			if err := node.Stop(); err != nil {
				rp = fail(r.ID, err)
			}
		case "exit":
			run = false
		default:
			rp = fail(r.ID, fmt.Errorf("unknown op %q", r.Op))
		}
		enc.Encode(rp)
		out.Flush()
	}
	node.Stop()
	node.Close()
	conn.Close()
}

func Hex(b []byte) string { return hex.EncodeToString(b) }

func doSimple(conn *sqlite.Conn, query string) ([][]string, error) {
	sqlite.LockWriter()
	defer sqlite.UnlockWriter()
	var rows [][]string
	rest := translate(query)
	for {
		if strings.TrimSpace(rest) == "" {
			return rows, nil
		}
		st, tail, err := conn.PrepareTail(rest)
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
				row[i] = col(st, i)
			}
			rows = append(rows, row)
		}
		st.Close()
	}
}

func doExecute(conn *sqlite.Conn, query string, args []any) (int64, error) {
	sqlite.LockWriter()
	defer sqlite.UnlockWriter()
	st, err := conn.Prepare(translate(query))
	if err != nil {
		return 0, err
	}
	defer st.Close()
	for i, a := range args {
		if err := bind(st, i+1, a); err != nil {
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
	return conn.Changes(), nil
}

func col(st *sqlite.Stmt, i int) string {
	switch st.ColumnType(i) {
	case 1:
		return fmt.Sprint(st.ColumnInt64(i))
	case 2:
		return fmt.Sprint(st.ColumnFloat(i))
	case 3:
		return st.ColumnText(i)
	case 4:
		return hex.EncodeToString(st.ColumnBlob(i))
	default:
		return ""
	}
}

func bind(st *sqlite.Stmt, i int, v any) error {
	switch t := v.(type) {
	case nil:
		return st.BindNull(i)
	case bool:
		if t {
			return st.BindInt64(i, 1)
		}
		return st.BindInt64(i, 0)
	case float64:
		// JSON numbers arrive float64; integral values bind as int.
		if t == float64(int64(t)) {
			return st.BindInt64(i, int64(t))
		}
		return st.BindFloat(i, t)
	case string:
		return st.BindText(i, t)
	default:
		return fmt.Errorf("unsupported bind type %T", v)
	}
}

func translate(sql string) string {
	var b []byte
	next := 1
	for i := 0; i < len(sql); {
		if sql[i] == '$' {
			j := i + 1
			for j < len(sql) && sql[j] >= '0' && sql[j] <= '9' {
				j++
			}
			if j > i+1 {
				var n int
				fmt.Sscanf(sql[i+1:j], "%d", &n)
				if n == next {
					b = append(b, '?')
					next++
					i = j
					continue
				}
			}
		}
		b = append(b, sql[i])
		i++
	}
	return string(b)
}
