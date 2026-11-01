// Child-process node transport: JSON lines over the node binary's
// stdio. The child owns its store exclusively; the parent sends SQL
// and admin ops and receives rows/snapshots.
package goharness

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"sync"

	"github.com/marcgauthier/sqlite-murmur-go/clients/go/bindings/files"
)

type childReq struct {
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

type childResp struct {
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

type childNode struct {
	mu     sync.Mutex
	cmd    *exec.Cmd
	stdin  *bufio.Writer
	stdout *bufio.Reader
	nextID uint64
	alive  bool
}

func nodeBinary() string {
	if v := os.Getenv("MURMUR_NODE_BIN"); v != "" {
		return v
	}
	return "murmur-test-node"
}

func bootChild(cfg NodeConfig) (*Node, error) {
	keyHex := Hex(cfg.Key[:])
	var trustHex []string
	for _, t := range cfg.Trust {
		trustHex = append(trustHex, Hex(t[:]))
	}
	args := []string{
		"--dir", cfg.Dir,
		"--id", Hex(cfg.ID[:]),
		"--group", Hex(cfg.Group[:]),
		"--addr", cfg.Addr,
		"--ca", cfg.TLS.Ca,
		"--cert", cfg.TLS.Chain,
		"--key", cfg.TLS.Key,
		"--unlock", keyHex,
	}
	for _, s := range cfg.Seeds {
		args = append(args, "--seed", s)
	}
	for _, t := range trustHex {
		args = append(args, "--trust", t)
	}
	if cfg.NoStart {
		args = append(args, "--no-start")
	}
	if cfg.SchemaMaster {
		args = append(args, "--schema-master")
	}
	if cfg.Files != nil {
		args = append(args, "--files-dir", cfg.Files.Dir,
			"--files-key", Hex(cfg.Files.Key[:]),
			"--files-ip", cfg.Files.IP,
			"--files-port", strconv.Itoa(int(cfg.Files.Port)))
	}
	cmd := exec.Command(nodeBinary(), args...)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start node child: %w", err)
	}
	c := &childNode{cmd: cmd, stdin: bufio.NewWriter(stdin),
		stdout: bufio.NewReader(stdout), alive: true}
	n := &Node{Dir: cfg.Dir, ID: cfg.ID, Addr: cfg.Addr, TLS: cfg.TLS, child: c}
	// Readiness: the child prints {"ready":true} after boot.
	line, err := c.stdout.ReadBytes('\n')
	if err != nil {
		cmd.Process.Kill()
		return nil, fmt.Errorf("node child boot: %w", err)
	}
	var ready struct {
		Ready bool   `json:"ready"`
		Error string `json:"error,omitempty"`
	}
	if err := json.Unmarshal(line, &ready); err != nil || !ready.Ready {
		cmd.Process.Kill()
		if err != nil {
			return nil, fmt.Errorf("node child boot: %w", err)
		}
		return nil, fmt.Errorf("node child boot: %s", ready.Error)
	}
	return n, nil
}

func (c *childNode) call(op string, fill func(*childReq)) (*childResp, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.alive {
		return nil, fmt.Errorf("node child is dead")
	}
	c.nextID++
	req := &childReq{ID: c.nextID, Op: op}
	if fill != nil {
		fill(req)
	}
	raw, _ := json.Marshal(req)
	raw = append(raw, '\n')
	if _, err := c.stdin.Write(raw); err != nil {
		return nil, err
	}
	if err := c.stdin.Flush(); err != nil {
		return nil, err
	}
	line, err := c.stdout.ReadBytes('\n')
	if err != nil {
		return nil, err
	}
	var resp childResp
	if err := json.Unmarshal(line, &resp); err != nil {
		return nil, fmt.Errorf("decode child resp: %w", err)
	}
	if resp.ID != req.ID {
		return nil, fmt.Errorf("child resp id mismatch")
	}
	if !resp.OK {
		return nil, fmt.Errorf("%s", resp.Error)
	}
	return &resp, nil
}

func (c *childNode) running() bool { return c.alive }

func (c *childNode) start() error {
	_, err := c.call("start", nil)
	return err
}

func (c *childNode) stop() error {
	_, err := c.call("stop", nil)
	return err
}

// Kill SIGKILLs the child (crash legs). Restart via a fresh child
// on the same dir (see Cluster.RestartNode).
func (c *childNode) kill() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.alive {
		return nil
	}
	c.alive = false
	if err := c.cmd.Process.Kill(); err != nil {
		return err
	}
	c.cmd.Wait()
	return nil
}

func (c *childNode) close() error {
	c.mu.Lock()
	exited := !c.alive
	c.mu.Unlock()
	if !exited {
		c.call("exit", nil)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.alive = false
	c.cmd.Wait()
	return nil
}

func (c *childNode) simple(sql string) ([][]string, error) {
	resp, err := c.call("simple", func(r *childReq) { r.SQL = sql })
	if err != nil {
		return nil, err
	}
	return resp.Rows, nil
}

func (c *childNode) execute(sql string, args ...any) (int64, error) {
	resp, err := c.call("execute", func(r *childReq) { r.SQL = sql; r.Args = args })
	if err != nil {
		return 0, err
	}
	return resp.Changes, nil
}

func (c *childNode) flush() error {
	_, err := c.call("flush", nil)
	return err
}

func (c *childNode) collect() (uint64, uint64, error) {
	resp, err := c.call("collect", nil)
	if err != nil {
		return 0, 0, err
	}
	return resp.Moved, resp.Pruned, nil
}

func (c *childNode) setTable(table string, replicated bool) error {
	_, err := c.call("set_table", func(r *childReq) {
		r.Table = table
		r.Replicated = replicated
	})
	return err
}

func (c *childNode) peerAdd(addr string) error {
	_, err := c.call("peer_add", func(r *childReq) { r.Addr = addr })
	return err
}

func (c *childNode) peers() (string, error) {
	resp, err := c.call("peers", nil)
	if err != nil {
		return "", err
	}
	return resp.Raw, nil
}

func (c *childNode) status() (string, error) {
	resp, err := c.call("status", nil)
	if err != nil {
		return "", err
	}
	return resp.Raw, nil
}

func (c *childNode) progress() (string, error) {
	resp, err := c.call("progress", nil)
	if err != nil {
		return "", err
	}
	return resp.Raw, nil
}

func (c *childNode) health() (string, error) {
	resp, err := c.call("health", nil)
	if err != nil {
		return "", err
	}
	return resp.Raw, nil
}

func (c *childNode) fileUpload(name string, data []byte) error {
	_, err := c.call("file_upload", func(r *childReq) { r.Name = name; r.Data = data })
	return err
}

func (c *childNode) fileDownload(name string) ([]byte, error) {
	resp, err := c.call("file_download", func(r *childReq) { r.Name = name })
	if err != nil {
		return nil, err
	}
	return resp.Data, nil
}

func (c *childNode) fileAvailable(name string) (bool, error) {
	resp, err := c.call("file_available", func(r *childReq) { r.Name = name })
	if err != nil {
		return false, err
	}
	return resp.Changes != 0, nil
}

func (c *childNode) fileList() ([]files.Meta, error) {
	resp, err := c.call("file_list", nil)
	if err != nil {
		return nil, err
	}
	return resp.Metas, nil
}
