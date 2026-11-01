package managedharness

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type Cluster struct {
	t          *testing.T
	Root       string
	Nodes      []*Process
	Configs    []Config
	generation []int
}

func NewCluster(t *testing.T, count int) *Cluster {
	t.Helper()
	if os.Getenv("MURMUR_ENGINE_INTEGRATION") != "1" {
		t.Skip("managed live tests require MURMUR_ENGINE_INTEGRATION=1")
	}
	base := os.Getenv("MURMUR_LIVE_RUNTIME")
	if base != "" {
		if err := os.MkdirAll(base, 0700); err != nil {
			t.Fatal(err)
		}
	}
	root, err := os.MkdirTemp(base, "murmur-managed-live-")
	if err != nil {
		t.Fatal(err)
	}
	c := &Cluster{t: t, Root: root, Nodes: make([]*Process, count), Configs: make([]Config, count), generation: make([]int, count)}
	t.Cleanup(func() {
		for i, node := range c.Nodes {
			if node == nil {
				continue
			}
			if t.Failed() {
				// Failure-only diagnostics cannot intervene in the strict
				// ACK-to-SIGKILL path exercised by the durability tests.
				if node.Alive() {
					for _, op := range []string{"progress", "stats"} {
						ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
						node.Call(ctx, Request{Op: op}) // retained in the RPC trace
						cancel()
					}
				}
				if err := node.Kill(); err != nil {
					t.Errorf("reap node %d: %v", i, err)
				}
			} else {
				if node.Alive() {
					if err := node.Close(); err != nil {
						t.Errorf("close node %d: %v", i, err)
					}
				} else if err := node.Kill(); err != nil {
					t.Errorf("reap stopped node %d: %v", i, err)
				}
			}
			if err := node.SaveTrace(filepath.Join(root, fmt.Sprintf("node-%d-%d.jsonl", i, c.generation[i]))); err != nil {
				t.Errorf("save node %d trace: %v", i, err)
			}
		}
		if t.Failed() {
			data, _ := json.MarshalIndent(c.Configs, "", "  ")
			os.WriteFile(filepath.Join(root, "test-identities.json"), data, 0600)
			t.Logf("managed failure artifacts: %s", root)
		} else {
			os.RemoveAll(root)
		}
	})
	for i := range c.Nodes {
		config := Config{Path: filepath.Join(root, fmt.Sprintf("store-%d", i))}
		config.Key[0] = 41
		config.Database[0] = 73
		config.Origin[0] = byte(i + 1)
		config.Seed[0] = byte(i + 11)
		c.Configs[i] = config
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		node, err := Start(ctx, config)
		cancel()
		if err != nil {
			t.Fatal(err)
		}
		c.Nodes[i] = node
	}
	for i := range c.Nodes {
		for j := range c.Nodes {
			if i != j {
				identity := c.Nodes[j].Identity
				c.Must(i, Request{Op: "trust", Identity: &identity, Enabled: true})
			}
		}
	}
	for i := 1; i < count; i++ {
		c.Must(i, Request{Op: "master", Origin: c.Configs[0].Origin})
	}
	return c
}

func (c *Cluster) Must(node int, request Request) Response {
	c.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	response, err := c.Nodes[node].Call(ctx, request)
	if err != nil || response.RC != 0 {
		c.t.Fatalf("node=%d op=%s rc=%d err=%v detail=%s", node, request.Op, response.RC, err, response.Error)
	}
	return response
}

func (c *Cluster) Exec(node int, sql ...string) {
	c.t.Helper()
	c.Must(node, Request{Op: "exec", SQL: sql})
}
func (c *Cluster) Query(node int, sql string) [][]Value {
	c.t.Helper()
	return c.Must(node, Request{Op: "query", SQL: []string{sql}}).Rows
}

func (c *Cluster) Publish() []byte {
	c.t.Helper()
	record := c.Must(0, Request{Op: "export-schema"}).Data
	for i := 1; i < len(c.Nodes); i++ {
		if c.Nodes[i].Alive() {
			c.Must(i, Request{Op: "adopt", Data: record})
		}
	}
	return record
}

func (c *Cluster) Restart(node int) {
	c.t.Helper()
	old := c.Nodes[node]
	if old.Alive() {
		if err := old.Kill(); err != nil {
			c.t.Fatal(err)
		}
	}
	if err := old.SaveTrace(filepath.Join(c.Root, fmt.Sprintf("node-%d-%d.jsonl", node, c.generation[node]))); err != nil {
		c.t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	replacement, err := Start(ctx, c.Configs[node])
	if err != nil {
		c.t.Fatal(err)
	}
	if replacement.Identity != old.Identity {
		replacement.Kill()
		c.t.Fatal("persistent signing/site identity changed across restart")
	}
	c.Nodes[node] = replacement
	c.generation[node]++
}

// CatchUp delivers immutable signed records with a controlled schedule. It
// makes no QUIC claim: native signed transport integration is still pending.
// Receipts, dependency rejection, persistence and materialization are real.
func (c *Cluster) CatchUp() {
	c.t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for round := 0; round < 10000 && time.Now().Before(deadline); round++ {
		progress, blocked := false, false
		for destination, node := range c.Nodes {
			if !node.Alive() {
				continue
			}
			heads := map[string]uint64{}
			for _, row := range c.Must(destination, Request{Op: "progress"}).Rows {
				heads[row[0].Hex] = uint64(row[1].Integer)
			}
			for _, origin := range c.Configs {
				after := heads[hex.EncodeToString(origin.Origin[:])]
				var record []byte
				for relay, source := range c.Nodes {
					if !source.Alive() {
						continue
					}
					ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
					response, err := source.Call(ctx, Request{Op: "next", Origin: origin.Origin, After: after})
					cancel()
					if err != nil {
						c.t.Fatalf("export relay=%d: %v", relay, err)
					}
					if response.RC == 12 {
						continue
					}
					if response.RC != 0 {
						c.t.Fatalf("export rc=%d", response.RC)
					}
					record = response.Data
					break
				}
				if record == nil {
					continue
				}
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				response, err := node.Call(ctx, Request{Op: "apply", Data: record})
				cancel()
				if err != nil {
					c.t.Fatal(err)
				}
				if response.RC == 5 {
					blocked = true
					continue
				}
				if response.RC != 0 {
					c.t.Fatalf("apply destination=%d rc=%d", destination, response.RC)
				}
				if !response.Changed {
					c.t.Fatal("new origin sequence reported duplicate")
				}
				progress = true
			}
		}
		if !progress {
			if blocked {
				c.t.Fatal("causal catch-up stalled with all available original records")
			}
			return
		}
	}
	c.t.Fatal("catch-up exceeded bounded rounds")
}
