// Cluster lifecycle: per-node dirs, certs, sequential boot and mesh.
package goharness

import (
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// ClusterOptions configures a live cluster.
type ClusterOptions struct {
	Name     string
	NumNodes int
	// ChildNodes runs every node as a child process. Mixed mode
	// (in-process plus selected child nodes) uses ChildSet.
	ChildNodes bool
	// ChildSet marks individual nodes for child-process mode.
	ChildSet map[int]bool
	// NoMesh skips the bootstrap mesh (suites wire peers manually).
	NoMesh bool
	// Group overrides the random database id.
	Group *[16]byte
	// Key overrides the random unlock key.
	Key *[32]byte
	// Files stages the file-object store on every node (one uniform
	// fetch port, distinct 127.0.0.x bind IPs).
	Files bool
	// SchemaMaster, when non-nil, is the index of the node that
	// acts as schema master (nil disables master pushes).
	SchemaMaster *int
}

// Cluster is a live multi-node deployment under runtime/<name>/.
type Cluster struct {
	Name  string
	Dir   string
	Group [16]byte
	Key   [32]byte
	Ca    *Ca

	mu    sync.Mutex
	nodes []*Node
}

// NewCluster boots NumNodes meshed nodes.
func NewCluster(opts ClusterOptions) (*Cluster, error) {
	if opts.NumNodes <= 0 {
		return nil, fmt.Errorf("NumNodes must be > 0")
	}
	dir, err := PrepareRuntimeDir(opts.Name)
	if err != nil {
		return nil, err
	}
	c := &Cluster{Name: opts.Name, Dir: dir}
	if opts.Group != nil {
		c.Group = *opts.Group
	} else if _, err := rand.Read(c.Group[:]); err != nil {
		return nil, err
	}
	if opts.Key != nil {
		c.Key = *opts.Key
	} else if _, err := rand.Read(c.Key[:]); err != nil {
		return nil, err
	}
	ca, err := GenerateCa()
	if err != nil {
		return nil, err
	}
	c.Ca = ca
	ids, err := newNodeIDs(opts.NumNodes)
	if err != nil {
		c.closeAll()
		return nil, err
	}
	addrs := make([]string, opts.NumNodes)
	for i := range addrs {
		ap, err := FreeUDPAddr()
		if err != nil {
			c.closeAll()
			return nil, err
		}
		addrs[i] = ap.String()
	}
	var fetchPort uint16
	if opts.Files {
		fp, err := FreeUDPAddr()
		if err != nil {
			c.closeAll()
			return nil, err
		}
		fetchPort = fp.Port()
	}
	for i := 0; i < opts.NumNodes; i++ {
		nodeDir := filepath.Join(dir, fmt.Sprintf("node%d", i))
		if err := os.MkdirAll(nodeDir, 0o755); err != nil {
			c.closeAll()
			return nil, err
		}
		issued, err := ca.Issue(ids[i], nil)
		if err != nil {
			c.closeAll()
			return nil, err
		}
		tls, err := ca.WriteTLSDir(issued, nodeDir)
		if err != nil {
			c.closeAll()
			return nil, err
		}
		var seeds []string
		if !opts.NoMesh && i > 0 {
			seeds = []string{addrs[0]}
		}
		child := opts.ChildNodes || opts.ChildSet[i]
		var fcfg *FilesConfig
		if opts.Files {
			fcfg = &FilesConfig{
				Dir:  filepath.Join(nodeDir, "files"),
				Key:  c.Key,
				IP:   fmt.Sprintf("127.0.0.%d", i+1),
				Port: fetchPort,
			}
		}
		n, err := BootNode(NodeConfig{
			Dir: nodeDir, ID: ids[i], Group: c.Group,
			Addr: addrs[i], TLS: tls, Key: c.Key,
			Seeds: seeds, Trust: ids, Child: child, Files: fcfg,
			SchemaMaster: opts.SchemaMaster != nil && *opts.SchemaMaster == i,
		})
		if err != nil {
			c.closeAll()
			return nil, fmt.Errorf("boot node %d: %w", i, err)
		}
		c.nodes = append(c.nodes, n)
	}
	return c, nil
}

// newNodeIDs mints n distinct node ids: random upper bytes per call
// (two clusters in one test must not collide: the engine accept path
// drops duplicate-id dials) with index+1 in the last byte.
func newNodeIDs(n int) ([][16]byte, error) {
	if n < 1 || n > 255 {
		return nil, fmt.Errorf("node count %d out of range 1..255", n)
	}
	ids := make([][16]byte, n)
	for i := range ids {
		if _, err := rand.Read(ids[i][:15]); err != nil {
			return nil, err
		}
		ids[i][15] = byte(i + 1)
	}
	return ids, nil
}

// Len returns the node count.
func (c *Cluster) Len() int { return len(c.nodes) }

// Node returns node i.
func (c *Cluster) Node(i int) *Node { return c.nodes[i] }

// NodeID returns node i's id hex.
func (c *Cluster) NodeID(i int) string { return c.nodes[i].IDHex() }

// GroupHex renders the database id.
func (c *Cluster) GroupHex() string { return Hex(c.Group[:]) }

// RuntimeDir returns the scenario runtime dir.
func (c *Cluster) RuntimeDir() string { return c.Dir }

// PeerMesh fully meshes every node to every other via runtime adds.
func (c *Cluster) PeerMesh() error {
	for i := 0; i < len(c.nodes); i++ {
		for j := 0; j < len(c.nodes); j++ {
			if i == j {
				continue
			}
			if err := c.nodes[i].PeerAdd(c.nodes[j].Addr); err != nil {
				return fmt.Errorf("mesh %d->%d: %w", i, j, err)
			}
		}
	}
	return nil
}

// WaitPeers waits until every listed node reports n connected peers.
func (c *Cluster) WaitPeers(nodes []int, n int, timeout time.Duration) error {
	return PeerCounts(c, nodes, repeatInt(n, len(nodes)), timeout)
}

func repeatInt(v, n int) []int {
	out := make([]int, n)
	for i := range out {
		out[i] = v
	}
	return out
}

// StopNode stops replication on node i (store stays open).
func (c *Cluster) StopNode(i int) error { return c.nodes[i].Stop() }

// StartNode starts replication on node i.
func (c *Cluster) StartNode(i int) error { return c.nodes[i].Start() }

// KillNode SIGKILLs a child-process node. In-process nodes Stop
// instead (no process to kill); crash legs must use child mode.
func (c *Cluster) KillNode(i int) error {
	n := c.nodes[i]
	n.mu.Lock()
	ch := n.child
	n.mu.Unlock()
	if ch == nil {
		return n.Stop()
	}
	return ch.kill()
}

// RestartNode reboots node i on its existing dir (post-kill/crash).
func (c *Cluster) RestartNode(i int) error {
	old := c.nodes[i]
	old.mu.Lock()
	dir, id, addr, tls := old.Dir, old.ID, old.Addr, old.TLS
	ch := old.child
	fcfg := old.fcfg
	old.mu.Unlock()
	if ch == nil {
		return old.Start()
	}
	// Reap the dead child, then boot fresh on the same dir.
	ch.kill()
	seeds := []string{}
	if i > 0 {
		seeds = []string{c.nodes[0].Addr}
	}
	var ids [][16]byte
	for _, n := range c.nodes {
		ids = append(ids, n.ID)
	}
	n, err := BootNode(NodeConfig{
		Dir: dir, ID: id, Group: c.Group, Addr: addr,
		TLS: tls, Key: c.Key, Seeds: seeds, Trust: ids, Child: true,
		Files: fcfg,
	})
	if err != nil {
		return err
	}
	c.mu.Lock()
	c.nodes[i] = n
	c.mu.Unlock()
	return nil
}

func (c *Cluster) closeAll() {
	for _, n := range c.nodes {
		if n != nil {
			n.Close()
		}
	}
	c.nodes = nil
}

// Finish dumps forensics on failure and closes everything.
func (c *Cluster) Finish(failed bool) {
	if failed {
		for i, n := range c.nodes {
			DumpNodeForensics(fmt.Sprintf("node%d", i), n.Dir, "scenario failed")
		}
	}
	c.closeAll()
	FinishArtifacts(c.Name, c.Dir, failed)
}
