package managedprofiles

import (
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	mh "github.com/marcgauthier/libmurmur/clients/go/tests-live/managedharness"
)

func TestManagedResourcePlateauAcrossSearchFailuresAndProcessChurn(t *testing.T) {
	c := mh.NewCluster(t, 2)
	for node := range c.Nodes {
		if node == 1 {
			c.Publish()
		}
		c.Must(node, mh.Request{Op: "migrate", SQL: []string{"CREATE TABLE scratch(id INTEGER PRIMARY KEY,body TEXT,embedding BLOB)"}})
		var inserts []string
		for id := 0; id < 150; id++ {
			inserts = append(inserts, fmt.Sprintf("INSERT INTO scratch VALUES(%d,'alpha %d',%s)", id, id, point(float32(id+1), 1)))
		}
		c.Exec(node, inserts...)
	}
	cycles := 80
	if value := os.Getenv("MURMUR_MANAGED_RESOURCE_CYCLES"); value != "" {
		n, err := strconv.Atoi(value)
		if err != nil || n < 20 || n > 10000 {
			t.Fatal("resource cycles must be 20..10000")
		}
		cycles = n
	}
	// A correctly signed but structurally invalid frame exercises both the
	// Go-owned wire buffer and native rejection paths on every cycle.
	invalid := make([]byte, 200+(64<<10))
	copy(invalid, "MOR2")
	copy(invalid[4:20], c.Configs[0].Database[:])
	copy(invalid[20:36], c.Configs[0].Origin[:])
	binary.LittleEndian.PutUint64(invalid[52:60], 1)
	invalid = resign(invalid, c.Configs[0].Seed)
	cycle := func(node int) {
		t.Helper()
		c.Must(node, mh.Request{Op: "search", Table: "scratch", Column: "body", FTS: true})
		c.Must(node, mh.Request{Op: "search", Table: "scratch", Column: "embedding", Dims: 2})
		c.Must(node, mh.Request{Op: "refresh"})
		c.Exec(node, "UPDATE scratch SET embedding=x'00' WHERE id=0")
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		broken, err := c.Nodes[node].Call(ctx, mh.Request{Op: "refresh"})
		cancel()
		if err != nil || broken.RC == 0 {
			t.Fatalf("failure cycle did not hit invalid vector: %+v %v", broken, err)
		}
		statuses := c.Must(node, mh.Request{Op: "search-status"}).Rows
		errors := 0
		for _, status := range statuses {
			if status[5].Type != 0 {
				errors++
			}
		}
		if len(statuses) != 2 || errors == 0 {
			t.Fatal("failed search rebuild did not expose real index errors")
		}
		c.Exec(node, "UPDATE scratch SET embedding="+point(1, 1)+" WHERE id=0")
		c.Must(node, mh.Request{Op: "refresh"})
		statuses = c.Must(node, mh.Request{Op: "search-status"}).Rows
		if len(statuses) != 2 {
			t.Fatal("repaired search indexes missing")
		}
		for _, status := range statuses {
			if status[1].Integer != 1 || status[3].Integer != 0 || status[4].Integer != 0 || status[5].Type != 0 {
				t.Fatalf("repaired search did not drain queues: %+v", statuses)
			}
		}
		c.Must(node, mh.Request{Op: "search", Table: "scratch", Column: "body", FTS: false})
		c.Must(node, mh.Request{Op: "search", Table: "scratch", Column: "embedding", Dims: 0})
		ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
		rejected, err := c.Nodes[node].Call(ctx, mh.Request{Op: "exec", SQL: []string{"INSERT INTO scratch VALUES(1000,'must rollback',NULL)", "INSERT INTO scratch VALUES(0,'duplicate',NULL)"}})
		cancel()
		if err != nil || rejected.RC == 0 {
			t.Fatalf("constraint failure not exercised: %+v %v", rejected, err)
		}
		if len(c.Query(node, "SELECT id FROM scratch WHERE id=1000")) != 0 {
			t.Fatal("failed resource transaction left a row")
		}
		ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
		failedApply, err := c.Nodes[node].Call(ctx, mh.Request{Op: "apply", Data: invalid})
		cancel()
		if err != nil || failedApply.RC == 0 || failedApply.Changed {
			t.Fatalf("invalid signed apply did not fail closed: %+v %v", failedApply, err)
		}
		if len(c.Must(node, mh.Request{Op: "progress"}).Rows) != 0 {
			t.Fatal("failed apply advanced an origin receipt")
		}
	}
	for i := 0; i < 12; i++ {
		for node := range c.Nodes {
			cycle(node)
		}
	}
	baseline := make([]mh.Resources, len(c.Nodes))
	for node := range c.Nodes {
		baseline[node] = *c.Must(node, mh.Request{Op: "resources"}).Resources
	}
	checkChildren := func(phase string, iteration int) {
		t.Helper()
		for node := range c.Nodes {
			deadline := time.Now().Add(5 * time.Second)
			for {
				current := c.Must(node, mh.Request{Op: "resources"})
				if current.Resources == nil || current.Stats == nil {
					t.Fatal("missing resource or scheduler measurements")
				}
				r := current.Resources
				b := baseline[node]
				queued := uint64(0)
				for _, class := range current.Stats.Classes {
					queued += class.Waiters
				}
				// Recovery can create new SSTs, whose live read descriptors
				// are legitimate persistent storage. Bound other descriptors
				// separately, and permit at most one SST reader per live file
				// plus two transient compaction readers. Deleted/duplicate
				// handles cannot hide in an ever-increasing total-FD budget.
				nonStorageFDs := r.FDs - r.StorageFDs
				fdOK := nonStorageFDs <= b.FDs-b.StorageFDs+2 && r.StorageFDs <= r.SSTFiles+2
				if r.Goroutines <= b.Goroutines+6 && fdOK && queued == 0 && !current.Stats.Active {
					if r.Heap > b.Heap+(16<<20) || r.RSS > b.RSS+(192<<20) {
						t.Fatalf("resource growth node=%d baseline=%+v current=%+v", node, b, *r)
					}
					t.Logf("phase=%s cycle=%d node=%d goroutines=%d fds=%d sst_readers=%d sst_files=%d heap=%d rss=%d", phase, iteration, node, r.Goroutines, r.FDs, r.StorageFDs, r.SSTFiles, r.Heap, r.RSS)
					break
				}
				if time.Now().After(deadline) {
					t.Fatalf("resources/queues failed to settle node=%d baseline=%+v current=%+v stats=%+v", node, b, *r, current.Stats)
				}
				time.Sleep(10 * time.Millisecond)
			}
			for _, status := range c.Must(node, mh.Request{Op: "search-status"}).Rows {
				if status[3].Integer != 0 || status[4].Integer != 0 {
					t.Fatal("disposed search index retained queued keys/bytes")
				}
			}
		}
	}
	// Keep the same children alive throughout this phase: restarting them
	// would erase leaked native allocations before we could measure them.
	for i := 0; i < cycles; i++ {
		for node := range c.Nodes {
			cycle(node)
		}
		if i%20 == 19 || i == cycles-1 {
			checkChildren("steady", i+1)
		}
	}
	parentBaseline, err := mh.SampleResources(c.Root)
	if err != nil {
		t.Fatal(err)
	}
	// Independently exercise subprocess pipes, waiters and output readers.
	for round := 0; round < 8; round++ {
		for node := range c.Nodes {
			c.Restart(node)
			for i := 0; i < 3; i++ {
				cycle(node)
			}
			if got := c.Query(node, "SELECT count(*) FROM scratch")[0][0].Integer; got != 150 {
				t.Fatalf("process restart lost source rows: %d", got)
			}
		}
		checkChildren("churn", round+1)
		deadline := time.Now().Add(5 * time.Second)
		for {
			current, err := mh.SampleResources(c.Root)
			if err != nil {
				t.Fatal(err)
			}
			// Two bounded 16 MiB RPC traces can grow after the baseline.
			if current.Goroutines <= parentBaseline.Goroutines+4 && current.FDs <= parentBaseline.FDs+2 && current.Heap <= parentBaseline.Heap+(40<<20) {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("parent resources did not settle after churn: baseline=%+v current=%+v", *parentBaseline, *current)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	if err := filepath.WalkDir(c.Root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !entry.IsDir() {
			for _, suffix := range []string{"-journal", "-wal", "-shm"} {
				if strings.HasSuffix(entry.Name(), suffix) {
					return fmt.Errorf("temporary SQLite artifact leaked: %s", path)
				}
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
