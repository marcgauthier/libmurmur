package murmurdb

import (
	"context"
	"database/sql/driver"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

// This is a resource contract, independent of the cache's implementation.
// Active caller-owned Rows may need additional statements, but the driver
// must not retain an unbounded number after those Rows have closed.
const statementCacheBudget = 128

func TestStatementCacheDoesNotGrowWithUniqueSQL(t *testing.T) {
	db := openTest(t, "?key="+testKeyHex)
	sqlConn, err := db.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer sqlConn.Close()
	for i := 0; i < 600; i++ {
		var got int
		query := fmt.Sprintf("SELECT ? /* unique-query-%d */", i)
		if err := sqlConn.QueryRowContext(context.Background(), query, i).Scan(&got); err != nil || got != i {
			t.Fatalf("unique query %d: got=%d err=%v", i, got, err)
		}
	}
	if err := sqlConn.Raw(func(raw any) error {
		c := raw.(*conn)
		c.mu.Lock()
		defer c.mu.Unlock()
		if len(c.cache) > statementCacheBudget {
			return fmt.Errorf("retained %d prepared statements after 600 unique queries; budget=%d", len(c.cache), statementCacheBudget)
		}
		for query, entry := range c.cache {
			if entry.busy {
				return fmt.Errorf("closed query still busy: %s", query)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestStatementCacheBoundWithLiveRows(t *testing.T) {
	db := openTest(t, "?key="+testKeyHex)
	sqlConn, err := db.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer sqlConn.Close()
	if err := sqlConn.Raw(func(raw any) error {
		c := raw.(*conn)
		var live []driver.Rows
		defer func() {
			for _, rows := range live {
				rows.Close()
			}
		}()
		for i := 0; i < statementCacheBudget+32; i++ {
			rows, err := c.QueryContext(context.Background(), fmt.Sprintf("SELECT %d", i), nil)
			if err != nil {
				return err
			}
			live = append(live, rows)
		}
		if len(c.cache) > statementCacheBudget {
			return fmt.Errorf("busy cache grew to %d entries; budget=%d", len(c.cache), statementCacheBudget)
		}
		// Eviction must never finalize a statement owned by an open Rows.
		for i, rows := range live {
			value := make([]driver.Value, 1)
			if err := rows.Next(value); err != nil || value[0] != int64(i) {
				return fmt.Errorf("live row %d lost during cache pressure: value=%v err=%v", i, value, err)
			}
			if err := rows.Close(); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := sqlConn.Close(); err != nil {
		t.Fatal(err)
	}
	assertUsable(t, db)
}

func TestStatementCacheReleasesOperandsAndBoundsNativeBytes(t *testing.T) {
	db := openTest(t, "?key="+testKeyHex)
	sqlConn, err := db.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer sqlConn.Close()
	large := make([]byte, 12<<20)
	var length int
	if err := sqlConn.QueryRowContext(context.Background(), "SELECT length(?)", large).Scan(&length); err != nil || length != len(large) {
		t.Fatalf("large operand: length=%d err=%v", length, err)
	}
	if err := sqlConn.Raw(func(raw any) error {
		c := raw.(*conn)
		entry := c.cache["SELECT length(?)"]
		if entry != nil && entry.st.MemoryUsed() > 64<<10 {
			return fmt.Errorf("idle statement retained large bound operand: %d bytes", entry.st.MemoryUsed())
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 4; i++ {
		query := fmt.Sprintf("SELECT length('%s') /* large-%d */", strings.Repeat("x", 1500<<10), i)
		if err := sqlConn.QueryRowContext(context.Background(), query).Scan(&length); err != nil || length != 1500<<10 {
			t.Fatalf("large SQL: length=%d err=%v", length, err)
		}
	}
	if err := sqlConn.Raw(func(raw any) error {
		c := raw.(*conn)
		actual := 0
		for query, entry := range c.cache {
			actual += entry.st.MemoryUsed() + len(query)
		}
		if actual > 8<<20 || actual != c.cacheBytes {
			return fmt.Errorf("native cache accounting/budget: measured=%d reported=%d budget=8MiB", actual, c.cacheBytes)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

type resourceSample struct {
	FDs, Goroutines int
	Heap, RSS       uint64
}

func sampleResources(t *testing.T) resourceSample {
	t.Helper()
	runtime.GC()
	var memory runtime.MemStats
	runtime.ReadMemStats(&memory)
	sample := resourceSample{Goroutines: runtime.NumGoroutine(), Heap: memory.HeapAlloc}
	if runtime.GOOS == "linux" {
		entries, err := os.ReadDir("/proc/self/fd")
		if err != nil {
			t.Fatal(err)
		}
		sample.FDs = len(entries)
		data, err := os.ReadFile("/proc/self/statm")
		if err != nil {
			t.Fatal(err)
		}
		fields := strings.Fields(string(data))
		if len(fields) < 2 {
			t.Fatalf("invalid statm: %q", data)
		}
		pages, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			t.Fatal(err)
		}
		sample.RSS = pages * uint64(os.Getpagesize())
	}
	return sample
}

func resourceCycle(t *testing.T, path string) {
	t.Helper()
	db, err := Open(path + "?key=" + testKeyHex)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec("CREATE TABLE t(id INTEGER PRIMARY KEY,b BLOB); INSERT INTO t VALUES(1,zeroblob(5000)),(2,x'00')"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 16; i++ {
		ctx, cancel := context.WithCancel(context.Background())
		rows, err := db.QueryContext(ctx, fmt.Sprintf("SELECT b FROM t WHERE id>=? /* cycle-%d */", i), 1)
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		if !rows.Next() {
			rows.Close()
			cancel()
			t.Fatal("resource cycle returned no row")
		}
		var blob []byte
		if err := rows.Scan(&blob); err != nil {
			t.Fatal(err)
		}
		if err := rows.Close(); err != nil {
			t.Fatal(err)
		}
		cancel()
	}
	if _, err := db.Exec("INSERT INTO t VALUES(1,x'ff')"); err == nil {
		t.Fatal("expected constraint failure")
	}
	assertUsable(t, db)
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestResourcesPlateauAcrossLifecycleAndFailures(t *testing.T) {
	root := t.TempDir()
	for i := 0; i < 12; i++ {
		resourceCycle(t, filepath.Join(root, fmt.Sprintf("warm-%d", i)))
	}
	baseline := sampleResources(t)
	for epoch := 0; epoch < 4; epoch++ {
		for i := 0; i < 20; i++ {
			resourceCycle(t, filepath.Join(root, fmt.Sprintf("epoch-%d-%d", epoch, i)))
		}
		deadline := time.Now().Add(3 * time.Second)
		var current resourceSample
		for {
			current = sampleResources(t)
			if current.Goroutines <= baseline.Goroutines+3 && current.FDs <= baseline.FDs+2 {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("resources failed to settle: baseline=%+v current=%+v", baseline, current)
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Logf("epoch=%d baseline=%+v current=%+v", epoch, baseline, current)
		if current.Heap > baseline.Heap+16<<20 {
			t.Fatalf("Go heap failed to plateau: baseline=%+v current=%+v", baseline, current)
		}
		// RSS includes Go, native caches and allocator arenas. Use a separate
		// generous bound after warmup, not a brittle requirement to return
		// every freed byte to the OS immediately.
		if current.RSS > baseline.RSS+96<<20 {
			t.Fatalf("process/native RSS failed to plateau: baseline=%+v current=%+v", baseline, current)
		}
	}
	if err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		name := entry.Name()
		if !entry.IsDir() && (strings.HasSuffix(name, "-journal") || strings.HasSuffix(name, "-wal") || strings.HasSuffix(name, "-shm")) {
			return fmt.Errorf("temporary SQLite artifact survived close: %s", path)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
