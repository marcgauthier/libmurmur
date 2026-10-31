// Live scenario: a real encrypted store holding 6000 rows x 2 tables is
// populated, closed and reopened, and every reopen must recover
// identical contents.
//
// Port of MURMUR-SQL open-progress: migrate and populate two tables,
// verify count + ordinal-sum contents, close and reopen twice with
// identical contents, and open a fresh empty database. Reloads are real
// close + BootNode reopens on the same dir and key (there is no unlock
// watchdog on this stack; the reopen is the substance). The wrong-key /
// short-key open-failure legs and the fail-closed watchdog leg need a
// wire unlock surface that native nodes do not expose, so they live in
// TestOpenFailureLegs and TestWatchdogFailsClosed, which skip.
package openprogress

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	goharness "github.com/marcgauthier/sqlite-murmur-go/clients/go/tests-live/goharness"
)

// rowsPerTable is the per-table row count (reference: rowsPerTable = 6000).
const rowsPerTable = 6000

// repeat32 returns 32 copies of b: the application key is 0x63 x32
// (reference: bytes.Repeat([]byte{0x63}, 32)).
func repeat32(b byte) [32]byte {
	var out [32]byte
	for i := range out {
		out[i] = b
	}
	return out
}

var appKey = repeat32(0x63)

// migrate creates both tables on the single node (reference: the
// `populate` role schema).
func migrate(node *goharness.Node) error {
	for _, table := range []string{"requests", "events"} {
		if _, err := node.Simple(
			fmt.Sprintf("CREATE TABLE %s(id INTEGER PRIMARY KEY NOT NULL, message TEXT NOT NULL DEFAULT '', ordinal INTEGER NOT NULL DEFAULT 0)", table)); err != nil {
			return fmt.Errorf("migrate %s: %w", table, err)
		}
	}
	return nil
}

// populate fills both tables (reference: the `populate` role). One
// durability barrier at the end; rows are visible locally as they
// commit.
func populate(node *goharness.Node) error {
	for _, table := range []string{"requests", "events"} {
		for i := int64(0); i < rowsPerTable; i++ {
			message := fmt.Sprintf("realistic diagnostic %d %s", i, strings.Repeat("trace ", 512))
			if _, err := node.Execute(
				fmt.Sprintf("INSERT INTO %s(id, message, ordinal) VALUES($1, $2, $3)", table),
				i, message, i); err != nil {
				return fmt.Errorf("populate: insert %s %d: %w", table, i, err)
			}
		}
	}
	if err := node.Flush(); err != nil {
		return fmt.Errorf("populate: flush: %w", err)
	}
	fmt.Fprintf(os.Stderr, "populate: %d rows x2 tables\n", rowsPerTable)
	return nil
}

// verifyContents checks count + ordinal-sum per table (reference:
// `verifyProgressTable`).
func verifyContents(node *goharness.Node, name string) error {
	for _, table := range []string{"requests", "events"} {
		rows, err := node.Simple(
			fmt.Sprintf("SELECT COUNT(*), COALESCE(SUM(ordinal), 0) FROM %s", table))
		if err != nil {
			return fmt.Errorf("%s: verify %s: %w", name, table, err)
		}
		if len(rows) == 0 {
			return fmt.Errorf("%s: verify %s: no rows", name, table)
		}
		if len(rows[0]) < 2 {
			return fmt.Errorf("%s: verify %s: bad row %v", name, table, rows[0])
		}
		count, err := strconv.ParseInt(rows[0][0], 10, 64)
		if err != nil {
			return fmt.Errorf("%s: verify %s: bad count %v", name, table, rows[0])
		}
		sum, err := strconv.ParseInt(rows[0][1], 10, 64)
		if err != nil {
			return fmt.Errorf("%s: verify %s: bad sum %v", name, table, rows[0])
		}
		if count != rowsPerTable {
			return fmt.Errorf("%s: wrong count %s: %d", name, table, count)
		}
		if sum != rowsPerTable*(rowsPerTable-1)/2 {
			return fmt.Errorf("%s: wrong contents %s: sum=%d", name, table, sum)
		}
	}
	return nil
}

// reloadAndVerify is the reload leg (reference: the `reload` role):
// close the store and reopen it on the same dir and key, then contents
// must verify exactly.
func reloadAndVerify(cluster *goharness.Cluster, node *goharness.Node, name string) (*goharness.Node, error) {
	start := time.Now()
	dir, id, addr, tls := node.Dir, node.ID, node.Addr, node.TLS
	if err := node.Close(); err != nil {
		return node, fmt.Errorf("%s: close: %w", name, err)
	}
	reopened, err := goharness.BootNode(goharness.NodeConfig{
		Dir: dir, ID: id, Group: cluster.Group, Addr: addr,
		TLS: tls, Key: cluster.Key, Trust: [][16]byte{id},
	})
	if err != nil {
		return node, fmt.Errorf("%s: reopen: %w", name, err)
	}
	fmt.Fprintf(os.Stderr, "%s: reopened in %v\n", name, time.Since(start))
	if err := verifyContents(reopened, name); err != nil {
		return reopened, err
	}
	fmt.Fprintf(os.Stderr, "PASS %s: contents identical after reopen\n", name)
	return reopened, nil
}

// emptyDBLeg is the empty-database leg (reference: the `empty-db` role):
// a fresh database opens with zero rows and answers queries.
func emptyDBLeg() error {
	cluster, err := goharness.NewCluster(goharness.ClusterOptions{
		Name:     "open-progress-empty",
		NumNodes: 1,
		Key:      &appKey,
	})
	if err != nil {
		return fmt.Errorf("empty-db cluster setup: %w", err)
	}
	failed := true
	defer func() { cluster.Finish(failed) }()
	if _, err := cluster.Node(0).Simple("CREATE TABLE probe(id INTEGER PRIMARY KEY NOT NULL)"); err != nil {
		fmt.Fprintf(os.Stderr, "scenario failed: empty-db migrate: %v\n", err)
		return fmt.Errorf("empty-db migrate: %w", err)
	}
	rows, err := cluster.Node(0).Simple("SELECT COUNT(*) FROM probe")
	if err != nil {
		fmt.Fprintf(os.Stderr, "scenario failed: empty-db count: %v\n", err)
		return fmt.Errorf("empty-db count: %w", err)
	}
	count := ""
	if len(rows) > 0 && len(rows[0]) > 0 {
		count = rows[0][0]
	}
	if count != "0" {
		err := fmt.Errorf("empty-db: fresh table holds %s rows, want 0", count)
		fmt.Fprintf(os.Stderr, "scenario failed: %v\n", err)
		return err
	}
	fmt.Fprintln(os.Stderr, "PASS empty-db: fresh database opened with zero rows")
	failed = false
	return nil
}

func runBody(cluster *goharness.Cluster) error {
	// Main flow: populate, reload, reload. The open-failure and
	// watchdog legs need a wire unlock surface and live in the
	// skipping tests below.
	node := cluster.Node(0)
	if err := migrate(node); err != nil {
		return err
	}
	if err := populate(node); err != nil {
		return err
	}
	if err := verifyContents(node, "populate"); err != nil {
		return err
	}
	var err error
	if node, err = reloadAndVerify(cluster, node, "reload-1"); err != nil {
		return err
	}
	if node, err = reloadAndVerify(cluster, node, "reload-2-recovery"); err != nil {
		return err
	}
	// The cluster still owns the original (closed) handle; close the
	// live reopened one here. Double closes are no-ops.
	defer node.Close()

	// Fresh empty database opens with zero rows.
	if err := emptyDBLeg(); err != nil {
		return err
	}

	fmt.Fprintln(os.Stderr, "PASS open-progress: all legs green")
	return nil
}

func TestOpenProgress(t *testing.T) {
	goharness.SkipUnlessLive(t)
	cluster, err := goharness.NewCluster(goharness.ClusterOptions{
		Name:     "open-progress",
		NumNodes: 1,
		Key:      &appKey,
	})
	if err != nil {
		t.Fatalf("cluster setup: %v", err)
	}
	if cluster.Len() != 1 {
		t.Fatalf("this scenario is written for 1 node, got %d", cluster.Len())
	}
	failed := true
	defer func() { cluster.Finish(failed) }()
	if err := runBody(cluster); err != nil {
		fmt.Fprintf(os.Stderr, "scenario failed: %v\n", err)
		t.Fatalf("scenario failed: %v", err)
	}
	failed = false
}

func TestOpenFailureLegs(t *testing.T) {
	goharness.SkipUnlessLive(t)
	// Blocked: native nodes expose no wire unlock surface on which to
	// present a wrong or short key (no MURMUR UNLOCK, no SQLSTATEs).
	t.Skip("harness: wire unlock handshake (wrong/short key rejection)")
}

func TestWatchdogFailsClosed(t *testing.T) {
	goharness.SkipUnlessLive(t)
	// Blocked: no unlock watchdog exists natively (no connect with a
	// stall window to fail closed).
	t.Skip("harness: unlock watchdog with stall window")
}
