// SQL assertions shared by live workloads.
package goharness

import (
	"fmt"
	"strings"
	"time"
)

// Fixture creates the shared records fixture on every node and enables
// its replication.
func Fixture(cluster *Cluster) error {
	for i := 0; i < cluster.Len(); i++ {
		if _, err := cluster.Node(i).Simple("CREATE TABLE IF NOT EXISTS records(id TEXT PRIMARY KEY NOT NULL DEFAULT '', name TEXT NOT NULL DEFAULT '')"); err != nil {
			return fmt.Errorf("create SQL fixture: %w", err)
		}
		if err := cluster.Node(i).SetTableReplicated("records", true); err != nil {
			return fmt.Errorf("enable fixture replication: %w", err)
		}
		if err := cluster.Node(i).Flush(); err != nil {
			return fmt.Errorf("flush fixture schema: %w", err)
		}
	}
	return nil
}

// Rows reads the fixture rows.
func Rows(client *Node) ([][]string, error) {
	rows, err := client.Simple("SELECT id, name FROM records ORDER BY id")
	if err != nil {
		return nil, fmt.Errorf("read SQL rows: %w", err)
	}
	return rows, nil
}

// Status returns the engine diagnostic snapshot.
func Status(client *Node) (any, error) {
	return client.ShowStatus()
}

// Peers returns decoded membership rows.
func Peers(client *Node) ([]PeerRow, error) {
	return client.ShowPeers()
}

// Converge waits until every listed node reads expected fixture rows.
func Converge(cluster *Cluster, nodes []int, expected [][]string, timeout time.Duration) error {
	end := time.Now().Add(timeout)
	for {
		type snapshot struct {
			node int
			rows [][]string
		}
		var last []snapshot
		for _, i := range nodes {
			rows, err := Rows(cluster.Node(i))
			if err != nil {
				return err
			}
			last = append(last, snapshot{node: i, rows: rows})
		}
		all := true
		for _, s := range last {
			if !rowsEqual(s.rows, expected) {
				all = false
				break
			}
		}
		if all {
			return nil
		}
		if !time.Now().Before(end) {
			actual := make([]string, 0, len(last))
			for _, s := range last {
				actual = append(actual, fmt.Sprintf("(%d, %q)", s.node, s.rows))
			}
			return fmt.Errorf("SQL convergence timeout: expected=%q, actual=[%s]",
				expected, strings.Join(actual, ", "))
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// AssertRows waits until every listed node reads expected rows for an
// arbitrary query (60 s deadline, 50 ms polls).
func AssertRows(cluster *Cluster, nodes []int, query string, expected [][]string) error {
	deadline := time.Now().Add(60 * time.Second)
	for {
		all := true
		type mismatch struct {
			node int
			rows [][]string
		}
		var last []mismatch
		for _, i := range nodes {
			rows, err := cluster.Node(i).Simple(query)
			if err != nil {
				if ErrorCode(err) == "noparam" {
					all = false
					continue
				}
				return fmt.Errorf("poll SQL state: %w", err)
			}
			if !rowsEqual(rows, expected) {
				all = false
				last = append(last, mismatch{node: i, rows: rows})
			}
		}
		if all {
			return nil
		}
		if !time.Now().Before(deadline) {
			return fmt.Errorf("SQL convergence timed out: %s; expected=%v, got=%v", query, expected, last)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// PeerCounts waits until the listed nodes report the expected
// connected peer counts.
func PeerCounts(cluster *Cluster, nodes []int, counts []int, timeout time.Duration) error {
	if len(nodes) != len(counts) {
		return fmt.Errorf("nodes/counts length mismatch")
	}
	end := time.Now().Add(timeout)
	for {
		all := true
		var last []string
		for k, i := range nodes {
			peers, err := cluster.Node(i).ShowPeers()
			if err != nil {
				return err
			}
			got := 0
			for _, p := range peers {
				if p.Connected {
					got++
				}
			}
			if got != counts[k] {
				all = false
				last = append(last, fmt.Sprintf("node %d: got %d want %d", i, got, counts[k]))
			}
		}
		if all {
			return nil
		}
		if !time.Now().Before(end) {
			return fmt.Errorf("peer counts timeout: %s", strings.Join(last, "; "))
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func rowsEqual(a, b [][]string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if len(a[i]) != len(b[i]) {
			return false
		}
		for j := range a[i] {
			if a[i][j] != b[i][j] {
				return false
			}
		}
	}
	return true
}
