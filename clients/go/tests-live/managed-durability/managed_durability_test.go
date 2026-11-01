package manageddurability

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	mh "github.com/marcgauthier/sqlite-murmur-go/clients/go/tests-live/managedharness"
)

func TestAcknowledgedTransactionsSurviveImmediateSIGKILL(t *testing.T) {
	c := mh.NewCluster(t, 3)
	c.Must(0, mh.Request{Op: "migrate", SQL: []string{"CREATE TABLE audit(txid INTEGER NOT NULL,part INTEGER NOT NULL,payload TEXT NOT NULL DEFAULT '',PRIMARY KEY(txid,part)); CREATE TABLE counters(id INTEGER NOT NULL PRIMARY KEY,n INTEGER)"}})
	c.Must(0, mh.Request{Op: "policy", Table: "counters", Column: "n", Policy: 1})
	for _, table := range []string{"audit", "counters"} {
		c.Must(0, mh.Request{Op: "replication", Table: table, Enabled: true})
	}
	c.Publish()
	c.Exec(0, "INSERT INTO counters VALUES(1,0)")
	c.CatchUp()
	var acknowledged []int
	expected := map[int]string{}
	t.Cleanup(func() {
		if t.Failed() {
			data, _ := json.Marshal(expected)
			os.WriteFile(filepath.Join(c.Root, "acknowledged-transactions.json"), data, 0600)
		}
	})
	for round := 0; round < 6; round++ {
		node := round % 3
		for j := 0; j < 4; j++ {
			id := round*4 + j
			payload := fmt.Sprintf("transaction-%d-%s", id, bytes.Repeat([]byte{'x'}, 2000))
			c.Exec(node, fmt.Sprintf("INSERT INTO audit VALUES(%d,0,'%s')", id, payload), fmt.Sprintf("INSERT INTO audit VALUES(%d,1,'%s')", id, payload), "SELECT murmur_counter_add('counters','[1]','n',1)")
			acknowledged = append(acknowledged, id)
			expected[id] = payload
		}
		// The next action after the final successful write response is kill.
		// No query, export, flush, drain, sleep, or graceful shutdown occurs.
		started := time.Now()
		if err := c.Nodes[node].Kill(); err != nil {
			t.Fatal(err)
		}
		if !c.Nodes[node].WasSIGKILL() {
			t.Fatal("victim did not actually terminate from SIGKILL")
		}
		t.Logf("round=%d SIGKILL/reap=%s", round, time.Since(started))
		c.Restart(node)
		for _, id := range acknowledged {
			// Previously converged writes plus this victim's last acknowledged
			// writes must already exist locally before replication resumes.
			rows := c.Query(node, fmt.Sprintf("SELECT part,payload FROM audit WHERE txid=%d ORDER BY part", id))
			if len(rows) != 2 || rows[0][0].Integer != 0 || rows[1][0].Integer != 1 || rows[0][1].Text() != expected[id] || rows[1][1].Text() != expected[id] {
				t.Fatalf("acknowledged transaction %d missing/torn after restart: %+v", id, rows)
			}
		}
		c.CatchUp()
		var baseline []byte
		for peer := range c.Nodes {
			rows := c.Query(peer, "SELECT txid,part,payload FROM audit ORDER BY txid,part")
			data, _ := json.Marshal(rows)
			if peer == 0 {
				baseline = data
			} else if !bytes.Equal(data, baseline) {
				t.Fatalf("exact acknowledged transaction sets differ at node %d", peer)
			}
			counter := c.Query(peer, "SELECT n FROM counters WHERE id=1")
			if counter[0][0].Integer != int64(len(acknowledged)) {
				t.Fatalf("counter applied twice/lost at node %d: %+v", peer, counter)
			}
		}
	}
}

func TestSIGKILLWithRealTransactionStagedBeforeCommit(t *testing.T) {
	c := mh.NewCluster(t, 3)
	c.Must(0, mh.Request{Op: "migrate", SQL: []string{"CREATE TABLE audit(id INTEGER NOT NULL PRIMARY KEY,v TEXT);CREATE TABLE counters(id INTEGER NOT NULL PRIMARY KEY,n INTEGER)"}})
	c.Must(0, mh.Request{Op: "policy", Table: "counters", Column: "n", Policy: 1})
	for _, table := range []string{"audit", "counters"} {
		c.Must(0, mh.Request{Op: "replication", Table: table, Enabled: true})
	}
	c.Publish()
	c.Exec(0, "INSERT INTO counters VALUES(1,0)")
	for i := 0; i < 6; i++ {
		c.Exec(0, fmt.Sprintf("INSERT INTO audit VALUES(%d,'acknowledged-%d')", i, i), "SELECT murmur_counter_add('counters','[1]','n',1)")
	}
	c.CatchUp()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		response, err := c.Nodes[0].Call(ctx, mh.Request{Op: "hold-write", SQL: []string{"INSERT INTO audit VALUES(999,'uncommitted')", "SELECT murmur_counter_add('counters','[1]','n',99)"}})
		if err == nil {
			err = fmt.Errorf("held transaction returned a response: %+v", response)
		}
		done <- err
	}()
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := os.Stat(c.Configs[0].Path + ".hold"); err == nil {
			break
		}
		select {
		case err := <-done:
			t.Fatal(err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("actual pre-COMMIT hold point was not reached")
		}
		time.Sleep(time.Millisecond)
	}
	if err := c.Nodes[0].Kill(); err != nil {
		t.Fatal(err)
	}
	if !c.Nodes[0].WasSIGKILL() {
		t.Fatal("active transaction victim was not SIGKILLed")
	}
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("held request leaked after process death")
	}
	c.Restart(0)
	if rows := c.Query(0, "SELECT id,v FROM audit ORDER BY id"); len(rows) != 6 {
		t.Fatalf("crash lost acknowledged rows or committed held work: %+v", rows)
	}
	if count := c.Query(0, "SELECT n FROM counters WHERE id=1")[0][0].Integer; count != 6 {
		t.Fatalf("uncommitted causal state survived: %d", count)
	}
	response, err := c.Nodes[0].Call(ctx, mh.Request{Op: "next", Origin: c.Configs[0].Origin, After: 7})
	if err != nil || response.RC != 12 {
		t.Fatalf("uncommitted signed log/receipt survived: %+v %v", response, err)
	}
	c.CatchUp()
	for node := range c.Nodes {
		if len(c.Query(node, "SELECT id FROM audit WHERE id=999")) != 0 {
			t.Fatal("held transaction leaked to a peer")
		}
	}
}
