package managedprofiles

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	mh "github.com/marcgauthier/sqlite-murmur-go/clients/go/tests-live/managedharness"
)

func TestManagedWriterServiceUnderRealRemoteApply(t *testing.T) {
	c := mh.NewCluster(t, 2)
	c.Must(0, mh.Request{Op: "migrate", SQL: []string{"CREATE TABLE work(id INTEGER NOT NULL PRIMARY KEY,v TEXT)"}})
	c.Must(0, mh.Request{Op: "replication", Table: "work", Enabled: true})
	c.Publish()
	baseline := *c.Must(0, mh.Request{Op: "stats"}).Stats
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	stop := make(chan struct{})
	errors := make(chan error, 9)
	var workers sync.WaitGroup
	var next atomic.Int64
	var acknowledgments sync.Mutex
	ack := map[int64]string{}
	recordAck := func(id int64, value string) { acknowledgments.Lock(); ack[id] = value; acknowledgments.Unlock() }
	call := func(node int, request mh.Request) (mh.Response, error) {
		response, err := c.Nodes[node].Call(ctx, request)
		if err != nil {
			return response, err
		}
		if response.RC != 0 {
			return response, fmt.Errorf("node=%d op=%s rc=%d", node, request.Op, response.RC)
		}
		return response, nil
	}
	for worker := 0; worker < 8; worker++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for i := 0; i < 128; i++ {
				select {
				case <-stop:
					return
				default:
				}
				id := next.Add(1)
				value := fmt.Sprintf("local-%d", id)
				_, err := call(0, mh.Request{Op: "exec", SQL: []string{fmt.Sprintf("INSERT INTO work VALUES(%d,'%s')", id, value), "WITH RECURSIVE r(n) AS (VALUES(1) UNION ALL SELECT n+1 FROM r WHERE n<10000) SELECT sum(n) FROM r"}})
				if err != nil {
					errors <- err
					return
				}
				recordAck(id, value)
			}
		}()
	}
	workers.Add(1)
	var remoteApplied atomic.Uint64
	go func() {
		defer workers.Done()
		var cursor uint64
		for i := 0; i < 512; i++ {
			select {
			case <-stop:
				return
			default:
			}
			id := -int64(i + 1)
			value := fmt.Sprintf("remote-%d", i)
			if _, err := call(1, mh.Request{Op: "exec", SQL: []string{fmt.Sprintf("INSERT INTO work VALUES(%d,'%s')", id, value)}}); err != nil {
				errors <- err
				return
			}
			record, err := call(1, mh.Request{Op: "next", Origin: c.Configs[1].Origin, After: cursor})
			if err != nil {
				errors <- err
				return
			}
			cursor++
			applied, err := call(0, mh.Request{Op: "apply", Data: record.Data})
			if err != nil {
				errors <- err
				return
			}
			if !applied.Changed {
				errors <- fmt.Errorf("remote work did not apply")
				return
			}
			remoteApplied.Add(1)
			recordAck(id, value)
		}
	}()
	var verdict mh.Stats
	contendedSamples := 0
	var problem error
	for {
		select {
		case problem = <-errors:
		case <-ctx.Done():
			problem = ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
		if problem != nil {
			break
		}
		response, err := call(0, mh.Request{Op: "stats"})
		if err != nil {
			problem = err
			break
		}
		if response.Stats == nil {
			problem = fmt.Errorf("missing actual service-time counters")
			break
		}
		verdict = *response.Stats
		if verdict.Classes[0].Waiters > 0 && verdict.Classes[1].Waiters > 0 {
			contendedSamples++
		}
		local := verdict.Classes[0].ServiceNS - baseline.Classes[0].ServiceNS
		remote := verdict.Classes[1].ServiceNS - baseline.Classes[1].ServiceNS
		if local+remote >= uint64(time.Second) && contendedSamples >= 3 && remoteApplied.Load() > 0 {
			break
		}
	}
	close(stop)
	workers.Wait()
	select {
	case err := <-errors:
		if problem == nil {
			problem = err
		}
	default:
	}
	if problem != nil {
		t.Fatal(problem)
	}
	local := verdict.Classes[0].ServiceNS - baseline.Classes[0].ServiceNS
	remote := verdict.Classes[1].ServiceNS - baseline.Classes[1].ServiceNS
	if remote == 0 || remote*4 > local+remote {
		t.Fatalf("remote writer service exceeded 25%% or made no progress: local_ns=%d remote_ns=%d samples=%d", local, remote, contendedSamples)
	}
	t.Logf("contended_samples=%d local_ns=%d remote_ns=%d remote_applied=%d", contendedSamples, local, remote, remoteApplied.Load())
	c.CatchUp()
	for node := range c.Nodes {
		rows := c.Query(node, "SELECT id,v FROM work ORDER BY id")
		if len(rows) != len(ack) {
			t.Fatalf("node=%d committed row count=%d acknowledged=%d", node, len(rows), len(ack))
		}
		for _, row := range rows {
			want, exists := ack[row[0].Integer]
			if !exists || row[1].Text() != want {
				t.Fatalf("node=%d lost/corrupt acknowledged row: %+v", node, row)
			}
		}
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		stats := c.Must(0, mh.Request{Op: "stats"}).Stats
		var queued uint64
		for _, class := range stats.Classes {
			queued += class.Waiters
		}
		if queued == 0 && !stats.Active {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("writer waiters leaked after workload stopped")
		}
		time.Sleep(time.Millisecond)
	}
}
