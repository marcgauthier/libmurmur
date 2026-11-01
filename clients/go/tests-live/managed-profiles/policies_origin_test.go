package managedprofiles

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"reflect"
	"strconv"
	"testing"
	"time"

	mh "github.com/marcgauthier/sqlite-murmur-go/clients/go/tests-live/managedharness"
)

func preparePolicies(t *testing.T, c *mh.Cluster) {
	t.Helper()
	c.Must(0, mh.Request{Op: "migrate", SQL: []string{"CREATE TABLE item(id INTEGER NOT NULL PRIMARY KEY,v TEXT,n INTEGER,labels BLOB,lo,hi,settings TEXT,events TEXT)"}})
	for policy, column := range []string{"n", "labels", "lo", "hi", "settings", "events"} {
		c.Must(0, mh.Request{Op: "policy", Table: "item", Column: column, Policy: policy + 1})
	}
	c.Must(0, mh.Request{Op: "replication", Table: "item", Enabled: true})
	c.Publish()
}

func exactRows(t *testing.T, c *mh.Cluster, sql string) {
	t.Helper()
	expected := c.Query(0, sql)
	for node := 1; node < len(c.Nodes); node++ {
		if actual := c.Query(node, sql); !reflect.DeepEqual(expected, actual) {
			t.Fatalf("exact policy projection differs: node0=%+v node%d=%+v", expected, node, actual)
		}
	}
}

func TestManagedPoliciesPartitionObservedRemoveAndReplacement(t *testing.T) {
	c := mh.NewCluster(t, 3)
	preparePolicies(t, c)
	c.Exec(0, "INSERT INTO item VALUES(1,'base',10,NULL,100,-100,'{}','[]')")
	c.CatchUp()
	for node := 0; node < 3; node++ {
		column := string(rune('a' + node))
		c.Exec(node, "SELECT murmur_counter_add('item','[1]','n',"+strconv.Itoa(node+1)+")", "SELECT murmur_set_add('item','[1]','labels','x')", "SELECT murmur_set_add('item','[1]','labels','"+column+"')", "SELECT murmur_min('item','[1]','lo',"+strconv.Itoa(7-node)+")", "SELECT murmur_max('item','[1]','hi',"+strconv.Itoa(7+node)+")", "SELECT murmur_json_set('item','[1]','settings','"+column+"','"+column+"')", "SELECT murmur_list_append('item','[1]','events','same')", "UPDATE item SET v='"+column+"' WHERE id=1")
	}
	c.CatchUp()
	exactRows(t, c, "SELECT * FROM item")
	for node := range c.Nodes {
		// Independent expected postcard Vec<Value>: four text members a,b,c,x.
		if got := c.Query(node, "SELECT labels FROM item")[0][0]; got.Type != 4 || got.Hex != "04030161030162030163030178" {
			t.Fatalf("merged set membership differs: %+v", got)
		}
		rows := c.Query(node, "SELECT n=16 AND lo=5 AND hi=9 AND json_extract(settings,'$.a')='a' AND json_extract(settings,'$.b')='b' AND json_extract(settings,'$.c')='c' AND json_array_length(events)=3 FROM item")
		if rows[0][0].Integer != 1 {
			t.Fatalf("merged values: %+v", rows)
		}
	}
	c.Exec(0, "SELECT murmur_set_remove('item','[1]','labels','x')", "SELECT murmur_json_remove('item','[1]','settings','a')", "SELECT murmur_list_remove('item','[1]','events','same')")
	c.Exec(1, "SELECT murmur_set_add('item','[1]','labels','x')", "SELECT murmur_json_set('item','[1]','settings','a','new')", "SELECT murmur_list_append('item','[1]','events','same')")
	c.CatchUp()
	exactRows(t, c, "SELECT * FROM item")
	for node := range c.Nodes {
		if got := c.Query(node, "SELECT labels FROM item")[0][0]; got.Type != 4 || got.Hex != "04030161030162030163030178" {
			t.Fatalf("concurrent set re-add was lost: %+v", got)
		}
		rows := c.Query(node, "SELECT json_extract(settings,'$.a')='new' AND json_array_length(events)=1 FROM item")
		if rows[0][0].Integer != 1 {
			t.Fatalf("concurrent re-add lost: %+v", rows)
		}
	}
	c.Exec(0, "DELETE FROM item WHERE id=1")
	c.Exec(1, "SELECT murmur_counter_add('item','[1]','n',99)")
	c.CatchUp()
	for node := range c.Nodes {
		if len(c.Query(node, "SELECT * FROM item")) != 0 {
			t.Fatal("old-generation edit resurrected deleted row")
		}
	}
	c.Exec(2, "INSERT INTO item VALUES(1,'replacement',100,NULL,50,50,NULL,NULL)")
	c.CatchUp()
	// SQL representations, not just abstract sets/JSON, must converge.
	exactRows(t, c, "SELECT * FROM item")
	c.Restart(1)
	c.Exec(1, "SELECT murmur_counter_add('item','[1]','n',1)")
	c.CatchUp()
	exactRows(t, c, "SELECT * FROM item")
	if got := c.Query(0, "SELECT n FROM item")[0][0].Integer; got != 101 {
		t.Fatalf("generation baseline mixed with old deltas: %d", got)
	}
}

func resign(data []byte, seed [32]byte) []byte {
	out := bytes.Clone(data)
	digest := sha256.Sum256(out[200:])
	copy(out[104:136], digest[:])
	message := append([]byte("murmur/native-origin/v2"), out[4:136]...)
	copy(out[136:200], ed25519.Sign(ed25519.NewKeyFromSeed(seed[:]), message))
	return out
}

func TestManagedOfflineOriginHostileRelayAndDurableReceipts(t *testing.T) {
	c := mh.NewCluster(t, 3)
	preparePolicies(t, c)
	c.Exec(0, "INSERT INTO item VALUES(1,'origin-A',10,NULL,1,1,'{}','[]')")
	original := c.Must(0, mh.Request{Op: "next", Origin: c.Configs[0].Origin}).Data
	c.Must(1, mh.Request{Op: "apply", Data: original})
	if err := c.Nodes[0].Kill(); err != nil {
		t.Fatal(err)
	}
	forwarded := c.Must(1, mh.Request{Op: "next", Origin: c.Configs[0].Origin}).Data
	if !bytes.Equal(forwarded, original) {
		t.Fatal("relay changed original envelope/payload")
	}
	before := c.Query(2, "SELECT * FROM item")
	progress := c.Must(2, mh.Request{Op: "progress"}).Rows
	tampered := bytes.Clone(forwarded)
	tampered[len(tampered)-1] ^= 1
	unsigned := bytes.Clone(forwarded)
	clear(unsigned[136:200])
	crossDB := bytes.Clone(forwarded)
	crossDB[4] ^= 1
	crossDB = resign(crossDB, c.Configs[0].Seed)
	for _, attack := range [][]byte{tampered, unsigned, crossDB, resign(forwarded, c.Configs[1].Seed)} {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		response, err := c.Nodes[2].Call(ctx, mh.Request{Op: "apply", Data: attack})
		cancel()
		if err != nil || response.RC != 23 || response.Changed {
			t.Fatalf("hostile relay accepted: %+v err=%v", response, err)
		}
		if !reflect.DeepEqual(before, c.Query(2, "SELECT * FROM item")) || !reflect.DeepEqual(progress, c.Must(2, mh.Request{Op: "progress"}).Rows) {
			t.Fatal("rejected relay changed rows/receipts")
		}
	}
	if !c.Must(2, mh.Request{Op: "apply", Data: forwarded}).Changed {
		t.Fatal("honest forwarded record not applied")
	}
	if err := c.Nodes[2].Kill(); err != nil {
		t.Fatal(err)
	}
	c.Restart(2)
	if c.Query(2, "SELECT n FROM item")[0][0].Integer != 10 {
		t.Fatal("remote acknowledgment was not durable")
	}
	if c.Must(2, mh.Request{Op: "apply", Data: forwarded}).Changed {
		t.Fatal("replay re-applied after process restart")
	}
	equivocation := bytes.Clone(forwarded)
	equivocation[36] ^= 1
	equivocation = resign(equivocation, c.Configs[0].Seed)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	response, err := c.Nodes[2].Call(ctx, mh.Request{Op: "apply", Data: equivocation})
	if err != nil || response.RC != 23 {
		t.Fatalf("signed equivocation accepted: %+v %v", response, err)
	}
	response, err = c.Nodes[2].Call(ctx, mh.Request{Op: "next", Origin: c.Configs[2].Origin})
	if err != nil || response.RC != 12 {
		t.Fatalf("import was re-originated: %+v %v", response, err)
	}
}
