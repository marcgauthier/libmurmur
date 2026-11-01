// Run from ../MURMUR-SQL: go run /absolute/path/to/this/file.go
// Output is consumed by causal_selftest.cc; the reference remains unmodified.
package main

import (
	"fmt"
	r "github.com/marcgauthier/murmur-sql/murmur/replication"
)

func id(n byte) (v r.NodeId) { v[0] = n; return }
func tag(n uint32) r.Tag { return r.Tag{Database: id(1), Node: id(2), Transaction: id(3), Operation: n} }
func emit(name string, c *r.Causal) { fmt.Printf("%s %x\n", name, r.EncodeCausal(c)) }
func main() {
	c := &r.Counter{}
	_ = c.Add(id(1), id(2), 5)
	_ = c.Add(id(1), id(2), -2)
	_ = c.Add(id(1), id(4), 10)
	emit("counter", &r.Causal{Counter: c})
	emit("counter-empty", &r.Causal{Counter: &r.Counter{}})
	min := &r.Counter{}; _ = min.Add(id(1), id(2), -1<<63)
	emit("counter-min", &r.Causal{Counter: min})
	s := &r.Set{}
	s.Add([]byte("b"), tag(1)); s.Add([]byte("a"), tag(2)); s.Remove([]byte("b")); s.Add([]byte("b"), tag(3))
	s.Add([]byte{0xff, 0}, tag(4))
	emit("set", &r.Causal{Set:s})
	emit("set-empty", &r.Causal{Set:&r.Set{}})
	j := &r.JsonMap{}
	j.Set("a", []byte("old"), tag(1)); j.Set("a", []byte("new"), tag(2))
	j.Set("b", []byte("gone"), tag(3)); j.Remove("b")
	concurrent := &r.JsonMap{}; concurrent.Set("b", []byte("survives"), tag(4)); j.Join(concurrent)
	emit("json", &r.Causal{Json:j})
	emit("json-empty", &r.Causal{Json:&r.JsonMap{}})
	l := &r.ListSet{}
	l.Append([]byte("a"),tag(1)); l.Append([]byte("a"),tag(2)); l.Remove([]byte("a")); l.Append([]byte("a"),tag(3)); l.Append([]byte("b"),tag(4))
	emit("list", &r.Causal{List:l})
	emit("list-empty", &r.Causal{List:&r.ListSet{}})
}
