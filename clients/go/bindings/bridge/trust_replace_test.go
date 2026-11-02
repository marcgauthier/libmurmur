package bridge_test

import (
	"context"
	"crypto/ed25519"
	"testing"

	"github.com/marcgauthier/libmurmur/clients/go/bindings/bridge"
	"github.com/marcgauthier/libmurmur/clients/go/bindings/sqlite"
	"github.com/marcgauthier/libmurmur/clients/go/murmurdb"
)

func TestReplacingTrustRevokesRemovedOriginsAndRetainsBindings(t *testing.T) {
	f := newFerryFixture(t)
	node, peer, writer := [16]byte{3}, [16]byte{4}, [16]byte{7}
	seed, peerSeed, writerSeed := [32]byte{11}, [32]byte{12}, [32]byte{13}
	public := func(seed [32]byte) (key [32]byte) { copy(key[:], ed25519.NewKeyFromSeed(seed[:])[32:]); return }
	peerKey, writerKey := public(peerSeed), public(writerSeed)
	f.with(f.high, func(c *sqlite.Conn) error {
		if err := bridge.ConfigurePeer(c, [16]byte{9}, node, seed); err != nil {
			return err
		}
		if err := bridge.ReplacePeerTrust(c, map[[16]byte][32]byte{peer: peerKey}); err != nil {
			return err
		}
		return bridge.ReplaceSourceTrust(c, f.lcfg.Database, map[[16]byte][32]byte{writer: writerKey})
	})
	active := func(table string, id [16]byte, want int) {
		t.Helper()
		var enabled int
		if err := f.high.QueryRow("SELECT enabled FROM "+table+" WHERE origin=?", id[:]).Scan(&enabled); err != nil || enabled != want {
			t.Fatalf("%s enabled=%d want=%d err=%v", table, enabled, want, err)
		}
	}
	active("murmur_bridge_peer_keys", peer, 1)
	active("murmur_bridge_source_keys", writer, 1)
	changed := peerKey
	changed[0] ^= 1
	if err := murmurdb.WithConnection(context.Background(), f.high, func(c *sqlite.Conn) error { return bridge.ReplacePeerTrust(c, map[[16]byte][32]byte{peer: changed}) }); err == nil {
		t.Fatal("changed peer key accepted")
	}
	active("murmur_bridge_peer_keys", peer, 1)
	f.with(f.high, func(c *sqlite.Conn) error {
		if err := bridge.ReplacePeerTrust(c, nil); err != nil {
			return err
		}
		return bridge.ReplaceSourceTrust(c, f.lcfg.Database, nil)
	})
	active("murmur_bridge_peer_keys", node, 1)
	active("murmur_bridge_peer_keys", peer, 0)
	active("murmur_bridge_source_keys", writer, 0)
	changed = writerKey
	changed[0] ^= 1
	if err := murmurdb.WithConnection(context.Background(), f.high, func(c *sqlite.Conn) error {
		return bridge.ReplaceSourceTrust(c, f.lcfg.Database, map[[16]byte][32]byte{writer: changed})
	}); err == nil {
		t.Fatal("revoked source binding was replaced")
	}
	active("murmur_bridge_source_keys", writer, 0)
}
