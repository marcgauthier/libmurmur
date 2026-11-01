// Live scenario: a three-node all-Plumtree mesh converges end to end,
// while a gossip-mode node meshed with Plumtree peers stays isolated in
// both directions.
//
// Port of MURMUR-SQL plumtree-live (fully skipped): the reference runs
// `plumtree_mesh_converges` (10 rows converge on all three Plumtree
// nodes) and `mixed_mode_refuses_gossip_peer` (the Plumtree pair
// converges while the gossip node keeps only its own row, handshake
// incompatibility refusals are recorded, and the gossip node holds zero
// sessions). The native engine has no dissemination mode at all —
// gossip is the only transport behavior, with no Plumtree setting and
// no per-node mode overlay — so neither the all-Plumtree mesh nor the
// mixed-mode isolation legs are expressible.
package plumtreelive

import (
	"testing"

	goharness "github.com/marcgauthier/libmurmur/clients/go/tests-live/goharness"
)

func TestPlumtreeMeshConverges(t *testing.T) {
	goharness.SkipUnlessLive(t)
	// Blocked end to end: the native engine has no Plumtree
	// dissemination mode (no dissemination setting at all).
	t.Skip("harness: Plumtree dissemination mode (per-node dissemination setting)")
}

func TestMixedModeRefusesGossipPeer(t *testing.T) {
	goharness.SkipUnlessLive(t)
	// Blocked end to end: mixed dissemination modes need a per-node
	// dissemination setting the native engine does not have.
	t.Skip("harness: Plumtree dissemination mode (per-node dissemination setting)")
}
