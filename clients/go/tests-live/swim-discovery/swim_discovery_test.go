// Live scenario: seed-only SWIM discovery forms a full mesh, and the
// mesh reheals after the seed is killed.
//
// Port of MURMUR-SQL swim-discovery (fully skipped): four nodes start
// with a single seed, discover the full mesh within
// MURMUR_SWIM_DISCOVERY_SECONDS with at least 3 replication members
// each, converge on 40 rows, and (restart leg) the seed is killed,
// survivors hold two-peer meshes and 12 more converged rows, the seed
// restarts, re-adds one peer, and the full four-mesh reconverges.
// Seed-bootstrapped native nodes never dial beyond their seeds, so the
// cluster stays hub-and-spoke and neither discovery leg can run; the
// native status snapshot also has no replication member count. The
// partial-mesh port skips its discovery leg for the same reason.
package swimdiscovery

import (
	"testing"

	goharness "github.com/marcgauthier/sqlite-murmur-go/clients/go/tests-live/goharness"
)

func TestSeedOnlyDiscoveryFormsFullMesh(t *testing.T) {
	goharness.SkipUnlessLive(t)
	// Blocked: seed-bootstrapped nodes never dial beyond their seeds,
	// so no gossip discovery forms the full mesh.
	t.Skip("harness: seed-bootstrapped dynamic peer discovery does not mesh the cluster")
}

func TestSeedKillAndRediscovery(t *testing.T) {
	goharness.SkipUnlessLive(t)
	// Blocked: same missing discovery; the seed cannot rejoin the mesh
	// through a single re-added peer.
	t.Skip("harness: seed-bootstrapped dynamic peer discovery does not mesh the cluster")
}
