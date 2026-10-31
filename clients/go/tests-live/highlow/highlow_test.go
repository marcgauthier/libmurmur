// Live scenarios: real Low (exporter) and High (importer) domains move
// logical writes across a directory drop.
//
// Port of MURMUR-SQL highlow (fully skipped): the reference moves
// contact writes across a one-way directory drop between separate
// Low exporter and High importer clusters — disconnected transfer
// with role gating, gap delivery with duplicate recovery, two
// receivers converging, forgery rejection without partial apply,
// restart resumption, schema-hold survival with local-migration
// release, signer rotation plus outage catch-up, and High-owned-field
// reorder convergence. Every leg needs bridge domains (exporter /
// receiver roles, bundle staging dirs, the one-way ferry, quarantine,
// signer/recipient config), none of which the harness or bindings
// expose (same gap as the bridge-two-streams and files-bridge ports).
package highlow

import (
	"testing"

	goharness "github.com/marcgauthier/sqlite-murmur-go/clients/go/tests-live/goharness"
)

// bridgeGap is the single blocking gap for every leg in this suite.
const bridgeGap = "harness: bridge domains (Low exporter / High receiver roles, bundle staging dirs, one-way ferry + quarantine, signer/recipient config)"

func TestDisconnectedTransferWithOneWayRoleGating(t *testing.T) {
	goharness.SkipUnlessLive(t)
	t.Skip(bridgeGap)
}

func TestGapDeliveryWithDuplicateRecovery(t *testing.T) {
	goharness.SkipUnlessLive(t)
	t.Skip(bridgeGap)
}

func TestTwoReceiversConverge(t *testing.T) {
	goharness.SkipUnlessLive(t)
	t.Skip(bridgeGap)
}

func TestForgeriesRejectedWithoutPartialApply(t *testing.T) {
	goharness.SkipUnlessLive(t)
	t.Skip(bridgeGap)
}

func TestRestartResumesWithoutRecaptureOrReapply(t *testing.T) {
	goharness.SkipUnlessLive(t)
	t.Skip(bridgeGap)
}

func TestSchemaHoldSurvivesRestartAndReleasesOnLocalMigration(t *testing.T) {
	goharness.SkipUnlessLive(t)
	t.Skip(bridgeGap)
}

func TestSignerRotationAndOutageCatchUp(t *testing.T) {
	goharness.SkipUnlessLive(t)
	t.Skip(bridgeGap)
}

func TestHighOwnedFieldReorderConvergesAcrossPeers(t *testing.T) {
	goharness.SkipUnlessLive(t)
	t.Skip(bridgeGap)
}
