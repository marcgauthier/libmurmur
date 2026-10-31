// Live scenario: a migrated peer crashes at the schema-manifest store
// boundary, recovers, rejoins, and converges with both peers.
//
// Port of MURMUR-SQL migration-crash (fully skipped): the reference
// seeds 24 rows, isolates node 0, stops/restarts it on either side of
// the synchronous migration store, rejoins, adopts the new schema on
// the peers, and converges on a migrated-field write. None of that is
// expressible natively: a bare ALTER TABLE ADD COLUMN on a replicated
// (CRR) table leaves stale triggers behind, so the very next write
// fails and neither the migration nor the converged migrated-field
// write can proceed (same block as schema-evolution).
package migrationcrash

import (
	"testing"

	goharness "github.com/marcgauthier/sqlite-murmur-go/clients/go/tests-live/goharness"
)

func TestMigratedPeerCrashBeforeStoreReopensAndConverges(t *testing.T) {
	goharness.SkipUnlessLive(t)
	// Blocked end to end: ALTER TABLE on a replicated table breaks
	// subsequent CRR writes, so the migration and its converged
	// migrated-field write cannot run.
	t.Skip("harness: ALTER TABLE on replicated tables breaks CRR writes")
}

func TestMigratedPeerCrashAfterStoreReopensAndConverges(t *testing.T) {
	goharness.SkipUnlessLive(t)
	// Blocked end to end: ALTER TABLE on a replicated table breaks
	// subsequent CRR writes, so the migration and its converged
	// migrated-field write cannot run.
	t.Skip("harness: ALTER TABLE on replicated tables breaks CRR writes")
}
