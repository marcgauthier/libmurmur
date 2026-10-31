// Live scenario: disconnected PN_COUNTER / OR_SET / MAX / MIN policy
// ops forward across restarts with observed-remove semantics.
//
// Port of MURMUR-SQL merge-policies (fully skipped): the reference
// writes counter/set/extrema policy ops on one shared row across three
// disconnected nodes, converges them through connection, restart, and
// forwarding legs, and proves observed-remove semantics. None of that
// is expressible natively: the engine exposes no MURMUR POLICY
// COUNTER_ADD / SET_ADD / SET_REMOVE / MIN / MAX ops and no OR_SET
// projection reads, so no leg can run.
package mergepolicies

import (
	"testing"

	goharness "github.com/marcgauthier/sqlite-murmur-go/clients/go/tests-live/goharness"
)

func TestDisconnectedPoliciesForwardAndRestart(t *testing.T) {
	goharness.SkipUnlessLive(t)
	// Blocked end to end: no native merge-policy ops (counter, set,
	// min/max) and no set-projection reads.
	t.Skip("harness: merge-policy ops (PN_COUNTER/OR_SET/MAX/MIN) have no native equivalent")
}
