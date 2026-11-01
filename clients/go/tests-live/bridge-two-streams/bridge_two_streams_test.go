// Live scenario: two low bridge domains export through one shared
// staging directory into a single high domain, and both streams keep
// separate budgets end to end.
//
// Port of MURMUR-SQL bridge-two-streams (fully skipped): the
// reference forms First/Second Low exporter domains and a High
// importer domain sharing one staging dir, converges marker rows
// through both bridge streams, and asserts per-stream outbox usage
// plus High-side import wins, burn-down, and isolation. None of that
// is expressible natively: the harness has no bridge-domain option
// and the bindings expose no bundle export/import path (same gap as
// the typed-bridge port).
package bridgetwostreams

import (
	"testing"

	goharness "github.com/marcgauthier/libmurmur/clients/go/tests-live/goharness"
)

func TestTwoLowDomainsIntoOneHigh(t *testing.T) {
	goharness.SkipUnlessLive(t)
	// Blocked end to end: no bridge-domain harness option, no bundle
	// export/import binding.
	t.Skip("harness: bridge domains (per-stream bridge export/import over a shared staging dir)")
}
