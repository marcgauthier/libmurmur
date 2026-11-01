// Live scenario: spool compression levels shrink the store, leave
// snapshots byte-identical, and keep per-tenant accounting exact.
//
// Port of MURMUR-SQL compression (fully skipped): the reference runs
// three single-node spools at levels 1, 6, and 12 over a
// text/config/blob workload, gates high-vs-low store shrinkage and
// snapshot identity, and asserts byte-exact per-tenant billable
// bytes. None of that is expressible natively: the engine exposes
// no compression-level knob (no engine.compression_level setting),
// so levels cannot be formed and the relational gates have nothing
// to compare.
package compression

import (
	"testing"

	goharness "github.com/marcgauthier/libmurmur/clients/go/tests-live/goharness"
)

func TestSpoolCompressionSizes(t *testing.T) {
	goharness.SkipUnlessLive(t)
	// Blocked end to end: no compression-level engine knob, so no
	// levels to compare.
	t.Skip("harness: spool compression levels (engine.compression_level knob)")
}
