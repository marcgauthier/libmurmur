// Live scenario: a typed bridge record imports into the native path,
// honors ownership, and survives restart.
//
// Port of MURMUR-SQL typed-bridge (fully skipped): the reference forms
// Low (exporter) and High (importer) bridge domains sharing one staging
// directory; a typed row inserted on Low is exported, imported through
// High's typed durable path, overridden by a High write (automatic
// ownership), shielded from a Low update, released over the wire (MURMUR
// BRIDGE RELEASE), updated by Low again, and the imported result's
// survival across a High restart is proven last. None of that is
// expressible natively: the harness has no bridge-domain option, the
// bindings expose no bundle export/import path, and there is no BRIDGE
// RELEASE verb.
package typedbridge

import (
	"testing"

	goharness "github.com/marcgauthier/sqlite-murmur-go/clients/go/tests-live/goharness"
)

func TestTypedBridgeImportsIntoNativeRime(t *testing.T) {
	goharness.SkipUnlessLive(t)
	// Blocked end to end: no bridge-domain harness option, no bundle
	// export/import binding, no BRIDGE RELEASE verb.
	t.Skip("harness: typed bridge (bridge domains, bundle export/import, BRIDGE RELEASE)")
}
