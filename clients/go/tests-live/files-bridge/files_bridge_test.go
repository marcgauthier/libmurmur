// Live scenario: a 384 KiB file crosses a Low/High bridge through a
// shared staging directory.
//
// Port of MURMUR-SQL files-bridge (reference:
// tests-live/files-bridge). The reference meshes a two-node Low cluster
// and a two-node High cluster (separate DBIDs, CAs, storage keys, and
// file object keys) and moves one file across: Low upload, Low mesh
// metadata + peer fetch, signed export of sealed chunks into a shared
// staging directory, High import with re-encryption under the High
// object key, High mesh metadata + peer fetch, and metadata search.
//
// Blocked: the native stack has no file-bridge surface at all -- no
// bridge exporter/receiver roles, no bundle capture/process, no staging
// directory handling, and no signer/recipient key configuration exist
// in the bindings or the harness (which stages one uniform file-object
// store per cluster). A single-cluster upload/fetch round-trip would not
// prove the bridge, so the suite stays a named skip rather than a
// weakened pass.
package filesbridge

import (
	"testing"

	goharness "github.com/marcgauthier/libmurmur/clients/go/tests-live/goharness"
)

func TestTwoLowTwoHighFileBridgeLive(t *testing.T) {
	goharness.SkipUnlessLive(t)
	t.Skip("harness: file bridge (Low/High export/import, bundle staging, signer/recipient config)")
}
