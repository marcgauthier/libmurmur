// Live scenario: managed search indexes (FTS5 + HNSW KNN) and JSON
// extraction replicate with reads served on every node.
//
// Port of MURMUR-SQL search-mesh (fully skipped): the reference
// registers FTS and VECTOR managed indexes over two tables
// (MURMUR SET COLUMN), writes documents on node 1, refreshes indexes
// everywhere (MURMUR REFRESH INDEXES), and asserts identical MATCH
// and KNN ordering on all nodes with SHOW COLUMNS indexing state,
// plus JSON_EXTRACT reads across the mesh and su=1 search under a
// restarted node. None of that is expressible natively: the engine
// has no managed search indexes and no SET COLUMN, REFRESH INDEXES,
// or SHOW COLUMNS verbs.
package searchmesh

import (
	"testing"

	goharness "github.com/marcgauthier/sqlite-murmur-go/clients/go/tests-live/goharness"
)

func TestManagedSearchAndJSONHoldAcrossTheMesh(t *testing.T) {
	goharness.SkipUnlessLive(t)
	// Blocked end to end: no managed FTS/vector indexes, no SET
	// COLUMN / REFRESH INDEXES / SHOW COLUMNS verbs.
	t.Skip("harness: managed search indexes (FTS/vector columns, index refresh and introspection)")
}
