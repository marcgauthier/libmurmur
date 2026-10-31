# search-mesh

Managed search indexes (FTS5 + HNSW KNN) and JSON extraction
replicate with reads served on every node: set FTS and VECTOR
managed indexes, write documents on node 1, refresh everywhere, and
assert identical MATCH and KNN ordering on all nodes, plus JSON
reads across the mesh and search under a restarted node.

## Status: skipped (no managed search in this stack)

Every leg needs engine verbs that do not exist here: `MURMUR SET
COLUMN` (FTS/VECTOR registration), `MURMUR REFRESH INDEXES`, and
`MURMUR SHOW COLUMNS` (indexing state). Porting only the JSON leg
would not preserve the suite's intent, so the whole suite skips with
`harness: managed search indexes (FTS/vector columns, index refresh
and introspection)`.

## Reference pass criteria (for when the verbs land)

- FTS `MATCH` ordering identical on all three nodes; KNN ordering
  identical; indexing state converges (`pending=0`, `indexed>0`).
- `JSON_EXTRACT` reads identical across the mesh.
- Search still correct on survivors and the restarted node.

Run from `clients/go`:

```sh
MURMUR_ENGINE_INTEGRATION=1 go test -count=1 -timeout 600s ./tests-live/search-mesh/
```
