// Package searchmesh ports the MURMUR-SQL search-mesh live scenario to
// native replication nodes driven by goharness.
//
// The scenario itself lives in search_mesh_test.go; this file only
// gives `go build ./...` a non-test file (Go reports test-only
// directories as build failures).
package searchmesh
