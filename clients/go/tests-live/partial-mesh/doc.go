// Package partialmesh is the native port of the MURMUR-SQL partial-mesh
// live scenario (tests/partial_mesh.rs via tests-live/partial-mesh),
// driven by clients/go/tests-live/goharness.
//
// The scenario itself lives in partial_mesh_test.go; this file only
// gives `go build ./...` a non-test file (Go reports test-only
// directories as build failures).
package partialmesh
