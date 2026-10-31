// Package scalemesh is the native port of the MURMUR-SQL scale-mesh
// live scenario (tests/scale_mesh.rs via tests-live/scale-mesh),
// driven by clients/go/tests-live/goharness.
//
// The scenario itself lives in scale_mesh_test.go; this file only gives
// `go build ./...` a non-test file (Go reports test-only directories as
// build failures).
package scalemesh
