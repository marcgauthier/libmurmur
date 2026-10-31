// Package filesbridge is the native port of the MURMUR-SQL files-bridge
// live scenario (tests/files_bridge.rs via tests-live/files-bridge),
// driven by clients/go/tests-live/goharness.
//
// The scenario itself lives in files_bridge_test.go; this file only
// gives `go build ./...` a non-test file (Go reports test-only
// directories as build failures).
package filesbridge
