// Package diskfulllive is the native port of the MURMUR-SQL diskfull-live
// live scenario (tests/diskfull_live.rs via tests-live/diskfull-live),
// driven by clients/go/tests-live/goharness.
//
// The scenario itself lives in diskfull_live_test.go; this file only
// gives `go build ./...` a non-test file (Go reports test-only
// directories as build failures).
package diskfulllive
