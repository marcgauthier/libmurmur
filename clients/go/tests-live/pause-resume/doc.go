// Package pauseresume is the native port of the MURMUR-SQL pause-resume
// live scenario (tests/pause_resume.rs via tests-live/pause-resume),
// driven by clients/go/tests-live/goharness.
//
// The scenario itself lives in pause_resume_test.go; this file only gives
// `go build ./...` a non-test file (Go reports test-only directories as
// build failures).
package pauseresume
