// Package filescrash is the native port of the MURMUR-SQL files-crash
// live scenario (tests/files_crash.rs via tests-live/files-crash),
// driven by clients/go/tests-live/goharness.
//
// The scenario itself lives in files_crash_test.go; this file only
// gives `go build ./...` a non-test file (Go reports test-only
// directories as build failures).
package filescrash
