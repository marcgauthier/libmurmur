// Package filescorruptsource is the native port of the MURMUR-SQL
// files-corrupt-source live scenario (tests/files_corrupt_source.rs via
// tests-live/files-corrupt-source), driven by
// clients/go/tests-live/goharness.
//
// The scenario itself lives in files_corrupt_source_test.go; this file
// only gives `go build ./...` a non-test file (Go reports test-only
// directories as build failures).
package filescorruptsource
