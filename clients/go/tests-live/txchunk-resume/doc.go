// Package txchunkresume is the native port of the MURMUR-SQL
// txchunk-resume live scenario (tests/txchunk_resume.rs via
// tests-live/txchunk-resume), driven by
// clients/go/tests-live/goharness.
//
// The scenario itself lives in txchunk_resume_test.go; this file only
// gives `go build ./...` a non-test file (Go reports test-only
// directories as build failures).
package txchunkresume
