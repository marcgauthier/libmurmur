// Package views is the native port of the MURMUR-SQL views live scenario
// (tests/views.rs via tests-live/views), driven by
// clients/go/tests-live/goharness.
//
// The scenario itself lives in views_test.go; this file only gives
// `go build ./...` a non-test file (Go reports test-only directories as
// build failures).
package views
