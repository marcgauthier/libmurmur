// Package typedrecords is the native port of the MURMUR-SQL
// typed-records live scenario (tests/typed_records.rs via
// tests-live/typed-records), driven by
// clients/go/tests-live/goharness.
//
// The scenario itself lives in typed_records_test.go; this file only
// gives `go build ./...` a non-test file (Go reports test-only
// directories as build failures).
package typedrecords
