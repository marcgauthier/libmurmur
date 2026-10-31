// Package corruptsnapshot is the native port of the MURMUR-SQL
// corrupt-snapshot live scenario (tests/corrupt_snapshot.rs via
// tests-live/corrupt-snapshot), driven by
// clients/go/tests-live/goharness.
//
// The scenario itself lives in corrupt_snapshot_test.go; this file only
// gives `go build ./...` a non-test file (Go reports test-only
// directories as build failures).
package corruptsnapshot
