// Package snapshotresync is the native port of the MURMUR-SQL
// snapshot-resync live scenario (tests/snapshot_resync.rs via
// tests-live/snapshot-resync), driven by
// clients/go/tests-live/goharness.
//
// The scenario itself lives in snapshot_resync_test.go; this file only
// gives `go build ./...` a non-test file (Go reports test-only
// directories as build failures).
package snapshotresync
