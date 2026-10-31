// Package migrationcrash is the native port of the MURMUR-SQL
// migration-crash live scenario (tests/migration_crash.rs via
// tests-live/migration-crash), driven by
// clients/go/tests-live/goharness.
//
// The scenario itself lives in migration_crash_test.go; this file only
// gives `go build ./...` a non-test file (Go reports test-only
// directories as build failures).
package migrationcrash
