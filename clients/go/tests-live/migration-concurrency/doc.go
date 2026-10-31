// Package migrationconcurrency ports the MURMUR-SQL
// migration-concurrency live scenario to native replication nodes driven
// by goharness.
//
// The scenario itself lives in migration_concurrency_test.go; this file
// only gives `go build ./...` a non-test file (Go reports test-only
// directories as build failures).
package migrationconcurrency
