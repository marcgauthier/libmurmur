// Package crashrecovery ports the MURMUR-SQL crash-recovery live
// scenario to native replication nodes driven by goharness.
//
// The scenario itself lives in crash_recovery_test.go; this file only
// gives `go build ./...` a non-test file (Go reports test-only directories
// as build failures).
package crashrecovery
