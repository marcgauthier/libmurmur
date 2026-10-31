// Package downgradeguard ports the MURMUR-SQL downgrade-guard live
// scenario to native replication nodes driven by goharness.
//
// The scenario itself lives in downgrade_guard_test.go; this file only
// gives `go build ./...` a non-test file (Go reports test-only
// directories as build failures).
package downgradeguard
