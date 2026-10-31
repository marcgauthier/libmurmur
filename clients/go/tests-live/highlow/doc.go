// Package highlow ports the MURMUR-SQL highlow live scenarios to
// native replication nodes driven by goharness.
//
// The scenarios themselves live in highlow_test.go; this file only
// gives `go build ./...` a non-test file (Go reports test-only
// directories as build failures).
package highlow
