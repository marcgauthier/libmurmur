// Package writepriority ports the MURMUR-SQL write-priority live scenario
// to native replication nodes driven by goharness.
//
// The scenario itself lives in write_priority_test.go; this file only
// gives `go build ./...` a non-test file (Go reports test-only
// directories as build failures).
package writepriority
