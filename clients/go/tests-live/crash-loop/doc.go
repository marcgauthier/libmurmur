// Package crashloop ports the MURMUR-SQL crash-loop live scenario to
// native replication nodes driven by goharness.
//
// The scenario itself lives in crash_loop_test.go; this file only gives
// `go build ./...` a non-test file (Go reports test-only directories as
// build failures).
package crashloop
