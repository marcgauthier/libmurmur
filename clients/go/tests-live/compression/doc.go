// Package compression ports the MURMUR-SQL compression live scenario
// to native replication nodes driven by goharness.
//
// The scenario itself lives in compression_test.go; this file only
// gives `go build ./...` a non-test file (Go reports test-only
// directories as build failures).
package compression
