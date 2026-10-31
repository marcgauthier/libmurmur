// Package openprogress ports the MURMUR-SQL open-progress live scenario
// to native replication nodes driven by goharness.
//
// The scenario itself lives in open_progress_test.go; this file only
// gives `go build ./...` a non-test file (Go reports test-only
// directories as build failures).
package openprogress
