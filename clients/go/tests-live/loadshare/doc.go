// Package loadshare ports the MURMUR-SQL loadshare live scenario to
// native replication nodes driven by goharness.
//
// The scenario itself lives in loadshare_test.go; this file only
// gives `go build ./...` a non-test file (Go reports test-only directories
// as build failures).
package loadshare
