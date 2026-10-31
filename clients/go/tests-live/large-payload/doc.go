// Package largepayload ports the MURMUR-SQL large-payload live scenario
// to native replication nodes driven by goharness.
//
// The scenario itself lives in large_payload_test.go; this file only
// gives `go build ./...` a non-test file (Go reports test-only directories
// as build failures).
package largepayload
