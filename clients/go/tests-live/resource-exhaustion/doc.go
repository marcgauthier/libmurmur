// Package resourceexhaustion ports the MURMUR-SQL resource-exhaustion
// live scenario to native replication nodes driven by goharness.
//
// The scenario itself lives in resource_exhaustion_test.go; this file
// only gives `go build ./...` a non-test file (Go reports test-only
// directories as build failures).
package resourceexhaustion
