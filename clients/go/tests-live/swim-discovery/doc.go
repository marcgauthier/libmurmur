// Package swimdiscovery ports the MURMUR-SQL swim-discovery live
// scenario to native replication nodes driven by goharness.
//
// The scenario itself lives in swim_discovery_test.go; this file only
// gives `go build ./...` a non-test file (Go reports test-only directories
// as build failures).
package swimdiscovery
