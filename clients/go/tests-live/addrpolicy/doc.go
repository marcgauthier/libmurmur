// Package addrpolicy ports the MURMUR-SQL addrpolicy live scenario to
// native replication nodes driven by goharness.
//
// The scenario itself lives in addrpolicy_test.go; this file only
// gives `go build ./...` a non-test file (Go reports test-only directories
// as build failures).
package addrpolicy
