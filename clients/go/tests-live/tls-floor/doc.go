// Package tlsfloor ports the MURMUR-SQL tls-floor live scenario to
// native replication nodes driven by goharness.
//
// The scenario itself lives in tls_floor_test.go; this file only gives
// `go build ./...` a non-test file (Go reports test-only directories as
// build failures).
package tlsfloor
