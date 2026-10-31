// Package rejoinstorm ports the MURMUR-SQL rejoin-storm live scenario to
// native replication nodes driven by goharness.
//
// The scenario itself lives in rejoin_storm_test.go; this file only
// gives `go build ./...` a non-test file (Go reports test-only directories
// as build failures).
package rejoinstorm
