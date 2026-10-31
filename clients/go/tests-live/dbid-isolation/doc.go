// Package dbidisolation ports the MURMUR-SQL dbid-isolation live
// scenario to native replication nodes driven by goharness.
//
// The scenario itself lives in dbid_isolation_test.go; this file only
// gives `go build ./...` a non-test file (Go reports test-only directories
// as build failures).
package dbidisolation
