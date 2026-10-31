// Package soakslo ports the MURMUR-SQL soak-slo live scenario to
// native replication nodes driven by goharness.
//
// The scenario itself lives in soak_slo_test.go; this file only
// gives `go build ./...` a non-test file (Go reports test-only directories
// as build failures).
package soakslo
