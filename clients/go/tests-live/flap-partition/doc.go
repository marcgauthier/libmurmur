// Package flappartition ports the MURMUR-SQL flap-partition live
// scenario to native replication nodes driven by goharness.
//
// The scenario itself lives in flap_partition_test.go; this file only
// gives `go build ./...` a non-test file (Go reports test-only
// directories as build failures).
package flappartition
