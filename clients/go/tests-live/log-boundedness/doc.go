// Package logboundedness ports the MURMUR-SQL log-boundedness live
// scenario to native replication nodes driven by goharness.
//
// The scenario itself lives in log_boundedness_test.go; this file only
// gives `go build ./...` a non-test file (Go reports test-only
// directories as build failures).
package logboundedness
