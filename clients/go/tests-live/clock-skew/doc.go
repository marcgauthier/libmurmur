// Package clockskew ports the MURMUR-SQL clock-skew live scenario to
// native replication nodes driven by goharness.
//
// The scenario itself lives in clock_skew_test.go; this file only gives
// `go build ./...` a non-test file (Go reports test-only directories as
// build failures).
package clockskew
