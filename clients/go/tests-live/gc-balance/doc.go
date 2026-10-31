// Package gcbalance is the native port of the MURMUR-SQL gc-balance live
// scenario (tests/gc_balance.rs via tests-live/gc-balance), driven by
// clients/go/tests-live/goharness.
//
// The scenario itself lives in gc_balance_test.go; this file only gives
// `go build ./...` a non-test file (Go reports test-only directories as
// build failures).
package gcbalance
