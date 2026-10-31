// Package rekey is the native port of the MURMUR-SQL rekey live
// scenario (tests/rekey.rs via tests-live/rekey), driven by
// clients/go/tests-live/goharness.
//
// The scenario itself lives in rekey_test.go; this file only gives
// `go build ./...` a non-test file (Go reports test-only directories as
// build failures).
package rekey
