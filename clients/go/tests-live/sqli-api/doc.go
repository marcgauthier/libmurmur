// Package sqliapi is the native port of the MURMUR-SQL sqli-api live
// scenario (tests/sqli_api.rs via tests-live/sqli-api), driven by
// clients/go/tests-live/goharness.
//
// The scenario itself lives in sqli_api_test.go; this file only gives
// `go build ./...` a non-test file (Go reports test-only directories as
// build failures).
package sqliapi
