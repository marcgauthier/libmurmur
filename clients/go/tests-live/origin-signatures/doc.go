// Package originsignatures is the native port of the MURMUR-SQL
// origin-signatures live scenario (tests/origin_signatures.rs via
// tests-live/origin-signatures), driven by
// clients/go/tests-live/goharness.
//
// The scenario itself lives in origin_signatures_test.go; this file only
// gives `go build ./...` a non-test file (Go reports test-only
// directories as build failures).
package originsignatures
