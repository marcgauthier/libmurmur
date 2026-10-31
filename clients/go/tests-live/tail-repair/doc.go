// Package tailrepair is the native port of the MURMUR-SQL tail-repair
// live scenario (tests/tail_repair.rs via tests-live/tail-repair),
// driven by clients/go/tests-live/goharness.
//
// The scenario itself lives in tail_repair_test.go; this file only
// gives `go build ./...` a non-test file (Go reports test-only
// directories as build failures).
package tailrepair
