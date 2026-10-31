// Package mergepolicies is the native port of the MURMUR-SQL
// merge-policies live scenario (tests/merge_policies.rs via
// tests-live/merge-policies), driven by
// clients/go/tests-live/goharness.
//
// The scenario itself lives in merge_policies_test.go; this file only
// gives `go build ./...` a non-test file (Go reports test-only
// directories as build failures).
package mergepolicies
