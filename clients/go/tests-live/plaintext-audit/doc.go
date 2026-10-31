// Package plaintextaudit is the native port of the MURMUR-SQL
// plaintext-audit live scenario (tests/plaintext_audit.rs via
// tests-live/plaintext-audit), driven by
// clients/go/tests-live/goharness.
//
// The scenario itself lives in plaintext_audit_test.go; this file only
// gives `go build ./...` a non-test file (Go reports test-only
// directories as build failures).
package plaintextaudit
