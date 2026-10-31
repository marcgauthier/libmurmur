// Package hostileschema is the native port of the MURMUR-SQL
// hostile-schema live scenario (tests/hostile_schema.rs via
// tests-live/hostile-schema), driven by
// clients/go/tests-live/goharness.
//
// The scenario itself lives in hostile_schema_test.go; this file only
// gives `go build ./...` a non-test file (Go reports test-only
// directories as build failures).
package hostileschema
