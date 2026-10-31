// Package schemaevolution is the native port of the MURMUR-SQL
// schema-evolution live scenario (tests/schema_evolution.rs via
// tests-live/schema-evolution), driven by
// clients/go/tests-live/goharness.
//
// The scenario itself lives in schema_evolution_test.go; this file only
// gives `go build ./...` a non-test file (Go reports test-only
// directories as build failures).
package schemaevolution
