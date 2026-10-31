// Package endurancechaos is the native port of the MURMUR-SQL
// endurance-chaos live scenario, driven by tests-live/goharness.
//
// The scenario itself lives in endurance_chaos_test.go; this file only
// gives `go build ./...` a non-test file (Go reports test-only
// directories as build failures).
package endurancechaos
