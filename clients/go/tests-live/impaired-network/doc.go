// Package impairednetwork is the native port of the MURMUR-SQL
// impaired-network live scenario (tests/impaired_network.rs via
// tests-live/impaired-network), driven by
// clients/go/tests-live/goharness.
//
// The scenario itself lives in impaired_network_test.go; this file only
// gives `go build ./...` a non-test file (Go reports test-only
// directories as build failures).
package impairednetwork
