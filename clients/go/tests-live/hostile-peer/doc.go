// Package hostilepeer is the native port of the MURMUR-SQL
// hostile-peer live scenario (tests/hostile_peer.rs via
// tests-live/hostile-peer), driven by
// clients/go/tests-live/goharness.
//
// The scenario itself lives in hostile_peer_test.go; this file only
// gives `go build ./...` a non-test file (Go reports test-only
// directories as build failures).
package hostilepeer
