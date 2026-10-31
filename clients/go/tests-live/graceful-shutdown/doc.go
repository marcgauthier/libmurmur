// Package gracefulshutdown is the native port of the MURMUR-SQL
// graceful-shutdown live scenario (tests/graceful_shutdown.rs via
// tests-live/graceful-shutdown), driven by
// clients/go/tests-live/goharness.
//
// The scenario itself lives in graceful_shutdown_test.go; this file
// only gives `go build ./...` a non-test file (Go reports test-only
// directories as build failures).
package gracefulshutdown
