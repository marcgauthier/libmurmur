// Package filessoak is the native port of the MURMUR-SQL files-soak live
// scenario (tests/files_soak.rs via tests-live/files-soak), driven by
// clients/go/tests-live/goharness.
//
// The scenario itself lives in files_soak_test.go; this file only gives
// `go build ./...` a non-test file (Go reports test-only directories as
// build failures).
package filessoak
