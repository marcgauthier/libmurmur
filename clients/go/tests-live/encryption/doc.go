// Package encryption is the native port of the MURMUR-SQL encryption
// live scenario (tests/encryption.rs via tests-live/encryption), driven
// by clients/go/tests-live/goharness.
//
// The scenario itself lives in encryption_test.go; this file only gives
// `go build ./...` a non-test file (Go reports test-only directories as
// build failures).
package encryption
