// Package unlockabuse is the native port of the MURMUR-SQL unlock-abuse
// live scenario (tests/unlock_abuse.rs via tests-live/unlock-abuse),
// driven by clients/go/tests-live/goharness.
//
// The scenario itself lives in unlock_abuse_test.go; this file only
// gives `go build ./...` a non-test file (Go reports test-only
// directories as build failures).
package unlockabuse
