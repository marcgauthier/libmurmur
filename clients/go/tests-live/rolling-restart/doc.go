// Package rollingrestart ports the MURMUR-SQL rolling-restart live
// scenario to native replication nodes driven by goharness.
//
// The scenario itself lives in rolling_restart_test.go; this file only
// gives `go build ./...` a non-test file (Go reports test-only directories
// as build failures).
package rollingrestart
