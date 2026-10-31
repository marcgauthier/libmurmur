// Package typedbridge ports the MURMUR-SQL typed-bridge live scenario
// to native replication nodes driven by goharness.
//
// The scenario itself lives in typed_bridge_test.go; this file only
// gives `go build ./...` a non-test file (Go reports test-only
// directories as build failures).
package typedbridge
