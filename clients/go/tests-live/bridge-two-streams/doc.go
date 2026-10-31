// Package bridgetwostreams ports the MURMUR-SQL bridge-two-streams
// live scenario to native replication nodes driven by goharness.
//
// The scenario itself lives in bridge_two_streams_test.go; this file
// only gives `go build ./...` a non-test file (Go reports test-only
// directories as build failures).
package bridgetwostreams
