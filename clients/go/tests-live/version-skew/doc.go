// Package versionskew ports the MURMUR-SQL version-skew live scenario
// to native replication nodes driven by goharness.
//
// The scenario itself lives in version_skew_test.go; this file only
// gives `go build ./...` a non-test file (Go reports test-only
// directories as build failures).
package versionskew
