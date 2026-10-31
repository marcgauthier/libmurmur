// Package dosclient ports the MURMUR-SQL dos-client live scenario to
// native replication nodes driven by goharness.
//
// The scenario itself lives in dos_client_test.go; this file only
// gives `go build ./...` a non-test file (Go reports test-only
// directories as build failures).
package dosclient
