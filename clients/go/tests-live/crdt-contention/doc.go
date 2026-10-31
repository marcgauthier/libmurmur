// Package crdtcontention ports the MURMUR-SQL crdt-contention live
// scenario to native replication nodes driven by goharness.
//
// The scenario itself lives in crdt_contention_test.go; this file only
// gives `go build ./...` a non-test file (Go reports test-only
// directories as build failures).
package crdtcontention
