// Package deletepruning ports the MURMUR-SQL delete-pruning live
// scenario to native replication nodes driven by goharness.
//
// The scenario itself lives in delete_pruning_test.go; this file only
// gives `go build ./...` a non-test file (Go reports test-only
// directories as build failures).
package deletepruning
