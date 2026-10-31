// Package churnretirement ports the MURMUR-SQL churn-retirement live
// scenario to native replication nodes driven by goharness.
//
// The scenario itself lives in churn_retirement_test.go; this file only
// gives `go build ./...` a non-test file (Go reports test-only
// directories as build failures).
package churnretirement
