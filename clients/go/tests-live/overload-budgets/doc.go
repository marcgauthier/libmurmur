// Package overloadbudgets ports the MURMUR-SQL overload-budgets live
// scenario to native replication nodes driven by goharness.
//
// The scenario itself lives in overload_budgets_test.go; this file only
// gives `go build ./...` a non-test file (Go reports test-only
// directories as build failures).
package overloadbudgets
