// Package chaosload ports the MURMUR-SQL chaos-load live scenario to
// native replication nodes driven by goharness.
//
// The scenario itself lives in chaos_load_test.go; this file only gives
// `go build ./...` a non-test file (Go reports test-only directories as
// build failures).
package chaosload
