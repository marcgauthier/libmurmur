// Package allownodes ports the MURMUR-SQL allow-nodes live scenario to
// native replication nodes driven by goharness.
//
// The scenario itself lives in allow_nodes_test.go; this file only gives
// `go build ./...` a non-test file (Go reports test-only directories as
// build failures).
package allownodes
