// Package threewayheal ports the MURMUR-SQL three-way-heal live scenario
// to native replication nodes driven by goharness.
//
// The scenario itself lives in three_way_heal_test.go; this file only
// gives `go build ./...` a non-test file (Go reports test-only
// directories as build failures).
package threewayheal
