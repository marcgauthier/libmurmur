// Package filepermissions ports the MURMUR-SQL file-permissions live
// scenario to native replication nodes driven by goharness.
//
// The scenario itself lives in file_permissions_test.go; this file only
// gives `go build ./...` a non-test file (Go reports test-only directories
// as build failures).
package filepermissions
