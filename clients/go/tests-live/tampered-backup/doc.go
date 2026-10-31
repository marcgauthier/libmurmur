// Package tamperedbackup ports the MURMUR-SQL tampered-backup live
// scenario to native replication nodes driven by goharness.
//
// The scenario itself lives in tampered_backup_test.go; this file only
// gives `go build ./...` a non-test file (Go reports test-only directories
// as build failures).
package tamperedbackup
