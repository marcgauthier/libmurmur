// Package backuprestore ports the MURMUR-SQL backup-restore live
// scenario to native replication nodes driven by goharness.
//
// The scenario itself lives in backup_restore_test.go; this file only
// gives `go build ./...` a non-test file (Go reports test-only directories
// as build failures).
package backuprestore
