// Package backupunderfire ports the MURMUR-SQL backup-under-fire live
// scenario to native replication nodes driven by goharness.
//
// The scenario itself lives in backup_under_fire_test.go; this file only
// gives `go build ./...` a non-test file (Go reports test-only directories
// as build failures).
package backupunderfire
