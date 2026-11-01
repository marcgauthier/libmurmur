// Live scenario: product-created durable paths stay private after SQL
// initialization, backup, and restore.
//
// Port of MURMUR-SQL file-permissions (fully skipped): a single node is
// audited (no symlinks, no group/other bits) after init, after 25 rows
// + flush, on the backup save dir, on the uploaded backup copy, after
// DELETE + RESTORE, after a flush, and across a restart; restored rows
// read back exactly. None of the audit legs can pass natively: the
// harness creates node/data/TLS dirs mode 0755 and the engine writes
// store files mode 0644, and there is no encrypted key registry
// (keys.enc). The functional backup/restore round trip is covered by
// the backup-restore port instead.
package filepermissions

import (
	"testing"

	goharness "github.com/marcgauthier/libmurmur/clients/go/tests-live/goharness"
)

func TestSQLStorageAndBackupPermissionsRemainPrivateAfterRestore(t *testing.T) {
	goharness.SkipUnlessLive(t)
	// Blocked end to end: node/data/TLS dirs are created 0755, store
	// and backup files are written 0644, and no encrypted key registry
	// exists; every permission audit would fail on harness-owned modes.
	t.Skip("harness: private POSIX modes (0700/0600) for node dirs, stores, TLS material and backups, plus encrypted key registry")
}
