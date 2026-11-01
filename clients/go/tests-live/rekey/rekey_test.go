// Live scenario: rotate the encryption key, survive a restart, and
// reject the old key.
//
// Port of MURMUR-SQL rekey (fully skipped): the reference takes a row,
// runs MURMUR ROTATE KEY, stops the server without a graceful shutdown,
// restarts with the new key, rejects the old key with 28000, reads the
// pre-rotation row, accepts a post-rotation row, and survives a second
// restart. None of that is expressible natively: the bindings expose no
// key-rotation verb, the harness cannot restart a node with a different
// key, and there is no wire surface to reject the old key on.
package rekey

import (
	"testing"

	goharness "github.com/marcgauthier/libmurmur/clients/go/tests-live/goharness"
)

func TestSQLKeyRotationSurvivesKillAndRejectsOldKey(t *testing.T) {
	goharness.SkipUnlessLive(t)
	// Blocked end to end: no native key-rotation verb, no restart
	// with an alternate key, no wire auth to reject the old key.
	t.Skip("harness: key rotation (rotate verb, restart with new key, old-key rejection)")
}
