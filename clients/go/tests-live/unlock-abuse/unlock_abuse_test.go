// Live scenario: bad credentials and unlock keys neither disclose secrets
// nor damage SQL.
//
// Port of MURMUR-SQL unlock-abuse (fully skipped): the reference holds
// one row on a real server, rejects twelve bad-credential connects
// (rotating password / user / unlock key) with 28P01 / 28P01 / 28000
// without echoing the secret, keeps the row readable after every
// attempt, and survives a restart. Native nodes expose no wire auth
// surface at all — there is no user, password, or unlock handshake to
// abuse — so no leg of this scenario is expressible.
package unlockabuse

import (
	"testing"

	goharness "github.com/marcgauthier/libmurmur/clients/go/tests-live/goharness"
)

func TestBadCredentialsAndUnlockKeysDoNotDiscloseSecretsOrDamageSQL(t *testing.T) {
	goharness.SkipUnlessLive(t)
	// Blocked end to end: native nodes have no wire auth surface
	// (no user/password/unlock handshake, no SQLSTATEs).
	t.Skip("harness: wire authentication and unlock handshake")
}
