// Live scenario: production SQL endpoints require a trusted client
// certificate.
//
// Port of MURMUR-SQL api-mtls (fully skipped): a single node takes a
// row, restarts with production TLS + mTLS required, serves the valid
// client, rejects plaintext / missing-certificate /
// untrusted-certificate clients, still enforces password and unlock-key
// auth for valid-certificate clients, accepts a new row, and keeps both
// rows across a restart. None of that is expressible natively: nodes
// expose no SQL wire endpoint at all (statements run on in-process
// store handles), so there is no production TLS mode, no client
// certificate verification, and no password/unlock handshake to probe.
// Replication-peer certificate admission is covered separately.
package apimtls

import (
	"testing"

	goharness "github.com/marcgauthier/sqlite-murmur-go/clients/go/tests-live/goharness"
)

func TestSQLMTLS(t *testing.T) {
	goharness.SkipUnlessLive(t)
	// Blocked end to end: native nodes expose no SQL wire endpoint, so
	// production TLS, client-certificate verification, and
	// password/unlock auth have no surface to test.
	t.Skip("harness: SQL wire endpoint with production TLS and mTLS client-certificate auth")
}
