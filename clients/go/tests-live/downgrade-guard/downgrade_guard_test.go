// Live SQL test: a database store written by a NEWER release format must
// be refused fail-closed during UNLOCK, leaving the store untouched,
// while the unmodified store reopens cleanly with exact data fidelity.
//
// Port of MURMUR-SQL downgrade-guard (fully skipped): the reference
// rotates the key over SQL, stops the server, copies the durable
// directory, runs an engine-owned Rust injector binary
// (MURMUR_FORMAT_FIXTURE_BIN) to bump the identity format on the copy
// only, repoints the server at the copy via SetConfig, requires the
// start to fail with "unsupported database format" without touching a
// byte, then reopens the pristine store with identical rows. None of
// that is expressible natively: there is no format-injector artifact,
// the native store has no release-format downgrade guard to trip, the
// bindings expose no key-rotation verb, and the harness cannot repoint
// a node at an alternate data dir.
package downgradeguard

import (
	"testing"

	goharness "github.com/marcgauthier/sqlite-murmur-go/clients/go/tests-live/goharness"
)

func TestDowngradeGuardRefusesNewStore(t *testing.T) {
	goharness.SkipUnlessLive(t)
	// Blocked end to end: no future-format injector, no native
	// downgrade guard, no key rotation, no restart against an
	// alternate store.
	t.Skip("harness: downgrade guard (format injector, format refusal check, rotate verb, restart against alternate store)")
}
