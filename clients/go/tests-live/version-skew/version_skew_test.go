// Live scenario: a peer advertising an unknown protocol version is
// refused fail-closed: it never joins, never receives rows, and
// never shifts the survivor's replication state.
//
// Port of MURMUR-SQL version-skew (fully skipped): the reference
// speaks the replication protocol from a raw QUIC fixture
// advertising version 99 and asserts the refusal gates. The native
// wire protocol has no protocol-version field at all (MsgHello
// carries group/node/site/schema/incarnation/addr; frames carry no
// version), so a version-99 fixture cannot be constructed and the
// suite's core assertion is untestable. The isolation/convergence
// legs alone would prove nothing about version skew, so the whole
// suite skips rather than shipping a vacuous port.
package versionskew

import (
	"testing"

	goharness "github.com/marcgauthier/sqlite-murmur-go/clients/go/tests-live/goharness"
)

func TestUnknownProtocolVersionRefused(t *testing.T) {
	goharness.SkipUnlessLive(t)
	// Blocked end to end: the native wire has no protocol version
	// to skew.
	t.Skip("harness: protocol versioning on the native wire (no version field to skew)")
}
