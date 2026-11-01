// Live scenario: a stale node rejoins while its only available snapshot
// source is hostile, rejects the corrupt chunk with nothing partially
// published, then converges via the honest snapshot path.
//
// Port of MURMUR-SQL corrupt-snapshot. Skipped with named harness
// gaps: the attack legs need a raw-QUIC peer speaking the
// replication wire protocol (unsolicited history-unavailable error,
// forged manifest, bit-flipped chunk), which has no harness
// equivalent and scenario packages must not import engine
// internals; and both the attack leg and the honest leg need the
// snapshot path, which never delivers on this stack (the established
// snapshot-resync gap, verified first-hand).
package corruptsnapshot

import (
	"testing"

	goharness "github.com/marcgauthier/libmurmur/clients/go/tests-live/goharness"
)

func TestStaleNodeDiscardsCorruptSnapshotThenConverges(t *testing.T) {
	goharness.SkipUnlessLive(t)
	// Blocked twice over. First, the attacker dialogue (raw QUIC
	// session: induce a snapshot pull with Error{code: 3}, serve a
	// forged manifest plus one intact and one bit-flipped chunk, and
	// assert no SnapshotApplied arrives) has no harness fixture, and
	// rebuilding it from engine internals would violate the porting
	// contract (goharness only). Second, both the corrupt-transfer leg
	// and the honest-resync leg need snapshot delivery, which never
	// arrives on this stack (the snapshot-resync gap).
	t.Skip("harness: raw-QUIC attacker fixture and snapshot delivery both unavailable (no wire-protocol peer; stale rejoin never converges)")
}
