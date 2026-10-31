// Live scenario: local writes keep priority over replication apply work.
//
// Port of MURMUR-SQL write-priority (fully skipped): the reference runs
// 128 concurrent SQL workers (64 per node) issuing atomic 25-row
// statements for 12 s while polling row counts, then requires at least
// 1 s of writer service time with remote apply work present but at most
// 25% of the total, and converges on every worker's final rows. The
// verdict reads engine scheduler counters (scheduler.local/remote
// service_nanos) that do not exist natively — the engine health
// snapshot reports scheduler.stats as null — so the fairness policy
// itself is unmeasurable on this stack and the load alone would prove
// nothing about priority.
package writepriority

import (
	"testing"

	goharness "github.com/marcgauthier/sqlite-murmur-go/clients/go/tests-live/goharness"
)

func TestLocalWritePriority(t *testing.T) {
	goharness.SkipUnlessLive(t)
	// Blocked end to end: no scheduler service-time stats
	// (scheduler.stats is null; no local/remote service_nanos).
	t.Skip("harness: scheduler service-time stats (local/remote service_nanos)")
}
