package highlowpeer

import "testing"

func TestSignedHighOwnershipAndReleaseAcrossNativePeers(t *testing.T) {
	RunSignedHighLowCluster(t, "highlow-peer")
}
