package picoquic_test

import (
	"testing"

	"github.com/marcgauthier/libmurmur/clients/go/bindings/picoquic"
)

func TestMbedTLSVersion(t *testing.T) {
	if got, want := picoquic.MbedTLSVersion(), "3.6.7"; got != want {
		t.Fatalf("MbedTLSVersion() = %q, want %q", got, want)
	}
}
