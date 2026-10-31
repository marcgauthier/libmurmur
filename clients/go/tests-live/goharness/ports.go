// Free-port allocation for node QUIC endpoints.
package goharness

import (
	"fmt"
	"net"
	"net/netip"
)

// FreeAddr returns a free 127.0.0.1 TCP addr (then closed).
func FreeAddr() (netip.AddrPort, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return netip.AddrPort{}, err
	}
	defer l.Close()
	ap, err := netip.ParseAddrPort(l.Addr().String())
	if err != nil {
		return netip.AddrPort{}, err
	}
	return ap, nil
}

// FreePort returns a free TCP port number.
func FreePort() (uint16, error) {
	ap, err := FreeAddr()
	if err != nil {
		return 0, err
	}
	return ap.Port(), nil
}

// FreeUDPAddr returns a free 127.0.0.1 UDP addr (then closed) for
// QUIC binds.
func FreeUDPAddr() (netip.AddrPort, error) {
	c, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("udp bind: %w", err)
	}
	defer c.Close()
	ap, err := netip.ParseAddrPort(c.LocalAddr().String())
	if err != nil {
		return netip.AddrPort{}, err
	}
	return ap, nil
}
