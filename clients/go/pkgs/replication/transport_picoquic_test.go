package replication

import (
	"io"
	"strings"
	"testing"
	"time"
)

// picoPair builds two native endpoints with URI-SAN identities.
func picoPair(t *testing.T, extraA, extraB map[string]string) (
	a, b *PicoquicTransport, aNode, bNode NodeID, pki *quicPKI) {
	t.Helper()
	pki = makeQuicPKI(t)
	aHex, bHex := strings.Repeat("11", 16), strings.Repeat("22", 16)
	aCert, aKey, _ := pki.leaf(t, "a", []string{nodeURI(aHex)})
	bCert, bKey, _ := pki.leaf(t, "b", []string{nodeURI(bHex)})
	var err error
	if aNode, err = ParseID(aHex); err != nil {
		t.Fatal(err)
	}
	if bNode, err = ParseID(bHex); err != nil {
		t.Fatal(err)
	}
	aDB := quicDB(t, "127.0.0.1:0", aCert, aKey, pki.caPath, extraA)
	bDB := quicDB(t, "127.0.0.1:0", bCert, bKey, pki.caPath, extraB)
	if a, err = ListenPicoquic(aDB, aNode); err != nil {
		t.Fatalf("listen a: %v", err)
	}
	t.Cleanup(func() { a.Close() })
	if b, err = ListenPicoquic(bDB, bNode); err != nil {
		t.Fatalf("listen b: %v", err)
	}
	t.Cleanup(func() { b.Close() })
	return a, b, aNode, bNode, pki
}

// dialAccept dials from dialer to listener and returns both sessions.
func dialAccept(t *testing.T, dialer, listener Transport) (dialed, accepted Session) {
	t.Helper()
	acceptCh := make(chan Session, 1)
	errCh := make(chan error, 1)
	go func() {
		sess, err := listener.Accept()
		if err != nil {
			errCh <- err
			return
		}
		acceptCh <- sess
	}()
	var err error
	if dialed, err = dialer.Dial(listener.LocalAddr()); err != nil {
		t.Fatalf("dial: %v", err)
	}
	select {
	case accepted = <-acceptCh:
	case err := <-errCh:
		t.Fatalf("accept: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("accept timed out")
	}
	return dialed, accepted
}

// exerciseSession runs the full loopback flow: peer ids, bidi
// streams with FIN, datagrams.
func exerciseSession(t *testing.T, dialed, accepted Session, dialerPeer, accepterPeer NodeID) {
	t.Helper()
	if dialed.PeerID() != dialerPeer {
		t.Fatalf("dialer peer = %s", dialed.PeerID())
	}
	if accepted.PeerID() != accepterPeer {
		t.Fatalf("acceptor peer = %s", accepted.PeerID())
	}
	out, err := dialed.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	if err := out.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	in, err := accepted.AcceptStream()
	if err != nil {
		t.Fatal(err)
	}
	if got := readFullStream(t, in, 4); string(got) != "ping" {
		t.Fatalf("stream a<-b = %q", got)
	}
	if err := in.Write([]byte("pongpong")); err != nil {
		t.Fatal(err)
	}
	if got := readFullStream(t, out, 8); string(got) != "pongpong" {
		t.Fatalf("stream b<-a = %q", got)
	}
	// Clean FIN surfaces as EOF once bytes drain.
	if err := out.Close(); err != nil {
		t.Fatal(err)
	}
	if err := in.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := in.Read(make([]byte, 4)); err != io.EOF {
		t.Fatalf("FIN read = %v", err)
	}
	if err := dialed.SendDatagram([]byte("gossip1")); err != nil {
		t.Fatalf("send datagram: %v", err)
	}
	// Datagrams are unreliable; retry the exchange a few times.
	var dg []byte
	deadline := time.Now().Add(5 * time.Second)
	for {
		type dgRes struct {
			b   []byte
			err error
		}
		ch := make(chan dgRes, 1)
		go func() {
			b, err := accepted.RecvDatagram()
			ch <- dgRes{b, err}
		}()
		select {
		case r := <-ch:
			if r.err != nil {
				t.Fatalf("recv datagram: %v", r.err)
			}
			dg = r.b
		case <-time.After(500 * time.Millisecond):
			if time.Now().After(deadline) {
				t.Fatal("datagram never arrived")
			}
			if err := dialed.SendDatagram([]byte("gossip1")); err != nil {
				t.Fatalf("resend datagram: %v", err)
			}
			continue
		}
		break
	}
	if string(dg) != "gossip1" {
		t.Fatalf("datagram = %q", dg)
	}
}

// TestPicoquicLoopbackSession runs the full flow over the native
// transport on both ends.
func TestPicoquicLoopbackSession(t *testing.T) {
	a, b, aNode, bNode, _ := picoPair(t, nil, nil)
	if !strings.HasPrefix(a.LocalAddr(), "127.0.0.1:") {
		t.Fatalf("local addr = %s", a.LocalAddr())
	}
	dialed, accepted := dialAccept(t, b, a)
	defer dialed.Close()
	defer accepted.Close()
	exerciseSession(t, dialed, accepted, aNode, bNode)
}

// TestPicoquicGoInterop dials each direction between the native
// transport and the Go quic-go transport: the wire must be standard
// QUIC+TLS on both sides.
func TestPicoquicGoInterop(t *testing.T) {
	a, b, aNode, bNode, pki := picoPair(t, nil, nil)

	// Go endpoint for a third identity in the same PKI.
	cHex := strings.Repeat("33", 16)
	cCert, cKey, _ := pki.leaf(t, "c", []string{nodeURI(cHex)})
	cNode, err := ParseID(cHex)
	if err != nil {
		t.Fatal(err)
	}
	cDB := quicDB(t, "127.0.0.1:0", cCert, cKey, pki.caPath, nil)
	g, err := ListenQuic(cDB, cNode)
	if err != nil {
		t.Fatalf("listen go: %v", err)
	}
	defer g.Close()

	// Native dials Go.
	dialed, accepted := dialAccept(t, a, g)
	exerciseSession(t, dialed, accepted, cNode, aNode)
	dialed.Close()
	accepted.Close()

	// Go dials native.
	dialed, accepted = dialAccept(t, g, b)
	exerciseSession(t, dialed, accepted, bNode, cNode)
	dialed.Close()
	accepted.Close()
}

// TestPicoquicRefusals mirrors the Go refusal cases on native.
func TestPicoquicRefusals(t *testing.T) {
	a, _, _, bNode, pki := picoPair(t, nil, nil)

	// Wrong node: create fails.
	other, _ := ParseID(strings.Repeat("44", 16))
	aHex := strings.Repeat("11", 16)
	aCert, aKey, _ := pki.leaf(t, "a2", []string{nodeURI(aHex)})
	db := quicDB(t, "127.0.0.1:0", aCert, aKey, pki.caPath, nil)
	if _, err := ListenPicoquic(db, other); err == nil ||
		!strings.Contains(err.Error(), "certificate is not for this node") {
		t.Fatalf("wrong-node listen = %v", err)
	}

	// Unknown CA: the dial fails the handshake (and the acceptor
	// never sees a session).
	rogue := makeQuicPKI(t)
	rCert, rKey, _ := rogue.leaf(t, "r", []string{nodeURI(strings.Repeat("55", 16))})
	rNode, _ := ParseID(strings.Repeat("55", 16))
	rDB := quicDB(t, "127.0.0.1:0", rCert, rKey, rogue.caPath, nil)
	r, err := ListenPicoquic(rDB, rNode)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	go func() {
		for {
			sess, err := a.Accept()
			if err != nil {
				return
			}
			sess.Close()
		}
	}()
	if _, err := r.Dial(a.LocalAddr()); err == nil {
		t.Fatal("expected rogue-CA dial to fail")
	}

	// Node allowlist: handshake succeeds, accept skips, streams fail.
	bHex := strings.Repeat("22", 16)
	bCert2, bKey2, _ := pki.leaf(t, "b2", []string{nodeURI(bHex)})
	bDB := quicDB(t, "127.0.0.1:0", bCert2, bKey2, pki.caPath,
		map[string]string{"allowed_peers": `["` + strings.Repeat("44", 16) + `"]`})
	bl, err := ListenPicoquic(bDB, bNode)
	if err != nil {
		t.Fatal(err)
	}
	defer bl.Close()
	acceptCh := make(chan Session, 1)
	go func() {
		sess, err := bl.Accept()
		if err == nil {
			acceptCh <- sess
		}
	}()
	sess, err := a.Dial(bl.LocalAddr())
	if err != nil {
		t.Fatalf("allowlisted dial handshake: %v", err)
	}
	defer sess.Close()
	select {
	case s := <-acceptCh:
		s.Close()
		t.Fatal("denied peer was accepted")
	case <-time.After(2 * time.Second):
	}
	if _, err := sess.OpenStream(); err == nil {
		t.Fatal("expected refused session to be unusable")
	}
}
