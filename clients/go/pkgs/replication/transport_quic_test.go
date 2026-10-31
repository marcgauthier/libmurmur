package replication

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marcgauthier/sqlite-murmur-go/clients/go/bindings/sqlite"
)

// quicPKI is a test CA plus one leaf per node hex.
type quicPKI struct {
	dir    string
	caPath string
	ca     *x509.Certificate
	caKey  *ecdsa.PrivateKey
}

func makeQuicPKI(t *testing.T) *quicPKI {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "murmur test ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.pem")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(caPath, pemBytes, 0o644); err != nil {
		t.Fatal(err)
	}
	return &quicPKI{dir: dir, caPath: caPath, ca: ca, caKey: key}
}

// leaf writes a leaf cert/key pair with the given URI SANs and
// returns the PEM paths plus the leaf DER.
func (p *quicPKI) leaf(t *testing.T, name string, uris []string) (certPath, keyPath string, der []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var parsed []*url.URL
	for _, u := range uris {
		pu, err := url.Parse(u)
		if err != nil {
			t.Fatal(err)
		}
		parsed = append(parsed, pu)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		URIs:         parsed,
	}
	der, err = x509.CreateCertificate(rand.Reader, tmpl, p.ca, &key.PublicKey, p.caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPath = filepath.Join(p.dir, name+".pem")
	keyPath = filepath.Join(p.dir, name+".key")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath, der
}

func nodeURI(hexID string) string { return "replicateddb://node/" + hexID }

// quicDB builds a settings database pointing at PEM paths.
func quicDB(t *testing.T, bind, cert, key, ca string, extra map[string]string) *sqlite.Conn {
	t.Helper()
	db, err := sqlite.Open(":memory:", sqlite.OpenReadWrite|sqlite.OpenCreate)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := EnsureSchema(db); err != nil {
		t.Fatal(err)
	}
	settings := map[string]string{"bind": bind, "certificate": cert, "private_key": key, "ca": ca}
	for k, v := range extra {
		settings[k] = v
	}
	for k, v := range settings {
		if err := SetSetting(db, k, v); err != nil {
			t.Fatal(err)
		}
	}
	return db
}

// TestNodeIDFromCertVectors mirrors the Rust certificate_tests:
// unique, nonzero, complete DER.
func TestNodeIDFromCertVectors(t *testing.T) {
	pki := makeQuicPKI(t)
	one := strings.Repeat("01", 16)

	_, _, der := pki.leaf(t, "good", []string{"https://example.com", nodeURI(one)})
	id, err := nodeIDFromCert(der)
	if err != nil {
		t.Fatalf("valid leaf: %v", err)
	}
	if id.String() != one {
		t.Fatalf("id = %s", id.String())
	}

	_, _, noSAN := pki.leaf(t, "nosan", []string{})
	if _, err := nodeIDFromCert(noSAN); err == nil {
		t.Fatal("expected missing-SAN error")
	}
	_, _, dup := pki.leaf(t, "dup", []string{nodeURI(one), nodeURI(one)})
	if _, err := nodeIDFromCert(dup); err == nil {
		t.Fatal("expected ambiguous-identity error")
	}
	_, _, zero := pki.leaf(t, "zero", []string{nodeURI(strings.Repeat("00", 16))})
	if _, err := nodeIDFromCert(zero); err == nil {
		t.Fatal("expected zero-identity error")
	}
	_, _, bad := pki.leaf(t, "bad", []string{"replicateddb://node/not-a-node"})
	if _, err := nodeIDFromCert(bad); err == nil {
		t.Fatal("expected invalid-identity error")
	}
	if _, err := nodeIDFromCert(der[:len(der)-1]); err == nil {
		t.Fatal("expected truncated-DER error")
	}
	trailing := append(append([]byte(nil), der...), 0)
	if _, err := nodeIDFromCert(trailing); err == nil {
		t.Fatal("expected trailing-data error")
	}
}

func readFullStream(t *testing.T, s Stream, n int) []byte {
	t.Helper()
	out := make([]byte, n)
	for off := 0; off < n; {
		m, err := s.Read(out[off:])
		if err != nil {
			t.Fatalf("stream read: %v", err)
		}
		off += m
	}
	return out
}

// TestQuicLoopbackSession runs a full dial/accept over real QUIC:
// mutual identity, bidi streams, datagrams.
func TestQuicLoopbackSession(t *testing.T) {
	pki := makeQuicPKI(t)
	aHex, bHex := strings.Repeat("11", 16), strings.Repeat("22", 16)
	aCert, aKey, _ := pki.leaf(t, "a", []string{nodeURI(aHex)})
	bCert, bKey, _ := pki.leaf(t, "b", []string{nodeURI(bHex)})
	aNode, err := ParseID(aHex)
	if err != nil {
		t.Fatal(err)
	}
	bNode, err := ParseID(bHex)
	if err != nil {
		t.Fatal(err)
	}

	aDB := quicDB(t, "127.0.0.1:0", aCert, aKey, pki.caPath, nil)
	bDB := quicDB(t, "127.0.0.1:0", bCert, bKey, pki.caPath, nil)
	a, err := ListenQuic(aDB, aNode)
	if err != nil {
		t.Fatalf("listen a: %v", err)
	}
	defer a.Close()
	b, err := ListenQuic(bDB, bNode)
	if err != nil {
		t.Fatalf("listen b: %v", err)
	}
	defer b.Close()

	if !strings.HasPrefix(a.LocalAddr(), "127.0.0.1:") {
		t.Fatalf("local addr = %s", a.LocalAddr())
	}

	acceptCh := make(chan Session, 1)
	errCh := make(chan error, 1)
	go func() {
		sess, err := a.Accept()
		if err != nil {
			errCh <- err
			return
		}
		acceptCh <- sess
	}()
	dialed, err := b.Dial(a.LocalAddr())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer dialed.Close()
	var accepted Session
	select {
	case accepted = <-acceptCh:
	case err := <-errCh:
		t.Fatalf("accept: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("accept timed out")
	}
	defer accepted.Close()

	if dialed.PeerID() != aNode {
		t.Fatalf("dialer peer = %s", dialed.PeerID())
	}
	if accepted.PeerID() != bNode {
		t.Fatalf("acceptor peer = %s", accepted.PeerID())
	}

	// Bidi stream both directions. QUIC only delivers an
	// inbound stream once the opener writes, so the first write
	// precedes AcceptStream (as in every engine flow, where the
	// opener always sends the request first).
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
	out.Close()
	in.Close()

	// Datagram roundtrip.
	if err := dialed.SendDatagram([]byte("gossip1")); err != nil {
		t.Fatalf("send datagram: %v", err)
	}
	dg, err := accepted.RecvDatagram()
	if err != nil {
		t.Fatalf("recv datagram: %v", err)
	}
	if string(dg) != "gossip1" {
		t.Fatalf("datagram = %q", dg)
	}
}

// TestQuicRefusals covers the identity and gate rejections.
func TestQuicRefusals(t *testing.T) {
	pki := makeQuicPKI(t)
	aHex, bHex := strings.Repeat("11", 16), strings.Repeat("22", 16)
	aCert, aKey, _ := pki.leaf(t, "a", []string{nodeURI(aHex)})
	bCert, bKey, _ := pki.leaf(t, "b", []string{nodeURI(bHex)})
	aNode, _ := ParseID(aHex)
	bNode, _ := ParseID(bHex)

	// Leaf identity must match the node the endpoint serves.
	other, _ := ParseID(strings.Repeat("33", 16))
	db := quicDB(t, "127.0.0.1:0", aCert, aKey, pki.caPath, nil)
	if _, err := ListenQuic(db, other); err == nil || !strings.Contains(err.Error(), "certificate is not for this node") {
		t.Fatalf("wrong-node listen = %v", err)
	}

	// Unknown CA: the dial fails the handshake.
	rogue := makeQuicPKI(t)
	rCert, rKey, _ := rogue.leaf(t, "r", []string{nodeURI(strings.Repeat("44", 16))})
	rNode, _ := ParseID(strings.Repeat("44", 16))
	aDB := quicDB(t, "127.0.0.1:0", aCert, aKey, pki.caPath, nil)
	a, err := ListenQuic(aDB, aNode)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	go func() {
		// Drain refused accepts; a failed handshake delivers no
		// session, so this must not produce one.
		for {
			sess, err := a.Accept()
			if err != nil {
				return
			}
			sess.Close()
		}
	}()
	rDB := quicDB(t, "127.0.0.1:0", rCert, rKey, rogue.caPath, nil)
	r, err := ListenQuic(rDB, rNode)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if _, err := r.Dial(a.LocalAddr()); err == nil {
		t.Fatal("expected rogue-CA dial to fail")
	}

	// Node allowlist: peer_id denies nodes outside the set.
	bDB := quicDB(t, "127.0.0.1:0", bCert, bKey, pki.caPath, map[string]string{
		"allowed_peers": `["` + strings.Repeat("33", 16) + `"]`,
	})
	b, err := ListenQuic(bDB, bNode)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	acceptCh := make(chan Session, 1)
	go func() {
		sess, err := b.Accept()
		if err == nil {
			acceptCh <- sess
		}
	}()
	sess, err := a.Dial(b.LocalAddr())
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
	// The acceptor closed the refused connection; streams fail.
	if _, err := sess.OpenStream(); err == nil {
		t.Fatal("expected refused session to be unusable")
	}
}

// TestPeerIDGates exercises the network/node gates without sockets.
func TestPeerIDGates(t *testing.T) {
	pki := makeQuicPKI(t)
	hexID := strings.Repeat("11", 16)
	_, _, der := pki.leaf(t, "a", []string{nodeURI(hexID)})
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	chain := []*x509.Certificate{leaf}
	loopback := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1}

	id, err := peerID(chain, loopback, nil, nil)
	if err != nil {
		t.Fatalf("open gates: %v", err)
	}
	if id.String() != hexID {
		t.Fatalf("id = %s", id.String())
	}
	if _, err := peerID(nil, loopback, nil, nil); err == nil {
		t.Fatal("expected missing-chain error")
	}
	_, denyNet, _ := net.ParseCIDR("10.0.0.0/8")
	if _, err := peerID(chain, loopback, nil, []*net.IPNet{denyNet}); err == nil {
		t.Fatal("expected network denial")
	}
	_, allowNet, _ := net.ParseCIDR("127.0.0.0/8")
	if _, err := peerID(chain, loopback, nil, []*net.IPNet{allowNet}); err != nil {
		t.Fatalf("allowed network: %v", err)
	}
	other, _ := ParseID(strings.Repeat("33", 16))
	if _, err := peerID(chain, loopback, map[NodeID]bool{other: true}, nil); err == nil {
		t.Fatal("expected node denial")
	}
	if _, err := peerID(chain, loopback, map[NodeID]bool{id: true}, nil); err != nil {
		t.Fatalf("allowed node: %v", err)
	}
}
