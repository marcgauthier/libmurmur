// Package replication: QUIC transport.
//
// Mirrors transport.rs: mutual TLS 1.3 over QUIC with ALPN
// "murmur-crsqlite/1". Node identity is the URI SAN
// "replicateddb://node/<32 hex>" of the leaf certificate — unique,
// nonzero, exactly one. Chain trust comes from the operator CA file;
// the allowed_peers / allowed_networks settings gate dials and
// accepts. Endpoint knobs match Rust: 30s idle timeout, 10s
// keep-alive, sessions+8 bidi streams, no uni streams, datagrams on.
package replication

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/marcgauthier/libmurmur/clients/go/bindings/sqlite"
)

// quicALPN is the wire protocol id, shared with the Rust nodes.
const quicALPN = "murmur-crsqlite/1"

// nodeURIPrefix is the identity SAN scheme.
const nodeURIPrefix = "replicateddb://node/"

// quicDefaults mirrors the Rust transport knobs.
const (
	quicIdleTimeout = 30 * time.Second
	quicKeepAlive   = 10 * time.Second
	quicStreamPad   = 8
	quicDefaultBind = "0.0.0.0:7443"
	quicDialTimeout = 10 * time.Second
)

// nodeIDFromCert extracts the node identity from one DER certificate:
// exactly one "replicateddb://node/<hex>" URI SAN, nonzero. Trailing
// DER bytes are rejected by the parser.
func nodeIDFromCert(der []byte) (NodeID, error) {
	var zero NodeID
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return zero, errAuth(err.Error())
	}
	found := false
	var id NodeID
	for _, uri := range cert.URIs {
		value, ok := strings.CutPrefix(uri.String(), nodeURIPrefix)
		if !ok {
			continue
		}
		digits := strings.ReplaceAll(value, "-", "")
		if len(digits) != 32 {
			return zero, errAuth("invalid node identity")
		}
		raw, err := hex.DecodeString(digits)
		if err != nil {
			return zero, errAuth("invalid node identity")
		}
		var next NodeID
		copy(next[:], raw)
		if next == zero || found {
			return zero, errAuth("ambiguous node identity")
		}
		id, found = next, true
	}
	if !found {
		return zero, errAuth("missing node URI SAN")
	}
	return id, nil
}

// pemCerts reads a PEM certificate file into DER blocks, mirroring
// the Rust certificates() helper.
func pemCerts(path string) ([][]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out [][]byte
	rest := raw
	for len(rest) > 0 {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" || len(block.Bytes) == 0 {
			continue
		}
		out = append(out, block.Bytes)
	}
	if len(out) == 0 {
		return nil, errInvalid("empty PEM certificate file")
	}
	return out, nil
}

// pemKey reads the first PEM private key from path and wipes the file
// bytes, mirroring the Rust private_key() helper.
func pemKey(path string) (any, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	defer clearBytes(raw)
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, errInvalid("missing PEM private key")
	}
	switch block.Type {
	case "PRIVATE KEY":
		return x509.ParsePKCS8PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	default:
		// PKCS#8 and SEC1 DER without PEM armor.
		if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
			return key, nil
		}
		return nil, errInvalid("missing PEM private key")
	}
}

func clearBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// quicParams are the endpoint settings: credential paths, bind,
// allowlists, and the stream budget.
type quicParams struct {
	bind         string
	certFile     string
	keyFile      string
	caFile       string
	crlFile      string
	allowedPeers map[NodeID]bool
	allowedNets  []*net.IPNet
	sessions     int
}

// loadQuicParams reads the endpoint settings with defaults.
func loadQuicParams(db *sqlite.Conn) (quicParams, error) {
	var p quicParams
	get := func(name string) (string, error) { return Setting(db, name) }
	var err error
	if p.bind, err = get("bind"); err != nil {
		return p, err
	}
	if p.bind == "" {
		p.bind = quicDefaultBind
	}
	if p.certFile, err = get("certificate"); err != nil {
		return p, err
	}
	if p.keyFile, err = get("private_key"); err != nil {
		return p, err
	}
	if p.caFile, err = get("ca"); err != nil {
		return p, err
	}
	// crl_file is optional: empty disables revocation checking.
	if p.crlFile, err = get("crl_file"); err != nil {
		return p, err
	}
	raw, err := get("allowed_peers")
	if err != nil {
		return p, err
	}
	var peers []string
	if err := json.Unmarshal([]byte(raw), &peers); err != nil {
		return p, errInvalid(err.Error())
	}
	p.allowedPeers = map[NodeID]bool{}
	for _, s := range peers {
		id, err := ParseID(s)
		if err != nil {
			return p, err
		}
		p.allowedPeers[id] = true
	}
	raw, err = get("allowed_networks")
	if err != nil {
		return p, err
	}
	var nets []string
	if err := json.Unmarshal([]byte(raw), &nets); err != nil {
		return p, errInvalid(err.Error())
	}
	for _, s := range nets {
		_, ipnet, err := net.ParseCIDR(s)
		if err != nil {
			return p, errInvalid(fmt.Sprintf("invalid network %q", s))
		}
		p.allowedNets = append(p.allowedNets, ipnet)
	}
	raw, err = get("sessions")
	if err != nil {
		return p, err
	}
	n, err := atoi(raw)
	if err != nil || n < 1 || n > 256 {
		return p, errInvalid("invalid sessions")
	}
	p.sessions = int(n)
	return p, nil
}

// networkAllowed mirrors transport.rs network_allowed: empty means
// open; IPv4-mapped IPv6 collapses to v4 before matching.
func networkAllowed(nets []*net.IPNet, addr net.Addr) bool {
	if len(nets) == 0 {
		return true
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	if ip.To4() != nil {
		ip = ip.To4()
	}
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// QuicTransport is a mutual-TLS QUIC endpoint implementing Transport.
type QuicTransport struct {
	listener *quic.Listener
	tls      *tls.Config
	quic     *quic.Config
	allowed  map[NodeID]bool
	nets     []*net.IPNet
	node     NodeID
}

// verifyChain checks rawCerts against roots, ignoring name checks:
// node identity is the URI SAN, not a DNS name. revoked holds
// decimal serials from the configured CRLs; a peer presenting a
// revoked certificate fails closed.
func verifyChain(roots *x509.CertPool, rawCerts [][]byte, revoked map[string]bool) ([]*x509.Certificate, error) {
	if len(rawCerts) == 0 {
		return nil, errAuth("empty peer chain")
	}
	leaf, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return nil, errAuth(err.Error())
	}
	intermediates := x509.NewCertPool()
	for _, raw := range rawCerts[1:] {
		c, err := x509.ParseCertificate(raw)
		if err != nil {
			return nil, errAuth(err.Error())
		}
		intermediates.AddCert(c)
	}
	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   time.Now(),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}
	if _, err := leaf.Verify(opts); err != nil {
		return nil, errAuth(err.Error())
	}
	if revoked[leaf.SerialNumber.String()] {
		return nil, errAuth("peer certificate revoked")
	}
	return []*x509.Certificate{leaf}, nil
}

// loadCRLs parses the revocation lists at path (PEM "X509 CRL"
// blocks, or raw DER) into a decimal-serial set. Every list must be
// signed by one of issuers and must not be past NextUpdate;
// anything else fails closed.
func loadCRLs(path string, issuers []*x509.Certificate) (map[string]bool, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var ders [][]byte
	if rest := raw; len(bytes.TrimSpace(rest)) > 0 {
		for len(rest) > 0 {
			var block *pem.Block
			block, rest = pem.Decode(rest)
			if block == nil {
				break
			}
			if block.Type != "X509 CRL" || len(block.Bytes) == 0 {
				continue
			}
			ders = append(ders, block.Bytes)
		}
		if len(ders) == 0 {
			ders = append(ders, raw)
		}
	}
	if len(ders) == 0 {
		return nil, errInvalid("empty CRL file")
	}
	revoked := map[string]bool{}
	for _, der := range ders {
		list, err := x509.ParseRevocationList(der)
		if err != nil {
			return nil, errAuth(err.Error())
		}
		signed := false
		for _, issuer := range issuers {
			if list.CheckSignatureFrom(issuer) == nil {
				signed = true
				break
			}
		}
		if !signed {
			return nil, errAuth("CRL not signed by a trusted issuer")
		}
		if time.Now().After(list.NextUpdate) {
			return nil, errAuth("CRL past NextUpdate")
		}
		for _, entry := range list.RevokedCertificates {
			revoked[entry.SerialNumber.String()] = true
		}
	}
	return revoked, nil
}

// ListenQuic binds the QUIC endpoint for node, loading credentials
// and allowlists from db settings. The leaf certificate must carry
// node's identity.
func ListenQuic(db *sqlite.Conn, node NodeID) (*QuicTransport, error) {
	p, err := loadQuicParams(db)
	if err != nil {
		return nil, err
	}
	return listenQuicParams(p, node)
}

func listenQuicParams(p quicParams, node NodeID) (*QuicTransport, error) {
	chain, err := pemCerts(p.certFile)
	if err != nil {
		return nil, err
	}
	if id, err := nodeIDFromCert(chain[0]); err != nil || id != node {
		if err != nil {
			return nil, err
		}
		return nil, errAuth("certificate is not for this node")
	}
	key, err := pemKey(p.keyFile)
	if err != nil {
		return nil, err
	}
	caDER, err := pemCerts(p.caFile)
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	var issuers []*x509.Certificate
	for _, raw := range caDER {
		c, err := x509.ParseCertificate(raw)
		if err != nil {
			return nil, errAuth(err.Error())
		}
		roots.AddCert(c)
		issuers = append(issuers, c)
	}
	var revoked map[string]bool
	if p.crlFile != "" {
		revoked, err = loadCRLs(p.crlFile, issuers)
		if err != nil {
			return nil, err
		}
	}
	cert := tls.Certificate{Certificate: chain, PrivateKey: key, Leaf: mustParseLeaf(chain[0])}

	// Client side: NodeVerifier — chain trust plus identity plus
	// the allowed_peers gate. Normal verification is off because
	// node identity is a URI SAN, not a DNS name; the callback
	// below performs the full chain check instead.
	clientTLS := &tls.Config{
		Certificates:       []tls.Certificate{cert},
		MinVersion:         tls.VersionTLS13,
		NextProtos:         []string{quicALPN},
		InsecureSkipVerify: true,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if _, err := verifyChain(roots, rawCerts, revoked); err != nil {
				return err
			}
			id, err := nodeIDFromCert(rawCerts[0])
			if err != nil {
				return err
			}
			if len(p.allowedPeers) > 0 && !p.allowedPeers[id] {
				return errAuth("peer identity denied")
			}
			return nil
		},
	}
	// Server side: chain trust at the handshake; identity and the
	// network/node gates run at accept (peer_id).
	serverTLS := &tls.Config{
		Certificates:       []tls.Certificate{cert},
		ClientAuth:         tls.RequireAndVerifyClientCert,
		MinVersion:         tls.VersionTLS13,
		NextProtos:         []string{quicALPN},
		InsecureSkipVerify: true,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			_, err := verifyChain(roots, rawCerts, revoked)
			return err
		},
	}
	// Go's default client-cert verification is replaced by the
	// callback above; point ClientCAs at the same pool for
	// completeness (acceptable-CA list on the wire).
	serverTLS.ClientCAs = roots

	qconf := &quic.Config{
		MaxIdleTimeout:        quicIdleTimeout,
		KeepAlivePeriod:       quicKeepAlive,
		MaxIncomingStreams:    int64(p.sessions + quicStreamPad),
		MaxIncomingUniStreams: -1,
		EnableDatagrams:       true,
	}
	listener, err := quic.ListenAddr(p.bind, serverTLS, qconf)
	if err != nil {
		return nil, err
	}
	return &QuicTransport{listener: listener, tls: clientTLS, quic: qconf, allowed: p.allowedPeers, nets: p.allowedNets, node: node}, nil
}

func mustParseLeaf(der []byte) *x509.Certificate {
	c, _ := x509.ParseCertificate(der)
	return c
}

// LocalAddr reports the bound address.
func (t *QuicTransport) LocalAddr() string {
	if t.listener == nil {
		return ""
	}
	return t.listener.Addr().String()
}

// Dial opens an authenticated session to addr.
func (t *QuicTransport) Dial(addr string) (Session, error) {
	ctx, cancel := context.WithTimeout(context.Background(), quicDialTimeout)
	defer cancel()
	// quic-go fills ServerName on the passed config; clone so
	// concurrent dials never race on the shared template.
	conn, err := quic.DialAddr(ctx, addr, t.tls.Clone(), t.quic)
	if err != nil {
		return nil, errAuth(err.Error())
	}
	id, err := peerID(conn.ConnectionState().TLS.PeerCertificates, conn.RemoteAddr(), t.allowed, t.nets)
	if err != nil {
		_ = conn.CloseWithError(0, err.Error())
		return nil, err
	}
	return &quicSession{conn: conn, id: id}, nil
}

// Accept takes the next inbound authenticated session, applying the
// network and node gates. Refused peers are closed; Accept keeps
// waiting.
func (t *QuicTransport) Accept() (Session, error) {
	for {
		conn, err := t.listener.Accept(context.Background())
		if err != nil {
			return nil, errAuth(err.Error())
		}
		id, err := peerID(conn.ConnectionState().TLS.PeerCertificates, conn.RemoteAddr(), t.allowed, t.nets)
		if err != nil {
			_ = conn.CloseWithError(0, err.Error())
			continue
		}
		return &quicSession{conn: conn, id: id}, nil
	}
}

// Close stops listening and all sessions.
func (t *QuicTransport) Close() error {
	if t.listener == nil {
		return nil
	}
	return t.listener.Close()
}

// peerID mirrors transport.rs peer_id: network gate, peer chain,
// identity SAN, node allowlist.
func peerID(chain []*x509.Certificate, remote net.Addr, allowed map[NodeID]bool, nets []*net.IPNet) (NodeID, error) {
	var zero NodeID
	if !networkAllowed(nets, remote) {
		return zero, errAuth("remote network denied")
	}
	if len(chain) == 0 {
		return zero, errAuth("missing peer certificate")
	}
	id, err := nodeIDFromCert(chain[0].Raw)
	if err != nil {
		return zero, err
	}
	if len(allowed) > 0 && !allowed[id] {
		return zero, errAuth("remote node denied")
	}
	return id, nil
}

// quicSession is one authenticated QUIC connection.
type quicSession struct {
	conn *quic.Conn
	id   NodeID
}

// PeerID is the verified remote node id.
func (s *quicSession) PeerID() NodeID { return s.id }

// OpenStream opens a bidirectional frame stream.
func (s *quicSession) OpenStream() (Stream, error) {
	st, err := s.conn.OpenStream()
	if err != nil {
		return nil, errAuth(err.Error())
	}
	return &quicStream{st: st}, nil
}

// AcceptStream takes the next inbound stream.
func (s *quicSession) AcceptStream() (Stream, error) {
	st, err := s.conn.AcceptStream(context.Background())
	if err != nil {
		return nil, errAuth(err.Error())
	}
	return &quicStream{st: st}, nil
}

// SendDatagram queues an unreliable membership datagram.
func (s *quicSession) SendDatagram(b []byte) error {
	if err := s.conn.SendDatagram(b); err != nil {
		return errAuth(err.Error())
	}
	return nil
}

// RecvDatagram takes the next datagram.
func (s *quicSession) RecvDatagram() ([]byte, error) {
	b, err := s.conn.ReceiveDatagram(context.Background())
	if err != nil {
		return nil, errAuth(err.Error())
	}
	return b, nil
}

// Close ends the session.
func (s *quicSession) Close() error { return s.conn.CloseWithError(0, "") }

// quicStream adapts quic.Stream to the engine Stream interface.
type quicStream struct {
	st *quic.Stream
}

// Write sends the full buffer.
func (s *quicStream) Write(b []byte) error {
	for len(b) > 0 {
		n, err := s.st.Write(b)
		if err != nil {
			return err
		}
		b = b[n:]
	}
	return nil
}

// Read fills b from the stream.
func (s *quicStream) Read(b []byte) (int, error) { return s.st.Read(b) }

// Close ends the stream.
func (s *quicStream) Close() error { return s.st.Close() }
