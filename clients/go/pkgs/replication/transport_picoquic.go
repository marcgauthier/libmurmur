package replication

import (
	"crypto/x509"
	"encoding/pem"
	"net"
	"os"
	"runtime"
	"time"

	"github.com/marcgauthier/libmurmur/clients/go/bindings/picoquic"
	"github.com/marcgauthier/libmurmur/clients/go/bindings/sqlite"
)

// PicoquicTransport is the native (picoquic + mbedTLS) QUIC endpoint
// implementing Transport. Wire behavior mirrors QuicTransport: mutual
// TLS 1.3, ALPN murmur-crsqlite/1, URI SAN identity, same gates.
type PicoquicTransport struct {
	ep *picoquic.Endpoint
}

// ListenPicoquic binds the native endpoint for node, loading
// credentials and allowlists from db settings (same keys as ListenQuic).
func ListenPicoquic(db *sqlite.Conn, node NodeID) (*PicoquicTransport, error) {
	p, err := loadQuicParams(db)
	if err != nil {
		return nil, err
	}
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
	keyPEM, err := picoquicKeyPEM(p.keyFile)
	if err != nil {
		return nil, err
	}
	caDER, err := pemCerts(p.caFile)
	if err != nil {
		return nil, err
	}
	var allowed [][16]byte
	for id := range p.allowedPeers {
		allowed = append(allowed, [16]byte(id))
	}
	var cidrs []string
	for _, n := range p.allowedNets {
		cidrs = append(cidrs, n.String())
	}
	var crlDER []byte
	if p.crlFile != "" {
		crlDER, err = os.ReadFile(p.crlFile)
		if err != nil {
			return nil, err
		}
	}
	ep, err := picoquic.Create(p.bind, chain, keyPEM, caDER, crlDER,
		[16]byte(node), allowed, cidrs, p.sessions)
	if err != nil {
		return nil, mapQuicError(err)
	}
	return &PicoquicTransport{ep: ep}, nil
}

// picoquicKeyPEM reads the private key and returns PKCS8 PEM bytes.
// The native loader needs PKCS8 for EC keys (never SEC1); RSA passes
// through in either armor.
func picoquicKeyPEM(path string) ([]byte, error) {
	key, err := pemKey(path)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, errInvalid(err.Error())
	}
	out := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	clearBytes(der)
	return out, nil
}

// mapQuicError projects a native status onto engine error kinds.
func mapQuicError(err error) error {
	qe, ok := err.(*picoquic.QuicError)
	if !ok {
		return err
	}
	msg := qe.Detail
	if msg == "" {
		msg = qe.Error()
	}
	switch qe.Code {
	case picoquic.StatusInvalid:
		return errInvalid(msg)
	case picoquic.StatusBusy:
		return errBusy(msg)
	case picoquic.StatusClosed:
		return errClosed(msg)
	case picoquic.StatusProtocol:
		return errProtocol(msg)
	case picoquic.StatusOverloaded:
		return errOverloaded(msg)
	case picoquic.StatusTimeout:
		return errAuth(msg) // dial timeout: Go wraps all dial errors Auth
	default:
		return errAuth(msg)
	}
}

// LocalAddr reports the bound address.
func (t *PicoquicTransport) LocalAddr() string {
	addr, err := t.ep.LocalAddr()
	if err != nil {
		return ""
	}
	return addr
}

// Dial opens an authenticated session to addr (10s timeout, like Go).
func (t *PicoquicTransport) Dial(addr string) (Session, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, errInvalid(err.Error())
	}
	n, err := atoi(portStr)
	if err != nil || n < 0 || n > 65535 {
		return nil, errInvalid("bad port")
	}
	s, err := t.ep.Dial(host, uint16(n), host, int(quicDialTimeout/time.Millisecond))
	if err != nil {
		return nil, mapQuicError(err)
	}
	id, err := s.Peer()
	if err != nil {
		_ = s.Close()
		s.Release()
		return nil, mapQuicError(err)
	}
	out := &picoquicSession{ep: t.ep, s: s, id: NodeID(id)}
	// The C handle outlives Close (post-close reads allowed, like
	// quic-go); the finalizer frees it once unreachable.
	runtime.SetFinalizer(out, func(o *picoquicSession) { o.s.Release() })
	return out, nil
}

// Accept returns the next inbound session, blocking. Refused peers
// are closed inside the native accept path; Accept keeps waiting.
func (t *PicoquicTransport) Accept() (Session, error) {
	for {
		s, err := t.ep.Accept(-1)
		if err != nil {
			return nil, mapQuicError(err)
		}
		id, err := s.Peer()
		if err != nil {
			_ = s.Close()
			s.Release()
			continue
		}
		out := &picoquicSession{ep: t.ep, s: s, id: NodeID(id)}
		runtime.SetFinalizer(out, func(o *picoquicSession) { o.s.Release() })
		return out, nil
	}
}

// Close stops listening and all sessions.
func (t *PicoquicTransport) Close() error {
	if t.ep == nil {
		return nil
	}
	err := t.ep.Close()
	t.ep.Free()
	t.ep = nil
	return mapQuicError(err)
}

// picoquicSession is one native authenticated connection.
type picoquicSession struct {
	ep *picoquic.Endpoint
	s  *picoquic.Session
	id NodeID
}

// PeerID is the verified remote node id.
func (s *picoquicSession) PeerID() NodeID { return s.id }

// OpenStream opens a bidirectional frame stream.
func (s *picoquicSession) OpenStream() (Stream, error) {
	st, err := s.s.OpenStream()
	if err != nil {
		return nil, mapQuicError(err)
	}
	out := &picoquicStream{st: st}
	runtime.SetFinalizer(out, func(o *picoquicStream) { o.st.Release() })
	return out, nil
}

// AcceptStream takes the next inbound stream.
func (s *picoquicSession) AcceptStream() (Stream, error) {
	st, err := s.s.AcceptStream(-1)
	if err != nil {
		return nil, mapQuicError(err)
	}
	out := &picoquicStream{st: st}
	runtime.SetFinalizer(out, func(o *picoquicStream) { o.st.Release() })
	return out, nil
}

// SendDatagram queues an unreliable membership datagram.
func (s *picoquicSession) SendDatagram(b []byte) error {
	if err := s.s.SendDatagram(b); err != nil {
		return mapQuicError(err)
	}
	return nil
}

// RecvDatagram takes the next datagram.
func (s *picoquicSession) RecvDatagram() ([]byte, error) {
	b, err := s.s.RecvDatagram(-1)
	if err != nil {
		return nil, mapQuicError(err)
	}
	return b, nil
}

// Close ends the session. The handle stays valid for post-close
// reads; the finalizer releases it.
func (s *picoquicSession) Close() error {
	return s.s.Close()
}

// picoquicStream adapts a native stream to the engine interface.
type picoquicStream struct {
	st *picoquic.Stream
}

// Write sends the full buffer.
func (s *picoquicStream) Write(b []byte) error { return s.st.Write(b) }

// Read fills b from the stream.
func (s *picoquicStream) Read(b []byte) (int, error) { return s.st.Read(b) }

// Close ends the stream. The handle stays valid for post-close
// reads (EOF drains after FIN); the finalizer releases it.
func (s *picoquicStream) Close() error {
	return s.st.Close()
}
