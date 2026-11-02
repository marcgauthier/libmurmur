package picoquic

/*
#cgo CFLAGS: -DPTLS_WITHOUT_OPENSSL -DPTLS_WITHOUT_FUSION -DPICOQUIC_WITH_MBEDTLS -I../../../../deps/murmur -I../../../../deps/picoquic/picoquic -I../../../../deps/picoquic/picoquic_mbedtls -I../../../../deps/picotls/include -I../../../../deps/mbedtls/include -O2
#cgo CXXFLAGS: -std=c++17 -DPTLS_WITHOUT_OPENSSL -DPTLS_WITHOUT_FUSION -DPICOQUIC_WITH_MBEDTLS -I../../../../deps/murmur -I../../../../deps/picoquic/picoquic -I../../../../deps/picoquic/picoquic_mbedtls -I../../../../deps/picotls/include -I../../../../deps/mbedtls/include -O2
#cgo LDFLAGS: ${SRCDIR}/../../../../libmurmur.a -lpthread -lstdc++
#include <stdlib.h>
#include "transport.h"
*/
import "C"

import (
	"fmt"
	"io"
	"net"
	"unsafe"
)

// Status codes mirror murmur_status_t (returned negated from C).
const (
	StatusInvalid    = 1
	StatusBusy       = 2
	StatusClosed     = 3
	StatusProtocol   = 4
	StatusOverloaded = 5
	StatusAuth       = 6
	StatusTimeout    = 7
	StatusCancelled  = 8
)

// QuicError is a failed transport call. Code matches Status*; Detail
// carries the endpoint's last-error text when available.
type QuicError struct {
	Code   int
	Detail string
}

func (e *QuicError) Error() string {
	if e.Detail == "" {
		return fmt.Sprintf("quic: status %d", e.Code)
	}
	return fmt.Sprintf("quic: status %d: %s", e.Code, e.Detail)
}

// Endpoint is one native QUIC endpoint (UDP socket + pump thread).
type Endpoint struct {
	q *C.murmur_quic_t
}

// Session is one authenticated connection. Release when done.
type Session struct {
	s *C.murmur_session_t
}

// Stream is one reliable bidi stream. Release when done.
type Stream struct {
	t *C.murmur_stream_t
}

func check(rc C.int, q *C.murmur_quic_t) error {
	if rc == 0 {
		return nil
	}
	code := int(-rc)
	detail := ""
	if q != nil {
		var buf [256]byte
		C.murmur_last_error(q, (*C.char)(unsafe.Pointer(&buf[0])), C.size_t(len(buf)))
		detail = C.GoString((*C.char)(unsafe.Pointer(&buf[0])))
	}
	return &QuicError{Code: code, Detail: detail}
}

// derVecs copies DER blocks into C arrays of (pointer, length).
// The C side copies everything it retains; free after the call.
func derVecs(blocks [][]byte) (ptrs **C.uint8_t, lens *C.size_t) {
	if len(blocks) == 0 {
		return nil, nil
	}
	ptrs = (**C.uint8_t)(C.calloc(C.size_t(len(blocks)), C.size_t(unsafe.Sizeof(uintptr(0)))))
	lens = (*C.size_t)(C.calloc(C.size_t(len(blocks)), C.size_t(unsafe.Sizeof(C.size_t(0)))))
	pSlice := (*[1 << 30]*C.uint8_t)(unsafe.Pointer(ptrs))[:len(blocks):len(blocks)]
	lSlice := (*[1 << 30]C.size_t)(unsafe.Pointer(lens))[:len(blocks):len(blocks)]
	for i, b := range blocks {
		pSlice[i] = (*C.uint8_t)(C.CBytes(b))
		lSlice[i] = C.size_t(len(b))
	}
	return ptrs, lens
}

func freeDerVecs(ptrs **C.uint8_t, lens *C.size_t, n int) {
	if ptrs == nil {
		return
	}
	pSlice := (*[1 << 30]*C.uint8_t)(unsafe.Pointer(ptrs))[:n:n]
	for _, p := range pSlice {
		C.free(unsafe.Pointer(p))
	}
	C.free(unsafe.Pointer(ptrs))
	C.free(unsafe.Pointer(lens))
}

// Create binds a native endpoint. chainDER is the leaf-first chain,
// keyPEM the private key PEM (PKCS8 for EC), caDER the trust anchors,
// crlDER the optional revocation list (DER or PEM bytes; nil/empty
// disables revocation), self the local node id. allowed empty = all
// peers; cidrs empty = all networks. sessions<=0 defaults to 32.
func Create(bind string, chainDER [][]byte, keyPEM []byte, caDER [][]byte,
	crlDER []byte, self [16]byte, allowed [][16]byte, cidrs []string, sessions int) (*Endpoint, error) {
	host, portStr, err := net.SplitHostPort(bind)
	if err != nil {
		return nil, err
	}
	var port int
	if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil || port < 0 || port > 65535 {
		return nil, fmt.Errorf("bad port %q", portStr)
	}
	cHost := C.CString(host)
	defer C.free(unsafe.Pointer(cHost))

	cChain, cChainLens := derVecs(chainDER)
	defer freeDerVecs(cChain, cChainLens, len(chainDER))
	cCA, cCALens := derVecs(caDER)
	defer freeDerVecs(cCA, cCALens, len(caDER))
	cKey := C.CBytes(keyPEM)
	defer C.free(cKey)

	var cAllowed *C.murmur_node_t
	if len(allowed) > 0 {
		cAllowed = (*C.murmur_node_t)(C.calloc(C.size_t(len(allowed)), C.size_t(unsafe.Sizeof(C.murmur_node_t{}))))
		defer C.free(unsafe.Pointer(cAllowed))
		aSlice := (*[1 << 20]C.murmur_node_t)(unsafe.Pointer(cAllowed))[:len(allowed):len(allowed)]
		for i, id := range allowed {
			*(*[16]byte)(unsafe.Pointer(&aSlice[i].b)) = id
		}
	}
	var cCIDRs **C.char
	if len(cidrs) > 0 {
		cCIDRs = (**C.char)(C.calloc(C.size_t(len(cidrs)), C.size_t(unsafe.Sizeof(uintptr(0)))))
		defer C.free(unsafe.Pointer(cCIDRs))
		cSlice := (*[1 << 20]*C.char)(unsafe.Pointer(cCIDRs))[:len(cidrs):len(cidrs)]
		for i, c := range cidrs {
			cSlice[i] = C.CString(c)
			defer C.free(unsafe.Pointer(cSlice[i]))
		}
	}

	var cSelf C.murmur_node_t
	*(*[16]byte)(unsafe.Pointer(&cSelf.b)) = self

	var cCRL *C.uint8_t
	if len(crlDER) > 0 {
		cCRL = (*C.uint8_t)(C.CBytes(crlDER))
		defer C.free(unsafe.Pointer(cCRL))
	}
	var q *C.murmur_quic_t
	rc := C.murmur_quic_create(&q, cHost, C.uint16_t(port),
		cChain, cChainLens, C.size_t(len(chainDER)),
		(*C.uint8_t)(cKey), C.size_t(len(keyPEM)),
		cCA, cCALens, C.size_t(len(caDER)),
		cCRL, C.size_t(len(crlDER)),
		&cSelf, cAllowed, C.size_t(len(allowed)),
		cCIDRs, C.size_t(len(cidrs)), 0, C.uint32_t(sessions))
	if err := check(rc, q); err != nil {
		return nil, err
	}
	return &Endpoint{q: q}, nil
}

// LocalAddr reports the bound "ip:port".
func (e *Endpoint) LocalAddr() (string, error) {
	var buf [128]byte
	if err := check(C.murmur_quic_local_addr(e.q, (*C.char)(unsafe.Pointer(&buf[0])), C.size_t(len(buf))), e.q); err != nil {
		return "", err
	}
	return C.GoString((*C.char)(unsafe.Pointer(&buf[0]))), nil
}

// Accept waits for the next inbound session. timeoutMs < 0 blocks forever.
func (e *Endpoint) Accept(timeoutMs int) (*Session, error) {
	var s *C.murmur_session_t
	if err := check(C.murmur_quic_accept(e.q, &s, C.int(timeoutMs)), e.q); err != nil {
		return nil, err
	}
	return &Session{s: s}, nil
}

// Dial opens a session to ip:port. timeoutMs < 0 blocks forever.
func (e *Endpoint) Dial(ip string, port uint16, sni string, timeoutMs int) (*Session, error) {
	cIP := C.CString(ip)
	defer C.free(unsafe.Pointer(cIP))
	cSNI := C.CString(sni)
	defer C.free(unsafe.Pointer(cSNI))
	var s *C.murmur_session_t
	if err := check(C.murmur_quic_dial(e.q, cIP, C.uint16_t(port), cSNI, &s, C.int(timeoutMs)), e.q); err != nil {
		return nil, err
	}
	return &Session{s: s}, nil
}

// Close stops listening and all sessions.
func (e *Endpoint) Close() error {
	return check(C.murmur_quic_close(e.q), e.q)
}

// Free closes and releases the endpoint. No calls may be in flight.
func (e *Endpoint) Free() {
	C.murmur_quic_free(e.q)
	e.q = nil
}

// Peer returns the verified remote node id.
func (s *Session) Peer() ([16]byte, error) {
	var out [16]byte
	var cOut C.murmur_node_t
	if err := check(C.murmur_session_peer(s.s, &cOut), nil); err != nil {
		return out, err
	}
	out = *(*[16]byte)(unsafe.Pointer(&cOut.b))
	return out, nil
}

// OpenStream opens a bidi stream.
func (s *Session) OpenStream() (*Stream, error) {
	var t *C.murmur_stream_t
	if err := check(C.murmur_session_open_stream(s.s, &t), nil); err != nil {
		return nil, err
	}
	return &Stream{t: t}, nil
}

// AcceptStream takes the next inbound stream. timeoutMs < 0 blocks forever.
func (s *Session) AcceptStream(timeoutMs int) (*Stream, error) {
	var t *C.murmur_stream_t
	if err := check(C.murmur_session_accept_stream(s.s, &t, C.int(timeoutMs)), nil); err != nil {
		return nil, err
	}
	return &Stream{t: t}, nil
}

// SendDatagram queues one unreliable datagram (best effort, <=1000 B).
func (s *Session) SendDatagram(b []byte) error {
	var ptr *C.uint8_t
	if len(b) > 0 {
		ptr = (*C.uint8_t)(C.CBytes(b))
		defer C.free(unsafe.Pointer(ptr))
	}
	return check(C.murmur_session_send_datagram(s.s, ptr, C.size_t(len(b))), nil)
}

// RecvDatagram takes the next datagram. timeoutMs < 0 blocks forever.
func (s *Session) RecvDatagram(timeoutMs int) ([]byte, error) {
	const cap = 1200
	buf := C.malloc(C.size_t(cap))
	defer C.free(buf)
	var n C.size_t
	if err := check(C.murmur_session_recv_datagram(s.s, (*C.uint8_t)(buf), C.size_t(cap), &n, C.int(timeoutMs)), nil); err != nil {
		return nil, err
	}
	return C.GoBytes(buf, C.int(n)), nil
}

// Close ends the session.
func (s *Session) Close() error {
	return check(C.murmur_session_close(s.s), nil)
}

// Release drops the handle. The session ends at Close or peer close.
func (s *Session) Release() {
	C.murmur_session_release(s.s)
	s.s = nil
}

// Write sends bytes (full buffer).
func (t *Stream) Write(b []byte) error {
	var ptr *C.uint8_t
	if len(b) > 0 {
		ptr = (*C.uint8_t)(C.CBytes(b))
		defer C.free(unsafe.Pointer(ptr))
	}
	return check(C.murmur_stream_write(t.t, ptr, C.size_t(len(b))), nil)
}

// Read fills b with the next bytes; io.EOF marks a clean FIN.
func (t *Stream) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	buf := C.malloc(C.size_t(len(b)))
	defer C.free(buf)
	var n C.size_t
	if err := check(C.murmur_stream_read(t.t, (*C.uint8_t)(buf), C.size_t(len(b)), &n), nil); err != nil {
		return 0, err
	}
	if n == 0 {
		return 0, io.EOF
	}
	copy(b, C.GoBytes(buf, C.int(n)))
	return int(n), nil
}

// Close sends FIN.
func (t *Stream) Close() error {
	return check(C.murmur_stream_close(t.t), nil)
}

// Release drops the handle.
func (t *Stream) Release() {
	C.murmur_stream_release(t.t)
	t.t = nil
}
