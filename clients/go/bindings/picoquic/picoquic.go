// Package picoquic is the native QUIC+TLS transport for Murmur replication.
//
// The stack is vendored in deps and compiled from per-file shims (see
// tools/gen_pq_shims.sh): picoquic (QUIC, BSD) + picotls (TLS 1.3, MIT) +
// mbedTLS (X.509/crypto backend, Apache). No OpenSSL, no BoringSSL, no
// async runtime: the transport runs its own threads and talks to Go only
// through a narrow session/stream/datagram API (later: driven entirely
// from C++, with Go as an ordinary client).
//
// Mutual TLS with ALPN "murmur-crsqlite/1" and URI SAN identity keeps
// wire compatibility with the Rust nodes.
package picoquic

/*
#cgo CFLAGS: -DPTLS_WITHOUT_OPENSSL -DPTLS_WITHOUT_FUSION -DPICOQUIC_WITH_MBEDTLS -I../../../../deps/picoquic/picoquic -I../../../../deps/picoquic/picoquic_mbedtls -I../../../../deps/picotls/include -I../../../../deps/mbedtls/include -O2
#cgo CXXFLAGS: -std=c++17 -DPTLS_WITHOUT_OPENSSL -DPTLS_WITHOUT_FUSION -DPICOQUIC_WITH_MBEDTLS -I../../../../deps/picoquic/picoquic -I../../../../deps/picoquic/picoquic_mbedtls -I../../../../deps/picotls/include -I../../../../deps/mbedtls/include -O2
#cgo LDFLAGS: -lpthread -lstdc++
#include <stdlib.h>
#include "mbedtls/version.h"
#include "transport.h"
*/
import "C"

import "unsafe"

// MbedTLSVersion reports the linked mbedTLS version string (link proof).
func MbedTLSVersion() string {
	var buf [32]byte
	C.mbedtls_version_get_string((*C.char)(unsafe.Pointer(&buf[0])))
	return C.GoString((*C.char)(unsafe.Pointer(&buf[0])))
}
