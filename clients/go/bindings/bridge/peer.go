package bridge

/*
#include "bridge_peer.h"
#include "sqlite3.h"
*/
import "C"

import (
	"github.com/marcgauthier/libmurmur/clients/go/bindings/sqlite"
	"unsafe"
)

// ConfigurePeer opts an attached High connection into signed ownership
// replication. Bridged user tables must use semantic projection, with direct
// user-table CRR disabled. The journal itself uses native CRR transport.
// Private signing keys stay in native connection memory. Reopen with the same
// pinned identity and key; use ordinary captured SQL for local High edits.
func ConfigurePeer(db *sqlite.Conn, database, node [16]byte, seed [32]byte) error {
	if db == nil {
		return &Error{Code: 21}
	}
	return result(C.murmur_bridge_peer_configure((*C.sqlite3)(db.NativeDB()), (*C.uint8_t)(unsafe.Pointer(&database[0])), (*C.uint8_t)(unsafe.Pointer(&node[0])), (*C.uint8_t)(unsafe.Pointer(&seed[0]))))
}

// TrustPeer pins a High node's signing key. Revocation preserves its binding;
// changing the key under an existing origin is rejected.
func TrustPeer(db *sqlite.Conn, node [16]byte, key [32]byte, enabled bool) error {
	if db == nil {
		return &Error{Code: 21}
	}
	var active C.int
	if enabled {
		active = 1
	}
	return result(C.murmur_bridge_peer_trust((*C.sqlite3)(db.NativeDB()), (*C.uint8_t)(unsafe.Pointer(&node[0])), (*C.uint8_t)(unsafe.Pointer(&key[0])), active))
}

// ApplyPeer applies bounded ready ownership records in the caller's native
// transaction. Native replication invokes it after CRR ingestion. Missing
// origin dependencies and schema mismatches remain pending.
func ApplyPeer(db *sqlite.Conn) error {
	if db == nil {
		return &Error{Code: 21}
	}
	return result(C.murmur_bridge_peer_apply((*C.sqlite3)(db.NativeDB())))
}

// ConfigurePeerSource loads the Low source verifier without opening or scanning
// a ferry directory. Reapply after reopening the signed High peer identity.
func ConfigurePeerSource(db *sqlite.Conn, cfg ReceiverConfig) error {
	if db == nil {
		return &Error{Code: 21}
	}
	return withReceiverConfig(cfg, func(c *C.murmur_bridge_receiver_config_t) error {
		return result(C.murmur_bridge_peer_source((*C.sqlite3)(db.NativeDB()), c))
	})
}

// PeerFiles authorizes file parts arriving through the signed High journal.
// The store must use db and remain live while the native driver applies files.
func PeerFiles(db *sqlite.Conn, store unsafe.Pointer) error {
	if db == nil || store == nil {
		return &Error{Code: 21}
	}
	return result(C.murmur_bridge_peer_files((*C.sqlite3)(db.NativeDB()), (*C.murmur_files_t)(store)))
}

// ConfigureLowPeer enables original signed row transactions on a Low node.
// Only exporter allocates ferry sequence numbers; other nodes replicate their
// original records through the native peer journal. Configure all Low peers
// together and disable raw transport for their registered user tables. A zero
// exporter enables signed peer replication without publishing ferry artifacts.
func ConfigureLowPeer(db *sqlite.Conn, database, node [16]byte, seed [32]byte, exporter [16]byte) error {
	if db == nil {
		return &Error{Code: 21}
	}
	return result(C.murmur_bridge_peer_low_configure((*C.sqlite3)(db.NativeDB()), (*C.uint8_t)(unsafe.Pointer(&database[0])), (*C.uint8_t)(unsafe.Pointer(&node[0])), (*C.uint8_t)(unsafe.Pointer(&seed[0])), (*C.uint8_t)(unsafe.Pointer(&exporter[0]))))
}

// TrustSourceOrigin pins an original Low writer key independently from the
// source exporter's sealing key. Rebinding an existing origin is rejected.
func TrustSourceOrigin(db *sqlite.Conn, source, origin [16]byte, key [32]byte, enabled bool) error {
	if db == nil {
		return &Error{Code: 21}
	}
	var active C.int
	if enabled {
		active = 1
	}
	return result(C.murmur_bridge_source_origin((*C.sqlite3)(db.NativeDB()), (*C.uint8_t)(unsafe.Pointer(&source[0])), (*C.uint8_t)(unsafe.Pointer(&origin[0])), (*C.uint8_t)(unsafe.Pointer(&key[0])), active))
}

// ReplacePeerTrust atomically reconciles configured peers. Removed peers are
// revoked, historical bindings remain immutable, and local trust is retained.
func ReplacePeerTrust(db *sqlite.Conn, keys map[[16]byte][32]byte) error {
	if db == nil {
		return &Error{Code: 21}
	}
	return withTrustedKeys(keys, func(keys *C.murmur_bridge_trusted_key_t, count C.size_t) error {
		return result(C.murmur_bridge_peer_replace_trust((*C.sqlite3)(db.NativeDB()), keys, count))
	})
}

// ReplaceSourceTrust reconciles original Low writers for one source domain.
// Revoked bindings remain stored, so removing all keys cannot enable fallback
// to an unsigned typed-row profile.
func ReplaceSourceTrust(db *sqlite.Conn, source [16]byte, keys map[[16]byte][32]byte) error {
	if db == nil {
		return &Error{Code: 21}
	}
	return withTrustedKeys(keys, func(keys *C.murmur_bridge_trusted_key_t, count C.size_t) error {
		return result(C.murmur_bridge_source_replace_trust((*C.sqlite3)(db.NativeDB()), (*C.uint8_t)(unsafe.Pointer(&source[0])), keys, count))
	})
}

func withTrustedKeys(keys map[[16]byte][32]byte, fn func(*C.murmur_bridge_trusted_key_t, C.size_t) error) error {
	if len(keys) > 1024 {
		return &Error{Code: 21}
	}
	if len(keys) == 0 {
		return fn(nil, 0)
	}
	native := make([]C.murmur_bridge_trusted_key_t, len(keys))
	i := 0
	for id, key := range keys {
		copy(unsafe.Slice((*byte)(unsafe.Pointer(&native[i].origin[0])), 16), id[:])
		copy(unsafe.Slice((*byte)(unsafe.Pointer(&native[i].public_key[0])), 32), key[:])
		i++
	}
	return fn(&native[0], C.size_t(len(native)))
}
