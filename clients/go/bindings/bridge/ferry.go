package bridge

/*
#include <stdlib.h>
#include "bridge_ferry.h"
#include "sqlite3.h"
*/
import "C"

import (
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/marcgauthier/libmurmur/clients/go/bindings/sqlite"
)

// ReceiverConfig pins the source stream, exporter node and authorized signing
// keys. Up to eight keys allow overlap during rotation. Directory must exist.
type ReceiverConfig struct {
	QuarantineDirectory string
	Source, Exporter    [16]byte
	Secret              [32]byte
	Signers             [][32]byte
	Stream, Directory   string
	StagingBytes        uint64
}

type FerryStatus struct {
	Scanned, Applied, Duplicate, Deferred, Rejected, FilesCompleted uint64
	LastResult                                                      int
}

// Receiver owns a native directory cursor and optional native polling thread.
// Close it BEFORE closing db or changing capture/table registrations. Lifecycle
// calls belong in murmurdb.WithNativeControl, never under WithConnection's
// writer guard. The native worker serializes its own SQL access.
type Receiver struct {
	mu  sync.Mutex
	ptr *C.murmur_bridge_receiver_t
}

func NewReceiver(db *sqlite.Conn, cfg ReceiverConfig) (*Receiver, error) {
	if db == nil || cfg.Directory == "" {
		return nil, &Error{Code: int(C.SQLITE_MISUSE)}
	}
	r := &Receiver{}
	err := withReceiverConfig(cfg, func(c *C.murmur_bridge_receiver_config_t) error {
		return result(C.murmur_bridge_receiver_new((*C.sqlite3)(db.NativeDB()), c, &r.ptr))
	})
	if err != nil {
		return nil, err
	}
	return r, nil
}

func withReceiverConfig(cfg ReceiverConfig, fn func(*C.murmur_bridge_receiver_config_t) error) error {
	if len(cfg.Signers) == 0 || len(cfg.Signers) > 8 || strings.IndexByte(cfg.Directory, 0) >= 0 || strings.IndexByte(cfg.QuarantineDirectory, 0) >= 0 {
		return &Error{Code: int(C.SQLITE_MISUSE)}
	}
	if _, err := native(Header{Stream: cfg.Stream}); err != nil {
		return err
	}
	c := (*C.murmur_bridge_receiver_config_t)(C.calloc(1, C.sizeof_murmur_bridge_receiver_config_t))
	if c == nil {
		return &Error{Code: int(C.SQLITE_NOMEM)}
	}
	defer func() {
		// Clear the C-owned receiver secret before freeing the temporary config.
		clear(unsafe.Slice((*byte)(unsafe.Pointer(&c.receiver[0])), 32))
		C.free(unsafe.Pointer(c))
	}()
	copy(unsafe.Slice((*byte)(unsafe.Pointer(&c.source[0])), 16), cfg.Source[:])
	copy(unsafe.Slice((*byte)(unsafe.Pointer(&c.exporter[0])), 16), cfg.Exporter[:])
	copy(unsafe.Slice((*byte)(unsafe.Pointer(&c.receiver[0])), 32), cfg.Secret[:])
	for i := range cfg.Signers {
		copy(unsafe.Slice((*byte)(unsafe.Pointer(&c.signers[i][0])), 32), cfg.Signers[i][:])
	}
	c.signer_count = C.size_t(len(cfg.Signers))
	c.stream = C.CString(cfg.Stream)
	defer C.free(unsafe.Pointer(c.stream))
	c.directory = C.CString(cfg.Directory)
	defer C.free(unsafe.Pointer(c.directory))
	if cfg.StagingBytes == 0 {
		cfg.StagingBytes = DefaultStaging
	}
	if cfg.QuarantineDirectory != "" {
		c.quarantine_directory = C.CString(cfg.QuarantineDirectory)
		defer C.free(unsafe.Pointer(c.quarantine_directory))
	}
	c.staging_bytes = C.uint64_t(cfg.StagingBytes)
	return fn(c)
}

func (r *Receiver) Poll(maxEntries int) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.ptr == nil || maxEntries < 1 || maxEntries > 256 {
		return &Error{Code: int(C.SQLITE_MISUSE)}
	}
	return result(C.murmur_bridge_receiver_poll(r.ptr, C.size_t(maxEntries)))
}
func (r *Receiver) Start(interval time.Duration) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.ptr == nil || interval < 10*time.Millisecond || interval > 60*time.Second {
		return &Error{Code: int(C.SQLITE_MISUSE)}
	}
	return result(C.murmur_bridge_receiver_start(r.ptr, C.uint(interval/time.Millisecond)))
}
func (r *Receiver) Stop() {
	r.mu.Lock()
	defer r.mu.Unlock()
	C.murmur_bridge_receiver_stop(r.ptr)
}
func (r *Receiver) Status() FerryStatus {
	r.mu.Lock()
	defer r.mu.Unlock()
	var s C.murmur_bridge_ferry_status_t
	C.murmur_bridge_receiver_status(r.ptr, &s)
	return FerryStatus{Scanned: uint64(s.scanned), Applied: uint64(s.applied), Duplicate: uint64(s.duplicate), Deferred: uint64(s.deferred), Rejected: uint64(s.rejected), FilesCompleted: uint64(s.files_completed), LastResult: int(s.last_result)}
}
func (r *Receiver) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	C.murmur_bridge_receiver_free(r.ptr)
	r.ptr = nil
	return nil
}

// Files attaches a borrowed native file store while the receiver is stopped.
// Completed bridge objects are encrypted using this store's High-side key.
// Close the receiver before closing its file store or SQL connection.
func (r *Receiver) Files(store unsafe.Pointer) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.ptr == nil || store == nil {
		return &Error{Code: int(C.SQLITE_MISUSE)}
	}
	return result(C.murmur_bridge_receiver_files(r.ptr, (*C.murmur_files_t)(store)))
}
